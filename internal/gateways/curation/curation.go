// Package curation projects a tool definition and enforces per-selection
// argument policy. It never changes its input and never includes values in errors.
package curation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxSchemaBytes = 256 << 10
	MaxPolicyBytes = 64 << 10
	MaxValueBytes  = 8 << 10
	MaxValueNodes  = 256
	MaxConstraints = 50
	MaxSchemaNodes = 2000 // schema nodes plus enum/required entries
	MaxAllowed     = 100
)

type Constraint struct {
	Fixed   json.RawMessage   `json:"fixed,omitempty"`
	Allowed []json.RawMessage `json:"allowed,omitempty"`
}

type Policy struct {
	NameOverride        *string               `json:"nameOverride,omitempty"`
	DescriptionOverride *string               `json:"descriptionOverride,omitempty"`
	Constraints         map[string]Constraint `json:"constraints,omitempty"`
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func validArgumentName(name string) bool {
	return utf8.ValidString(name) && name != "" && utf8.RuneCountInString(name) <= 128 && strings.IndexFunc(name, unicode.IsControl) < 0
}

var errSchema = errors.New("constraints require a supported top-level object schema without references, composition or dependencies")

// Decode rejects malformed/unknown shapes, including fixed and allowed together.
func Decode(raw []byte) (*Policy, error) {
	if len(raw) > MaxPolicyBytes {
		return nil, errors.New("curation exceeds 64 KiB")
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || dec.Decode(&p) != nil {
		return nil, errors.New("invalid curation object")
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(raw, &shape) != nil || shape == nil {
		return nil, errors.New("invalid curation object")
	}
	if p.NameOverride != nil && !namePattern.MatchString(*p.NameOverride) {
		return nil, errors.New("nameOverride must be 1-128 letters, digits, dots, underscores or hyphens")
	}
	if p.DescriptionOverride != nil && (!utf8.ValidString(*p.DescriptionOverride) || utf8.RuneCountInString(*p.DescriptionOverride) > 2000) {
		return nil, errors.New("descriptionOverride must be at most 2000 characters")
	}
	if len(p.Constraints) > MaxConstraints {
		return nil, errors.New("at most 50 argument constraints are allowed")
	}
	// Raw shape distinguishes allowed:null/[] and fixed:null from omission.
	var constraints map[string]map[string]json.RawMessage
	if c, ok := shape["constraints"]; ok && (bytes.Equal(bytes.TrimSpace(c), []byte("null")) || json.Unmarshal(c, &constraints) != nil) {
		return nil, errors.New("constraints must be an object")
	}
	for name, c := range p.Constraints {
		sh := constraints[name]
		_, fixed := sh["fixed"]
		_, allowed := sh["allowed"]
		if !validArgumentName(name) || fixed == allowed || (allowed && (len(c.Allowed) == 0 || len(c.Allowed) > MaxAllowed)) {
			return nil, errors.New("each argument constraint needs exactly one fixed value or 1-100 allowed values")
		}
		vals := c.Allowed
		if fixed {
			vals = []json.RawMessage{c.Fixed}
		}
		for _, v := range vals {
			if len(v) > MaxValueBytes {
				return nil, errors.New("constraint value exceeds 8 KiB")
			}
			if _, err := parseValue(v, nil, true); err != nil {
				return nil, errors.New("invalid constraint value: numbers must round-trip exactly through JSON binary64 and integral values must be safe integers")
			}
		}
	}
	return &p, nil
}

// Project returns a private model-facing copy and normalized policy (allowed
// lists intersect the original enum and type). Rename-only works on any schema.
func Project(definition []byte, p *Policy) ([]byte, *Policy, error) {
	if p == nil {
		return bytes.Clone(definition), nil, nil
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, nil, errors.New("invalid curation")
	}
	p, err = Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	var def map[string]json.RawMessage
	if json.Unmarshal(definition, &def) != nil || def == nil {
		return nil, nil, errors.New("invalid tool definition")
	}
	if p.NameOverride != nil {
		def["name"], _ = json.Marshal(*p.NameOverride)
	}
	if p.DescriptionOverride != nil {
		def["description"], _ = json.Marshal(*p.DescriptionOverride)
	}
	if len(p.Constraints) > 0 {
		schemaRaw := def["inputSchema"]
		if len(schemaRaw) > MaxSchemaBytes {
			return nil, nil, errors.New("input schema exceeds 256 KiB")
		}
		schema, err := object(schemaRaw)
		if err != nil {
			return nil, nil, errSchema
		}
		if !rootSupported(schema) {
			return nil, nil, errSchema
		}
		props, err := object(schema["properties"])
		if err != nil {
			return nil, nil, errSchema
		}
		// An unconstrained property's reference/composition can still depend
		// on a fixed property we remove (including via an absolute $ref).
		// Check the entire property tree, not just the constrained nodes.
		work := newWorkBudget()
		compiled := make(map[string]*compiledSchema, len(props))
		for name, raw := range props {
			property, err := object(raw)
			if err != nil {
				return nil, nil, errSchema
			}
			c, ok := compileSchema(property, 0, work)
			if !ok {
				return nil, nil, errSchema
			}
			compiled[name] = c
		}
		required := []string{}
		if r, ok := schema["required"]; ok && (string(r) == "null" || json.Unmarshal(r, &required) != nil) {
			return nil, nil, errSchema
		}
		if !spend(&work.schema, len(required)) {
			return nil, nil, errSchema
		}
		for arg, c := range p.Constraints {
			original, ok := props[arg]
			if !ok {
				return nil, nil, fmt.Errorf("argument %s is not in the original schema", arg)
			}
			prop, err := object(original)
			if err != nil {
				return nil, nil, fmt.Errorf("argument %s has an unsupported schema", arg)
			}
			validator := compiled[arg]
			if c.Fixed != nil {
				v, err := parseValue(c.Fixed, work, true)
				if err != nil || !validator.valid(v, work) {
					return nil, nil, fmt.Errorf("argument %s fixed value does not satisfy the original schema", arg)
				}
				delete(props, arg)
				next := []string{}
				for _, r := range required {
					if r != arg {
						next = append(next, r)
					}
				}
				required = next
			} else {
				next := []json.RawMessage{}
				seen := map[string]bool{}
				for _, v := range c.Allowed {
					parsed, err := parseValue(v, work, true)
					if err != nil {
						return nil, nil, errSchema
					}
					key, ok := valueKey(parsed, work)
					if !ok {
						return nil, nil, errSchema
					}
					valid := validator.valid(parsed, work)
					if work.validation < 0 || work.arithmetic < 0 {
						return nil, nil, errSchema
					}
					if valid && !seen[key] {
						next = append(next, v)
						seen[key] = true
					}
				}
				if len(next) == 0 {
					return nil, nil, fmt.Errorf("argument %s allowed list has no values satisfying the original schema", arg)
				}
				c.Allowed = next
				p.Constraints[arg] = c
				prop["enum"], _ = json.Marshal(next)
				props[arg], _ = json.Marshal(prop)
			}
		}
		schema["properties"], _ = json.Marshal(props)
		if _, ok := schema["required"]; ok {
			schema["required"], _ = json.Marshal(required)
		}
		def["inputSchema"], _ = json.Marshal(schema)
	}
	out, err := json.Marshal(def)
	return out, p, err
}

// Merge enforces constraints before any consent or upstream operation. Fixed
// arguments are always replaced with the policy's representation, including
// equal client values, so retry bindings do not depend on client spelling.
func Merge(p *Policy, args json.RawMessage) (json.RawMessage, error) {
	if p == nil || len(p.Constraints) == 0 {
		return args, nil
	}
	obj := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(args)) > 0 && !bytes.Equal(bytes.TrimSpace(args), []byte("null")) {
		if json.Unmarshal(args, &obj) != nil || obj == nil {
			return nil, errors.New("arguments must be an object")
		}
	}
	for arg, c := range p.Constraints {
		v, present := obj[arg]
		if c.Fixed != nil {
			if present && !Equal(v, c.Fixed) {
				return nil, fmt.Errorf("argument %s is fixed by this gateway", arg)
			}
			obj[arg] = c.Fixed
		} else if present && !contains(c.Allowed, v) {
			return nil, fmt.Errorf("argument %s is not allowed by this gateway", arg)
		}
	}
	return json.Marshal(obj)
}

// Summary is safe for audit: it never contains a constraint value. Text fields
// are bounded by Decode; omit descriptions entirely to avoid accidental secrets.
func Summary(p *Policy) map[string]any {
	if p == nil {
		return nil
	}
	raw, _ := json.Marshal(p.Constraints)
	sum := sha256.Sum256(raw)
	m := map[string]any{"constraintCount": len(p.Constraints), "constraintsDigest": hex.EncodeToString(sum[:])}
	if p.NameOverride != nil {
		m["nameOverride"] = *p.NameOverride
	}
	if p.DescriptionOverride != nil {
		b := sha256.Sum256([]byte(*p.DescriptionOverride))
		m["descriptionDigest"] = hex.EncodeToString(b[:])
		m["descriptionLength"] = utf8.RuneCountInString(*p.DescriptionOverride)
	}
	return m
}

func object(raw []byte) (map[string]json.RawMessage, error) {
	var o map[string]json.RawMessage
	err := json.Unmarshal(raw, &o)
	if err == nil && o == nil {
		err = errSchema
	}
	return o, err
}
func contains(vals []json.RawMessage, v json.RawMessage) bool {
	parsed, err := value(v)
	if err != nil {
		return false
	}
	for _, x := range vals {
		candidate, err := value(x)
		if err == nil && equal(candidate, parsed) {
			return true
		}
	}
	return false
}
