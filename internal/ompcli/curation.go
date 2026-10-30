package ompcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	gwcuration "github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// Curation is a tool's per-selection policy (docs/gateway-curation.md): a
// name override, a description override and per-argument constraints. It is
// the portal's own policy type, so the file is validated and normalized by
// exactly the code that validates and stores it.
//
// In a file, an absent `curation` leaves the selection's policy alone and
// `curation: null` declares "no policy". An automation token cannot write
// either (403 session_required), so omp only compares: a declaration that
// equals the portal's is no change; one that differs is refused before
// anything is written (docs/cli.md, "Curation").
type Curation struct {
	// Clear is `curation: null`: the selection has no policy.
	Clear  bool
	Policy *gwcuration.Policy
}

var allowedCurationKeys = map[string]bool{"nameOverride": true, "descriptionOverride": true, "constraints": true}

var yaml11Bool = regexp.MustCompile(`(?i)^(y|yes|n|no|on|off)$`)

var jsonNumberRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// UnmarshalYAML reads a non-null curation mapping. Values are converted to
// JSON from their YAML spelling, so a number keeps its exact digits (the
// portal refuses numbers that would be rounded) and nothing YAML-specific (a
// timestamp, a hexadecimal integer, an alias) can turn into a different value.
func (c *Curation) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: curation must be a mapping or null", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i].Value; !allowedCurationKeys[k] {
			return fmt.Errorf("line %d: curation has no field %q (nameOverride, descriptionOverride, constraints)", n.Content[i].Line, k)
		}
	}
	var buf bytes.Buffer
	if err := yamlToJSON(n, &buf, 0); err != nil {
		return err
	}
	if buf.Len() > gwcuration.MaxPolicyBytes {
		return fmt.Errorf("line %d: curation exceeds 64 KiB", n.Line)
	}
	p, err := gwcuration.Decode(buf.Bytes())
	if err != nil {
		return fmt.Errorf("line %d: curation: %v", n.Line, err)
	}
	c.Clear, c.Policy = false, p
	return nil
}

func yamlToJSON(n *yaml.Node, buf *bytes.Buffer, depth int) error {
	if depth > 40 {
		return fmt.Errorf("line %d: curation is nested too deeply", n.Line)
	}
	switch n.Kind {
	case yaml.AliasNode:
		return fmt.Errorf("line %d: anchors and aliases are not supported in curation", n.Line)
	case yaml.MappingNode:
		buf.WriteByte('{')
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return fmt.Errorf("line %d: keys in curation must be strings (quote %q)", k.Line, k.Value)
			}
			if seen[k.Value] {
				return fmt.Errorf("line %d: %q is given twice", k.Line, k.Value)
			}
			seen[k.Value] = true
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k.Value)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := yamlToJSON(v, buf, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for i, v := range n.Content {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := yamlToJSON(v, buf, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str":
			b, _ := json.Marshal(n.Value)
			buf.Write(b)
		case "!!null":
			buf.WriteString("null")
		case "!!bool":
			switch n.Value {
			case "true", "True", "TRUE":
				buf.WriteString("true")
			case "false", "False", "FALSE":
				buf.WriteString("false")
			default:
				return fmt.Errorf("line %d: %q is not a JSON boolean", n.Line, n.Value)
			}
		case "!!int", "!!float":
			if !jsonNumberRE.MatchString(n.Value) {
				return fmt.Errorf("line %d: %q is not a plain decimal number (write it as one, or quote it to make it a string)", n.Line, n.Value)
			}
			buf.WriteString(n.Value)
		default:
			return fmt.Errorf("line %d: %q is a %s, which has no JSON form (quote it to make it a string)", n.Line, n.Value, strings.TrimPrefix(n.ShortTag(), "!!"))
		}
	default:
		return fmt.Errorf("line %d: unsupported YAML in curation", n.Line)
	}
	return nil
}

// MarshalYAML writes the policy in the order the portal returns it; the
// values keep their canonical spelling.
func (c Curation) MarshalYAML() (any, error) {
	if c.Clear || c.Policy == nil {
		return nil, nil
	}
	raw, err := json.Marshal(c.Policy)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return jsonToNode(dec)
}

// MarshalJSON writes `null` for a declared clear.
func (c Curation) MarshalJSON() ([]byte, error) {
	if c.Clear || c.Policy == nil {
		return []byte("null"), nil
	}
	return json.Marshal(c.Policy)
}

func jsonToNode(dec *json.Decoder) (*yaml.Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := jsonToNode(dec)
				if err != nil {
					return nil, err
				}
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kt.(string)}, v)
			}
			_, err = dec.Token()
			return m, err
		}
		s := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for dec.More() {
			v, err := jsonToNode(dec)
			if err != nil {
				return nil, err
			}
			s.Content = append(s.Content, v)
		}
		_, err = dec.Token()
		return s, err
	case string:
		n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}
		if yaml11Bool.MatchString(t) {
			n.Style = yaml.DoubleQuotedStyle // YAML 1.1 readers take a bare yes or on for a boolean
		}
		return n, nil
	case json.Number:
		tag := "!!float"
		if !strings.ContainsAny(t.String(), ".eE") {
			tag = "!!int"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: t.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(t)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, errors.New("unsupported JSON value")
}

// validate checks a policy exactly as the portal does when it is written
// (shape, bounds, value spelling); it needs no network.
func (c *Curation) validate() error {
	if c.Clear {
		return nil
	}
	if c.Policy == nil {
		return errors.New("curation must be a mapping or null")
	}
	raw, err := json.Marshal(c.Policy)
	if err != nil {
		return err
	}
	_, err = gwcuration.Decode(raw)
	return err
}

// summary describes a policy without any constraint value, which may be a
// secret (docs/gateway-curation.md audit rules): names, counts and a digest.
func curationSummary(p *gwcuration.Policy) string {
	if p == nil {
		return "none"
	}
	var parts []string
	if p.NameOverride != nil {
		parts = append(parts, "nameOverride="+*p.NameOverride)
	}
	if p.DescriptionOverride != nil {
		parts = append(parts, fmt.Sprintf("descriptionOverride(%d chars)", len([]rune(*p.DescriptionOverride))))
	}
	if len(p.Constraints) > 0 {
		names := make([]string, 0, len(p.Constraints))
		for k := range p.Constraints {
			names = append(names, k)
		}
		sort.Strings(names)
		raw, _ := json.Marshal(p)
		sum := sha256.Sum256(raw)
		parts = append(parts, fmt.Sprintf("constraints on %s [%s]", strings.Join(names, ", "), hex.EncodeToString(sum[:4])))
	}
	if len(parts) == 0 {
		return "empty policy"
	}
	return strings.Join(parts, ", ")
}

// ---- reading what the portal returns -------------------------------------------

// readCuration is the policy a selection read carries: nil when the selection
// is not curated. A selection that the portal says is curated (it has a base
// fingerprint) but whose policy the read does not carry, or carries in a shape
// this client cannot decode, is an error: omp must not export or compare a
// policy it cannot see, and never treats it as "none".
func readCuration(it ompclient.GatewayCapability) (*gwcuration.Policy, error) {
	raw := bytes.TrimSpace(it.Curation)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		if it.BaseFingerprint != nil {
			return nil, errors.New("the portal reports a curation policy but did not return it")
		}
		return nil, nil
	}
	p, err := gwcuration.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("the portal's curation policy is not one this version of omp can read (%v)", err)
	}
	return p, nil
}

func curationStale(it ompclient.GatewayCapability) bool { return it.Stale != nil && *it.Stale }

// curationMatches reports whether a declared curation equals what the portal
// has for the selection. A policy is compared as the portal would store it: the
// declared one is projected against the tool's original definition, so allowed
// lists narrowed to the schema's enum compare equal. A stale policy (its tool's
// definition changed after it was saved) is compared as stored.
func curationMatches(it ompclient.GatewayCapability, decl *Curation) (bool, error) {
	have, err := readCuration(it)
	if err != nil {
		return false, err
	}
	if decl.Clear {
		return have == nil, nil
	}
	if have == nil {
		return false, nil
	}
	want := decl.Policy
	if !curationStale(it) {
		_, normalized, err := gwcuration.Project(it.OriginalDefinition, want)
		if err != nil {
			return false, fmt.Errorf("the declared curation does not hold for the tool's current definition: %v", err)
		}
		want = normalized
	} else {
		raw, _ := json.Marshal(want)
		if want, err = gwcuration.Decode(raw); err != nil {
			return false, err
		}
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(have)
	return bytes.Equal(a, b), nil
}

// curationSig identifies a selection's whole policy state, to prove that a
// write left it unchanged.
func curationSig(it ompclient.GatewayCapability) string {
	var compact bytes.Buffer
	if raw := bytes.TrimSpace(it.Curation); len(raw) > 0 {
		if err := json.Compact(&compact, raw); err != nil {
			compact.Reset()
			compact.Write(raw)
		}
	}
	return deref(it.BaseFingerprint) + "|" + compact.String()
}
