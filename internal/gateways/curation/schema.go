package curation

import (
	"encoding/json"
	"math/big"
	"regexp"
	"strconv"
	"unicode/utf8"
)

func annotation(k string) bool {
	switch k {
	case "title", "description", "default", "examples", "$comment", "deprecated", "readOnly", "writeOnly", "x-mcp-header":
		return true
	}
	return false
}
func rootSupported(s map[string]json.RawMessage) bool {
	if string(s["type"]) != `"object"` {
		return false
	}
	for k, v := range s {
		switch k {
		case "type", "properties", "required", "$schema":
		case "additionalProperties":
			if string(v) != "true" && string(v) != "false" {
				return false
			}
		default:
			if !annotation(k) {
				return false
			}
		}
	}
	return true
}

// All parsing/normalization (including enum entries, numbers and patterns) is
// done once. No schema raw JSON is reparsed by valid, even for nested values.
type compiledSchema struct {
	types             []string
	enum              map[string]bool
	constant          *string
	numbers           map[string]*decimal
	lengths           map[string]int
	pattern           *regexp.Regexp
	unique            bool
	required          []string
	properties        map[string]*compiledSchema
	items, additional *compiledSchema
	noAdditional      bool
}

// Deliberately closed keyword set. No refs, compositions, conditionals,
// dependencies, unevaluated*, patternProperties, or formats.
func compileSchema(s map[string]json.RawMessage, depth int, w *workBudget) (*compiledSchema, bool) {
	if depth > 16 || !spend(&w.schema, 1) {
		return nil, false
	}
	c := &compiledSchema{numbers: map[string]*decimal{}, lengths: map[string]int{}}
	for k, v := range s {
		if annotation(k) {
			continue
		}
		switch k {
		case "type":
			var t string
			if json.Unmarshal(v, &t) == nil {
				c.types = []string{t}
			} else if json.Unmarshal(v, &c.types) != nil {
				return nil, false
			}
			if len(c.types) == 0 || len(c.types) > 7 {
				return nil, false
			}
			for _, t := range c.types {
				switch t {
				case "string", "number", "integer", "boolean", "null", "object", "array":
				default:
					return nil, false
				}
			}
		case "enum":
			var a []json.RawMessage
			if json.Unmarshal(v, &a) != nil || len(a) == 0 || len(a) > 1000 || !spend(&w.schema, len(a)) {
				return nil, false
			}
			c.enum = make(map[string]bool, len(a))
			for _, raw := range a {
				x, err := parseValue(raw, w, true)
				if err != nil {
					return nil, false
				}
				key, ok := valueKey(x, w)
				if !ok {
					return nil, false
				}
				c.enum[key] = true
			}
		case "const":
			x, err := parseValue(v, w, true)
			if err != nil {
				return nil, false
			}
			key, ok := valueKey(x, w)
			if !ok {
				return nil, false
			}
			c.constant = &key
		case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf":
			x, err := parseValue(v, w, true)
			n, ok := x.(*decimal)
			if err != nil || !ok || (k == "multipleOf" && n.rat.Sign() <= 0) {
				return nil, false
			}
			c.numbers[k] = n
		case "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties":
			n, err := strconv.ParseInt(string(v), 10, 32)
			if err != nil || n < 0 {
				return nil, false
			}
			c.lengths[k] = int(n)
		case "pattern":
			var p string
			if string(v) == "null" || json.Unmarshal(v, &p) != nil || len(p) > 4096 {
				return nil, false
			}
			r, err := regexp.Compile(p)
			if err != nil {
				return nil, false
			}
			c.pattern = r
		case "uniqueItems":
			if string(v) != "true" && string(v) != "false" {
				return nil, false
			}
			c.unique = string(v) == "true"
		case "required":
			if string(v) == "null" || json.Unmarshal(v, &c.required) != nil || !spend(&w.schema, len(c.required)) {
				return nil, false
			}
		case "properties":
			props, err := object(v)
			if err != nil {
				return nil, false
			}
			c.properties = make(map[string]*compiledSchema, len(props))
			for k, raw := range props {
				o, err := object(raw)
				if err != nil {
					return nil, false
				}
				child, ok := compileSchema(o, depth+1, w)
				if !ok {
					return nil, false
				}
				c.properties[k] = child
			}
		case "items", "additionalProperties":
			if k == "additionalProperties" {
				if string(v) == "true" {
					continue
				}
				if string(v) == "false" {
					c.noAdditional = true
					continue
				}
			}
			o, err := object(v)
			if err != nil {
				return nil, false
			}
			child, ok := compileSchema(o, depth+1, w)
			if !ok {
				return nil, false
			}
			if k == "items" {
				c.items = child
			} else {
				c.additional = child
			}
		default:
			return nil, false
		}
	}
	return c, true
}

func (s *compiledSchema) valid(v any, w *workBudget) bool {
	if !spend(&w.validation, 1) {
		return false
	}
	if len(s.types) > 0 {
		matches := false
		for _, t := range s.types {
			switch t {
			case "null":
				matches = matches || v == nil
			case "boolean":
				_, ok := v.(bool)
				matches = matches || ok
			case "string":
				_, ok := v.(string)
				matches = matches || ok
			case "number", "integer":
				if n, ok := v.(*decimal); ok {
					matches = matches || t == "number" || n.exponent >= 0
				}
			case "object":
				_, ok := v.(map[string]any)
				matches = matches || ok
			case "array":
				_, ok := v.([]any)
				matches = matches || ok
			}
		}
		if !matches {
			return false
		}
	}
	if s.constant != nil || s.enum != nil {
		key, ok := valueKey(v, w)
		if !ok || (s.constant != nil && *s.constant != key) || (s.enum != nil && !s.enum[key]) {
			return false
		}
	}
	length := func(min, max string, n int) bool {
		if x, ok := s.lengths[min]; ok && n < x {
			return false
		}
		if x, ok := s.lengths[max]; ok && n > x {
			return false
		}
		return true
	}
	switch x := v.(type) {
	case *decimal:
		for k, b := range s.numbers {
			// Rat.Cmp/Quo multiply bounded integers. Charge a conservative
			// bit-product bound BEFORE doing either operation, cumulatively.
			n := x.rat
			m := b.rat
			bitsN := n.Num().BitLen() + n.Denom().BitLen()
			bitsM := m.Num().BitLen() + m.Denom().BitLen()
			if !spend(&w.arithmetic, (bitsN+1)*(bitsM+1)) {
				return false
			}
			cmp := n.Cmp(m)
			switch k {
			case "minimum":
				if cmp < 0 {
					return false
				}
			case "maximum":
				if cmp > 0 {
					return false
				}
			case "exclusiveMinimum":
				if cmp <= 0 {
					return false
				}
			case "exclusiveMaximum":
				if cmp >= 0 {
					return false
				}
			case "multipleOf":
				if !new(big.Rat).Quo(n, m).IsInt() {
					return false
				}
			}
		}
	case string:
		if !length("minLength", "maxLength", utf8.RuneCountInString(x)) {
			return false
		}
		// RE2 is linear, but input times patterns still needs a total budget.
		if s.pattern != nil && (!spend(&w.validation, len(x)+1) || !s.pattern.MatchString(x)) {
			return false
		}
	case []any:
		if !length("minItems", "maxItems", len(x)) {
			return false
		}
		seen := map[string]bool{}
		for _, v := range x {
			if s.unique {
				key, ok := valueKey(v, w)
				if !ok || seen[key] {
					return false
				}
				seen[key] = true
			}
			if s.items != nil && !s.items.valid(v, w) {
				return false
			}
		}
	case map[string]any:
		if !length("minProperties", "maxProperties", len(x)) || !spend(&w.validation, len(s.required)) {
			return false
		}
		for _, k := range s.required {
			if _, ok := x[k]; !ok {
				return false
			}
		}
		for k, v := range x {
			if child, ok := s.properties[k]; ok {
				if !child.valid(v, w) {
					return false
				}
			} else if s.noAdditional || (s.additional != nil && !s.additional.valid(v, w)) {
				return false
			}
		}
	}
	return true
}
