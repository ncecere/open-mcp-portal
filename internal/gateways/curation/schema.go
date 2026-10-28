package curation

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Numbers are parsed exactly and bounded before rational allocation. Never
// round through float64: 9007199254740992 and 9007199254740993 differ.
func number(s string) (*big.Rat, bool) {
	if len(s) > 256 {
		return nil, false
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n > 10000 || n < -10000 {
			return nil, false
		}
	}
	n, ok := new(big.Rat).SetString(s)
	return n, ok
}
func value(raw []byte) (any, error) {
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON value")
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	work := MaxValueNodes
	if d.Decode(&v) != nil || !safeValue(v, 0, &work) {
		return nil, errors.New("invalid JSON value")
	}
	return v, nil
}
func safeValue(v any, depth int, budget *int) bool {
	*budget -= 1
	if depth > 32 || *budget < 0 {
		return false
	}
	switch x := v.(type) {
	case json.Number:
		_, ok := number(string(x))
		return ok
	case []any:
		for _, v := range x {
			if !safeValue(v, depth+1, budget) {
				return false
			}
		}
	case map[string]any:
		for _, v := range x {
			if !safeValue(v, depth+1, budget) {
				return false
			}
		}
	}
	return true
}

// Equal compares JSON values with exact numeric equality and distinct types.
func Equal(a, b []byte) bool {
	x, e := value(a)
	if e != nil {
		return false
	}
	y, e := value(b)
	return e == nil && equal(x, y)
}
func equal(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		n, ok := number(string(x))
		m, ok2 := number(string(y))
		return ok && ok2 && n.Cmp(m) == 0
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !equal(v, w) {
				return false
			}
		}
		return true
	}
	return false
}
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

// Deliberately closed keyword set. In particular no refs, compositions,
// conditionals, dependencies, unevaluated*, patternProperties or formats.
func supported(s map[string]json.RawMessage, depth int, budget *int) bool {
	*budget -= 1
	if depth > 16 || *budget < 0 {
		return false
	}
	for k, v := range s {
		if annotation(k) {
			continue
		}
		switch k {
		case "type":
			var t any
			if json.Unmarshal(v, &t) != nil {
				return false
			}
			validType := func(t string) bool {
				return t == "string" || t == "number" || t == "integer" || t == "boolean" || t == "null" || t == "object" || t == "array"
			}
			switch t := t.(type) {
			case string:
				if !validType(t) {
					return false
				}
			case []any:
				if len(t) == 0 || len(t) > 7 {
					return false
				}
				for _, x := range t {
					s, ok := x.(string)
					if !ok || !validType(s) {
						return false
					}
				}
			default:
				return false
			}
		case "enum":
			var a []json.RawMessage
			if json.Unmarshal(v, &a) != nil || len(a) == 0 || len(a) > 1000 {
				return false
			}
			*budget -= len(a)
			if *budget < 0 {
				return false
			}
			for _, r := range a {
				if _, err := value(r); err != nil {
					return false
				}
			}
		case "const":
			if _, err := value(v); err != nil {
				return false
			}
		case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf":
			n, ok := number(string(v))
			if !ok || (k == "multipleOf" && n.Sign() <= 0) {
				return false
			}
		case "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties":
			n, err := strconv.ParseInt(string(v), 10, 32)
			if err != nil || n < 0 {
				return false
			}
		case "pattern":
			var p string
			if string(v) == "null" || json.Unmarshal(v, &p) != nil || len(p) > 4096 {
				return false
			}
			if _, err := regexp.Compile(p); err != nil {
				return false
			}
		case "uniqueItems":
			if string(v) != "true" && string(v) != "false" {
				return false
			}
		case "required":
			var a []string
			if string(v) == "null" || json.Unmarshal(v, &a) != nil {
				return false
			}
			*budget -= len(a)
			if *budget < 0 {
				return false
			}
		case "properties":
			props, err := object(v)
			if err != nil {
				return false
			}
			for _, raw := range props {
				o, err := object(raw)
				if err != nil || !supported(o, depth+1, budget) {
					return false
				}
			}
		case "items":
			o, err := object(v)
			if err != nil || !supported(o, depth+1, budget) {
				return false
			}
		case "additionalProperties":
			if string(v) != "true" && string(v) != "false" {
				o, err := object(v)
				if err != nil || !supported(o, depth+1, budget) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
func valid(s map[string]json.RawMessage, v any, depth int) bool {
	if depth > 32 {
		return false
	}
	if raw, ok := s["type"]; ok {
		var types []string
		var t string
		if json.Unmarshal(raw, &t) == nil {
			types = []string{t}
		} else {
			_ = json.Unmarshal(raw, &types)
		}
		matches := false
		for _, t := range types {
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
				if n, ok := v.(json.Number); ok {
					r, _ := number(string(n))
					matches = matches || (r != nil && (t == "number" || r.IsInt()))
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
	if raw, ok := s["const"]; ok {
		c, _ := value(raw)
		if !equal(v, c) {
			return false
		}
	}
	if raw, ok := s["enum"]; ok {
		var a []json.RawMessage
		_ = json.Unmarshal(raw, &a)
		found := false
		for _, r := range a {
			x, _ := value(r)
			found = found || equal(v, x)
		}
		if !found {
			return false
		}
	}
	length := func(min, max string, n int) bool {
		if raw, ok := s[min]; ok {
			x, _ := strconv.Atoi(string(raw))
			if n < x {
				return false
			}
		}
		if raw, ok := s[max]; ok {
			x, _ := strconv.Atoi(string(raw))
			if n > x {
				return false
			}
		}
		return true
	}
	switch x := v.(type) {
	case json.Number:
		n, _ := number(string(x))
		if n == nil {
			return false
		}
		for _, k := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
			if raw, ok := s[k]; ok {
				b, ok := number(string(raw))
				if !ok {
					return false
				}
				cmp := n.Cmp(b)
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
					if !new(big.Rat).Quo(n, b).IsInt() {
						return false
					}
				}
			}
		}
	case string:
		if !length("minLength", "maxLength", utf8.RuneCountInString(x)) {
			return false
		}
		if raw, ok := s["pattern"]; ok {
			var p string
			_ = json.Unmarshal(raw, &p)
			r, err := regexp.Compile(p)
			if err != nil || !r.MatchString(x) {
				return false
			}
		}
	case []any:
		if !length("minItems", "maxItems", len(x)) {
			return false
		}
		if string(s["uniqueItems"]) == "true" {
			for i := range x {
				for j := 0; j < i; j++ {
					if equal(x[i], x[j]) {
						return false
					}
				}
			}
		}
		if raw, ok := s["items"]; ok {
			o, _ := object(raw)
			for _, v := range x {
				if !valid(o, v, depth+1) {
					return false
				}
			}
		}
	case map[string]any:
		if !length("minProperties", "maxProperties", len(x)) {
			return false
		}
		var required []string
		_ = json.Unmarshal(s["required"], &required)
		for _, k := range required {
			if _, ok := x[k]; !ok {
				return false
			}
		}
		props, _ := object(s["properties"])
		for k, v := range x {
			if raw, ok := props[k]; ok {
				o, _ := object(raw)
				if !valid(o, v, depth+1) {
					return false
				}
			} else if a, ok := s["additionalProperties"]; ok {
				if string(a) == "false" {
					return false
				}
				if string(a) != "true" {
					o, _ := object(a)
					if !valid(o, v, depth+1) {
						return false
					}
				}
			}
		}
	}
	return true
}
