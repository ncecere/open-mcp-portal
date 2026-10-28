package curation

import (
	"bytes"
	"encoding/json"
	"errors"
)

const (
	MaxCompiledValueNodes = 8192
	MaxValidationWork     = 100000
	MaxArithmeticWork     = 16 << 20
)

// Local to one projection: no cached authorization or stale schema state.
// Each budget is charged BEFORE the corresponding traversal/arithmetic.
type workBudget struct {
	schema, values, validation, arithmetic int
}

func newWorkBudget() *workBudget {
	return &workBudget{MaxSchemaNodes, MaxCompiledValueNodes, MaxValidationWork, MaxArithmeticWork}
}
func spend(left *int, cost int) bool {
	if cost < 0 || cost > *left {
		*left = -1
		return false
	}
	*left -= cost
	return true
}

func value(raw []byte) (any, error) { return parseValue(raw, nil, false) }

func parseValue(raw []byte, w *workBudget, portable bool) (any, error) {
	if len(raw) > MaxValueBytes || !json.Valid(raw) {
		return nil, errors.New("invalid JSON value")
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := MaxValueNodes
	if d.Decode(&v) != nil || !normalizeValue(&v, 0, &budget, w, portable) {
		return nil, errors.New("invalid or unsupported JSON value")
	}
	return v, nil
}

func normalizeValue(v *any, depth int, budget *int, w *workBudget, portable bool) bool {
	if depth > 32 || !spend(budget, 1) || (w != nil && !spend(&w.values, 1)) {
		return false
	}
	switch x := (*v).(type) {
	case json.Number:
		n, ok := normalizeNumber(string(x))
		if !ok || (w == nil && portable && !portableNumber(n)) || (w != nil && !n.compile(w)) {
			return false
		}
		*v = n
	case []any:
		for i := range x {
			if !normalizeValue(&x[i], depth+1, budget, w, portable) {
				return false
			}
		}
	case map[string]any:
		for k, child := range x {
			if !normalizeValue(&child, depth+1, budget, w, portable) {
				return false
			}
			x[k] = child
		}
	}
	return true
}

// Equal compares exact normalized decimals, with distinct JSON types. It does
// not apply the narrower curation-authoring numeric limits to client arguments.
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
	case *decimal:
		y, ok := b.(*decimal)
		return ok && x.text == y.text
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

// Canonical JSON keys make enum membership/deduplication linear in the total
// value size, rather than enum-size times allowed-size times numeric parsing.
func valueKey(v any, w *workBudget) (string, bool) {
	var visit func(any) bool
	visit = func(v any) bool {
		if !spend(&w.validation, 1) {
			return false
		}
		switch x := v.(type) {
		case []any:
			for _, v := range x {
				if !visit(v) {
					return false
				}
			}
		case map[string]any:
			for _, v := range x {
				if !visit(v) {
					return false
				}
			}
		}
		return true
	}
	if !visit(v) {
		return "", false
	}
	b, err := json.Marshal(v)
	return string(b), err == nil
}
