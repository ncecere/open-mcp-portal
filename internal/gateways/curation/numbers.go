package curation

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// decimal is an exact, normalized decimal, not a binary floating-point value.
// Normalization only moves the decimal point; it never constructs exponent powers.
// rat is populated once, only for bounded projection-time arithmetic.
type decimal struct {
	text     string
	exponent int
	rat      *big.Rat
}

func (n *decimal) MarshalJSON() ([]byte, error) { return []byte(n.text), nil }

func normalizeNumber(s string) (*decimal, bool) {
	if len(s) == 0 || len(s) > 256 {
		return nil, false
	}
	exponent := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n < -10000 || n > 10000 {
			return nil, false
		}
		exponent, s = n, s[:i]
	}
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent -= len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return &decimal{text: "0"}, true
	}
	n := len(s)
	s = strings.TrimRight(s, "0")
	exponent += n - len(s)
	return &decimal{text: sign + s + "e" + strconv.Itoa(exponent), exponent: exponent}, true
}

// portableNumber implements the curation-only JSON binary64 round-trip policy.
// It compares bounded decimal spellings, not binary fractions (0.1 is accepted).
// Unconstrained runtime arguments are not subject to this authoring restriction.
func portableNumber(n *decimal) bool {
	f, err := strconv.ParseFloat(n.text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || (n.exponent >= 0 && math.Abs(f) > 9007199254740991) {
		return false
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return false
	}
	roundtrip, ok := normalizeNumber(string(raw))
	return ok && n.text == roundtrip.text
}

func (n *decimal) compile(w *workBudget) bool {
	if !portableNumber(n) {
		return false
	}
	// Bound all rational allocation before SetString, cumulatively across the
	// projection. Portable decimals have at most 324 fractional exponent places.
	cost := len(n.text) + max(0, -n.exponent)
	if !spend(&w.arithmetic, cost*cost) {
		return false
	}
	var ok bool
	n.rat, ok = new(big.Rat).SetString(n.text)
	return ok
}
