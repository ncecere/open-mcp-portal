package curation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalConstraintRepresentations(t *testing.T) {
	for _, tc := range []struct{ input, canonical string }{
		{"0e-9999", "0"}, {"-0e10000", "0"}, {"0.1000000000000000", "1e-1"},
		{"2e0", "2"}, {"20.000", "20"}, {"9007199254740991.0", "9007199254740991"},
		{"0." + strings.Repeat("0", 323) + "5", "5e-324"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			p := policy(t, `{"constraints":{"x":{"fixed":{"nested":[`+tc.input+`,null,"0e-9999"]}},"y":{"allowed":[`+tc.input+`,null,"0e-9999"]},"nil":{"fixed":null}}}`)
			c := p.Constraints
			if string(c["x"].Fixed) != `{"nested":[`+tc.canonical+`,null,"0e-9999"]}` || string(c["y"].Allowed[0]) != tc.canonical {
				t.Fatalf("noncanonical numeric representations: %+v", p)
			}
			if string(c["nil"].Fixed) != "null" || c["nil"].Allowed != nil || c["y"].Fixed != nil || string(c["y"].Allowed[1]) != "null" || string(c["y"].Allowed[2]) != `"0e-9999"` {
				t.Fatal("canonicalization changed null/omission/string semantics")
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			q := policy(t, string(raw))
			if string(mustJSON(t, q)) != string(raw) {
				t.Fatal("canonicalization was not idempotent")
			}
		})
	}
	for _, oversized := range []string{"0e" + strings.Repeat("0", 511), "0." + strings.Repeat("0", 511) + "1"} {
		if _, err := Decode([]byte(`{"constraints":{"x":{"fixed":` + oversized + `}}}`)); err == nil {
			t.Fatal("numeric lexeme exceeded the 512-byte bound")
		}
	}
}
