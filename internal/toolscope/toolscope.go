// Package toolscope implements tool ceilings, never grants of access.
// Nil scopes include unclassified tools; empty scopes deny everything.
package toolscope

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
)

const MaxTools = 500
const MaxNameLength = 1100

func Class(c *string) string {
	if c == nil {
		return ""
	}
	return *c
}

var classes = []string{"read", "write", "destructive"}

// Scope is a disjunction of trusted classes and exact exposed tool names.
type Scope struct {
	Classes []string `json:"classes,omitempty"`
	Tools   []string `json:"tools,omitempty"`
}

// Parse validates and canonicalizes a scope. An absent value is unrestricted.
func Parse(raw []byte) (*Scope, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	bad := func() (*Scope, error) {
		return nil, apperr.Invalid("invalid_tool_scope", "toolScope accepts at most 3 valid classes and 500 exact tool names (1-1100 UTF-8 bytes, no controls or glob operators)")
	}
	if raw[0] != '{' || !utf8.Valid(raw) {
		return bad()
	}
	var s Scope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return bad()
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return bad()
	}
	if len(s.Classes) > 3 || len(s.Tools) > MaxTools {
		return bad()
	}
	for _, c := range s.Classes {
		if !slices.Contains(classes, c) {
			return bad()
		}
	}
	for _, n := range s.Tools {
		if len(n) == 0 || len(n) > MaxNameLength || !utf8.ValidString(n) || strings.ContainsAny(n, `*?[]{}\`) || strings.IndexFunc(n, unicode.IsControl) >= 0 {
			return bad()
		}
	}
	slices.Sort(s.Classes)
	s.Classes = slices.Compact(s.Classes)
	slices.Sort(s.Tools)
	s.Tools = slices.Compact(s.Tools)
	return &s, nil
}

// Stored reads database JSON, denying all on corruption instead of widening.
func Stored(raw []byte) *Scope {
	s, err := Parse(raw)
	if err != nil {
		return &Scope{}
	}
	return s
}

// OAuthStored additionally rejects named tools: OAuth grants carry class
// scopes only. Corrupt data must not advertise deny-all while allowing names.
func OAuthStored(raw []byte) *Scope {
	s := Stored(raw)
	if s != nil && len(s.Tools) > 0 {
		return &Scope{}
	}
	return s
}

// JSON is the canonical stored form (nil is SQL NULL).
func JSON(s *Scope) []byte {
	if s == nil {
		return nil
	}
	b, _ := json.Marshal(s)
	return b
}
func Canonical(raw []byte) ([]byte, error) { s, err := Parse(raw); return JSON(s), err }

// Allows matches a class OR name. An unclassified tool has an empty class.
func Allows(s *Scope, class, name string) bool {
	return s == nil || (class != "" && slices.Contains(s.Classes, class)) || slices.Contains(s.Tools, name)
}

// Policy retains independent AND layers of OR alternatives. Its zero value
// is unrestricted; an empty union is deny-all. Do not intersect arrays: a
// read-class scope AND a named-tool scope must still match that read tool.
type Policy struct{ layers [][]*Scope }

func Union(scopes ...*Scope) Policy { return Policy{layers: [][]*Scope{scopes}} }
func Intersect(ps ...Policy) Policy {
	var p Policy
	for _, q := range ps {
		p.layers = append(p.layers, q.layers...)
	}
	return p
}
func (p Policy) Allows(class, name string) bool {
	for _, layer := range p.layers {
		ok := false
		for _, s := range layer {
			if Allows(s, class, name) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Subset checks these simple scope predicates for every possible class/name,
// including future and unclassified tools. Nil alone includes all of them.
func Subset(s, ceiling *Scope) bool {
	if ceiling == nil {
		return true
	}
	if s == nil {
		return false
	}
	for _, c := range s.Classes {
		if !slices.Contains(ceiling.Classes, c) {
			return false
		}
	}
	for _, n := range s.Tools {
		if !slices.Contains(ceiling.Tools, n) {
			return false
		}
	}
	return true
}
func Equal(a, b *Scope) bool { return Subset(a, b) && Subset(b, a) }

// OAuth parses the protocol class strings. Missing scope is unrestricted;
// explicit empty scope is the deny-all set.
func OAuth(value string, present bool) (*Scope, error) {
	if !present && value == "" {
		return nil, nil
	}
	s := &Scope{}
	for _, v := range strings.Fields(value) {
		if !strings.HasPrefix(v, "omp:") || !slices.Contains(classes, strings.TrimPrefix(v, "omp:")) {
			return nil, errors.New("unknown OAuth tool scope")
		}
		s.Classes = append(s.Classes, strings.TrimPrefix(v, "omp:"))
	}
	slices.Sort(s.Classes)
	s.Classes = slices.Compact(s.Classes)
	return s, nil
}
func OAuthString(s *Scope) *string {
	if s == nil {
		return nil
	}
	out := []string{}
	for _, c := range classes {
		if slices.Contains(s.Classes, c) {
			out = append(out, "omp:"+c)
		}
	}
	v := strings.Join(out, " ")
	return &v
}
