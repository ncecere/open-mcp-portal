package toolscope

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestScopeAlgebra(t *testing.T) {
	read := &Scope{Classes: []string{"read"}}
	write := &Scope{Classes: []string{"write"}}
	named := &Scope{Tools: []string{"status__find"}}
	mixed := &Scope{Classes: []string{"read"}, Tools: []string{"status__destroy"}}
	for _, tc := range []struct {
		name        string
		policy      Policy
		class, tool string
		want        bool
	}{
		{"zero unrestricted", Policy{}, "", "status__find", true},
		{"null unrestricted", Union(nil), "", "status__find", true},
		{"empty denies", Union(&Scope{}), "read", "status__find", false},
		{"empty union denies", Union(), "read", "status__find", false},
		{"unclassified fails class", Union(read), "", "status__find", false},
		{"unclassified exact name", Union(named), "", "status__find", true},
		{"no partial names", Union(named), "read", "status__finder", false},
		{"mixed name branch", Union(mixed), "destructive", "status__destroy", true},
		{"mixed class branch", Union(mixed), "read", "status__other", true},
		{"mixed intersection", Intersect(Union(read), Union(named)), "read", "status__find", true},
		{"mixed intersection name insufficient", Intersect(Union(read), Union(named)), "write", "status__find", false},
		{"mixed intersection class insufficient", Intersect(Union(read), Union(named)), "read", "status__other", false},
		{"grants union", Union(read, write), "write", "status__other", true},
		{"matching null grant", Intersect(Union(read, nil), Union(named)), "", "status__find", true},
		{"independent grant unions", Intersect(Union(read, write), Union(named)), "write", "status__find", true},
		{"relay cannot widen", Intersect(Union(read, write), Union(named), Union(mixed)), "write", "status__find", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Allows(tc.class, tc.tool); got != tc.want {
				t.Fatalf("Allows=%v want %v", got, tc.want)
			}
		})
	}
	if Subset(nil, &Scope{Classes: []string{"read", "write", "destructive"}}) {
		t.Fatal("all classes must not cover unrestricted/unclassified")
	}
	if !Subset(&Scope{}, read) || !Subset(read, nil) || Subset(write, read) {
		t.Fatal("bad subset relation")
	}
}

func TestScopeValidationAndCorruptStorage(t *testing.T) {
	long := "s__" + strings.Repeat("x", MaxNameLength-3)
	valid, err := Canonical([]byte(fmt.Sprintf(`{"tools":[%q,"s__a","s__a"],"classes":["write","read","read"]}`, long)))
	if err != nil {
		t.Fatal(err)
	}
	s := Stored(valid)
	if len(s.Classes) != 2 || len(s.Tools) != 2 || s.Classes[0] != "read" || s.Tools[0] != "s__a" {
		t.Fatalf("not canonical: %s", valid)
	}
	tooMany := make([]string, MaxTools+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("s__t%d", i)
	}
	many, _ := json.Marshal(Scope{Tools: tooMany})
	for _, raw := range []string{
		`[]`, `true`, `"read"`, `{"classes":["admin"]}`, `{"classes":["READ"]}`, `{"classes":["read",null]}`,
		`{"tools":["*"]}`, `{"tools":["s__*"]}`, `{"tools":["s__a?"]}`, `{"tools":["[abc]"]}`, `{"tools":["{a,b}"]}`,
		`{"tools":["s__a\n"]}`, `{"tools":["a\u0085"]}`, `{"tools":["a\\b"]}`, `{"scope":["read"]}`, `{} {}`, `{"classes":1}`,
		`{"classes":["read","read","read","read"]}`, fmt.Sprintf(`{"tools":[%q]}`, long+"x"), string(many), `{`,
	} {
		t.Run(raw[:min(50, len(raw))], func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("accepted %s", raw)
			}
			if Allows(Stored([]byte(raw)), "read", "s__a") {
				t.Fatalf("corrupt JSON widened: %s", raw)
			}
		})
	}
	if b, err := Canonical(nil); err != nil || b != nil {
		t.Fatalf("absent: %s %v", b, err)
	}
	if b, err := Canonical([]byte("null")); err != nil || b != nil {
		t.Fatalf("null: %s %v", b, err)
	}
	if b, err := Canonical([]byte(`{"classes":[],"tools":[]}`)); err != nil || string(b) != "{}" {
		t.Fatalf("empty: %s %v", b, err)
	}
}

func TestOAuthScopes(t *testing.T) {
	for _, tc := range []struct {
		value   string
		present bool
		want    *string
		bad     bool
	}{
		{"", false, nil, false}, {"", true, str(""), false},
		{"omp:read", true, str("omp:read"), false},
		{"omp:destructive omp:read omp:write omp:read", true, str("omp:read omp:write omp:destructive"), false},
		{"omp:*", true, nil, true}, {"read", true, nil, true}, {"omp:read unknown", true, nil, true},
	} {
		s, err := OAuth(tc.value, tc.present)
		if (err != nil) != tc.bad {
			t.Fatalf("OAuth(%q): %v", tc.value, err)
		}
		if tc.bad {
			continue
		}
		v := OAuthString(s)
		if (v == nil) != (tc.want == nil) || v != nil && *v != *tc.want {
			t.Fatalf("OAuth(%q): %v", tc.value, v)
		}
	}
}
func str(s string) *string { return &s }
