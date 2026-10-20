package registry

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func part(kind, name, value, secondary string) CredentialInput {
	return CredentialInput{Kind: kind, Name: name, Value: value, Secondary: secondary}
}

func TestCheckCredentialShape(t *testing.T) {
	ok := []CredentialInput{
		part("header", "X-Tenant", "acme", ""), part("query", "api_key", "k-1", ""), part("basic", "", "alice", "pa:ss"),
	}
	if err := checkCredentialShape(ok); err != nil {
		t.Fatalf("a valid list: %v", err)
	}
	if err := checkCredentialShape([]CredentialInput{part("bearer", "", "tok", ""), part("header", "X-Tenant", "t", "")}); err != nil {
		t.Fatalf("bearer with another header: %v", err)
	}
	many := make([]CredentialInput, MaxCredentials+1)
	for i := range many {
		many[i] = part("header", "X-H"+strings.Repeat("a", i+1), "v", "")
	}
	if err := checkCredentialShape(many[:MaxCredentials]); err != nil {
		t.Fatalf("eight parts: %v", err)
	}
	for _, c := range []struct {
		name  string
		items []CredentialInput
		code  string
	}{
		{"nine parts", many, "too_many_credentials"},
		{"unknown kind", []CredentialInput{part("cookie", "a", "v", "")}, "invalid_credential_kind"},
		{"a reserved header", []CredentialInput{part("header", "Host", "v", "")}, "invalid_auth_header"},
		{"the identity header", []CredentialInput{part("header", "mcp-gateway-identity", "v", "")}, "invalid_auth_header"},
		{"a bad header name", []CredentialInput{part("header", "X Key", "v", "")}, "invalid_auth_header"},
		{"a query name with a space", []CredentialInput{part("query", "api key", "v", "")}, "invalid_auth_query"},
		{"a long query name", []CredentialInput{part("query", strings.Repeat("a", 65), "v", "")}, "invalid_auth_query"},
		{"an mcp-* query name", []CredentialInput{part("query", "MCP-Session", "v", "")}, "invalid_auth_query"},
		{"a query name with an equals sign", []CredentialInput{part("query", "a=b", "v", "")}, "invalid_auth_query"},
		{"a named bearer", []CredentialInput{part("bearer", "x", "v", "")}, "invalid_credential"},
		{"a duplicate header, any case", []CredentialInput{part("header", "X-Key", "a", ""), part("header", "x-key", "b", "")}, "invalid_credential"},
		{"a duplicate bearer", []CredentialInput{part("bearer", "", "a", ""), part("bearer", "", "b", "")}, "invalid_credential"},
		{"an empty value", []CredentialInput{part("header", "X-Key", "", "")}, "invalid_auth_value"},
		{"a value with a newline", []CredentialInput{part("query", "k", "a\nb", "")}, "invalid_auth_value"},
		{"a long value", []CredentialInput{part("bearer", "", strings.Repeat("a", 4097), "")}, "invalid_auth_value"},
		{"basic without a password", []CredentialInput{part("basic", "", "alice", "")}, "invalid_auth_value"},
		{"basic with a colon in the user", []CredentialInput{part("basic", "", "a:b", "p")}, "invalid_auth_value"},
		{"a second value on a header", []CredentialInput{part("header", "X-Key", "v", "w")}, "invalid_credential"},
		{"a kept part with a value", []CredentialInput{{Kind: "header", Name: "X-Key", Value: "v", Keep: true}}, "invalid_credential"},
		// Only one part may set Authorization (decision 39: one credential per call).
		{"Authorization twice", []CredentialInput{part("header", "Authorization", "Token x", ""), part("bearer", "", "t", "")}, "auth_conflict"},
		{"bearer and basic", []CredentialInput{part("bearer", "", "t", ""), part("basic", "", "u", "p")}, "auth_conflict"},
	} {
		err := checkCredentialShape(c.items)
		e, isApp := apperr.As(err)
		if !isApp || e.Code != c.code {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
			continue
		}
		if d, _ := e.Details.(map[string]any); d == nil || d["field"] == nil {
			t.Errorf("%s: no details.field in %+v", c.name, e)
		}
	}
	// Kept parts carry no values and still count for duplicates.
	if err := checkCredentialShape([]CredentialInput{{Kind: "header", Name: "X-Key", Keep: true}, part("query", "k", "v", "")}); err != nil {
		t.Errorf("a kept part: %v", err)
	}
}

// F-1 for every kind: a URL on another origin never keeps a stored value; a
// request that names the parts must enter each one again.
func TestRequireValueForOriginParts(t *testing.T) {
	cur := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthStaticHeader}
	rows := func(kinds ...string) storedCredentials {
		var out storedCredentials
		for i, k := range kinds {
			r := dbgen.McpServerCredential{Kind: k, Position: int16(i)}
			if k == CredHeader || k == CredQuery {
				n := "X-Name" + string(rune('a'+i))
				r.Name = &n
			}
			out.rows = append(out.rows, r)
		}
		return out
	}
	list := func(items ...CredentialInput) UpdateInput { return UpdateInput{Credentials: &items} }
	for _, kind := range []string{CredHeader, CredBearer, CredBasic, CredQuery} {
		stored := rows(kind)
		// Another origin and no values: refused, naming the part.
		err := requireValueForOrigin(cur, stored, "https://b.example/mcp", UpdateInput{}, AuthStaticHeader)
		if e, _ := apperr.As(err); e == nil || e.Code != "auth_value_required" || e.Details.(map[string]any)["field"] != "credentials[0]" ||
			e.Details.(map[string]any)["kind"] != kind {
			t.Errorf("%s with no list: %v", kind, err)
		}
		// Keeping the part is no new value.
		err = requireValueForOrigin(cur, stored, "https://b.example/mcp", list(CredentialInput{Kind: kind, Name: "X-Namea", Keep: true}), AuthStaticHeader)
		if e, _ := apperr.As(err); e == nil || e.Code != "auth_value_required" {
			t.Errorf("%s kept: %v", kind, err)
		}
		// The same origin is free; so are no parts, none-mode, and every value entered again.
		for name, c := range map[string]struct {
			url  string
			in   UpdateInput
			mode string
		}{
			"same origin":   {"https://a.example/other", UpdateInput{}, AuthStaticHeader},
			"authMode none": {"https://b.example/mcp", UpdateInput{}, AuthNone},
			"emptied":       {"https://b.example/mcp", list(), AuthStaticHeader},
			"entered again": {"https://b.example/mcp", list(part(kind, map[string]string{CredHeader: "X-Namea", CredQuery: "X-Namea"}[kind], "new", "pw")), AuthStaticHeader},
		} {
			if err := requireValueForOrigin(cur, stored, c.url, c.in, c.mode); err != nil {
				t.Errorf("%s %s: %v", kind, name, err)
			}
		}
	}
	// A basic part needs its password entered again too; and every part of
	// several must be entered: the second one is named.
	err := requireValueForOrigin(cur, rows(CredBasic), "https://b.example/mcp", list(CredentialInput{Kind: CredBasic, Value: "u"}), AuthStaticHeader)
	if e, _ := apperr.As(err); e == nil || e.Code != "auth_value_required" {
		t.Errorf("basic without the password: %v", err)
	}
	err = requireValueForOrigin(cur, rows(CredHeader, CredQuery), "https://b.example/mcp",
		list(part("header", "X-Namea", "new", ""), CredentialInput{Kind: "query", Name: "X-Nameb", Keep: true}), AuthStaticHeader)
	if e, _ := apperr.As(err); e == nil || e.Details.(map[string]any)["field"] != "credentials[1]" || e.Details.(map[string]any)["name"] != "X-Nameb" {
		t.Errorf("second part kept: %v", err)
	}
	// Nothing stored, nothing to carry along.
	if err := requireValueForOrigin(cur, storedCredentials{}, "https://b.example/mcp", UpdateInput{}, AuthStaticHeader); err != nil {
		t.Errorf("no credential: %v", err)
	}
	// The legacy single header keeps its old rule.
	legacy := storedCredentials{legacy: &CredentialView{Kind: CredHeader, Name: "X-Api-Key"}}
	if err := requireValueForOrigin(cur, legacy, "https://b.example/mcp", UpdateInput{}, AuthStaticHeader); err != errAuthValueRequired {
		t.Errorf("legacy header: %v", err)
	}
	v := "x"
	if err := requireValueForOrigin(cur, legacy, "https://b.example/mcp", UpdateInput{AuthValue: &v}, AuthStaticHeader); err != nil {
		t.Errorf("legacy header with a new value: %v", err)
	}
}

// The review digest covers the kind and name of every part (never a value), so
// a part added after a review shows; moving the single header between the
// legacy columns and the table does not change it.
func TestReviewDigestCoversCredentialParts(t *testing.T) {
	sv := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthStaticHeader}
	caps := []CapabilityRef{{Kind: "tool", Name: "a", Fingerprint: "f1"}}
	tenant := CredentialView{Kind: CredHeader, Name: "X-Tenant"}
	key := CredentialView{Kind: CredQuery, Name: "api_key"}
	base := ReviewDigest(sv, caps, tenant)
	if ReviewDigest(sv, caps, tenant) != base {
		t.Fatal("not stable")
	}
	if ReviewDigest(sv, caps, key, tenant) != ReviewDigest(sv, caps, tenant, key) {
		t.Error("the order of parts changes the digest")
	}
	hint := tenant
	hint.Hint = "1234"
	if ReviewDigest(sv, caps, hint) != base {
		t.Error("a hint (part of the value) changes the digest")
	}
	for name, got := range map[string]string{
		"a query part added":     ReviewDigest(sv, caps, tenant, key),
		"a basic part added":     ReviewDigest(sv, caps, tenant, CredentialView{Kind: CredBasic}),
		"a part removed":         ReviewDigest(sv, caps),
		"another header name":    ReviewDigest(sv, caps, CredentialView{Kind: CredHeader, Name: "X-Other"}),
		"the same name as query": ReviewDigest(sv, caps, CredentialView{Kind: CredQuery, Name: "X-Tenant"}),
	} {
		if got == base {
			t.Errorf("%s: the digest did not change", name)
		}
	}
	header := "X-Tenant"
	legacy := sv
	legacy.AuthHeaderName = &header
	if ReviewDigest(legacy, caps) != base {
		t.Error("the legacy header and the same part in the table digest differently")
	}
	if ReviewDigest(legacy, caps, tenant) != base {
		t.Error("the legacy header listed as a part digests differently")
	}
}
