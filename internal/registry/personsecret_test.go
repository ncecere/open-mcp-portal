package registry

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestNormalizePersonSecret(t *testing.T) {
	ok := func(in PersonSecretInput) PersonSecretInput {
		t.Helper()
		out, err := normalizePersonSecret(in)
		if err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		return out
	}
	bad := func(name string, in PersonSecretInput, field string) {
		t.Helper()
		_, err := normalizePersonSecret(in)
		e, isApp := apperr.As(err)
		if !isApp || e.Code != "invalid_person_secret" || e.Details.(map[string]any)["field"] != "personSecret."+field {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := ok(PersonSecretInput{Placement: "header", Name: " X-Api-Key ", Prefix: "Token ", Label: " Acme key "}); got.Name != "X-Api-Key" || got.Prefix != "Token " || got.Label != "Acme key" {
		t.Errorf("trimmed = %+v", got)
	}
	ok(PersonSecretInput{Placement: "header", Name: "Authorization", Prefix: "Key "})
	ok(PersonSecretInput{Placement: "bearer"})
	ok(PersonSecretInput{Placement: "query", Name: "api_key"})
	bad("placement", PersonSecretInput{Placement: "cookie", Name: "x"}, "placement")
	bad("no placement", PersonSecretInput{Name: "x"}, "placement")
	bad("header name", PersonSecretInput{Placement: "header", Name: "bad name"}, "name")
	bad("reserved", PersonSecretInput{Placement: "header", Name: "Mcp-Session-Id"}, "name")
	bad("identity header", PersonSecretInput{Placement: "header", Name: "MCP-Gateway-Identity"}, "name")
	bad("query name", PersonSecretInput{Placement: "query", Name: "a b"}, "name")
	bad("mcp- query", PersonSecretInput{Placement: "query", Name: "MCP-token"}, "name")
	bad("bearer name", PersonSecretInput{Placement: "bearer", Name: "x"}, "name")
	bad("bearer prefix", PersonSecretInput{Placement: "bearer", Prefix: "Key "}, "prefix")
	bad("prefix newline", PersonSecretInput{Placement: "header", Name: "X-K", Prefix: "a\r\nX-Evil: 1"}, "prefix")
	bad("long prefix", PersonSecretInput{Placement: "header", Name: "X-K", Prefix: strings.Repeat("a", 65)}, "prefix")
	bad("label", PersonSecretInput{Placement: "bearer", Label: strings.Repeat("a", 101)}, "label")
	bad("help", PersonSecretInput{Placement: "bearer", Help: strings.Repeat("a", 2001)}, "help")
}

func TestCheckPersonSecretValue(t *testing.T) {
	for _, v := range []string{"abcdefgh", strings.Repeat("a", 4096), "with space inside"} {
		if err := CheckPersonSecretValue(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"", "short", "abcdefg", strings.Repeat("a", 4097), "line1-aaaa\nline2-bbbb", "nul-aaaaaaaa\x00", " leading-space", "trailing-space "} {
		if err := CheckPersonSecretValue(v); err == nil {
			t.Errorf("%q was accepted", v)
		}
	}
}

func TestPersonSecretConflicts(t *testing.T) {
	statics := func(vs ...CredentialView) []CredentialView { return vs }
	cases := []struct {
		name   string
		cfg    PersonSecretInput
		parts  []CredentialView
		req    bool
		reason string
	}{
		{"clean", PersonSecretInput{Placement: PlaceHeader, Name: "X-Api-Key"}, statics(CredentialView{Kind: CredHeader, Name: "X-Tenant"}), false, ""},
		{"requirement", PersonSecretInput{Placement: PlaceBearer}, nil, true, "requirement"},
		{"bearer and static bearer", PersonSecretInput{Placement: PlaceBearer}, statics(CredentialView{Kind: CredBearer}), false, "static_authorization"},
		{"bearer and static basic", PersonSecretInput{Placement: PlaceBearer}, statics(CredentialView{Kind: CredBasic}), false, "static_authorization"},
		{"bearer and static Authorization", PersonSecretInput{Placement: PlaceBearer}, statics(CredentialView{Kind: CredHeader, Name: "authorization"}), false, "static_authorization"},
		{"Authorization header and basic", PersonSecretInput{Placement: PlaceHeader, Name: "Authorization"}, statics(CredentialView{Kind: CredBasic}), false, "static_authorization"},
		{"same header", PersonSecretInput{Placement: PlaceHeader, Name: "X-Api-Key"}, statics(CredentialView{Kind: CredHeader, Name: "x-api-key"}), false, "static_duplicate"},
		{"same query", PersonSecretInput{Placement: PlaceQuery, Name: "k"}, statics(CredentialView{Kind: CredQuery, Name: "K"}), false, "static_duplicate"},
		{"query next to a header of that name", PersonSecretInput{Placement: PlaceQuery, Name: "k"}, statics(CredentialView{Kind: CredHeader, Name: "k"}), false, ""},
		{"query next to static bearer", PersonSecretInput{Placement: PlaceQuery, Name: "k"}, statics(CredentialView{Kind: CredBearer}), false, ""},
	}
	for _, tc := range cases {
		err := personSecretConflicts(tc.cfg, tc.parts, tc.req)
		if tc.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		e, ok := apperr.As(err)
		if !ok || e.Code != "auth_conflict" || e.Details.(map[string]any)["reason"] != tc.reason {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// What ends everyone's secrets (F-1 extended): another origin, another mode or
// another placement. A path, a name, a prefix, a label do not.
func TestSecretResetReason(t *testing.T) {
	ps := func(url, mode, placement string) dbgen.McpServer {
		sv := dbgen.McpServer{URL: url, AuthMode: mode}
		if placement != "" {
			sv.SecretPlacement = &placement
		}
		return sv
	}
	base := ps("https://a.example/mcp", AuthPersonSecret, PlaceHeader)
	for name, tc := range map[string]struct {
		row  dbgen.McpServer
		want string
	}{
		"same":               {base, ""},
		"another path":       {ps("https://a.example/v2/mcp", AuthPersonSecret, PlaceHeader), ""},
		"explicit port":      {ps("https://A.example:443/mcp", AuthPersonSecret, PlaceHeader), ""},
		"another host":       {ps("https://b.example/mcp", AuthPersonSecret, PlaceHeader), "origin_changed"},
		"another port":       {ps("https://a.example:8443/mcp", AuthPersonSecret, PlaceHeader), "origin_changed"},
		"another scheme":     {ps("http://a.example/mcp", AuthPersonSecret, PlaceHeader), "origin_changed"},
		"another mode":       {ps("https://a.example/mcp", AuthNone, ""), "mode_changed"},
		"another placement":  {ps("https://a.example/mcp", AuthPersonSecret, PlaceQuery), "placement_changed"},
		"origin and mode":    {ps("https://b.example/mcp", AuthNone, ""), "origin_changed"},
		"static to the mode": {ps("https://a.example/mcp", AuthStaticHeader, ""), "mode_changed"},
	} {
		if got := secretResetReason(base, tc.row); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// The review digest covers where people's secrets go, in person_secret mode
// only (no other server's digest moves).
func TestReviewDigestCoversPersonSecretPlacement(t *testing.T) {
	mk := func(placement, name, prefix string) dbgen.McpServer {
		sv := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthPersonSecret, SecretPlacement: &placement, SecretPrefix: prefix}
		if name != "" {
			sv.SecretName = &name
		}
		return sv
	}
	base := ReviewDigest(mk("header", "X-K", ""), nil)
	for name, sv := range map[string]dbgen.McpServer{"placement": mk("query", "X-K", ""), "name": mk("header", "X-Other", ""), "prefix": mk("header", "X-K", "Key ")} {
		if ReviewDigest(sv, nil) == base {
			t.Errorf("another %s didn't change the digest", name)
		}
	}
	label := mk("header", "X-K", "")
	label.SecretLabel, label.SecretHelp = "Another label", "other help"
	if ReviewDigest(label, nil) != base {
		t.Error("the label and help are not what a reviewer approves")
	}
	none := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthNone}
	withStray := none
	placement := "header"
	withStray.SecretPlacement = &placement
	if ReviewDigest(none, nil) != ReviewDigest(withStray, nil) {
		t.Error("another mode's digest moved")
	}
}
