package registry

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestReviewDigest(t *testing.T) {
	provider := uuid.New()
	base := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthNone}
	caps := []CapabilityRef{
		{Kind: "tool", Name: "a", Fingerprint: "f1"}, {Kind: "tool", Name: "b", Fingerprint: "f2"}, {Kind: "resource", Name: "status://x", Fingerprint: "f3"}, {Kind: "prompt", Name: "p", Fingerprint: "f4"},
	}
	want := ReviewDigest(base, caps)
	if len(want) != 64 {
		t.Fatalf("digest = %q", want)
	}
	if got := ReviewDigest(base, []CapabilityRef{caps[3], caps[1], caps[2], caps[0]}); got != want {
		t.Error("the order of capabilities changes the digest")
	}
	if got := ReviewDigest(base, caps); got != want {
		t.Error("the digest is not stable")
	}
	withRequirement := func(scopes ...string) dbgen.McpServer {
		sv := base
		sv.AuthProviderID = uuid.NullUUID{UUID: provider, Valid: true}
		sv.AuthScopes = scopes
		return sv
	}
	header := "X-API-Key"
	oauth := base
	oauth.AuthMode = AuthOAuth
	for name, got := range map[string]string{
		"a changed fingerprint":   ReviewDigest(base, []CapabilityRef{{Kind: "tool", Name: "a", Fingerprint: "f1x"}, caps[1], caps[2], caps[3]}),
		"a new capability":        ReviewDigest(base, append([]CapabilityRef{{Kind: "tool", Name: "c", Fingerprint: "f5"}}, caps...)),
		"a dropped capability":    ReviewDigest(base, caps[:3]),
		"a renamed capability":    ReviewDigest(base, []CapabilityRef{{Kind: "tool", Name: "a2", Fingerprint: "f1"}, caps[1], caps[2], caps[3]}),
		"another kind":            ReviewDigest(base, []CapabilityRef{{Kind: "prompt", Name: "a", Fingerprint: "f1"}, caps[1], caps[2], caps[3]}),
		"another URL":             ReviewDigest(dbgen.McpServer{URL: "https://a.example/mcp2", AuthMode: AuthNone}, caps),
		"another origin":          ReviewDigest(dbgen.McpServer{URL: "https://b.example/mcp", AuthMode: AuthNone}, caps),
		"another auth mode":       ReviewDigest(oauth, caps),
		"a static header":         ReviewDigest(dbgen.McpServer{URL: base.URL, AuthHeaderName: &header}, caps),
		"a requirement":           ReviewDigest(withRequirement(), caps),
		"requirement scopes":      ReviewDigest(withRequirement("repo"), caps),
		"other requirement scope": ReviewDigest(withRequirement("repo", "admin:org"), caps),
	} {
		if got == want {
			t.Errorf("%s doesn't change the digest", name)
		}
	}
	if ReviewDigest(withRequirement("a", "b"), caps) != ReviewDigest(withRequirement("b", "a"), caps) {
		t.Error("the order of scopes changes the digest")
	}
	// A present-person requirement is covered (L-4): the server's switch, and
	// each capability's effective value, only when on.
	on := base
	on.RequiresPresentPerson = true
	if ReviewDigest(on, caps) == want {
		t.Error("the server's switch doesn't change the digest")
	}
	required := slices.Clone(caps)
	required[1].PresentPerson = true
	if ReviewDigest(base, required) == want {
		t.Error("a capability's requirement doesn't change the digest")
	}
	otherOne := slices.Clone(caps)
	otherOne[2].PresentPerson = true
	if ReviewDigest(base, otherOne) == ReviewDigest(base, required) {
		t.Error("which capability requires it doesn't change the digest")
	}
	if ReviewDigest(base, []CapabilityRef{{Kind: "tool", Name: "a", Fingerprint: "f1", PresentPerson: false}, caps[1], caps[2], caps[3]}) != want {
		t.Error("a capability without the requirement changes the digest")
	}
	// The effective value: the override, else the server's switch.
	yes, no := true, false
	for name, c := range map[string]struct {
		sv       dbgen.McpServer
		override *bool
		want     bool
	}{
		"off, follows":     {base, nil, false},
		"on, follows":      {on, nil, true},
		"off, required":    {base, &yes, true},
		"on, not required": {on, &no, false},
		"on, required":     {on, &yes, true},
	} {
		if got := CapabilityRefOf(c.sv, "tool", "a", "f1", c.override, nil).PresentPerson; got != c.want {
			t.Errorf("%s: effective = %v, want %v", name, got, c.want)
		}
	}
	// Fields can't run into each other.
	if ReviewDigest(base, []CapabilityRef{{Kind: "tool", Name: "ab", Fingerprint: "c"}}) == ReviewDigest(base, []CapabilityRef{{Kind: "tool", Name: "a", Fingerprint: "bc"}}) {
		t.Error("name and fingerprint collide")
	}
}
