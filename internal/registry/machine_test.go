package registry

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The review digest covers a machine client as a reviewer sees it (decision
// 73): changing the token endpoint, the client, the scopes, the audience or the
// resource stales an earlier look, a different order of scopes does not, and
// the secret (which the digest never sees) is no part of it. A server that is
// not in the mode has the digest it had before.
func TestReviewDigestCoversMachineClient(t *testing.T) {
	sv := dbgen.McpServer{URL: "https://a.example/mcp", AuthMode: AuthMachineOAuth}
	caps := []CapabilityRef{{Kind: "tool", Name: "a", Fingerprint: "f1"}}
	base := &MachineOAuthView{TokenURL: "https://idp.example/token", ClientID: "client", TokenAuthMethod: MachineAuthBasic,
		Scopes: []string{"read", "write"}, Audience: "api://a", Resource: "https://a.example/mcp", SecretHint: "1234"}
	want := ReviewDigestMachine(sv, caps, base)
	same := *base
	same.Scopes, same.SecretHint = []string{"write", "read"}, "9999"
	if got := ReviewDigestMachine(sv, caps, &same); got != want {
		t.Error("the order of scopes or the secret's hint changed the digest")
	}
	for name, change := range map[string]func(m *MachineOAuthView){
		"the token endpoint": func(m *MachineOAuthView) { m.TokenURL = "https://other.example/token" },
		"the client":         func(m *MachineOAuthView) { m.ClientID = "another" },
		"the method":         func(m *MachineOAuthView) { m.TokenAuthMethod = MachineAuthPost },
		"a scope added":      func(m *MachineOAuthView) { m.Scopes = []string{"read", "write", "admin"} },
		"a scope removed":    func(m *MachineOAuthView) { m.Scopes = []string{"read"} },
		"the audience":       func(m *MachineOAuthView) { m.Audience = "" },
		"the resource":       func(m *MachineOAuthView) { m.Resource = "https://b.example/mcp" },
	} {
		m := *base
		change(&m)
		if ReviewDigestMachine(sv, caps, &m) == want {
			t.Errorf("a changed %s left the digest as it was", name)
		}
	}
	if ReviewDigestMachine(sv, caps, nil) == want {
		t.Error("a machine server without its client has the digest of one with it")
	}
	// Fields that run into each other can't collide.
	a, b := *base, *base
	a.TokenURL, a.ClientID = "https://idp.example/tokenc", "lient"
	b.TokenURL, b.ClientID = "https://idp.example/token", "clientlient"
	if ReviewDigestMachine(sv, caps, &a) == ReviewDigestMachine(sv, caps, &b) {
		t.Error("two clients collide")
	}
	// Another mode ignores a client it is given: the digest is the plain one.
	none := dbgen.McpServer{URL: sv.URL, AuthMode: AuthNone}
	if ReviewDigestMachine(none, caps, base) != ReviewDigest(none, caps) {
		t.Error("a server that is not in machine_oauth mode has a machine client in its digest")
	}
	if ReviewDigest(sv, caps) == ReviewDigest(none, caps) {
		t.Error("the mode is not in the digest")
	}
}

func TestMachineAuditSnapshotNeverHoldsASecretOrClientID(t *testing.T) {
	sv := dbgen.McpServer{AuthMode: AuthMachineOAuth, SendIdentity: true}
	m := &MachineOAuthView{TokenURL: "https://idp.example/token", ClientID: "client-id-sentinel", SecretHint: "1234", TokenAuthMethod: MachineAuthPost,
		Scopes: []string{"read"}, Audience: "aud", Resource: "https://a.example/mcp"}
	snap := machineSnapshot(sv, m)
	text := fmt.Sprint(snap)
	for _, bad := range []string{"sentinel", "1234", "client-id"} {
		if strings.Contains(text, bad) {
			t.Errorf("the audit snapshot holds %q: %s", bad, text)
		}
	}
	o, _ := snap["machineOAuth"].(map[string]any)
	if o["tokenUrl"] != "https://idp.example/token" || o["audience"] != "aud" || snap["authMode"] != AuthMachineOAuth {
		t.Errorf("snapshot = %v", snap)
	}
	if machineSnapshot(dbgen.McpServer{AuthMode: AuthNone}, m)["machineOAuth"] != nil {
		t.Error("a server that is not in the mode shows a client")
	}
}
