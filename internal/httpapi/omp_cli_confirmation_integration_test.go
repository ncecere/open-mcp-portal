package httpapi_test

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/ompcli"
)

func TestOmpCLIConfirmationDeclarationNeverConfirms(t *testing.T) {
	f := newPolicyFixture(t)
	secret := tokenSecret("omppub_", 5050)
	f.e.mintToken("team_publisher", f.e.b.id, "", secret, []string{"servers:read", "servers:write"}, "-1 hour", "1 day", "")
	pub := newOmpRun(t, f.e, secret)
	export := func() ompcli.Server {
		t.Helper()
		doc, err := ompcli.ParseFile([]byte(pub.mustRun("export")))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range doc.Servers {
			if s.Slug == f.server {
				return s
			}
		}
		t.Fatal("server absent from export")
		return ompcli.Server{}
	}
	state := func() string {
		return f.e.exec(`SELECT revision::text||'/'||coalesce(sensitivity_confirmed_at::text,'unset')||'/'||
		(SELECT count(*)::text FROM audit_log) FROM mcp_servers WHERE slug=$1`, f.server)
	}
	file := func(s ompcli.Server) string {
		t.Helper()
		b, err := (&ompcli.File{Schema: ompcli.SchemaID, Servers: []ompcli.Server{s}}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return f.file(string(b))
	}
	refuse := func(s ompcli.Server) {
		t.Helper()
		before := state()
		path := file(s)
		for _, suffix := range [][]string{{"--plan"}, {}} {
			args := append([]string{"import", "-f", path}, suffix...)
			if code, _, errOut := pub.run(args...); code != ompcli.ExitUsage || !strings.Contains(errOut, "refused") {
				t.Fatalf("mismatched confirmation accepted: %d %s", code, errOut)
			}
		}
		if state() != before {
			t.Fatal("comparison-only confirmation mutated the portal")
		}
	}
	s := export()
	if s.Governance == nil || s.Governance.SensitivityConfirmed == nil || *s.Governance.SensitivityConfirmed {
		t.Fatal("the unconfirmed marker was not exported explicitly false")
	}
	confirmed := true
	s.Governance.SensitivityConfirmed = &confirmed
	refuse(s) // A declaration cannot become an attestation by the token.

	id := f.e.exec(`SELECT id::text FROM mcp_servers WHERE slug=$1`, f.server)
	rev := f.e.exec(`SELECT revision::text FROM mcp_servers WHERE slug=$1`, f.server)
	code, _ := f.e.callers[cOwner].raw("PATCH", "/v1/teams/bravo/mcp-servers/"+id,
		map[string]any{"governance": map[string]any{"sensitivity": "internal"}}, map[string]string{"If-Match": `"` + rev + `"`})
	if code != 200 {
		t.Fatalf("human confirmation: %d", code)
	}
	s = export()
	if s.Governance.SensitivityConfirmed == nil || !*s.Governance.SensitivityConfirmed {
		t.Fatal("confirmed marker not exported true")
	}
	unconfirmed := false
	s.Governance.SensitivityConfirmed = &unconfirmed
	refuse(s) // Nor may the token clear an existing marker.
	s = export()
	path := file(s)
	if code, out, errOut := pub.run("import", "-f", path, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("unchanged confirmed export: %d %s %s", code, out, errOut)
	}
	at := f.e.exec(`SELECT sensitivity_confirmed_at::text FROM mcp_servers WHERE slug=$1`, f.server)
	description := "token metadata only"
	s.Description = &description
	pub.mustRun("import", "-f", file(s))
	if f.e.exec(`SELECT sensitivity_confirmed_at::text FROM mcp_servers WHERE slug=$1`, f.server) != at {
		t.Fatal("token metadata edit moved the human confirmation")
	}
	if f.e.exec(`SELECT count(*)::text FROM audit_log WHERE action='mcp_server.governance_update' AND actor_kind='automation_token'`) != "0" {
		t.Fatal("CLI wrote session-only governance")
	}
}
