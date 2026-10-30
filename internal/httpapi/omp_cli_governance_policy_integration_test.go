package httpapi_test

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/ompcli"
)

// Governance is session-only. Token-based export/import must carry a
// comparison-only declaration, never silently clone a stricter policy into
// the new object's less restrictive defaults.
func TestOmpCLIGovernanceGatewayCloneCannotLoseSensitivityCeiling(t *testing.T) {
	f := newPolicyFixture(t)
	f.omp.mustRun("import", "-f", f.file("schema: omp/v1\ngateways:\n- slug: fenced\n  name: Fenced\n  capabilities:\n"+f.capLine("lookup")+"  grants:\n  - {group: eng}\n"))
	code, ec := f.admin.call("PATCH", "/v1/admin/gateways/"+f.gatewayID("fenced"), map[string]any{"maxSensitivity": "public"}, nil, ifMatch(f.selection("fenced").Revision))
	mustCode(t, "set ceiling by session", code, ec, 200, "")
	if got := f.selection("fenced").Items[0]; got.Available || got.UnavailableReason == nil || *got.UnavailableReason != "sensitivity_exceeds_gateway" {
		t.Fatalf("source ceiling does not fence the selected internal server: %+v", got)
	}
	exported := f.omp.mustRun("export")
	if code, out, errOut := f.omp.run("import", "-f", f.file(exported), "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("unchanged ceiling export must compare without writes: %d %s %s", code, out, errOut)
	}
	doc, err := ompcli.ParseFile([]byte(exported))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range doc.Gateways {
		if g.Slug == "fenced" {
			metadata := g
			metadata.Name = "Metadata-only edit"
			unchangedPolicy := &ompcli.File{Schema: ompcli.SchemaID, Gateways: []ompcli.Gateway{metadata}}
			encoded, err := unchangedPolicy.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			f.omp.mustRun("import", "-f", f.file(string(encoded)))
			if f.e.exec(`SELECT max_sensitivity FROM gateways WHERE slug='fenced'`) != "public" {
				t.Fatal("metadata edit changed the ceiling")
			}
			g.Slug = "ceiling-copy"
			doc = &ompcli.File{Schema: ompcli.SchemaID, Gateways: []ompcli.Gateway{g}}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("gateway missing from export")
	}
	raw, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	before := f.e.exec(`SELECT count(*)::text FROM audit_log`)
	code, out, errOut := f.omp.run("import", "-f", f.file(string(raw)))
	if code != ompcli.ExitUsage || !strings.Contains(errOut, "refused") || !strings.Contains(errOut, "Nothing was changed") {
		actual := f.e.exec(`SELECT coalesce((SELECT max_sensitivity FROM gateways WHERE slug='ceiling-copy'), 'absent')`)
		t.Fatalf("cloned an unwriteable ceiling policy: exit=%d ceiling=%s stdout=%s stderr=%s", code, actual, out, errOut)
	}
	if f.e.exec(`SELECT count(*)::text FROM gateways WHERE slug='ceiling-copy'`) != "0" || f.e.exec(`SELECT count(*)::text FROM audit_log`) != before {
		t.Fatal("refused ceiling clone mutated the portal")
	}
}

func TestOmpCLIGovernanceServerCloneCannotLoseSensitivityOrRetirement(t *testing.T) {
	f := newPolicyFixture(t)
	// Only this test's disposable source row is changed, before CLI
	// export/import. This establishes policy; it does not authorize the token.
	f.e.exec(`UPDATE mcp_servers SET sensitivity='confidential', lifecycle='deprecated',
		deprecated_at=clock_timestamp(), sunset_at=clock_timestamp()+interval '1 day'
		WHERE slug=$1 RETURNING id::text`, f.server)
	secret := tokenSecret("omppub_", 4040)
	f.e.mintToken("team_publisher", f.e.b.id, "", secret, []string{"servers:read", "servers:write"}, "-1 hour", "1 day", "")
	pub := newOmpRun(t, f.e, secret)
	exported := pub.mustRun("export")
	if code, out, errOut := pub.run("import", "-f", f.file(exported), "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("unchanged governance export must compare without writes: %d %s %s", code, out, errOut)
	}
	doc, err := ompcli.ParseFile([]byte(exported))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range doc.Servers {
		if s.Slug == f.server {
			metadata := s
			description := "Metadata-only edit"
			metadata.Description = &description
			unchangedPolicy := &ompcli.File{Schema: ompcli.SchemaID, Servers: []ompcli.Server{metadata}}
			encoded, err := unchangedPolicy.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			pub.mustRun("import", "-f", f.file(string(encoded)))
			if f.e.exec(`SELECT sensitivity||'/'||lifecycle||'/'||(sunset_at IS NOT NULL)::text FROM mcp_servers WHERE slug=$1`, f.server) != "confidential/deprecated/true" {
				t.Fatal("metadata edit changed governance")
			}
			s.Slug, s.Publish = "governance-copy", ""
			doc = &ompcli.File{Schema: ompcli.SchemaID, Servers: []ompcli.Server{s}}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("server missing from export")
	}
	raw, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	before := f.e.exec(`SELECT count(*)::text FROM audit_log`)
	code, out, errOut := pub.run("import", "-f", f.file(string(raw)))
	if code != ompcli.ExitUsage || !strings.Contains(errOut, "refused") || !strings.Contains(errOut, "Nothing was changed") {
		actual := f.e.exec(`SELECT coalesce((SELECT sensitivity||'/'||lifecycle||'/'||(sunset_at IS NULL)::text
			FROM mcp_servers WHERE slug='governance-copy'), 'absent')`)
		t.Fatalf("cloned unwriteable server governance: exit=%d policy=%s stdout=%s stderr=%s", code, actual, out, errOut)
	}
	if f.e.exec(`SELECT count(*)::text FROM mcp_servers WHERE slug='governance-copy'`) != "0" || f.e.exec(`SELECT count(*)::text FROM audit_log`) != before {
		t.Fatal("refused governance clone mutated the portal")
	}
}
