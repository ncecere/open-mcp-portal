package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gwcuration "github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/ompcli"
)

// Lossless authority through the real handler and PostgreSQL: a curated tool's
// policy and a grant's deadline survive everything omp import does, are written
// by export, and omp refuses (before any write) what it cannot keep. The unit
// tests in internal/ompcli cover the same rules against a fake; these prove the
// fake is faithful.

const lookupDefinition = `{"name":"%s","description":"Look something up","inputSchema":{"type":"object","properties":{"region":{"type":"string"},"limit":{"type":"integer"}},"required":["region"]}}`

// policyFixture is a platform-write CLI, a published server with three tools,
// and the admin's browser session (the only thing that can write curation).
type policyFixture struct {
	t      *testing.T
	e      *matrixEnv
	omp    *ompRun
	admin  *session
	server string // slug
	tools  map[string]string
}

func newPolicyFixture(t *testing.T) *policyFixture {
	t.Helper()
	e := newMatrixEnv(t)
	f := &policyFixture{t: t, e: e, omp: newOmpRun(t, e, tokenCredsByName(e)["platform-write"].secret), admin: e.callers[cPlatformAdmin], tools: map[string]string{}}
	id := e.newServer(e.b, "published")
	f.server = e.exec(`SELECT slug FROM mcp_servers WHERE id = $1`, id)
	for i, name := range []string{"lookup", "other", "extra"} {
		def := strings.Replace(lookupDefinition, "%s", name, 1)
		f.tools[name] = e.exec(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint)
			VALUES ($1, 'tool', $2, $3::jsonb, $4, $4) RETURNING id::text`, id, name, def, strings.Repeat(string(rune('1'+i)), 64))
	}
	return f
}

func (f *policyFixture) gatewayID(slug string) string {
	return f.e.exec(`SELECT id::text FROM gateways WHERE slug = $1`, slug)
}

func (f *policyFixture) selection(slug string) apitypes.GatewayCapabilities {
	f.t.Helper()
	var out apitypes.GatewayCapabilities
	if code := f.admin.get("/v1/admin/gateways/"+f.gatewayID(slug)+"/capabilities", &out); code != 200 {
		f.t.Fatalf("selection: %d", code)
	}
	return out
}

func (f *policyFixture) grants(slug string) map[string]apitypes.GatewayGrant {
	f.t.Helper()
	var list []apitypes.GatewayGrant
	if code := f.admin.get("/v1/admin/gateways/"+f.gatewayID(slug)+"/grants", &list); code != 200 {
		f.t.Fatalf("grants: %d", code)
	}
	out := map[string]apitypes.GatewayGrant{}
	for _, g := range list {
		out[deref(g.Group)] = g
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// curate is what the web UI does: a session saves the selection with a policy.
func (f *policyFixture) curate(slug, tool string, policy map[string]any) {
	f.t.Helper()
	sel := f.selection(slug)
	items := []map[string]any{}
	for _, c := range sel.Items {
		it := map[string]any{"capabilityId": c.CapabilityId.String()}
		if c.CapabilityId.String() == f.tools[tool] {
			it["expectedFingerprint"], it["curation"] = *c.Fingerprint, policy
		}
		items = append(items, it)
	}
	code, ec := f.admin.call("PUT", "/v1/admin/gateways/"+f.gatewayID(slug)+"/capabilities", map[string]any{"items": items}, nil, ifMatch(int64(sel.Revision)))
	mustCode(f.t, "curate", code, ec, 200, "")
}

// policyRow is everything the portal stores about a selection's policy.
func (f *policyFixture) policyRow(slug, tool string) string {
	return f.e.exec(`SELECT concat_ws('|', name_override, description_override, constraints::text, base_fingerprint, curated_by::text, curated_at::text)
		FROM gateway_capabilities WHERE gateway_id = $1 AND capability_id = $2`, f.gatewayID(slug), f.tools[tool])
}

func (f *policyFixture) file(doc string) string {
	f.t.Helper()
	p := filepath.Join(f.t.TempDir(), "omp.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *policyFixture) audits(action string) string {
	return f.e.exec(`SELECT count(*)::text FROM audit_log WHERE action = $1`, action)
}

func (f *policyFixture) capLine(name string) string {
	return "  - {server: " + f.server + ", kind: tool, name: " + name + "}\n"
}

// refuses runs the file in plan and apply modes: both refuse with exit 2 and
// the code `refused`, and the portal's state is exactly as it was.
func (f *policyFixture) refuses(doc, contain string) {
	f.t.Helper()
	path := f.file(doc)
	state := f.e.exec(`SELECT (SELECT count(*) FROM audit_log)::text || '/' || (SELECT count(*) FROM gateways)::text || '/' || (SELECT count(*) FROM gateway_grants)::text || '/' || (SELECT coalesce(sum(revision), 0) FROM gateways)::text`)
	for _, args := range [][]string{{"import", "-f", path, "--plan"}, {"import", "-f", path}} {
		code, out, errOut := f.omp.run(args...)
		if code != ompcli.ExitUsage || !strings.Contains(errOut, "refused") || !strings.Contains(errOut, contain) || !strings.Contains(errOut, "Nothing was changed") {
			f.t.Fatalf("omp %v: exit %d\nstdout: %s\nstderr: %s\nwant a refusal mentioning %q", args, code, out, errOut, contain)
		}
	}
	if after := f.e.exec(`SELECT (SELECT count(*) FROM audit_log)::text || '/' || (SELECT count(*) FROM gateways)::text || '/' || (SELECT count(*) FROM gateway_grants)::text || '/' || (SELECT coalesce(sum(revision), 0) FROM gateways)::text`); after != state {
		f.t.Fatalf("a refused import changed the portal: %s -> %s", state, after)
	}
}

// ---- curation -----------------------------------------------------------------

func TestOmpCLIKeepsCuratedSelectionsLossless(t *testing.T) {
	f := newPolicyFixture(t)
	omp := f.omp
	omp.mustRun("import", "-f", f.file("schema: omp/v1\ngateways:\n- slug: curated\n  name: Curated\n  capabilities:\n"+f.capLine("lookup")+f.capLine("other")+"  grants:\n  - {group: eng}\n"))
	f.curate("curated", "lookup", map[string]any{
		"nameOverride": "lookup_team", "descriptionOverride": "Look up our region only",
		"constraints": map[string]any{"region": map[string]any{"fixed": "us"}, "limit": map[string]any{"allowed": []int{2, 3}}},
	})
	row := f.policyRow("curated", "lookup")
	if !strings.Contains(row, "lookup_team") || !strings.Contains(row, `"fixed": "us"`) {
		t.Fatalf("the fixture is not curated: %s", row)
	}

	// Export carries the policy (raw, under the tool's own name) and imports back with no drift.
	exported := omp.mustRun("export")
	for _, want := range []string{"curation:", "nameOverride: lookup_team", "descriptionOverride: Look up our region only", "fixed: us", "name: lookup\n"} {
		if !strings.Contains(exported, want) {
			t.Fatalf("export lacks %q:\n%s", want, exported)
		}
	}
	if strings.Contains(exported, "name: lookup_team\n") {
		t.Fatal("the exposed name must not replace the tool's own name as the key")
	}
	file := f.file(exported)
	if code, out, errOut := omp.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("export -> plan: %d %q %q", code, out, errOut)
	}
	setsBefore := f.audits("gateway.capabilities_set")
	omp.mustRun("import", "-f", file)
	if f.audits("gateway.capabilities_set") != setsBefore || f.policyRow("curated", "lookup") != row {
		t.Fatal("importing an unchanged export wrote something")
	}

	// edit parses the export afresh, lets fn change the curated gateway, and writes it back.
	edit := func(fn func(gw *ompcli.Gateway)) string {
		parsed, err := ompcli.ParseFile([]byte(exported))
		if err != nil {
			t.Fatal(err)
		}
		for i := range parsed.Gateways {
			if parsed.Gateways[i].Slug == "curated" {
				fn(&parsed.Gateways[i])
			}
		}
		out, err := parsed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	lookup := func(gw *ompcli.Gateway) *ompcli.CapabilityRef {
		for i := range *gw.Capabilities {
			if c := &(*gw.Capabilities)[i]; c.Name == "lookup" {
				return c
			}
		}
		t.Fatal("no lookup")
		return nil
	}
	policy := func(gw *ompcli.Gateway) *gwcuration.Policy { return lookup(gw).Curation.Policy }
	addCap := func(gw *ompcli.Gateway, c ompcli.CapabilityRef) {
		caps := append(append([]ompcli.CapabilityRef(nil), *gw.Capabilities...), c)
		gw.Capabilities = &caps
	}

	// Adding a selection keeps the curated one's policy: same definition, same row, nothing re-saved.
	omp.mustRun("import", "-f", f.file(edit(func(gw *ompcli.Gateway) {
		addCap(gw, ompcli.CapabilityRef{Server: f.server, Kind: "tool", Name: "extra"})
	})))
	if got := f.policyRow("curated", "lookup"); got != row {
		t.Fatalf("adding a selection changed the curated tool's policy:\n%s\n%s", row, got)
	}
	sel := f.selection("curated")
	if len(sel.Items) != 3 {
		t.Fatalf("selection: %d items", len(sel.Items))
	}
	for _, c := range sel.Items {
		if c.Name == "lookup" && (c.ExposedName != "lookup_team" || !strings.Contains(strings.ReplaceAll(string(c.Curation), " ", ""), `"fixed":"us"`) || string(c.OriginalDefinition) == string(c.EffectiveDefinition)) {
			t.Fatalf("the curated tool's raw and effective definitions: %+v", c)
		}
	}
	// ...and so does removing the others.
	omp.mustRun("import", "-f", f.file(edit(func(gw *ompcli.Gateway) {
		only := []ompcli.CapabilityRef{*lookup(gw)}
		gw.Capabilities = &only
	})))
	if got := f.policyRow("curated", "lookup"); got != row || len(f.selection("curated").Items) != 1 {
		t.Fatalf("removing selections changed the curated tool's policy:\n%s\n%s", row, got)
	}
	if n := f.e.exec(`SELECT count(*)::text FROM audit_log WHERE action = 'gateway.capabilities_set' AND actor_kind <> 'automation_token'`); n != "1" { // the one curation, by the admin's browser session
		t.Errorf("selection changes were not audited as the token (non-token rows: %s)", n)
	}

	// What omp cannot write is refused, in plan and apply, before anything changes.
	differs := map[string]string{
		"another fixed value": edit(func(gw *ompcli.Gateway) {
			policy(gw).Constraints["region"] = gwcuration.Constraint{Fixed: json.RawMessage(`"eu"`)}
		}),
		"a widened allowed list": edit(func(gw *ompcli.Gateway) {
			policy(gw).Constraints["limit"] = gwcuration.Constraint{Allowed: []json.RawMessage{json.RawMessage("2"), json.RawMessage("3"), json.RawMessage("4")}}
		}),
		"another exposed name":  edit(func(gw *ompcli.Gateway) { n := "lookup_all"; policy(gw).NameOverride = &n }),
		"a constraint left out": edit(func(gw *ompcli.Gateway) { delete(policy(gw).Constraints, "region") }),
		"an emptied policy":     edit(func(gw *ompcli.Gateway) { lookup(gw).Curation = &ompcli.Curation{Policy: &gwcuration.Policy{}} }),
		"curation on a new selection": edit(func(gw *ompcli.Gateway) {
			n := "x_extra"
			addCap(gw, ompcli.CapabilityRef{Server: f.server, Kind: "tool", Name: "extra", Curation: &ompcli.Curation{Policy: &gwcuration.Policy{NameOverride: &n}}})
		}),
	}
	for name, doc := range differs {
		t.Run(name, func(t *testing.T) { f.refuses(doc, "curation") })
	}
	// Declared as no policy while the portal has one.
	nullDoc := "schema: omp/v1\ngateways:\n- slug: curated\n  name: Curated\n  capabilities:\n  - {server: " + f.server + ", kind: tool, name: lookup, curation: null}\n"
	f.refuses(nullDoc, "differs from the portal's")
	// A new gateway declared with a curated tool is not created uncurated.
	fresh := "schema: omp/v1\ngateways:\n- slug: fresh\n  name: Fresh\n  capabilities:\n  - {server: " + f.server + ", kind: tool, name: lookup, curation: {nameOverride: lookup_team}}\n"
	f.refuses(fresh, "not selected yet")
	if n := f.e.exec(`SELECT count(*)::text FROM gateways WHERE slug = 'fresh'`); n != "0" {
		t.Fatal("the refused gateway was created")
	}
	if got := f.policyRow("curated", "lookup"); got != row {
		t.Fatal("a refusal changed the policy")
	}
}

func TestOmpCLIExportsAndKeepsAStalePolicy(t *testing.T) {
	f := newPolicyFixture(t)
	f.omp.mustRun("import", "-f", f.file("schema: omp/v1\ngateways:\n- slug: curated\n  name: Curated\n  capabilities:\n"+f.capLine("lookup")+"  grants: []\n"))
	f.curate("curated", "lookup", map[string]any{"nameOverride": "lookup_team", "constraints": map[string]any{"region": map[string]any{"fixed": "us"}}})
	row := f.policyRow("curated", "lookup")
	// The tool's definition changes and is approved again: the policy is stale until an owner saves it.
	f.e.exec(`UPDATE mcp_capabilities SET fingerprint = repeat('f', 64), approved_fingerprint = repeat('f', 64) WHERE id = $1 RETURNING 'x'`, f.tools["lookup"])
	if sel := f.selection("curated"); len(sel.Items) != 1 || sel.Items[0].Stale == nil || !*sel.Items[0].Stale {
		t.Fatalf("not stale: %+v", sel.Items)
	}
	code, exported, errOut := f.omp.run("export")
	if code != 0 || !strings.Contains(errOut, "is stale") || !strings.Contains(exported, "nameOverride: lookup_team") {
		t.Fatalf("export of a stale policy: %d\n%s\n%s", code, exported, errOut)
	}
	if code, out, errOut := f.omp.run("import", "-f", f.file(exported), "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("stale round trip: %d %q %q", code, out, errOut)
	}
	// Adding a selection leaves the stale policy exactly as it is (the portal preserves omitted policy).
	parsed, err := ompcli.ParseFile([]byte(exported))
	if err != nil {
		t.Fatal(err)
	}
	for i := range parsed.Gateways {
		if parsed.Gateways[i].Slug == "curated" {
			caps := append(*parsed.Gateways[i].Capabilities, ompcli.CapabilityRef{Server: f.server, Kind: "tool", Name: "other"})
			parsed.Gateways[i].Capabilities = &caps
		}
	}
	out, _ := parsed.Marshal()
	f.omp.mustRun("import", "-f", f.file(string(out)))
	if got := f.policyRow("curated", "lookup"); got != row {
		t.Fatalf("a stale policy changed:\n%s\n%s", row, got)
	}
}

// ---- grants -------------------------------------------------------------------

func TestOmpCLIKeepsGrantDeadlinesAndRefusesToExtendThem(t *testing.T) {
	f := newPolicyFixture(t)
	omp, e := f.omp, f.e
	utc := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }
	day := 24 * time.Hour
	head := "schema: omp/v1\ngateways:\n- slug: expiring\n  name: Expiring\n  grants:\n"
	omp.mustRun("import", "-f", f.file(head+
		"  - {group: eng, expiresAt: '"+utc(10*day+12*time.Hour)+"'}\n"+
		"  - {group: ops}\n"+
		"  - {group: reader, toolScope: {classes: [read]}, expiresAt: '"+utc(3*day+5*time.Hour)+"'}\n"))
	grants := f.grants("expiring")
	eng := grants["eng"]
	if eng.ExpiresAt == nil || eng.ExpiresAt.After(time.Now().Add(10*day+12*time.Hour+time.Minute)) || eng.ExpiresAt.Before(time.Now().Add(10*day-time.Minute)) {
		t.Fatalf("eng deadline: %v (declared 10.5 days, whole days only, never later)", eng.ExpiresAt)
	}
	if grants["ops"].ExpiresAt != nil {
		t.Fatal("a grant declared without a deadline must be permanent")
	}

	// Zero drift both ways, with the deadlines.
	exported := omp.mustRun("export")
	if !strings.Contains(exported, "expiresAt: \""+eng.ExpiresAt.UTC().Format(time.RFC3339Nano)+"\"") || !strings.Contains(exported, "toolScope: null") {
		t.Fatalf("export lacks the deadline or the explicit unrestricted scope:\n%s", exported)
	}
	file := f.file(exported)
	if code, out, errOut := omp.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("export -> plan: %d %q %q", code, out, errOut)
	}
	omp.mustRun("import", "-f", file)
	if f.grants("expiring")["eng"].Id != eng.Id {
		t.Fatal("an unchanged import recreated a grant")
	}

	// A scope change keeps the deadline: the new grant expires no later than the old one.
	grantAudits := func() string {
		return e.exec(`SELECT count(*)::text FROM audit_log WHERE action IN ('gateway.grant_remove', 'gateway.grant_add') AND actor_kind = 'automation_token' AND metadata->>'name' LIKE '%eng'`)
	}
	auditsBefore := grantAudits()
	omp.mustRun("import", "-f", f.file(head+"  - {group: eng, toolScope: {classes: [read, write]}}\n  - {group: ops}\n  - {group: reader, toolScope: {classes: [read]}}\n"))
	after := f.grants("expiring")["eng"]
	if after.Id == eng.Id || after.ExpiresAt == nil || after.ExpiresAt.After(*eng.ExpiresAt) || after.ExpiresAt.Before(eng.ExpiresAt.Add(-day-10*time.Minute)) {
		t.Fatalf("eng after a scope change: %+v (was %v)", after, eng.ExpiresAt)
	}
	if after.ToolScope == nil || after.ToolScope.Classes == nil || len(*after.ToolScope.Classes) != 2 {
		t.Fatalf("scope: %+v", after.ToolScope)
	}
	if n := e.exec(`SELECT count(*)::text FROM gateway_grants WHERE gateway_id = $1 AND group_name = 'eng'`, f.gatewayID("expiring")); n != "1" {
		t.Fatalf("%s grants for eng", n)
	}
	if n := grantAudits(); n == auditsBefore {
		t.Errorf("the removal and creation were not audited as the token (%s rows)", n)
	}
	// An omitted scope and deadline leave an expiring grant alone; the next plan agrees.
	if code, out, _ := omp.run("import", "-f", f.file(head+"  - {group: eng}\n  - {group: ops}\n  - {group: reader}\n"), "--plan"); code != 0 {
		t.Fatalf("omitted scope and deadline: %d %s", code, out)
	}
	// Extending is refused; shortening works.
	f.refuses(head+"  - {group: eng, expiresAt: '"+utc(40*day)+"'}\n  - {group: ops}\n  - {group: reader}\n", "never extends")
	omp.mustRun("import", "-f", f.file(head+"  - {group: eng, expiresAt: '"+utc(2*day+3*time.Hour)+"'}\n  - {group: ops}\n  - {group: reader}\n"))
	if short := f.grants("expiring")["eng"]; short.ExpiresAt == nil || short.ExpiresAt.After(time.Now().Add(2*day+3*time.Hour)) || short.ToolScope == nil {
		t.Fatalf("shortened: %+v", short)
	}

	// Less than a day left: it cannot be recreated (the portal sets whole days), so a scope change is refused untouched.
	e.exec(`UPDATE gateway_grants SET expires_at = now() + interval '2 hours' WHERE gateway_id = $1 AND group_name = 'reader' RETURNING 'x'`, f.gatewayID("expiring"))
	reader := f.grants("expiring")["reader"]
	f.refuses(head+"  - {group: eng}\n  - {group: ops}\n  - {group: reader, toolScope: {classes: [read, write]}}\n", "less than one whole day")
	if got := f.grants("expiring")["reader"]; got.Id != reader.Id || !got.ExpiresAt.Equal(*reader.ExpiresAt) {
		t.Fatal("a refused change touched the grant")
	}

	// An expired grant grants nothing and is never extended or made permanent by omp.
	e.exec(`UPDATE gateway_grants SET added_at = now() - interval '5 days', expires_at = now() - interval '1 hour' WHERE gateway_id = $1 AND group_name = 'reader' RETURNING 'x'`, f.gatewayID("expiring"))
	code, exportedExpired, errOut := omp.run("export")
	if code != 0 || !strings.Contains(errOut, "grants nothing") {
		t.Fatalf("export with an expired grant: %d %s", code, errOut)
	}
	if code, out, errOut := omp.run("import", "-f", f.file(exportedExpired), "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("an expired grant recorded as such is no drift: %d %q %q", code, out, errOut)
	}
	f.refuses(head+"  - {group: eng}\n  - {group: ops}\n  - {group: reader, toolScope: {classes: [read]}}\n", "expired at")
	if n := e.exec(`SELECT count(*)::text FROM gateway_grants WHERE gateway_id = $1 AND group_name = 'reader' AND expires_at < now()`, f.gatewayID("expiring")); n != "1" {
		t.Fatal("the expired grant was recreated")
	}
	// Renewal needs a future deadline, and the portal replaces the elapsed row.
	omp.mustRun("import", "-f", f.file(head+"  - {group: eng}\n  - {group: ops}\n  - {group: reader, expiresAt: '"+utc(20*day+2*time.Hour)+"'}\n"))
	renewed := f.grants("expiring")["reader"]
	if renewed.ExpiresAt == nil || !renewed.ExpiresAt.After(time.Now().Add(19*day)) || renewed.ToolScope == nil || renewed.ToolScope.Classes == nil || len(*renewed.ToolScope.Classes) != 1 {
		t.Fatalf("renewed: %+v (a renewal keeps the ceiling)", renewed)
	}
}

// ---- concurrency --------------------------------------------------------------

// interposer is a reverse proxy that lets another writer act between the
// CLI's read of a gateway's selection and its write.
func interposer(t *testing.T, target string, match func(*http.Request) bool, hook func()) *httptest.Server {
	t.Helper()
	var once sync.Once
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequest(r.Method, target+r.URL.RequestURI(), bytes.NewReader(body))
		req.Header = r.Header.Clone()
		res, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		out, _ := io.ReadAll(res.Body)
		if match(r) {
			once.Do(hook) // the response the CLI gets is the one from before the edit
		}
		for k, v := range res.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(res.StatusCode)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOmpCLIConcurrentGatewayEditIsAConflictNotRebased(t *testing.T) {
	f := newPolicyFixture(t)
	omp := f.omp
	omp.mustRun("import", "-f", f.file("schema: omp/v1\ngateways:\n- slug: busy\n  name: Busy\n  capabilities:\n"+f.capLine("lookup")+"  grants: []\n"))
	f.curate("busy", "lookup", map[string]any{"nameOverride": "lookup_team"})
	row := f.policyRow("busy", "lookup")
	gwID := f.gatewayID("busy")

	// After omp has read the selection, someone selects another tool in the web UI.
	var edited atomic.Bool
	proxy := interposer(t, f.e.app.URL, func(r *http.Request) bool {
		return r.Method == http.MethodGet && r.URL.Path == "/v1/admin/gateways/"+gwID+"/capabilities"
	}, func() {
		var sel apitypes.GatewayCapabilities
		if code := f.admin.get("/v1/admin/gateways/"+gwID+"/capabilities", &sel); code != 200 {
			t.Errorf("concurrent read: %d", code)
			return
		}
		items := []map[string]any{}
		for _, c := range sel.Items {
			items = append(items, map[string]any{"capabilityId": c.CapabilityId.String()})
		}
		items = append(items, map[string]any{"capabilityId": f.tools["extra"]})
		if code, ec := f.admin.call("PUT", "/v1/admin/gateways/"+gwID+"/capabilities", map[string]any{"items": items}, nil, ifMatch(int64(sel.Revision))); code != 200 {
			t.Errorf("concurrent edit: %d %s", code, ec)
			return
		}
		edited.Store(true)
	})
	omp.env["OMP_URL"] = proxy.URL
	doc := f.file("schema: omp/v1\ngateways:\n- slug: busy\n  name: Busy\n  capabilities:\n" + f.capLine("lookup") + f.capLine("other") + "  grants: []\n")
	code, _, errOut := omp.run("import", "-f", doc)
	if !edited.Load() {
		t.Fatal("the concurrent edit never happened")
	}
	if code != ompcli.ExitConflict || !strings.Contains(errOut, "run the command again") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	// The concurrent change was not overwritten by the stale plan, and the policy is intact.
	names := []string{}
	for _, c := range f.selection("busy").Items {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "extra,lookup" && strings.Join(names, ",") != "lookup,extra" {
		t.Fatalf("selection after the conflict: %v (the concurrent edit must survive, the plan must not apply)", names)
	}
	if f.policyRow("busy", "lookup") != row {
		t.Fatal("the policy changed")
	}
	// Running again plans against the new state and applies.
	omp.env["OMP_URL"] = f.e.app.URL
	omp.mustRun("import", "-f", doc)
	if got := len(f.selection("busy").Items); got != 2 || f.policyRow("busy", "lookup") != row {
		t.Fatalf("second run: %d items", got)
	}
}
