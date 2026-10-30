package ompcli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

const secretSentinel = "sk-sentinel-never-export-7f3a91c2"

// seedServers registers a few servers through the CLI itself.
func seedServers(t *testing.T, h *harness, f *fakePortal) {
	t.Helper()
	h.env["STATUS_API_KEY"] = secretSentinel
	for _, args := range [][]string{
		{"servers", "register", "--slug", "status", "--name", "Service status", "--description", "Is it up", "--url", "https://status.example.com/mcp"},
		{"servers", "register", "--slug", "billing", "--name", "Billing", "--url", "https://billing.example.com/mcp", "--auth", "static_header", "--auth-header", "X-API-Key", "--auth-value-env", "STATUS_API_KEY", "--timeout-seconds", "45"},
	} {
		if code, out, errOut := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d %q %q", args, code, out, errOut)
		}
	}
	if code, _, errOut := h.run("servers", "publish", "billing"); code != 0 {
		t.Fatal(errOut)
	}
}

func TestExportServersNeverIncludesASecret(t *testing.T) {
	f := newFakePortal(t)
	tok := f.publisher("bravo")
	h := newHarness(t)
	h.connect(f, tok)
	seedServers(t, h, f)

	code, out, errOut := h.run("export")
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	for _, label := range []string{"yaml", "json"} {
		if label == "json" {
			code, out, errOut = h.run("export", "--json")
			if code != 0 {
				t.Fatal(errOut)
			}
		}
		if strings.Contains(out+errOut, secretSentinel) || strings.Contains(out+errOut, secretSentinel[len(secretSentinel)-4:]) {
			t.Errorf("%s export leaked the secret or its hint:\n%s", label, out)
		}
		if strings.Contains(out, tok) {
			t.Errorf("%s export has the token", label)
		}
	}
	code, out, _ = h.run("export")
	for _, want := range []string{"schema: omp/v1", "slug: billing", "authMode: static_header", "authHeaderName: X-API-Key", "authValueEnv: OMP_BILLING_AUTH_VALUE", "publish: request", "timeoutSeconds: 45", "slug: status", "authMode: none", "publish: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("export lacks %q:\n%s", want, out)
		}
	}
	// To a file, the same, and also without the secret.
	path := t.TempDir() + "/omp.yaml"
	if code, _, errOut := h.run("export", "-o", path); code != 0 {
		t.Fatal(errOut)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), secretSentinel) || !strings.Contains(string(raw), "schema: omp/v1") {
		t.Errorf("exported file:\n%s", raw)
	}
	// The export is a valid file.
	if _, err := ParseFile(raw); err != nil {
		t.Errorf("the export is not valid omp/v1: %v", err)
	}
}

func TestServersRoundTripHasZeroDrift(t *testing.T) {
	src := newFakePortal(t)
	h := newHarness(t)
	h.connect(src, src.publisher("bravo"))
	seedServers(t, h, src)
	_, exported, _ := h.run("export")
	file := writeTempFile(t, "omp.yaml", exported, 0o600)

	// Plan against the portal it came from: no changes, exit 0, no secret.
	h.env["OMP_BILLING_AUTH_VALUE"] = ""
	code, out, errOut := h.run("import", "-f", file, "--plan")
	if code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("plan on an unchanged file: exit %d out %q err %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, secretSentinel) {
		t.Fatal("the plan printed a secret")
	}
	code, out, _ = h.run("import", "-f", file, "--plan", "--json")
	var plan struct {
		Drift   bool
		Changes []any
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil || code != 0 || plan.Drift || len(plan.Changes) != 0 {
		t.Fatalf("plan --json: exit %d %s", code, out)
	}
	if strings.Contains(out, `"changes": null`) {
		t.Error("changes must be an empty list, not null")
	}

	// Import into an empty portal, with the secret in the environment.
	dst := newFakePortal(t)
	h2 := newHarness(t)
	h2.connect(dst, dst.publisher("bravo"))
	h2.env["OMP_BILLING_AUTH_VALUE"] = secretSentinel
	code, out, errOut = h2.run("import", "-f", file, "--plan")
	if code != ExitChanges || !strings.Contains(out, "+ server bravo/billing") || !strings.Contains(out, "+ server bravo/status") || !strings.Contains(out, "Plan: 2 to create, 0 to update.") {
		t.Fatalf("plan into an empty portal: exit %d out %q err %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, secretSentinel) || !strings.Contains(out, "(read from $OMP_BILLING_AUTH_VALUE)") {
		t.Errorf("the plan must name the variable and never print the value:\n%s", out)
	}
	if n := dst.countRequests("POST", "/v1/teams/bravo/mcp-servers"); n != 0 {
		t.Fatalf("--plan made %d create requests", n)
	}
	code, out, errOut = h2.run("import", "-f", file)
	if code != 0 || !strings.Contains(out, "applied: + server bravo/billing") {
		t.Fatalf("apply: exit %d out %q err %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, secretSentinel) {
		t.Fatal("apply printed the secret")
	}
	if dst.servers["billing"].secret != secretSentinel {
		t.Error("the portal did not receive the secret from the environment variable")
	}
	if dst.servers["billing"].PublishState != ompclient.PublishStatePublished {
		t.Errorf("publish: request was not applied: %s", dst.servers["billing"].PublishState)
	}

	// Plan again: zero drift; and the second export is byte-identical.
	if code, out, _ := h2.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("plan after apply: exit %d %q", code, out)
	}
	_, again, _ := h2.run("export")
	if again != exported {
		t.Errorf("export -> import -> export differs:\n--- first\n%s\n--- second\n%s", exported, again)
	}
	// Applying an unchanged file writes nothing.
	before := len(dst.lastRequests(1000))
	if code, out, _ := h2.run("import", "-f", file); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("second apply: %d %q", code, out)
	}
	for _, r := range dst.lastRequests(len(dst.lastRequests(1000)) - before) {
		if r.Method != "GET" {
			t.Errorf("an unchanged import sent %s %s", r.Method, r.Path)
		}
	}
}

func TestPlanDetectsDriftAndApplyConverges(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	seedServers(t, h, f)
	_, exported, _ := h.run("export")
	file := writeTempFile(t, "omp.yaml", exported, 0o600)

	// Someone edits the portal (UI) behind the file's back.
	st := f.servers["status"]
	st.Name, st.Url, st.Enabled, st.Revision = "Renamed", "https://other.example.com/mcp", false, st.Revision+1
	f.servers["billing"].PublishState = ompclient.PublishStatePrivate

	code, out, errOut := h.run("import", "-f", file, "--plan")
	if code != ExitChanges {
		t.Fatalf("exit %d, want %d (out %q)", code, ExitChanges, out)
	}
	for _, want := range []string{
		"~ server bravo/status", `name: "Renamed" -> "Service status"`, `url: "https://other.example.com/mcp" -> "https://status.example.com/mcp"`, "enabled: false -> true",
		"~ server bravo/billing", `publish: "private" -> "request"`, "Plan: 0 to create, 2 to update.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "changes_found") {
		t.Errorf("stderr %q", errOut)
	}
	code, out, _ = h.run("import", "-f", file, "--plan", "--json")
	var js struct {
		Drift   bool
		Changes []struct {
			Kind, Key, Action string
			Fields            []struct{ Field string }
		}
	}
	if err := json.Unmarshal([]byte(out), &js); err != nil || code != ExitChanges || !js.Drift || len(js.Changes) != 2 || js.Changes[0].Key != "bravo/billing" {
		t.Fatalf("plan --json: %d %s", code, out)
	}
	// Nothing was written by planning.
	if f.countRequests("PATCH", "/v1/teams/bravo/mcp-servers/") != 0 {
		t.Fatal("--plan wrote")
	}

	if code, out, errOut := h.run("import", "-f", file); code != 0 {
		t.Fatalf("apply: %d %q %q", code, out, errOut)
	}
	if st.Name != "Service status" || st.Url != "https://status.example.com/mcp" || !st.Enabled || f.servers["billing"].PublishState != ompclient.PublishStatePublished {
		t.Errorf("not converged: %+v", st.McpServer)
	}
	if code, out, _ := h.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Errorf("plan after converging: %d %q", code, out)
	}
	// The PATCH carried the revision it read.
	for _, r := range f.lastRequests(50) {
		if r.Method == "PATCH" && r.IfMatch == "" {
			t.Errorf("PATCH without If-Match: %s", r.Path)
		}
	}
}

func TestSecretsAreNeverComparedOrSentUnlessAsked(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	seedServers(t, h, f)
	_, exported, _ := h.run("export")
	file := writeTempFile(t, "omp.yaml", exported, 0o600)

	// A set variable with a different value is not drift: secrets are write-only.
	h.env["OMP_BILLING_AUTH_VALUE"] = "rotated-" + secretSentinel
	if code, out, _ := h.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("plan: %d %q", code, out)
	}
	before := f.servers["billing"].secret
	if code, _, _ := h.run("import", "-f", file); code != 0 || f.servers["billing"].secret != before {
		t.Fatal("an unchanged import must not send the secret")
	}
	// --replace-secrets asks for it, in the plan and in the apply.
	code, out, errOut := h.run("import", "-f", file, "--plan", "--replace-secrets")
	if code != ExitChanges || !strings.Contains(out, "authValue") || !strings.Contains(out, "(read from $OMP_BILLING_AUTH_VALUE)") {
		t.Fatalf("plan --replace-secrets: %d %q", code, out)
	}
	if strings.Contains(out+errOut, "rotated-") {
		t.Fatal("the plan printed the new secret")
	}
	code, out, errOut = h.run("import", "-f", file, "--replace-secrets")
	if code != 0 || f.servers["billing"].secret != "rotated-"+secretSentinel {
		t.Fatalf("apply --replace-secrets: %d %q %q secret %q", code, out, errOut, f.servers["billing"].secret)
	}
	if strings.Contains(out+errOut, "rotated-") || strings.Contains(out+errOut, secretSentinel) {
		t.Fatal("apply printed a secret")
	}
	// With the variable unset, nothing is sent and nothing is applied.
	delete(h.env, "OMP_BILLING_AUTH_VALUE")
	writes := countWrites(f)
	code, _, errOut = h.run("import", "-f", file, "--replace-secrets")
	if code != ExitUsage || !strings.Contains(errOut, "OMP_BILLING_AUTH_VALUE") || countWrites(f) != writes {
		t.Fatalf("missing variable: exit %d err %q, writes %d -> %d", code, errOut, writes, countWrites(f))
	}
	// A plan warns instead of failing.
	if code, _, errOut := h.run("import", "-f", file, "--plan", "--replace-secrets"); code != ExitChanges || !strings.Contains(errOut, "warning: server billing: $OMP_BILLING_AUTH_VALUE is not set") {
		t.Errorf("plan with a missing variable: %d %q", code, errOut)
	}
}

func countWrites(f *fakePortal) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Method != "GET" {
			n++
		}
	}
	return n
}

func TestImportRefusesAnythingThatNeedsAnotherToken(t *testing.T) {
	f := newFakePortal(t)
	pub := f.publisher("bravo")
	adm := f.platformAdmin()
	readOnly := f.addToken(ompclient.AutomationTokenKindPlatformAdmin, "", "platform:read")
	both := "schema: omp/v1\nservers:\n- team: bravo\n  slug: s\n  name: S\n  url: https://s.example.com/mcp\nteams:\n- slug: t\n  name: T\n  ownerEmail: o@example.com\n"
	file := writeTempFile(t, "both.yaml", both, 0o600)
	h := newHarness(t)

	h.connect(f, pub)
	code, _, errOut := h.run("import", "-f", file, "--plan")
	if code != ExitUsage || !strings.Contains(errOut, "platform-admin token") || !strings.Contains(errOut, "--only servers") {
		t.Errorf("publisher with platform objects: %d %q", code, errOut)
	}
	if code, out, _ := h.run("import", "-f", file, "--plan", "--only", "servers"); code != ExitChanges || !strings.Contains(out, "bravo/s") || strings.Contains(out, "team t") {
		t.Errorf("publisher --only servers: %d %q", code, out)
	}
	h.connect(f, adm)
	code, _, errOut = h.run("import", "-f", file, "--plan")
	if code != ExitUsage || !strings.Contains(errOut, "team publisher token") {
		t.Errorf("platform token with servers: %d %q", code, errOut)
	}
	if code, out, _ := h.run("import", "-f", file, "--plan", "--only", "platform"); code != ExitChanges || !strings.Contains(out, "+ team t") {
		t.Errorf("platform --only platform: %d %q", code, out)
	}
	// A team that is not the token's is refused, and nothing is sent.
	other := writeTempFile(t, "other.yaml", "schema: omp/v1\nservers:\n- team: alpha\n  slug: s\n  name: S\n  url: https://s.example.com/mcp\n", 0o600)
	h.connect(f, pub)
	if code, _, errOut := h.run("import", "-f", other, "--plan"); code != ExitUsage || !strings.Contains(errOut, `team "alpha"`) {
		t.Errorf("other team: %d %q", code, errOut)
	}
	// Applying platform objects needs platform:write, checked before any change; planning needs only read.
	teams := writeTempFile(t, "teams.yaml", "schema: omp/v1\nteams:\n- slug: t\n  name: T\n  ownerEmail: o@example.com\n", 0o600)
	h.connect(f, readOnly)
	if code, out, _ := h.run("import", "-f", teams, "--plan"); code != ExitChanges || !strings.Contains(out, "+ team t") {
		t.Errorf("read-only plan: %d %q", code, out)
	}
	code, _, errOut = h.run("import", "-f", teams)
	if code != ExitForbidden || !strings.Contains(errOut, "platform:write") || countWrites(f) != 0 {
		t.Errorf("read-only apply: %d %q (writes %d)", code, errOut, countWrites(f))
	}
	// Export reads what the token can.
	h.connect(f, pub)
	if code, _, _ := h.run("export", "--only", "platform"); code != ExitUsage {
		t.Errorf("publisher export --only platform: %d", code)
	}
	h.connect(f, adm)
	if code, _, _ := h.run("export", "--only", "servers"); code != ExitUsage {
		t.Errorf("platform export --only servers: %d", code)
	}
}

func TestExportSkipsAndImportRefusesServersOmpCannotManage(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	seedServers(t, h, f)
	oauth := ompclient.McpServerAuthModeOauth
	f.servers["status"].AuthMode = &oauth
	code, out, errOut := h.run("export")
	if code != 0 || strings.Contains(out, "slug: status") || !strings.Contains(errOut, "warning: skipped server status: it uses authMode oauth") {
		t.Fatalf("export: %d out %q err %q", code, out, errOut)
	}
	file := writeTempFile(t, "s.yaml", "schema: omp/v1\nservers:\n- team: bravo\n  slug: status\n  name: Service status\n  url: https://status.example.com/mcp\n  authMode: none\n", 0o600)
	code, _, errOut = h.run("import", "-f", file, "--plan")
	if code != ExitUsage || !strings.Contains(errOut, "browser session") || !strings.Contains(errOut, "remove it from the file") {
		t.Errorf("import: %d %q", code, errOut)
	}
}

func TestImportAppliesServersWithPublishAndRefresh(t *testing.T) {
	f := newFakePortal(t)
	f.policy = "approval_required"
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	file := writeTempFile(t, "s.yaml", "schema: omp/v1\nservers:\n- team: bravo\n  slug: status\n  name: Status\n  url: https://status.example.com/mcp\n  publish: request\n", 0o600)
	f.refreshChanged = 2
	code, out, errOut := h.run("import", "-f", file, "--refresh", "--fail-on-changes")
	if code != ExitChanges || !strings.Contains(errOut, "capabilities_changed") {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
	if !strings.Contains(out, "applied: + server bravo/status") || !strings.Contains(out, "refreshed status: 3 listed, 0 added, 2 changed, 0 gone") {
		t.Errorf("out %q", out)
	}
	if f.servers["status"].PublishState != ompclient.PublishStatePending {
		t.Errorf("under approval_required a request is pending, got %s", f.servers["status"].PublishState)
	}
	// Refresh runs for unchanged files too (the deploy-time use), and is not drift.
	f.refreshChanged = 0
	before := f.countRequests("POST", "/v1/teams/bravo/mcp-servers/")
	code, out, _ = h.run("import", "-f", file, "--refresh")
	if code != 0 || f.countRequests("POST", "/v1/teams/bravo/mcp-servers/") != before+1 || !strings.Contains(out, "refreshed status") {
		t.Errorf("refresh of an unchanged file: %d %q", code, out)
	}
	// publish: none withdraws.
	file2 := writeTempFile(t, "s2.yaml", "schema: omp/v1\nservers:\n- team: bravo\n  slug: status\n  name: Status\n  url: https://status.example.com/mcp\n  publish: none\n", 0o600)
	if code, out, _ := h.run("import", "-f", file2); code != 0 || f.servers["status"].PublishState != ompclient.PublishStatePrivate {
		t.Errorf("publish none: %d %q state %s", code, out, f.servers["status"].PublishState)
	}
}

func TestImportFromStdinAndJSONApplyOutput(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	h.stdin = `{"schema":"omp/v1","servers":[{"team":"bravo","slug":"status","name":"Status","url":"https://status.example.com/mcp"}]}`
	code, out, errOut := h.run("import", "-f", "-", "--json")
	if code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	var res struct {
		Applied  []Change
		Warnings []string
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Applied) != 1 || res.Applied[0].Key != "bravo/status" || res.Applied[0].Action != "create" {
		t.Fatalf("%v %s", err, out)
	}
}

func TestStaleRevisionIsAConflictWithAHint(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	seedServers(t, h, f)
	file := writeTempFile(t, "s.yaml", "schema: omp/v1\nservers:\n- team: bravo\n  slug: status\n  name: Changed name\n  url: https://status.example.com/mcp\n", 0o600)
	// Another writer gets in between the plan's read and the PATCH.
	f.forceStatus = map[string]int{}
	f.servers["status"].Revision = 7
	hook := f.srv.Config.Handler
	f.srv.Config.Handler = bumpOnGet(f, hook)
	code, _, errOut := h.run("import", "-f", file)
	if code != ExitConflict || !strings.Contains(errOut, "revision_conflict") || !strings.Contains(errOut, "run the command again") {
		t.Fatalf("exit %d err %q", code, errOut)
	}
}

// ---- platform objects ---------------------------------------------------------

func seedPlatform(f *fakePortal) {
	d, c := int64(600), int64(1200)
	for i := range f.limits {
		if f.limits[i].Key == "gateway_per_minute" {
			f.limits[i].Default, f.limits[i].Ceiling = &d, &c
		}
	}
	lim := int64(50)
	f.teams["bravo"] = &fakeTeam{Team: ompclient.Team{Id: uuid.New(), Slug: "bravo", Name: "Bravo", Description: "The B team", Status: ompclient.TeamStatusActive, Revision: 3, CreatedAt: time.Now()}, limits: map[string]*int64{"gateway_per_minute": &lim}}
	f.teams["old"] = &fakeTeam{Team: ompclient.Team{Id: uuid.New(), Slug: "old", Name: "Old", Status: ompclient.TeamStatusArchived, Revision: 1}, limits: map[string]*int64{}}
	toolID, promptID := uuid.New(), uuid.New()
	f.options = []ompclient.GatewayOption{
		{CapabilityId: toolID, Kind: ompclient.GatewayCapabilityKindTool, Name: "check", ServerSlug: "status", ExposedName: "status__check"},
		{CapabilityId: promptID, Kind: ompclient.GatewayCapabilityKindPrompt, Name: "summarize", ServerSlug: "status", ExposedName: "status__summarize"},
		{CapabilityId: uuid.New(), Kind: ompclient.GatewayCapabilityKindTool, Name: "bill", ServerSlug: "billing", ExposedName: "billing__bill"},
	}
	classes := []ompclient.ToolClass{"read"}
	f.gateways["support"] = &fakeGateway{
		Gateway: ompclient.Gateway{Id: uuid.New(), Slug: "support", Name: "Support tools", Description: "For support", Enabled: true, OwnerKind: ompclient.GatewayOwnerKindPlatform, Revision: 2},
		caps:    []ompclient.GatewayCapability{{CapabilityId: toolID, Kind: ompclient.GatewayCapabilityKindTool, Name: "check", ServerSlug: "status"}},
		grants: []ompclient.GatewayGrant{
			{Id: uuid.New(), SubjectKind: ompclient.GatewayGrantSubjectKindTeam, Team: &ompclient.GrantTeam{Id: uuid.New(), Slug: "bravo", Name: "Bravo"}},
			{Id: uuid.New(), SubjectKind: ompclient.GatewayGrantSubjectKindUser, User: &ompclient.MemberUser{Email: "ann@example.com"}, ToolScope: &ompclient.ToolScope{Classes: &classes}},
		},
	}
}

func TestPlatformRoundTripHasZeroDrift(t *testing.T) {
	src := newFakePortal(t)
	seedPlatform(src)
	h := newHarness(t)
	h.connect(src, src.platformAdmin())
	code, exported, errOut := h.run("export")
	if code != 0 {
		t.Fatalf("export: %d %s", code, errOut)
	}
	for _, want := range []string{"slug: bravo", "status: archived", "gateway_per_minute: 50", "slug: support", "kind: tool", "name: check", "userEmail: ann@example.com", "toolScope:", "- read", "person_per_minute:", "ceiling: 1200"} {
		if !strings.Contains(exported, want) {
			t.Errorf("export lacks %q:\n%s", want, exported)
		}
	}
	file := writeTempFile(t, "omp.yaml", exported, 0o600)
	if code, out, errOut := h.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("plan: %d %q %q", code, out, errOut)
	}

	// Import into a portal that has only the selectable options, and compare the exports.
	dst := newFakePortal(t)
	dst.options = src.options
	h2 := newHarness(t)
	h2.connect(dst, dst.platformAdmin())
	// ownerEmail is needed to create a team and is not exported.
	withOwners := strings.ReplaceAll(exported, "    name: Bravo\n", "    name: Bravo\n    ownerEmail: boss@example.com\n")
	withOwners = strings.ReplaceAll(withOwners, "    name: Old\n", "    name: Old\n    ownerEmail: boss@example.com\n")
	file2 := writeTempFile(t, "omp2.yaml", withOwners, 0o600)
	code, out, errOut := h2.run("import", "-f", file2)
	if code != 0 {
		t.Fatalf("apply: %d %q %q", code, out, errOut)
	}
	_, again, _ := h2.run("export")
	if again != exported {
		t.Errorf("export -> import -> export differs:\n--- first\n%s\n--- second\n%s", exported, again)
	}
	if code, out, _ := h2.run("import", "-f", file2, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Errorf("plan after import: %d %q", code, out)
	}
}

func TestPlatformDriftAndConvergence(t *testing.T) {
	f := newFakePortal(t)
	seedPlatform(f)
	h := newHarness(t)
	h.connect(f, f.platformAdmin())
	_, exported, _ := h.run("export")
	file := writeTempFile(t, "omp.yaml", exported, 0o600)

	// Drift everywhere: a team renamed, a limit changed, a grant removed and another added, a capability swapped.
	f.teams["bravo"].Name = "Bravo Renamed"
	f.teams["bravo"].Revision++
	one := int64(75)
	f.teams["bravo"].limits["gateway_per_minute"] = &one
	f.limitRev++
	for i := range f.limits {
		if f.limits[i].Key == "person_per_minute" {
			v := int64(10)
			f.limits[i].Default = &v
		}
	}
	gw := f.gateways["support"]
	gw.grants = append(gw.grants[1:], ompclient.GatewayGrant{Id: uuid.New(), SubjectKind: ompclient.GatewayGrantSubjectKindGroup, Group: ptr("interns")})
	gw.caps = []ompclient.GatewayCapability{{CapabilityId: f.options[2].CapabilityId, Kind: ompclient.GatewayCapabilityKindTool, Name: "bill", ServerSlug: "billing"}}
	gw.Enabled = false
	gw.Revision++

	code, out, errOut := h.run("import", "-f", file, "--plan")
	if code != ExitChanges {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
	for _, want := range []string{
		"~ team bravo", `name: "Bravo Renamed" -> "Bravo"`, "limits.gateway_per_minute: 75 -> 50",
		"~ gateway support", "enabled: false -> true", `capability: (none) -> "tool status/check"`, `capability: "tool billing/bill" -> (none)`, `grant: (none) -> "team:bravo"`, `grant: "group:interns" -> (none)`, "~ limits platform", "person_per_minute.default: 10 -> 600",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if code, out, errOut := h.run("import", "-f", file); code != 0 {
		t.Fatalf("apply: %d %q %q", code, out, errOut)
	}
	if code, out, _ := h.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Errorf("plan after converging: %d %q", code, out)
	}
	if f.teams["bravo"].Name != "Bravo" || *f.teams["bravo"].limits["gateway_per_minute"] != 50 || !f.gateways["support"].Enabled || len(f.gateways["support"].grants) != 2 {
		t.Errorf("not converged")
	}
}

func TestPlatformCreateNeedsAnOwnerAndASelectableCapability(t *testing.T) {
	f := newFakePortal(t)
	f.options = []ompclient.GatewayOption{{CapabilityId: uuid.New(), Kind: ompclient.GatewayCapabilityKindTool, Name: "check", ServerSlug: "status"}}
	h := newHarness(t)
	h.connect(f, f.platformAdmin())
	noOwner := writeTempFile(t, "a.yaml", "schema: omp/v1\nteams:\n- slug: t\n  name: T\n", 0o600)
	if code, _, errOut := h.run("import", "-f", noOwner, "--plan"); code != ExitUsage || !strings.Contains(errOut, "ownerEmail is required") {
		t.Errorf("no owner: %d %q", code, errOut)
	}
	bad := writeTempFile(t, "b.yaml", "schema: omp/v1\ngateways:\n- slug: g\n  name: G\n  capabilities:\n  - {server: status, kind: tool, name: check}\n  - {server: status, kind: tool, name: not-approved}\n", 0o600)
	code, out, errOut := h.run("import", "-f", bad, "--plan")
	if code != ExitChanges || !strings.Contains(errOut, "status/not-approved is not selectable now") || !strings.Contains(out, "+ gateway g") {
		t.Errorf("plan: %d %q %q", code, out, errOut)
	}
	code, _, errOut = h.run("import", "-f", bad)
	if code != ExitRejected || !strings.Contains(errOut, "capability_not_found") {
		t.Errorf("apply: %d %q", code, errOut)
	}
}

func ptr[T any](v T) *T { return &v }
