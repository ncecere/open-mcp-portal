package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/ompcli"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// ompRun runs the omp CLI against the real portal handler with an automation
// token, in a private environment and home directory.
type ompRun struct {
	t    *testing.T
	env  map[string]string
	home string
}

func newOmpRun(t *testing.T, e *matrixEnv, token string) *ompRun {
	t.Helper()
	return &ompRun{t: t, home: t.TempDir(), env: map[string]string{"OMP_URL": e.app.URL, "OMP_TOKEN": token}}
}

func (r *ompRun) run(args ...string) (code int, stdout, stderr string) {
	r.t.Helper()
	var out, errOut bytes.Buffer
	app := &ompcli.App{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut,
		Getenv:  func(k string) string { return r.env[k] },
		HomeDir: func() (string, error) { return r.home, nil },
		Version: "integration", Commit: "test",
	}
	code = app.Run(context.Background(), args)
	return code, out.String(), errOut.String()
}

func (r *ompRun) mustRun(args ...string) string {
	r.t.Helper()
	code, out, errOut := r.run(args...)
	if code != 0 {
		r.t.Fatalf("omp %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// tokenCredsByName mints the matrix's token credentials once (they are unique
// rows) and indexes them by name.
func tokenCredsByName(e *matrixEnv) map[string]tokenCred {
	out := map[string]tokenCred{}
	for _, c := range e.tokenCreds() {
		out[c.name] = c
	}
	return out
}

// A clean CI job with only a publisher token registers a server, tests it,
// refreshes it and publishes it, through the real handler and PostgreSQL
// (token operations only; the token matrix covers everything else).
func TestOmpCLIPublisherWorkflowAgainstThePortal(t *testing.T) {
	e := newMatrixEnv(t)
	pub := tokenCredsByName(e)["publisher-write"]
	omp := newOmpRun(t, e, pub.secret)

	out := omp.mustRun("whoami", "--json")
	var who struct {
		URL   string
		Token struct {
			Kind  string
			Team  struct{ Slug string }
			Scope []string
		}
	}
	if err := json.Unmarshal([]byte(out), &who); err != nil || who.Token.Kind != "team_publisher" || who.Token.Team.Slug != "bravo" {
		t.Fatalf("whoami: %v %s", err, out)
	}

	// The team comes from the token: no --team flag.
	out = omp.mustRun("servers", "register", "--slug", "from-omp", "--name", "From omp", "--url", e.fakeURL)
	if !strings.Contains(out, "registered from-omp") || !strings.Contains(out, "discovery:") {
		t.Fatalf("register: %s", out)
	}
	if got := omp.mustRun("servers", "list"); !strings.Contains(got, "from-omp") || !strings.Contains(got, "private") {
		t.Fatalf("list: %s", got)
	}
	if got := omp.mustRun("servers", "get", "from-omp"); !strings.Contains(got, "Publish:   private") {
		t.Fatalf("get: %s", got)
	}
	if got := omp.mustRun("servers", "test", "from-omp"); !strings.Contains(got, "from-omp: ok") {
		t.Fatalf("test: %s", got)
	}
	if got := omp.mustRun("servers", "refresh", "from-omp", "--fail-on-changes"); !strings.Contains(got, "listed") {
		t.Fatalf("refresh: %s", got)
	}
	// Team bravo self-publishes in the matrix environment.
	if got := omp.mustRun("servers", "publish", "from-omp"); !strings.Contains(got, "from-omp: published") {
		t.Fatalf("publish: %s", got)
	}
	// Publishing twice is a conflict with the API's code and exit code 7.
	code, _, errOut := omp.run("servers", "publish", "from-omp")
	if code != ompcli.ExitConflict || !strings.Contains(errOut, "already_published") {
		t.Fatalf("second publish: exit %d %q", code, errOut)
	}
	if got := omp.mustRun("servers", "unpublish", "from-omp", "--json"); !strings.Contains(got, `"publishState": "private"`) {
		t.Fatalf("unpublish: %s", got)
	}

	// Every mutation is in the log as the token, never as a user.
	if n := e.exec(`SELECT count(*)::text FROM audit_log WHERE actor_kind = 'automation_token' AND action LIKE 'mcp_server.%'`); n == "0" {
		t.Error("the CLI's mutations are not audited as the token")
	}
	if n := e.exec(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.create' AND actor_kind <> 'automation_token' AND target_id = (SELECT id::text FROM mcp_servers WHERE slug = 'from-omp')`); n != "0" {
		t.Error("a CLI mutation was audited as a person")
	}

	// Errors: the API's code and a stable exit code.
	if code, _, errOut := omp.run("servers", "get", "nope"); code != ompcli.ExitNotFound || !strings.Contains(errOut, "server_not_found") {
		t.Errorf("get unknown: %d %q", code, errOut)
	}
	if code, _, errOut := omp.run("servers", "list", "--team", "alpha"); code != ompcli.ExitNotFound || !strings.Contains(errOut, "team_not_found") {
		t.Errorf("other team: %d %q", code, errOut)
	}
	if code, _, errOut := omp.run("servers", "register", "--slug", "from-omp", "--url", e.fakeURL); code != ompcli.ExitConflict || !strings.Contains(errOut, "slug_taken") {
		t.Errorf("slug taken: %d %q", code, errOut)
	}
	if code, _, errOut := omp.run("servers", "register", "--slug", "bad-url", "--url", "http://169.254.169.254/mcp"); code != ompcli.ExitRejected || !strings.Contains(errOut, "url_not_allowed") {
		t.Errorf("refused url: %d %q", code, errOut)
	}
}

// A token without servers:write gets token_not_allowed with the missing scope.
func TestOmpCLIWithAReadOnlyAndAWrongKindOfToken(t *testing.T) {
	e := newMatrixEnv(t)
	creds := tokenCredsByName(e)
	readOnly := creds["publisher-read"]
	omp := newOmpRun(t, e, readOnly.secret)
	if got := omp.mustRun("servers", "list"); !strings.Contains(got, "SLUG") {
		t.Fatalf("list: %s", got)
	}
	code, _, errOut := omp.run("servers", "refresh", e.b.server)
	if code != ompcli.ExitForbidden && code != ompcli.ExitNotFound {
		t.Fatalf("refresh with a read-only token: %d %q", code, errOut)
	}
	code, _, errOut = omp.run("servers", "register", "--slug", "nope", "--url", e.fakeURL)
	if code != ompcli.ExitForbidden || !strings.Contains(errOut, "token_not_allowed") || !strings.Contains(errOut, "servers:write") {
		t.Fatalf("register with a read-only token: %d %q", code, errOut)
	}
	// A personal key is refused before it leaves the machine; a revoked token is 401.
	omp.env["OMP_TOKEN"] = "omp_" + strings.Repeat("k", 43)
	if code, _, errOut := omp.run("whoami"); code != ompcli.ExitConfig || strings.Contains(errOut, "omp_kkkk") {
		t.Errorf("personal key: %d %q", code, errOut)
	}
	omp.env["OMP_TOKEN"] = creds["revoked"].secret
	if code, _, errOut := omp.run("whoami"); code != ompcli.ExitAuth || !strings.Contains(errOut, "invalid_token") {
		t.Errorf("revoked: %d %q", code, errOut)
	}
}

// Export, import and plan against the real API: a header secret read from the
// environment reaches the upstream server and never appears in any output.
func TestOmpCLIExportImportServersAgainstThePortal(t *testing.T) {
	e := newMatrixEnv(t)
	pub := tokenCredsByName(e)["publisher-write"]
	omp := newOmpRun(t, e, pub.secret)
	const secret = "integration-secret-sentinel-5d1e"
	upstream := testutil.NewFakeMCP(t)
	upstream.RequireHeader("X-API-Key", secret)

	file := filepath.Join(t.TempDir(), "omp.yaml")
	doc := "schema: omp/v1\nservers:\n" +
		"  - team: bravo\n    slug: from-file\n    name: From file\n    description: declared\n    url: " + upstream.URL() + "\n    enabled: true\n    authMode: static_header\n    authHeaderName: X-API-Key\n    authValueEnv: FROM_FILE_KEY\n    publish: request\n" +
		"  - team: bravo\n    slug: plain\n    name: Plain\n    url: " + e.fakeURL + "\n    publish: none\n"
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	omp.env["FROM_FILE_KEY"] = secret

	code, out, errOut := omp.run("import", "-f", file, "--plan")
	if code != ompcli.ExitChanges || !strings.Contains(out, "+ server bravo/from-file") || !strings.Contains(out, "+ server bravo/plain") {
		t.Fatalf("plan: %d %q %q", code, out, errOut)
	}
	if strings.Contains(out+errOut, secret) {
		t.Fatal("the plan printed the secret")
	}
	if n := e.exec(`SELECT count(*)::text FROM mcp_servers WHERE slug IN ('from-file', 'plain')`); n != "0" {
		t.Fatal("--plan created a server")
	}
	out = omp.mustRun("import", "-f", file, "--refresh", "--fail-on-changes")
	if strings.Contains(out, secret) {
		t.Fatal("apply printed the secret")
	}
	if !strings.Contains(out, "applied: + server bravo/from-file") {
		t.Fatalf("apply: %s", out)
	}
	// The secret reached the upstream (discovery needed it), and is stored, not exposed.
	if state := e.exec(`SELECT publish_state FROM mcp_servers WHERE slug = 'from-file'`); state != "published" {
		t.Errorf("publish: request under self_publish gave %q", state)
	}
	if n := e.exec(`SELECT count(*)::text FROM mcp_capabilities c JOIN mcp_servers s ON s.id = c.server_id WHERE s.slug = 'from-file'`); n == "0" {
		t.Error("the secret did not reach the upstream: no capabilities were discovered")
	}
	// Zero drift, in both directions.
	if code, out, errOut := omp.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("plan after apply: %d %q %q", code, out, errOut)
	}
	omp.env["FROM_FILE_KEY"] = ""
	exported := omp.mustRun("export")
	if strings.Contains(exported, secret) || strings.Contains(exported, secret[len(secret)-4:]) {
		t.Fatalf("export leaked the secret or its hint:\n%s", exported)
	}
	exportFile := filepath.Join(t.TempDir(), "export.yaml")
	if err := os.WriteFile(exportFile, []byte(exported), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"slug: from-file", "authValueEnv: OMP_FROM_FILE_AUTH_VALUE", "slug: plain"} {
		if !strings.Contains(exported, want) {
			t.Errorf("export lacks %q:\n%s", want, exported)
		}
	}
	if code, out, errOut := omp.run("import", "-f", exportFile, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("export -> plan: %d %q %q", code, out, errOut)
	}
	if dump := e.exec(`SELECT string_agg(a::text, ' ') FROM audit_log a`); strings.Contains(dump, secret) {
		t.Error("the secret is in the audit log")
	}

	// Drift made in the portal (the UI) is found, and apply converges.
	e.exec(`UPDATE mcp_servers SET name = 'Renamed in the UI', revision = revision + 1 WHERE slug = 'plain' RETURNING 'x'`)
	code, out, _ = omp.run("import", "-f", file, "--plan")
	if code != ompcli.ExitChanges || !strings.Contains(out, `name: "Renamed in the UI" -> "Plain"`) {
		t.Fatalf("drift: %d %q", code, out)
	}
	omp.env["FROM_FILE_KEY"] = secret
	omp.mustRun("import", "-f", file)
	if code, out, _ := omp.run("import", "-f", file, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("converged: %d %q", code, out)
	}
}

// A platform token reads and (with platform:write) provisions platform objects:
// the export of a real portal imports back with no drift.
func TestOmpCLIPlatformExportImportAgainstThePortal(t *testing.T) {
	e := newMatrixEnv(t)
	creds := tokenCredsByName(e)
	omp := newOmpRun(t, e, creds["platform-write"].secret)

	exported := omp.mustRun("export")
	for _, want := range []string{"teams:", "slug: alpha", "slug: bravo", "gateways:", "limits:", "person_per_minute:"} {
		if !strings.Contains(exported, want) {
			t.Errorf("export lacks %q:\n%s", want, exported)
		}
	}
	file := filepath.Join(t.TempDir(), "platform.yaml")
	if err := os.WriteFile(file, []byte(exported), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := omp.run("import", "-f", file, "--plan")
	if code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("export -> plan: %d %q %q", code, out, errOut)
	}

	// Provision a team and a gateway from a file, then converge a drifted limit.
	declared := exported + "" // the exported document, extended below
	declared = strings.Replace(declared, "teams:\n", "teams:\n  - slug: from-omp\n    name: From omp\n    description: provisioned\n    ownerEmail: nobody@example.com\n    limits:\n      server_per_minute: 120\n", 1)
	declared = strings.Replace(declared, "gateways:\n", "gateways:\n  - slug: from-omp-gw\n    name: From omp gateway\n    description: provisioned\n    enabled: true\n    capabilities: []\n    grants:\n      - team: from-omp\n", 1)
	declared = strings.Replace(declared, "\n  gateway_per_minute:\n    default: null\n    ceiling: null\n", "\n  gateway_per_minute:\n    default: 900\n    ceiling: 1800\n", 1)
	if declared == exported || !strings.Contains(declared, "default: 900") {
		t.Fatalf("the test document was not extended:\n%s", exported)
	}
	declFile := filepath.Join(t.TempDir(), "declared.yaml")
	if err := os.WriteFile(declFile, []byte(declared), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ompcli.ParseFile([]byte(declared)); err != nil {
		t.Fatalf("test document: %v\n%s", err, declared)
	}
	code, out, errOut = omp.run("import", "-f", declFile, "--plan")
	if code != ompcli.ExitChanges || !strings.Contains(out, "+ team from-omp") || !strings.Contains(out, "+ gateway from-omp-gw") {
		t.Fatalf("plan: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := omp.run("import", "-f", declFile); code != 0 {
		t.Fatalf("apply: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := omp.run("import", "-f", declFile, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("converged: %d %q %q", code, out, errOut)
	}
	if n := e.exec(`SELECT count(*)::text FROM gateway_grants gg JOIN gateways g ON g.id = gg.gateway_id WHERE g.slug = 'from-omp-gw'`); n != "1" {
		t.Errorf("grants of the new gateway: %s", n)
	}
	// Audited as the token, not a person.
	if n := e.exec(`SELECT count(*)::text FROM audit_log WHERE actor_kind = 'automation_token' AND action IN ('team.create', 'gateway.create', 'settings.limits_update')`); n == "0" {
		t.Error("platform changes were not audited as the token")
	}

	// A read-only platform token plans, and cannot apply.
	ro := creds["platform-read"]
	omp.env["OMP_TOKEN"] = ro.secret
	if code, out, _ := omp.run("import", "-f", declFile, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Errorf("read-only plan: %d %q", code, out)
	}
	drifted := strings.Replace(declared, "name: From omp gateway", "name: Renamed", 1)
	driftFile := filepath.Join(t.TempDir(), "drift.yaml")
	if err := os.WriteFile(driftFile, []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = omp.run("import", "-f", driftFile)
	if code != ompcli.ExitForbidden || !strings.Contains(errOut, "platform:write") {
		t.Errorf("read-only apply: %d %q", code, errOut)
	}
	// A platform token never reaches team routes: the API says so, with its code.
	code, _, errOut = omp.run("servers", "list", "--team", "bravo")
	if code != ompcli.ExitForbidden || !strings.Contains(errOut, "token_not_allowed") {
		t.Errorf("platform token on a team route: %d %q", code, errOut)
	}
}
