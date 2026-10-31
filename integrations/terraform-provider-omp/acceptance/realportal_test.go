// Package acceptance exercises the real handler, PostgreSQL, provider process and
// Terraform CLI. Its parent namespace permits supported internal test setup; no
// httpapi_test helpers or substituted metadata responses are used.
package acceptance

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestRealPortal(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("TF_ACC=1 opts into real portal/Terraform acceptance")
	}
	if os.Getenv("OMP_TEST_REQUIRE_DB") != "1" {
		t.Fatal("acceptance requires OMP_TEST_REQUIRE_DB=1; skips are not acceptance")
	}
	cli := os.Getenv("OMP_TERRAFORM_CLI")
	if !filepath.IsAbs(cli) {
		t.Fatal("OMP_TERRAFORM_CLI must name a verified absolute Terraform executable")
	}
	u, err := url.Parse(os.Getenv("OMP_TEST_DATABASE_URL"))
	if err != nil || u == nil || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/postgres" {
		t.Fatal("explicit owned loopback PostgreSQL /postgres URL required (value suppressed)")
	}
	if mode := os.Getenv("OMP_TEST_SPLIT_ROLES"); mode != "0" && mode != "1" {
		t.Fatal("set actual OMP_TEST_SPLIT_ROLES=0 or 1")
	}
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, pool)
	var dbName, runtimeRole, ownerRole string
	var super, createDB, createRole, bypassRLS bool
	if err := pool.QueryRow(ctx, `SELECT current_database(), current_user, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&dbName, &runtimeRole, &super, &createDB, &createRole, &bypassRLS); err != nil {
		t.Fatal("inspect runtime fixture role")
	}
	if err := owner.QueryRow(ctx, `SELECT current_user`).Scan(&ownerRole); err != nil {
		t.Fatal("inspect owner fixture role")
	}
	if os.Getenv("OMP_TEST_SPLIT_ROLES") == "1" && (runtimeRole == ownerRole || super || createDB || createRole || bypassRLS) {
		t.Fatal("split fixture is not genuinely restricted/authenticated")
	}
	if os.Getenv("OMP_TEST_SPLIT_ROLES") == "0" && runtimeRole != ownerRole {
		t.Fatal("single-owner fixture unexpectedly split")
	}
	t.Logf("owned scratch database=%s split_roles=%s restricted_runtime=%t", dbName, os.Getenv("OMP_TEST_SPLIT_ROLES"), !super && !createDB && !createRole && !bypassRLS)
	var version int
	if err := owner.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil || version/10000 != 17 {
		t.Fatal("owned PostgreSQL 17 required")
	}
	execSQL := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("fixture SQL: %v", err)
		}
	}
	idSQL := func(sql string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := owner.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	key := func() string {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	const secret = "fixture-upstream-private-sentinel-47"
	const contact = "fixture-contact-47@example.invalid"
	const claims = "fixture-claims-private-47"
	user := idSQL(`INSERT INTO users (oidc_issuer,oidc_subject,email,display_name,platform_role,claims) VALUES ('https://issuer.invalid','tf-acc','admin@example.invalid','Fixture admin','platform_admin',jsonb_build_object('private',$1::text)) RETURNING id`, claims)
	team := idSQL(`INSERT INTO teams (slug,name,description) VALUES ('bravo','Bravo fixture',$1) RETURNING id`, secret)
	foreign := idSQL(`INSERT INTO teams (slug,name) VALUES ('foreign','Foreign fixture') RETURNING id`)
	execSQL(`INSERT INTO team_members (team_id,user_id,role) VALUES ($1,$2,'owner')`, team, user)
	cfg := config.Defaults()
	cfg.AppURL = "https://127.0.0.1"
	cfg.EncryptionKey = key()
	cfg.APIKeyPepper = key()
	cfg.RequestsPerMinute = 100000
	deps, err := app.NewDeps(cfg, pool, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	// Direct synthetic server setup avoids discovery or any upstream call.
	server := uuid.New()
	k, err := secrets.ParseKey(cfg.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(k)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := box.Seal([]byte(secret), registry.ServerAAD(server))
	if err != nil {
		t.Fatal(err)
	}
	execSQL(`INSERT INTO mcp_servers (id,team_id,slug,name,url,description,enabled,auth_mode,auth_header_name,auth_value_cipher,auth_value_hint,oncall_contact) VALUES ($1,$2,'status','Status fixture','https://upstream.invalid/mcp',$3,false,'static_header','Authorization',$4,'t-47',$5)`, server, team, secret, cipher, contact)
	foreignServer := idSQL(`INSERT INTO mcp_servers (team_id,slug,name,url) VALUES ($1,'foreign-status','Foreign status','https://upstream.invalid/mcp') RETURNING id`, foreign)
	actor := authz.Actor{UserID: user, PlatformRole: authz.PlatformAdmin}
	pub, err := deps.Automation.CreateTeam(ctx, actor, "bravo", automation.CreateInput{Name: "TF publisher", Scopes: []string{"servers:read"}})
	if err != nil {
		t.Fatal(err)
	}
	adm, err := deps.Automation.CreatePlatform(ctx, actor, automation.CreateInput{Name: "TF platform", Scopes: []string{"platform:read"}})
	if err != nil {
		t.Fatal(err)
	}
	// This SQL fixture is deliberately write-only (the service normally expands
	// write to read). It satisfies all schema constraints without changing roles,
	// tables or auth rules, and tests the portal's actual missing-scope decision.
	noScope, err := deps.Automation.CreateTeam(ctx, actor, "bravo", automation.CreateInput{Name: "TF missing read", Scopes: []string{"servers:write"}})
	if err != nil {
		t.Fatal(err)
	}
	execSQL(`UPDATE automation_tokens SET scopes=ARRAY['servers:write']::text[] WHERE id=$1`, noScope.Row.ID)
	expired, err := deps.Automation.CreateTeam(ctx, actor, "bravo", automation.CreateInput{Name: "TF forced expired", Scopes: []string{"servers:read"}})
	if err != nil {
		t.Fatal(err)
	}
	execSQL(`UPDATE automation_tokens SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE id=$1`, expired.Row.ID)
	revoked, err := deps.Automation.CreateTeam(ctx, actor, "bravo", automation.CreateInput{Name: "TF revoked", Scopes: []string{"servers:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.Automation.RevokeTeam(ctx, actor, "bravo", revoked.Row.ID); err != nil {
		t.Fatal(err)
	}
	sentinels := []string{secret, contact, claims, pub.Secret, adm.Secret, noScope.Secret, expired.Secret, revoked.Secret, base64.StdEncoding.EncodeToString(cipher), fmt.Sprintf("%x", cipher), cfg.EncryptionKey, cfg.APIKeyPepper}
	clean := func(b []byte) {
		t.Helper()
		for _, s := range sentinels {
			if strings.Contains(string(b), s) {
				t.Fatal("private fixture sentinel leaked (value suppressed)")
			}
		}
	}
	type hit struct {
		Method, Path string
		Status       int
		Phase        string
	}
	var mu sync.Mutex
	var hits []hit
	phase := "provider"
	handler := httpapi.NewAPIHandler(deps)
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusWriter{ResponseWriter: w, status: 200}
		handler.ServeHTTP(rec, r)
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, hit{r.Method, r.URL.Path, rec.status, phase})
	}))
	ca := testutil.NewCA(t, "TF acceptance CA")
	cert := ca.Issue(t, testutil.IssueOptions{Server: true, IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	pair, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	front.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	front.StartTLS()
	defer front.Close()
	write("ca.pem", ca.CertPEM)
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(bin, "terraform-provider-omp"), ".")
	build.Dir = ".."
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("provider build: %v %s", err, b)
	}
	write("terraform.rc", fmt.Sprintf(`provider_installation { dev_overrides { "registry.terraform.io/ncecere/omp" = %q } direct {} }`, bin))
	hcl := func(teamRef, lookup string) string {
		return fmt.Sprintf(`
terraform {
 required_providers {
  omp = { source = "ncecere/omp" }
 }
}
provider "omp" { url = %q }
provider "omp" {
 alias = "platform"
 url = %q
 token_env = "OMP_TOKEN_PLATFORM"
}
data "omp_team_mcp_server" "test" {
 team = %q
 lookup = %q
}
data "omp_team" "test" {
 provider = omp.platform
 lookup = "bravo"
}
output "server" { value = data.omp_team_mcp_server.test }
output "team" { value = data.omp_team.test }
`, front.URL, front.URL, teamRef, lookup)
	}
	write("main.tf", hcl("bravo", "status"))
	// Tokens live only in this child environment. Do not inherit credentials,
	// provider discovery overrides, proxy settings, or the owner's Terraform home.
	trustCA := true
	run := func(token, platform string, success bool, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, cli, args...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TF_CLI_CONFIG_FILE=" + filepath.Join(dir, "terraform.rc"), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "SSL_CERT_FILE=" + filepath.Join(dir, "ca.pem"), "OMP_TOKEN=" + token, "OMP_TOKEN_PLATFORM=" + platform, "TF_LOG=TRACE", "TF_LOG_PATH=" + filepath.Join(dir, "trace.log")}
		if !trustCA {
			cmd.Env = append(cmd.Env, "SSL_CERT_FILE="+filepath.Join(dir, "untrusted-ca.pem"), "SSL_CERT_DIR="+filepath.Join(dir, "empty-certs"))
		}
		b, err := cmd.CombinedOutput()
		clean(b)
		if (err == nil) != success {
			t.Fatalf("terraform %v success=%v: %v\n%s", args, success, err, b)
		}
		return b
	}
	good := func(args ...string) []byte { return run(pub.Secret, adm.Secret, true, args...) }
	revision := func() int64 {
		var n int64
		if err := owner.QueryRow(ctx, `SELECT revision FROM mcp_servers WHERE id=$1`, server).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	initialRevision := revision()
	unrelatedCA := testutil.NewCA(t, "Untrusted acceptance CA")
	write("untrusted-ca.pem", unrelatedCA.CertPEM)
	if err := os.Mkdir(filepath.Join(dir, "empty-certs"), 0700); err != nil {
		t.Fatal(err)
	}
	trustCA = false
	run(pub.Secret, adm.Secret, false, "plan", "-no-color")
	mu.Lock()
	beforeTrusted := len(hits)
	mu.Unlock()
	if beforeTrusted != 0 {
		t.Fatal("provider accepted untrusted TLS certificate")
	}
	trustCA = true
	good("validate", "-no-color")
	good("plan", "-no-color", "-out=initial.tfplan")
	initial := good("show", "-json", "initial.tfplan")
	write("initial-plan.json", string(initial))
	good("apply", "-no-color", "-auto-approve", "initial.tfplan")
	state := good("show", "-json")
	write("initial-state.json", string(state))
	assertState(t, state, server.String(), team.String(), initialRevision, "Status fixture")
	if revision() != initialRevision {
		t.Fatal("provider reads changed server revision")
	}
	// Intentional synthetic UI-equivalent edit, outside all provider requests.
	execSQL(`UPDATE mcp_servers SET name='External fixture edit',revision=revision+1 WHERE id=$1`, server)
	driftRevision := revision()
	good("plan", "-refresh-only", "-no-color", "-out=refresh.tfplan")
	refreshed := good("show", "-json", "refresh.tfplan")
	write("refresh-plan.json", string(refreshed))
	if !strings.Contains(string(refreshed), "External fixture edit") {
		t.Fatal("refresh did not observe synthetic drift")
	}
	good("apply", "-no-color", "-auto-approve", "refresh.tfplan")
	final := good("show", "-json")
	write("refreshed-state.json", string(final))
	assertState(t, final, server.String(), team.String(), driftRevision, "External fixture edit")
	// Exercise canonical UUIDs as well as exact slugs.
	write("main.tf", hcl(team.String(), server.String()))
	good("plan", "-no-color")
	write("main.tf", hcl("foreign", foreignServer.String()))
	run(pub.Secret, adm.Secret, false, "plan", "-no-color")
	write("main.tf", hcl("bravo", foreignServer.String()))
	run(pub.Secret, adm.Secret, false, "plan", "-no-color")
	write("main.tf", hcl("bravo", "status"))
	for _, c := range []struct {
		name, token string
		status      int
	}{{"missing-read-scope", noScope.Secret, 403}, {"revoked", revoked.Secret, 401}, {"forced-expired", expired.Secret, 401}} {
		mu.Lock()
		start := len(hits)
		mu.Unlock()
		b := run(c.token, adm.Secret, false, "plan", "-no-color")
		if c.status == 403 && !strings.Contains(string(b), "servers:read") {
			t.Fatal("missing scope diagnostic")
		}
		mu.Lock()
		found := false
		for _, h := range hits[start:] {
			if strings.HasPrefix(h.Path, "/v1/teams/") && h.Status == c.status {
				found = true
			}
		}
		mu.Unlock()
		if !found {
			t.Fatalf("%s did not receive actual portal %d", c.name, c.status)
		}
		t.Logf("%s: real portal HTTP %d", c.name, c.status)
	}
	// Wrong-kind is rejected by the provider before HTTP. Also prove the portal's
	// independent wrong-kind denial with a separately recorded GET control probe.
	mu.Lock()
	beforeWrongKind := len(hits)
	mu.Unlock()
	run(adm.Secret, pub.Secret, false, "plan", "-no-color")
	mu.Lock()
	afterWrongKind := len(hits)
	mu.Unlock()
	if beforeWrongKind != afterWrongKind {
		t.Fatal("wrong-kind provider credentials reached HTTP")
	}
	mu.Lock()
	phase = "wrong-kind-control"
	mu.Unlock()
	roots := testutil.Pool(ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	req, err := http.NewRequestWithContext(ctx, "GET", front.URL+"/v1/teams/bravo/mcp-servers", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adm.Secret)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("portal accepted wrong token kind")
	}
	var foreignRevision int64
	if err := owner.QueryRow(ctx, `SELECT revision FROM mcp_servers WHERE id=$1`, foreignServer).Scan(&foreignRevision); err != nil {
		t.Fatal(err)
	}
	if foreignRevision != 1 {
		t.Fatal("provider changed foreign server revision")
	}
	if revision() != driftRevision {
		t.Fatal("provider reads changed drifted revision")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		clean(b)
		checked++
	}
	mu.Lock()
	defer mu.Unlock()
	foreignDenied := false
	for _, h := range hits {
		if h.Method != "GET" {
			t.Fatal("non-GET provider request")
		}
		if strings.Contains(h.Path, "foreign") && h.Status == 404 {
			foreignDenied = true
		}
		if !strings.HasPrefix(h.Path, "/v1/teams/") && !strings.HasPrefix(h.Path, "/v1/admin/teams/") {
			t.Fatal("unexpected route")
		}
	}
	if !foreignDenied {
		t.Fatal("foreign-team denial not observed")
	}
	if evidence := os.Getenv("OMP_TERRAFORM_EVIDENCE_DIR"); evidence != "" {
		evidence = filepath.Join(evidence, "role-"+os.Getenv("OMP_TEST_SPLIT_ROLES"))
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"initial-plan.json", "initial-state.json", "refresh-plan.json", "refreshed-state.json"} {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(evidence, name), b, 0600); err != nil {
				t.Fatal(err)
			}
		}
		b, err := json.MarshalIndent(hits, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(evidence, "requests.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("PG17 split_roles=%s: %d GET-only requests (last is wrong-kind control probe), %d sentinel-clean files; revisions %d -> synthetic edit -> %d unchanged by reads", os.Getenv("OMP_TEST_SPLIT_ROLES"), len(hits), checked, initialRevision, driftRevision)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

func assertState(t *testing.T, b []byte, server, team string, revision int64, name string) {
	// No raw API object, governance, contacts, URLs or credential/claim keys may
	// hide elsewhere in resource values, separate from the output assertions.
	for _, key := range []string{"auth_value", "authValue", "auth_value_cipher", "authValueCipher", "authValueHint", "credentials", "description", "oncallContact", "claims", "url", "governance"} {
		if strings.Contains(string(b), fmt.Sprintf("%q:", key)) {
			t.Fatalf("forbidden state field %s", key)
		}
	}
	t.Helper()
	var s struct {
		Values struct {
			Outputs map[string]struct{ Value map[string]any }
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	v := s.Values.Outputs["server"].Value
	want := map[string]any{"id": server, "slug": "status", "name": name, "revision": float64(revision), "team_id": team, "team_slug": "bravo", "enabled": false, "tools": float64(0), "prompts": float64(0), "resources": float64(0), "resource_templates": float64(0), "supports_tasks": false}
	for k, w := range want {
		got, exists := v[k]
		if !exists || got != w {
			t.Fatalf("server %s: got %v, want %v", k, got, w)
		}
	}
	if len(v) != len(want)+2 {
		t.Fatal("unexpected server state fields")
	}
	tm := s.Values.Outputs["team"].Value
	if tm["id"] != team || tm["name"] != "Bravo fixture" || tm["slug"] != "bravo" || tm["status"] != "active" || tm["revision"] != float64(1) || len(tm) != 6 {
		t.Fatal("unexpected team metadata/state fields")
	}
}
