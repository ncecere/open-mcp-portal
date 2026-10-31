package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// This runs the production Python adapter and a real omp executable, without
// replacing its HTTPS checks or mocking any portal operation. Only the TLS
// front, identities, upstream and mandatory PostgreSQL database are fixtures.
// It is not execution of a composite step inside a hosted GitHub runner.
func TestOmpActionWorkflowAgainstThePortal(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("OMP_TEST_REQUIRE_DB") == "1" {
			t.Fatal("mandatory Action acceptance requires python3")
		}
		t.Skip("Action acceptance requires python3")
	}
	e := newMatrixEnv(t)
	creds := tokenCredsByName(e)
	upstream := testutil.NewFakeMCP(t)
	const secret = "omp-action-owned-upstream-sentinel-617d"
	upstream.RequireHeader("X-Action-Key", secret)
	upstreamURL, err := url.Parse(e.app.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(upstreamURL))
	t.Cleanup(front.Close)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	binary := filepath.Join(private, "omp")
	buildCtx, cancelBuild := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-p=2", "-o", binary, "./cmd/omp")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build scratch CLI: %v\n%s", err, out)
	}
	ca := filepath.Join(private, "test-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(private, "server.json")
	server := map[string]any{"team": "bravo", "slug": "from-action", "name": "From Action", "url": upstream.URL(),
		"authMode": "static_header", "authHeaderName": "X-Action-Key", "authValueEnv": "OMP_SECRET_UPSTREAM"}
	writeConfig := func() {
		t.Helper()
		data, err := json.Marshal(map[string]any{"schema": "omp/v1", "servers": []any{server}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	run := func(token, publish, fail string, wantCode int) (string, string) {
		t.Helper()
		output := filepath.Join(t.TempDir(), "outputs")
		if err := os.WriteFile(output, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, python, filepath.Join(root, "integrations/github-action/run.py"))
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + private, "SSL_CERT_FILE=" + ca,
			"GITHUB_WORKSPACE=" + private, "GITHUB_OUTPUT=" + output, "ACTION_CLI=" + binary,
			"ACTION_URL=" + front.URL, "ACTION_TOKEN=" + token, "ACTION_TEAM=bravo", "ACTION_SLUG=from-action",
			"ACTION_CONFIG=server.json", "ACTION_REFRESH=true", "ACTION_PUBLISH=" + publish,
			"ACTION_FAIL_ON_CHANGES=" + fail, "OMP_SECRET_UPSTREAM=" + secret}
		var log bytes.Buffer
		cmd.Stdout, cmd.Stderr = &log, &log
		err := cmd.Run()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("run Action adapter: %v", err)
			}
			code = exit.ExitCode()
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(log.String()+string(data), token) || strings.Contains(log.String()+string(data), secret) {
			t.Fatal("Action output leaked a synthetic credential")
		}
		if code != wantCode {
			t.Fatalf("Action exit %d, want %d: %s", code, wantCode, log.String())
		}
		return log.String(), string(data)
	}

	_, output := run(creds["publisher-write"].secret, "none", "true", 0)
	id := e.exec(`SELECT id::text FROM mcp_servers WHERE slug = 'from-action'`)
	if !strings.Contains(output, "server-id="+id) || !strings.Contains(output, "needs-approval=false") {
		t.Fatalf("unexpected Action output: %s", output)
	}
	revision := e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, id)
	run(creds["publisher-write"].secret, "none", "true", 0)
	if got := e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, id); got != revision {
		t.Fatal("identical Action apply bumped the server revision")
	}
	server["name"] = "Updated by Action"
	writeConfig()
	run(creds["publisher-write"].secret, "none", "true", 0)
	if got := e.exec(`SELECT name FROM mcp_servers WHERE id = $1`, id); got != "Updated by Action" {
		t.Fatal("Action did not update the real server")
	}
	// Read-only token cannot mutate, and failed diagnostics remain secret-free.
	server["name"] = "Not allowed"
	writeConfig()
	run(creds["publisher-read"].secret, "none", "true", 1)
	if got := e.exec(`SELECT name FROM mcp_servers WHERE id = $1`, id); got != "Updated by Action" {
		t.Fatal("read-only Action changed the server")
	}
	server["name"] = "Updated by Action"
	writeConfig()
	e.exec(`UPDATE teams SET publish_policy_override = 'approval_required' WHERE id = $1 RETURNING id::text`, e.b.id)
	_, output = run(creds["publisher-write"].secret, "request", "true", 1)
	if got := e.exec(`SELECT publish_state FROM mcp_servers WHERE id = $1`, id); got != "pending" || !strings.Contains(output, "needs-approval=true") {
		t.Fatal("publication request was mistaken for approval")
	}
	if got := e.exec(`SELECT count(*)::text FROM mcp_capabilities WHERE server_id = $1 AND kind = 'tool' AND name = 'check_outage'`, id); got != "1" {
		t.Fatal("changed-definition fixture tool is missing")
	}
	upstream.SetDescription("check_outage", "changed definition requires review")
	_, output = run(creds["publisher-write"].secret, "none", "true", 1)
	if !strings.Contains(output, "changed-capabilities=1") || !strings.Contains(output, "needs-approval=true") {
		t.Fatalf("changed definition not surfaced: %s", output)
	}
	log, output := run(creds["publisher-write"].secret, "none", "false", 0)
	if !strings.Contains(log, "::warning::") || !strings.Contains(output, "needs-approval=true") {
		t.Fatal("explicit warning mode hid existing pending approval")
	}
	if got := e.exec(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.approve' AND actor_kind = 'automation_token'`); got != "0" {
		t.Fatal("Action exercised approval authority")
	}
}
