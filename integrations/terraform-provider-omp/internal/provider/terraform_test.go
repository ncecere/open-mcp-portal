package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func TestFrameworkSchema(t *testing.T) {
	p := providerserver.NewProtocol6(New())()
	result, err := p.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil || len(result.Diagnostics) > 0 {
		t.Fatalf("schema: %v %v", err, result.Diagnostics)
	}
	if len(result.ResourceSchemas) != 0 || len(result.DataSourceSchemas) != 2 {
		t.Fatal("incorrect surface")
	}
	for _, a := range result.Provider.Block.Attributes {
		if a.Name != "url" && a.Name != "token_env" {
			t.Fatalf("unsafe provider attribute %s", a.Name)
		}
	}
}

// This is a genuine Terraform CLI test against a local HTTP fixture, not full
// TF_ACC coverage against a real portal. No resource operations are implemented.
func TestTerraformCLI(t *testing.T) {
	cli := os.Getenv("OMP_TERRAFORM_CLI")
	if cli == "" {
		t.Skip("set OMP_TERRAFORM_CLI to a verified Terraform executable")
	}
	ctx := context.Background()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(bin, "terraform-provider-omp"), "../..")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, b)
	}
	cfg := fmt.Sprintf("provider_installation { dev_overrides { \"registry.terraform.io/ncecere/omp\" = %q } direct {} }", bin)
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("terraform.rc", cfg)
	var mu sync.Mutex
	m := serverFixture()
	status := 200
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.Method != "GET" {
			t.Errorf("mutation: %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer "+token(false) && r.Header.Get("Authorization") != "Bearer "+token(true) {
			t.Error("missing fixture token")
		}
		if status != 200 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(secret + token(false)))
			return
		}
		switch r.URL.Path {
		case "/v1/teams/bravo/mcp-servers":
			reply(w, map[string]any{"items": []any{m}})
		case "/v1/teams/bravo/mcp-servers/" + serverID:
			reply(w, m)
		case "/v1/admin/teams/bravo":
			reply(w, map[string]any{"team": map[string]any{"id": teamID, "slug": "bravo", "name": "Bravo", "revision": 1, "status": "active", "description": secret}})
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	mainHCL := fmt.Sprintf(`
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
 team = "bravo"
 lookup = "status"
}
data "omp_team" "test" {
 provider = omp.platform
 lookup = "bravo"
}
output "server" { value = data.omp_team_mcp_server.test }
output "team" { value = data.omp_team.test }
`, ts.URL, ts.URL)
	write("main.tf", mainHCL)
	run := func(success bool, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, cli, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_CLI_CONFIG_FILE="+filepath.Join(dir, "terraform.rc"), "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "OMP_TOKEN="+token(false), "OMP_TOKEN_PLATFORM="+token(true), "TF_LOG=TRACE", "TF_LOG_PATH="+filepath.Join(dir, "trace.log"))
		b, err := cmd.CombinedOutput()
		if strings.Contains(string(b), secret) || strings.Contains(string(b), token(false)) || strings.Contains(string(b), token(true)) {
			t.Fatal("sentinel in CLI diagnostics")
		}
		if (err == nil) != success {
			t.Fatalf("terraform %v: %v\n%s", args, err, b)
		}
		return b
	}
	run(true, "validate", "-no-color")
	run(true, "plan", "-no-color", "-out=initial.tfplan")
	initial := run(true, "show", "-json", "initial.tfplan")
	if !strings.Contains(string(initial), serverID) {
		t.Fatal("plan missing metadata")
	}
	run(true, "apply", "-no-color", "-auto-approve", "initial.tfplan")
	state := run(true, "show", "-json")
	if !strings.Contains(string(state), "\"supports_tasks\":null") {
		t.Fatal("absent optional metadata not null")
	}
	mu.Lock()
	m["name"] = "External edit"
	m["revision"] = int64(2)
	mu.Unlock()
	run(true, "plan", "-refresh-only", "-no-color", "-out=refresh.tfplan")
	refreshed := run(true, "show", "-json", "refresh.tfplan")
	var plan map[string]any
	if json.Unmarshal(refreshed, &plan) != nil || !strings.Contains(string(refreshed), "External edit") {
		t.Fatal("external drift not read")
	}
	run(true, "apply", "-no-color", "-auto-approve", "refresh.tfplan")
	final := run(true, "show", "-json")
	if !strings.Contains(string(final), "External edit") {
		t.Fatal("refreshed state missing external change")
	}
	for _, code := range []int{401, 403, 404, 302, 500} {
		mu.Lock()
		status = code
		mu.Unlock()
		run(false, "plan", "-no-color")
	}
	// Restricted alias names fail before reading arbitrary environment keys.
	mu.Lock()
	status = 200
	mu.Unlock()
	for _, forbidden := range []string{"GITHUB_TOKEN", "OPENAI_API_KEY", "OMP_TOKEN_lowercase"} {
		write("main.tf", strings.ReplaceAll(mainHCL, "OMP_TOKEN_PLATFORM", forbidden))
		output := run(false, "plan", "-no-color")
		if !strings.Contains(string(output), "Invalid token environment name") {
			t.Fatal("environment restriction missing")
		}
	}
	write("main.tf", mainHCL)
	// Inspect actual saved binary plans, JSON output, state and TRACE logs, not
	// just attributes marked Sensitive. Auth has no Terraform schema attribute.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{secret, token(false), token(true)} {
			if strings.Contains(string(b), s) {
				t.Fatalf("sentinel in %s", entry.Name())
			}
		}
		checked++
	}
	if evidence := os.Getenv("OMP_TERRAFORM_EVIDENCE_DIR"); evidence != "" {
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{"initial-plan.json": initial, "initial-state.json": state, "refresh-plan.json": refreshed, "refreshed-state.json": final} {
			if err := os.WriteFile(filepath.Join(evidence, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("Terraform validate, plan, data-only apply, refresh-only drift and five failure plans passed; %d saved files sentinel-clean; %d HTTP GETs, zero mutations", checked, calls)
}
