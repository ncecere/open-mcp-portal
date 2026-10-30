package ompcli

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return m
}

func TestWhoami(t *testing.T) {
	f := newFakePortal(t)
	tok := f.publisher("bravo")
	h := newHarness(t)
	h.connect(f, tok)
	code, out, errOut := h.run("whoami")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d err %q", code, errOut)
	}
	for _, want := range []string{"Portal:   " + f.URL(), "ci (team_publisher, omppub_", "Team:     bravo", "Scopes:   servers:read servers:write", "Status:   active", "Expires:  2027-01-02T03:04:05Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	code, out, _ = h.run("whoami", "--json")
	if code != 0 {
		t.Fatal(code)
	}
	m := decode(t, out)
	token := m["token"].(map[string]any)
	if m["url"] != f.URL() || token["kind"] != "team_publisher" || token["name"] != "ci" {
		t.Errorf("json: %s", out)
	}
	// Global flags work before and after the command.
	if code, _, _ := h.run("--json", "whoami"); code != 0 {
		t.Errorf("leading --json: %d", code)
	}
	if code, out, _ := h.run("--portal", f.URL(), "whoami", "--json"); code != 0 || !strings.Contains(out, `"kind"`) {
		t.Errorf("--portal flag: %d %s", code, out)
	}
}

func TestServersLifecycleFromACleanPublisherToken(t *testing.T) {
	f := newFakePortal(t)
	tok := f.publisher("bravo")
	h := newHarness(t)
	h.connect(f, tok)

	code, out, errOut := h.run("servers", "register", "--slug", "status", "--url", "https://status.example.com/mcp", "--name", "Service status")
	if code != 0 {
		t.Fatalf("register: exit %d out %q err %q", code, out, errOut)
	}
	if !strings.Contains(out, "registered status") || !strings.Contains(out, "3 tools") {
		t.Errorf("register output %q", out)
	}
	code, out, _ = h.run("servers", "list")
	if code != 0 || !strings.Contains(out, "SLUG") || !strings.Contains(out, "status") || !strings.Contains(out, "private") {
		t.Fatalf("list: %d %q", code, out)
	}
	code, out, _ = h.run("servers", "get", "status")
	if code != 0 || !strings.Contains(out, "Name:      Service status") || !strings.Contains(out, "Publish:   private") {
		t.Fatalf("get: %d %q", code, out)
	}
	code, out, _ = h.run("servers", "test", "status")
	if code != 0 || !strings.Contains(out, "status: ok") || !strings.Contains(out, "3 tools") {
		t.Fatalf("test: %d %q", code, out)
	}
	code, out, _ = h.run("servers", "refresh", "status")
	if code != 0 || !strings.Contains(out, "3 listed") {
		t.Fatalf("refresh: %d %q", code, out)
	}
	code, out, _ = h.run("servers", "publish", "status", "--note", "ready")
	if code != 0 || !strings.Contains(out, "status: published") {
		t.Fatalf("publish: %d %q", code, out)
	}
	code, out, _ = h.run("servers", "unpublish", "status", "--json")
	if code != 0 || decode(t, out)["publishState"] != "private" {
		t.Fatalf("unpublish: %d %q", code, out)
	}
	// The team came from the token; the token went in every request, and only there.
	for _, r := range f.lastRequests(100) {
		if r.Auth != "Bearer "+tok {
			t.Errorf("%s %s sent Authorization %q", r.Method, r.Path, r.Auth)
		}
	}
	// By ID too.
	id := f.servers["status"].Id.String()
	if code, out, _ := h.run("servers", "get", id, "--json"); code != 0 || decode(t, out)["slug"] != "status" {
		t.Errorf("get by id: %d %q", code, out)
	}
}

func TestServersJSONOutput(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	code, out, _ := h.run("servers", "register", "--slug", "status", "--url", "https://status.example.com/mcp", "--json")
	if code != 0 {
		t.Fatal(code)
	}
	created := decode(t, out)
	if created["server"].(map[string]any)["slug"] != "status" || created["refresh"].(map[string]any)["listed"] != float64(3) {
		t.Errorf("register json: %s", out)
	}
	code, out, _ = h.run("servers", "list", "--json")
	list := decode(t, out)
	if code != 0 || list["team"] != "bravo" || len(list["items"].([]any)) != 1 {
		t.Errorf("list json: %s", out)
	}
	code, out, _ = h.run("servers", "refresh", "status", "--json")
	if r := decode(t, out); code != 0 || r["server"] != "status" || r["changed"] != float64(0) {
		t.Errorf("refresh json: %s", out)
	}
	code, out, _ = h.run("servers", "test", "status", "--json")
	if r := decode(t, out); code != 0 || r["ok"] != true {
		t.Errorf("test json: %s", out)
	}
}

func TestRegisterWithAHeaderSecretFromTheEnvironment(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	const secret = "s3cr3t-sentinel-value-9f2a"
	h.env["STATUS_KEY"] = secret
	code, out, errOut := h.run("servers", "register", "--slug", "status", "--url", "https://status.example.com/mcp",
		"--auth", "static_header", "--auth-header", "X-API-Key", "--auth-value-env", "STATUS_KEY", "--json")
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if strings.Contains(out+errOut, secret) {
		t.Fatal("the secret was printed")
	}
	if f.servers["status"].secret != secret || deref(f.servers["status"].AuthHeaderName) != "X-API-Key" {
		t.Errorf("the portal did not receive the secret: %+v", f.servers["status"])
	}
	// Flags that would take the secret from the command line do not exist.
	if code, _, _ := h.run("servers", "register", "--slug", "x", "--url", "https://x.example.com", "--auth-value", secret); code != ExitUsage {
		t.Errorf("--auth-value was accepted (exit %d)", code)
	}
	// The variable must be set.
	delete(h.env, "STATUS_KEY")
	if code, _, errOut := h.run("servers", "register", "--slug", "y", "--url", "https://y.example.com/mcp", "--auth", "static_header", "--auth-header", "X-API-Key", "--auth-value-env", "STATUS_KEY"); code != ExitUsage || !strings.Contains(errOut, "STATUS_KEY") {
		t.Errorf("unset variable: exit %d %q", code, errOut)
	}
	if _, ok := f.servers["y"]; ok {
		t.Error("a server was created without its secret")
	}
}

func TestRegisterWhenDiscoveryFails(t *testing.T) {
	f := newFakePortal(t)
	f.discover = func(string) (int, string) { return 0, "connection refused" }
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	code, out, errOut := h.run("servers", "register", "--slug", "status", "--url", "https://down.example.com/mcp")
	if code != ExitCheckFailed || !strings.Contains(out, "discovery failed") || !strings.Contains(errOut, "discovery_failed") {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
	if _, ok := f.servers["status"]; !ok {
		t.Error("the server should exist even when discovery fails")
	}
}

func TestTestAndRefreshFailuresHaveTheirOwnExitCodes(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	if code, _, _ := h.run("servers", "register", "--slug", "status", "--url", "https://s.example.com/mcp"); code != 0 {
		t.Fatal(code)
	}
	f.testOK = false
	code, out, errOut := h.run("servers", "test", "status")
	if code != ExitCheckFailed || !strings.Contains(out, "FAILED") || !strings.Contains(errOut, "test_failed") {
		t.Errorf("failed test: exit %d out %q err %q", code, out, errOut)
	}
	f.refreshChanged = 2
	if code, out, _ := h.run("servers", "refresh", "status"); code != 0 || !strings.Contains(out, "2 changed") {
		t.Errorf("refresh without the flag: %d %q", code, out)
	}
	code, _, errOut = h.run("servers", "refresh", "status", "--fail-on-changes")
	if code != ExitChanges || !strings.Contains(errOut, "capabilities_changed") {
		t.Errorf("--fail-on-changes: exit %d err %q", code, errOut)
	}
	f.discover = func(string) (int, string) { return 0, "boom" }
	code, _, errOut = h.run("servers", "refresh", "status")
	if code != ExitCheckFailed || !strings.Contains(errOut, "discovery_failed") {
		t.Errorf("refresh when the server is down: exit %d err %q", code, errOut)
	}
}

// Every error carries the API's error.code, and its own exit code.
func TestErrorsCarryTheAPICodeAndAStableExitCode(t *testing.T) {
	f := newFakePortal(t)
	pub := f.publisher("bravo")
	readOnly := f.addToken(ompclient.AutomationTokenKindTeamPublisher, "bravo", "servers:read")
	h := newHarness(t)
	h.connect(f, pub)
	if code, _, _ := h.run("servers", "register", "--slug", "status", "--url", "https://s.example.com/mcp"); code != 0 {
		t.Fatal(code)
	}

	type tc struct {
		name     string
		token    string
		args     []string
		exit     int
		code     string
		status   float64
		contains string
	}
	cases := []tc{
		{"unknown token", "omppub_" + strings.Repeat("9", 43), []string{"whoami"}, ExitAuth, "invalid_token", 401, ""},
		{"missing scope", readOnly, []string{"servers", "refresh", "status"}, ExitForbidden, "token_not_allowed", 403, "servers:write"},
		{"other team", pub, []string{"servers", "list", "--team", "alpha"}, ExitNotFound, "team_not_found", 404, ""},
		{"no such server", pub, []string{"servers", "get", "ghost"}, ExitNotFound, "server_not_found", 404, ""},
		{"slug taken", pub, []string{"servers", "register", "--slug", "status", "--url", "https://x.example.com/mcp"}, ExitConflict, "slug_taken", 409, ""},
		{"already published", pub, []string{"servers", "publish", "status"}, 0, "", 0, ""},
	}
	for _, c := range cases {
		h.env["OMP_TOKEN"] = c.token
		code, out, errOut := h.run(append(c.args, "--json")...)
		if c.exit == 0 {
			continue
		}
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d (out %q err %q)", c.name, code, c.exit, out, errOut)
			continue
		}
		var e struct {
			Error struct {
				Code     string
				Message  string
				ExitCode int
				Status   float64
				Details  map[string]any
			}
		}
		if err := json.Unmarshal([]byte(errOut), &e); err != nil {
			t.Errorf("%s: stderr is not the JSON error: %q", c.name, errOut)
			continue
		}
		if e.Error.Code != c.code || e.Error.ExitCode != c.exit || e.Error.Status != c.status {
			t.Errorf("%s: %+v", c.name, e.Error)
		}
		if c.contains != "" && !strings.Contains(errOut, c.contains) {
			t.Errorf("%s: %q should mention %q", c.name, errOut, c.contains)
		}
		// The text form has the code too.
		code, _, errOut = h.run(c.args...)
		if code != c.exit || !strings.Contains(errOut, "omp: error: "+c.code+":") {
			t.Errorf("%s (text): exit %d err %q", c.name, code, errOut)
		}
	}
	// 403 details show the scope that is missing.
	h.env["OMP_TOKEN"] = readOnly
	_, _, errOut := h.run("servers", "refresh", "status")
	if !strings.Contains(errOut, "required scopes: servers:write (token has: servers:read)") {
		t.Errorf("the missing scope is not shown: %q", errOut)
	}
}

func TestExitCodeForEveryStatus(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	for status, want := range map[int]int{
		400: ExitRejected, 401: ExitAuth, 403: ExitForbidden, 404: ExitNotFound, 409: ExitConflict, 412: ExitConflict,
		422: ExitRejected, 428: ExitConflict, 429: ExitUnavailable, 500: ExitUnavailable, 502: ExitUnavailable, 503: ExitUnavailable,
	} {
		f.forceStatus["GET /v1/token"] = status
		code, _, errOut := h.run("whoami")
		if code != want || !strings.Contains(errOut, "forced_"+itoa(status)) {
			t.Errorf("status %d: exit %d (want %d), err %q", status, code, want, errOut)
		}
	}
	// A reply that is not the API's error shape still has a code.
	f.forceStatus = map[string]int{}
	f.srv.Config.Handler = nilBodyHandler(503)
	code, _, errOut := h.run("whoami")
	if code != ExitUnavailable || !strings.Contains(errOut, "http_503") {
		t.Errorf("plain 503: exit %d err %q", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.env["OMP_URL"] = "https://p.example.com"
	h.env["OMP_TOKEN"] = goodToken
	for _, args := range [][]string{
		{}, {"frobnicate"}, {"connect"}, {"connect", "x"}, {"connect", "x", "--client", "emacs"}, {"connect", "x", "--client", "claude", "--auth", "magic"},
		{"connect", "bad slug!", "--client", "claude"}, {"connect", "https://p.example.com/other", "--client", "claude"},
		{"servers"}, {"servers", "nope"}, {"servers", "get"}, {"servers", "register"}, {"servers", "register", "--slug", "x"},
		{"import"}, {"import", "-f", "x", "--only", "everything"}, {"import", "-f", "x", "--refresh", "--plan"},
		{"whoami", "extra"}, {"whoami", "--no-such-flag"}, {"export", "--only", "bad"},
	} {
		code, _, errOut := h.run(args...)
		if code != ExitUsage {
			t.Errorf("%v: exit %d, want %d (err %q)", args, code, ExitUsage, errOut)
		}
	}
	// No omp keys command, and no sign-in flow (decision 89).
	for _, args := range [][]string{{"keys"}, {"keys", "list"}, {"login"}, {"auth"}} {
		if code, _, errOut := h.run(args...); code != ExitUsage || (args[0] == "keys" && !strings.Contains(errOut, "automation token only")) {
			t.Errorf("%v: exit %d err %q", args, code, errOut)
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}, {"servers", "--help"}, {"whoami", "--help"}, {"import", "-h"}, {"servers", "register", "--help"}} {
		code, out, _ := h.run(args...)
		if code != 0 || !strings.Contains(out, "omp") {
			t.Errorf("%v: exit %d out %q", args, code, out)
		}
	}
	code, out, _ := h.run("help")
	for _, want := range []string{"Exit codes:", "whoami", "connect", "servers list|get|register|test|refresh|publish|unpublish", "export", "import", "OMP_TOKEN"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	if code != 0 {
		t.Fatal(code)
	}
	code, out, _ = h.run("version")
	if code != 0 || out != "omp test (abc123)\n" {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ = h.run("version", "--json"); code != 0 || decode(t, out)["version"] != "test" {
		t.Errorf("version --json: %d %q", code, out)
	}
}

// No command writes the token anywhere: not on success, not on any error,
// even when a hostile portal repeats the Authorization header in its message.
func TestNoCommandPrintsTheToken(t *testing.T) {
	f := newFakePortal(t)
	tok := f.publisher("bravo")
	platform := f.platformAdmin()
	h := newHarness(t)
	h.connect(f, tok)
	h.env["STATUS_KEY"] = "header-secret-sentinel-4417"
	if code, _, _ := h.run("servers", "register", "--slug", "status", "--url", "https://s.example.com/mcp"); code != 0 {
		t.Fatal(code)
	}
	exportFile := writeTempFile(t, "in.yaml", "schema: omp/v1\nservers:\n- team: bravo\n  slug: status\n  name: Status\n  url: https://s.example.com/mcp\n", 0o600)
	commands := [][]string{
		{"whoami"}, {"whoami", "--json"}, {"servers", "list"}, {"servers", "list", "--json"}, {"servers", "get", "status"}, {"servers", "get", "status", "--json"},
		{"servers", "test", "status"}, {"servers", "refresh", "status"}, {"servers", "publish", "status"}, {"servers", "unpublish", "status"},
		{"servers", "get", "ghost"}, {"servers", "list", "--team", "other"}, {"export"}, {"export", "--json"},
		{"import", "-f", exportFile, "--plan"}, {"import", "-f", exportFile, "--plan", "--json"}, {"import", "-f", exportFile},
		{"connect", "gw", "--client", "curl"}, {"connect", "gw", "--client", "claude", "--auth", "key", "--json"},
		{"help"}, {"version"},
	}
	run := func(label string) {
		for _, args := range commands {
			code, out, errOut := h.run(args...)
			all := out + errOut
			if strings.Contains(all, tok) || strings.Contains(all, tok[7:]) || strings.Contains(all, platform) {
				t.Errorf("%s: %v printed a token (exit %d):\n%s", label, args, code, all)
			}
			if strings.Contains(all, "header-secret-sentinel-4417") {
				t.Errorf("%s: %v printed the header secret", label, args)
			}
		}
	}
	run("normal")
	f.echoAuthInError = true
	h.env["OMP_TOKEN"] = tok[:len(tok)-1] + "X" // a token the portal rejects, repeating the header
	f.tokens = map[string]ompclient.AutomationToken{}
	run("hostile portal")
	h.env["OMP_TOKEN"] = tok
	code, _, errOut := h.run("whoami")
	if code != ExitAuth || strings.Contains(errOut, tok) || !strings.Contains(errOut, "[redacted]") {
		t.Errorf("a portal that echoes the Authorization header: exit %d err %q", code, errOut)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
