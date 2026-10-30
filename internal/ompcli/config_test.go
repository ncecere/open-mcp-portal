package ompcli

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var goodToken = "omppub_" + tokenBody

func TestValidateURL(t *testing.T) {
	good := map[string]string{
		"https://portal.example.com":     "https://portal.example.com",
		"https://portal.example.com/":    "https://portal.example.com",
		"HTTPS://Portal.example.com/omp": "https://Portal.example.com/omp",
		"http://localhost:8088":          "http://localhost:8088",
		"http://127.0.0.1:8088/":         "http://127.0.0.1:8088",
		"http://127.1.2.3":               "http://127.1.2.3",
		"http://[::1]:8088":              "http://[::1]:8088",
	}
	for in, want := range good {
		got, err := ValidateURL(in)
		if err != nil || got != want {
			t.Errorf("ValidateURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"http://portal.example.com", "http://10.0.0.5:8088", "http://localhost.evil.example.com", "http://127.0.0.1.evil.com",
		"ftp://portal.example.com", "portal.example.com", "", "https://", "https://user:pw@portal.example.com",
		"https://portal.example.com?x=1", "https://portal.example.com#frag", "http://0.0.0.0:80", "file:///etc/passwd",
	}
	for _, in := range bad {
		if got, err := ValidateURL(in); err == nil {
			t.Errorf("ValidateURL(%q) = %q, want an error", in, got)
		} else if e := asError(err); e.Exit != ExitConfig {
			t.Errorf("ValidateURL(%q): exit %d, want %d", in, e.Exit, ExitConfig)
		}
	}
	// A URL with a password is not echoed in the message.
	_, err := ValidateURL("http://user:hunter2secret@example.com")
	if err == nil || strings.Contains(err.Error(), "hunter2secret") {
		t.Errorf("credentials in a URL must not be echoed: %v", err)
	}
}

func TestValidateToken(t *testing.T) {
	for _, tok := range []string{goodToken, "ompadm_" + tokenBody, "ompadm_" + strings.Repeat("a-_Z", 10) + "123"} {
		if err := ValidateToken(tok); err != nil {
			t.Errorf("%q: %v", tok, err)
		}
	}
	for _, tok := range []string{"", "omp_" + tokenBody, "omp_sa_" + tokenBody, "ompat_" + tokenBody, "omppub_short", "omppub_" + tokenBody + "x", "Bearer " + goodToken, " " + goodToken} {
		err := ValidateToken(tok)
		if err == nil {
			t.Errorf("%q accepted", tok)
		} else if strings.Contains(err.Error(), tok) && tok != "" {
			t.Errorf("the error echoes the token: %v", err)
		}
	}
}

func TestConfigFromEnvDoesNotReadTheFile(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(h.home, "config.yaml")
	// A world-readable file would be refused if it were read.
	if err := os.WriteFile(cfg, []byte("url: https://other.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.env["OMP_CONFIG"] = cfg
	h.env["OMP_URL"] = "https://env.example.com"
	h.env["OMP_TOKEN"] = goodToken
	code, out, errOut := h.run("connect", "support", "--client", "claude")
	if code != 0 || !strings.Contains(out, "https://env.example.com/mcp/support") {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not describe access on Windows")
	}
	h := newHarness(t)
	cfg := filepath.Join(h.home, ".config", "omp", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "url: https://portal.example.com\ntoken: " + goodToken + "\n"
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o604} {
		if err := os.WriteFile(cfg, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(cfg, mode); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := h.run("connect", "support", "--client", "claude")
		if code != ExitConfig {
			t.Errorf("mode %04o: exit %d, want %d (out %q)", mode, code, ExitConfig, out)
		}
		if !strings.Contains(errOut, "readable by other users") || !strings.Contains(errOut, "chmod 600") {
			t.Errorf("mode %04o: stderr %q", mode, errOut)
		}
		if strings.Contains(out+errOut, goodToken) {
			t.Errorf("mode %04o: the token was printed", mode)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(cfg, mode); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := h.run("connect", "support", "--client", "claude")
		if code != 0 || !strings.Contains(out, "https://portal.example.com/mcp/support") {
			t.Errorf("mode %04o: exit %d out %q err %q", mode, code, out, errOut)
		}
	}
	// Not a regular file.
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := h.run("connect", "support", "--client", "claude"); code != ExitConfig {
		t.Errorf("a directory as config: exit %d", code)
	}
}

func TestConfigFileWithBadContentDoesNotLeakIt(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(h.home, "c.yaml")
	if err := os.WriteFile(cfg, []byte("token: "+goodToken+"\nbogus: [1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.env["OMP_CONFIG"] = cfg
	code, out, errOut := h.run("whoami")
	if code != ExitConfig || strings.Contains(out+errOut, goodToken) {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
	// An unknown key is refused too.
	if err := os.WriteFile(cfg, []byte("url: https://p.example.com\ntokn: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := h.run("whoami"); code != ExitConfig {
		t.Fatalf("unknown key: exit %d", code)
	}
}

func TestConfigurePortalAndTokenFromStdin(t *testing.T) {
	h := newHarness(t)
	h.stdin = goodToken + "\n"
	code, out, errOut := h.run("configure", "--portal", "https://portal.example.com/", "--token-stdin")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	path := filepath.Join(h.home, ".config", "omp", "config.yaml")
	if !strings.Contains(out, path) || strings.Contains(out+errOut, goodToken) {
		t.Fatalf("out %q err %q", out, errOut)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o600 {
			t.Errorf("config mode %04o, want 0600", info.Mode().Perm())
		}
		dir, _ := os.Stat(filepath.Dir(path))
		if dir.Mode().Perm() != 0o700 {
			t.Errorf("config dir mode %04o, want 0700", dir.Mode().Perm())
		}
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "url: https://portal.example.com\n") || !strings.Contains(string(raw), goodToken) {
		t.Errorf("config content %q", raw)
	}
	// The stored configuration is used, and a later --portal-only change keeps the token.
	if code, out, _ := h.run("connect", "x", "--client", "curl"); code != 0 || !strings.Contains(out, "https://portal.example.com/mcp/x") {
		t.Errorf("connect from the file: %d %q", code, out)
	}
	if code, _, errOut := h.run("configure", "--portal", "https://other.example.com"); code != 0 {
		t.Fatalf("second configure: %s", errOut)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), "other.example.com") || !strings.Contains(string(raw), goodToken) {
		t.Errorf("config after update %q", raw)
	}
}

func TestConfigureRefusesBadInput(t *testing.T) {
	h := newHarness(t)
	for name, tc := range map[string]struct {
		args  []string
		stdin string
	}{
		"http url":      {[]string{"configure", "--portal", "http://portal.example.com"}, ""},
		"personal key":  {[]string{"configure", "--token-stdin"}, "omp_" + tokenBody + "\n"},
		"empty stdin":   {[]string{"configure", "--token-stdin"}, ""},
		"both sources":  {[]string{"configure", "--token-stdin", "--token-env", "X"}, goodToken},
		"nothing given": {[]string{"configure"}, ""},
		"unset env":     {[]string{"configure", "--token-env", "NOPE"}, ""},
	} {
		h.stdin = tc.stdin
		code, out, errOut := h.run(tc.args...)
		if code == 0 {
			t.Errorf("%s: exit 0, out %q", name, out)
		}
		if strings.Contains(out+errOut, "omp_"+tokenBody) || strings.Contains(out+errOut, goodToken) {
			t.Errorf("%s: a token was printed: %q %q", name, out, errOut)
		}
	}
	if _, err := os.Stat(filepath.Join(h.home, ".config")); err == nil {
		t.Error("a refused configure still wrote a file")
	}
}

func TestPlainHTTPToANonLoopbackHostIsRefusedBeforeAnyRequest(t *testing.T) {
	h := newHarness(t)
	h.env["OMP_URL"] = "http://portal.example.com"
	h.env["OMP_TOKEN"] = goodToken
	for _, args := range [][]string{{"whoami"}, {"servers", "list", "--team", "x"}, {"export"}, {"connect", "gw", "--client", "claude"}} {
		code, out, errOut := h.run(args...)
		if code != ExitConfig || !strings.Contains(errOut, "plain http") {
			t.Errorf("%v: exit %d out %q err %q", args, code, out, errOut)
		}
	}
}

// TLS verification cannot be turned off: a server with a certificate the
// system does not trust is a connection failure, never a success.
func TestTLSVerificationIsAlwaysOn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request reached a server with an untrusted certificate")
	}))
	defer srv.Close()
	h := newHarness(t)
	h.env["OMP_URL"] = srv.URL
	h.env["OMP_TOKEN"] = goodToken
	code, out, errOut := h.run("whoami")
	if code != ExitUnavailable || !strings.Contains(errOut, "network") {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
	if !strings.Contains(strings.ToLower(errOut), "certificate") && !strings.Contains(strings.ToLower(errOut), "x509") {
		t.Errorf("expected a certificate error, got %q", errOut)
	}
	// No flag or variable offers to skip verification.
	for _, flagName := range []string{"--insecure", "-k", "--skip-tls-verify", "--insecure-skip-verify"} {
		if code, _, _ := h.run("whoami", flagName); code != ExitUsage {
			t.Errorf("%s was accepted (exit %d)", flagName, code)
		}
	}
}

// A trusted https server works, with the same client code (the test injects
// only the CA pool, which is what installing a private CA does).
func TestHTTPSWithATrustedCertificate(t *testing.T) {
	f := newFakePortal(t)
	srv := httptest.NewTLSServer(f.srv.Config.Handler)
	defer srv.Close()
	h := newHarness(t)
	h.env["OMP_URL"] = srv.URL
	tok := f.publisher("bravo")
	h.env["OMP_TOKEN"] = tok
	app := &App{Stdout: &h.stdout, Stderr: &h.stderr, Getenv: func(k string) string { return h.env[k] }, HomeDir: func() (string, error) { return h.home, nil }, Version: "t", httpClient: srv.Client()}
	if code := app.Run(t.Context(), []string{"whoami"}); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	tr := srv.Client().Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the test client must verify")
	}
	_ = tls.VersionTLS12
}

func TestNeverFollowsRedirects(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") != "" {
			t.Error("the token followed a redirect")
		}
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/token", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	h := newHarness(t)
	h.env["OMP_URL"] = redirector.URL
	h.env["OMP_TOKEN"] = goodToken
	code, _, errOut := h.run("whoami")
	if code == 0 || hits != 0 || !strings.Contains(errOut, "unexpected_redirect") {
		t.Fatalf("exit %d hits %d err %q", code, hits, errOut)
	}
}
