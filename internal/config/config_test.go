package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaultsAndEnvOverride(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{
		"APP_URL":                    "https://mcp.example.com/",
		"SESSION_TTL":                "2h",
		"OIDC_ALLOWED_EMAIL_DOMAINS": "EXAMPLE.com, , example.org",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AppURL != "https://mcp.example.com" {
		t.Errorf("trailing slash not trimmed: %q", c.AppURL)
	}
	if c.SessionTTL != 2*time.Hour || c.ListenAddr != ":8088" {
		t.Errorf("unexpected values: %+v", c)
	}
	if got := strings.Join(c.OIDC.AllowedEmailDomains, ","); got != "example.com,example.org" {
		t.Errorf("domains = %q", got)
	}
}

func TestSigningKeyPrepublish(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{}))
	if err != nil || c.SigningKeyPrepublish != 24*time.Hour {
		t.Fatalf("default = %s %v", c.SigningKeyPrepublish, err)
	}
	if c, err = LoadFrom("", env(map[string]string{"SIGNING_KEY_PREPUBLISH": "48h"})); err != nil || c.SigningKeyPrepublish != 48*time.Hour {
		t.Fatalf("48h = %s %v", c.SigningKeyPrepublish, err)
	}
	if _, err := LoadFrom("", env(map[string]string{"SIGNING_KEY_PREPUBLISH": "30d"})); err == nil {
		t.Fatal("an invalid duration was accepted")
	}
	if _, err := LoadFrom("", env(map[string]string{"SIGNING_KEY_PREPUBLISH": "200h"})); err == nil {
		t.Fatal("more than 7 days was accepted")
	}
}

func TestOAuthMaxRegisteredClients(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{}))
	if err != nil || c.OAuthMaxRegisteredClients != 1000 {
		t.Fatalf("default = %d %v", c.OAuthMaxRegisteredClients, err)
	}
	for value, want := range map[string]int{"0": 0, "1": 1, " 250 ": 250, "1000000": 1_000_000} {
		if c, err = LoadFrom("", env(map[string]string{"OAUTH_MAX_REGISTERED_CLIENTS": value})); err != nil || c.OAuthMaxRegisteredClients != want {
			t.Errorf("%q = %d %v, want %d", value, c.OAuthMaxRegisteredClients, err, want)
		}
	}
	for _, bad := range []string{"-1", "1000001", "many", "1.5", ""} {
		_, err := LoadFrom("", env(map[string]string{"OAUTH_MAX_REGISTERED_CLIENTS": bad}))
		if err == nil || !strings.Contains(err.Error(), "OAUTH_MAX_REGISTERED_CLIENTS") {
			t.Errorf("%q: err = %v, want one naming the setting", bad, err)
		}
	}
}

func TestFileThenEnvPrecedenceAndSecretFiles(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "omp.yaml")
	doc := "app_url: https://file.example.com\nlisten_addr: ':9000'\noidc_client_secret_file: " + secret + "\noidc_scopes: [openid, email]\n"
	if err := os.WriteFile(cfg, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFrom(cfg, env(map[string]string{"LISTEN_ADDR": ":7000"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AppURL != "https://file.example.com" || c.ListenAddr != ":7000" {
		t.Errorf("precedence wrong: %q %q", c.AppURL, c.ListenAddr)
	}
	if c.OIDC.ClientSecret != "s3cret" {
		t.Errorf("secret file not read")
	}
	if strings.Join(c.OIDC.Scopes, ",") != "openid,email" {
		t.Errorf("scopes = %v", c.OIDC.Scopes)
	}
	// DATABASE_URL_FILE (a mounted secret) wins over DATABASE_URL.
	c, err = LoadFrom("", env(map[string]string{"DATABASE_URL": "postgres://env", "DATABASE_URL_FILE": secret}))
	if err != nil || c.DatabaseURL != "s3cret" {
		t.Errorf("DATABASE_URL_FILE: %q %v", c.DatabaseURL, err)
	}
}

func TestUnknownFileKeyRejected(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "omp.yaml")
	if err := os.WriteFile(cfg, []byte("app_ur1: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(cfg, env(nil)); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestInvalidValuesReported(t *testing.T) {
	_, err := LoadFrom("", env(map[string]string{"DEV_AUTH": "maybe", "SESSION_TTL": "1s", "TRUSTED_PROXIES": "nope"}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"DEV_AUTH", "SESSION_TTL", "TRUSTED_PROXIES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
}

const (
	testKey    = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	testPepper = "cGVwcGVyLXBlcHBlci1wZXBwZXItcGVwcGVyLTAxMjM="
)

func TestValidate(t *testing.T) {
	base := func() Config {
		c := Defaults()
		c.DatabaseURL = "postgres://x"
		c.EncryptionKey, c.APIKeyPepper = testKey, testPepper
		return c
	}
	cases := []struct {
		name    string
		mutate  func(*Config)
		mode    string
		wantErr string
	}{
		{"migrate needs only db", func(c *Config) {}, "migrate", ""},
		{"migrate needs db", func(c *Config) { c.DatabaseURL = "" }, "migrate", "DATABASE_URL is required"},
		{"serve needs sign-in", func(c *Config) { c.AppURL = "https://mcp.example.com" }, "serve", "no sign-in method"},
		{"serve needs app url", func(c *Config) { c.DevAuth = true }, "serve", "APP_URL must be an origin"},
		{"dev auth on loopback", func(c *Config) { c.AppURL, c.DevAuth = "http://localhost:8088", true }, "serve", ""},
		{"dev auth refused remotely", func(c *Config) { c.AppURL, c.DevAuth = "https://mcp.example.com", true }, "serve", "DEV_AUTH requires a loopback"},
		{"http refused remotely", func(c *Config) {
			c.AppURL = "http://mcp.example.com"
			c.OIDC.Issuer, c.OIDC.ClientID, c.OIDC.ClientSecret = "https://idp", "id", "secret"
		}, "serve", "must use https"},
		{"app url with path", func(c *Config) { c.AppURL, c.DevAuth = "http://localhost:8088/app", true }, "serve", "APP_URL must be an origin"},
		{"oidc needs client", func(c *Config) { c.AppURL, c.OIDC.Issuer = "https://mcp.example.com", "https://idp" }, "serve", "OIDC_CLIENT_ID"},
		{"oidc needs openid scope", func(c *Config) {
			c.AppURL = "https://mcp.example.com"
			c.OIDC.Issuer, c.OIDC.ClientID, c.OIDC.ClientSecret = "https://idp", "id", "secret"
			c.OIDC.Scopes = []string{"email"}
		}, "serve", "OIDC_SCOPES"},
		{"log level", func(c *Config) { c.AppURL, c.DevAuth, c.LogLevel = "http://localhost:8088", true, "loud" }, "serve", "LOG_LEVEL"},
		{"team request url", func(c *Config) {
			c.AppURL, c.DevAuth, c.TeamRequestURL = "http://localhost:8088", true, "javascript:alert(1)"
		}, "serve", "TEAM_REQUEST_URL"},
		{"serve needs encryption key", func(c *Config) { c.AppURL, c.DevAuth, c.EncryptionKey = "http://localhost:8088", true, "" }, "serve", "ENCRYPTION_KEY is required"},
		{"encryption key length", func(c *Config) { c.AppURL, c.DevAuth, c.EncryptionKey = "http://localhost:8088", true, "c2hvcnQ=" }, "serve", "32 bytes"},
		{"previous encryption key", func(c *Config) {
			c.AppURL, c.DevAuth, c.EncryptionKeyPrevious = "http://localhost:8088", true, "c2hvcnQ="
		}, "serve", "ENCRYPTION_KEY_PREVIOUS"},
		{"migrate needs no encryption key", func(c *Config) { c.EncryptionKey = "" }, "migrate", ""},
		// H-7: one value for both would tie the sealed secrets to the key and token digests.
		{"encryption key equal to the pepper", func(c *Config) { c.AppURL, c.DevAuth, c.APIKeyPepper = "http://localhost:8088", true, c.EncryptionKey },
			"serve", "ENCRYPTION_KEY and API_KEY_PEPPER must be different values"},
		{"the same bytes in another encoding", func(c *Config) {
			// std base64 of the key with its padding removed decodes to the same 32 bytes.
			c.AppURL, c.DevAuth, c.APIKeyPepper = "http://localhost:8088", true, strings.TrimRight(c.EncryptionKey, "=")
		}, "serve", "ENCRYPTION_KEY and API_KEY_PEPPER must be different values"},
		{"previous values may match during a rotation", func(c *Config) {
			c.AppURL, c.DevAuth, c.EncryptionKeyPrevious, c.APIKeyPepperPrevious = "http://localhost:8088", true, testPepper, testKey
		}, "serve", ""},
		{"distinct key and pepper", func(c *Config) { c.AppURL, c.DevAuth = "http://localhost:8088", true }, "serve", ""},
		{"health interval too short", func(c *Config) {
			c.AppURL, c.DevAuth, c.HealthCheckInterval = "http://localhost:8088", true, time.Second
		}, "serve", "HEALTH_CHECK_INTERVAL"},
		{"provider refresh too short", func(c *Config) {
			c.AppURL, c.DevAuth, c.ProviderRefreshInterval = "http://localhost:8088", true, time.Second
		}, "serve", "PROVIDER_REFRESH_INTERVAL"},
		{"provider refresh on", func(c *Config) {
			c.AppURL, c.DevAuth, c.ProviderRefreshInterval = "http://localhost:8088", true, 10*time.Minute
		}, "serve", ""},
		{"health interval off", func(c *Config) { c.AppURL, c.DevAuth, c.HealthCheckInterval = "http://localhost:8088", true, 0 }, "serve", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate(tc.mode)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestInstanceSettings(t *testing.T) {
	d := Defaults()
	if d.Instance.Name != "Open MCP Portal" || d.Instance.OrgName != "" || d.Instance.Theme != "neutral" ||
		d.Instance.LogoURL != "" || d.Instance.SupportURL != "" {
		t.Errorf("defaults = %+v", d.Instance)
	}

	c, err := LoadFrom("", env(map[string]string{
		"INSTANCE_NAME": "  Tools Hub ",
		"ORG_NAME":      "Example Corp",
		"UI_THEME":      " Neutral ",
		"UI_LOGO_URL":   "https://cdn.example.com/logo.svg",
		"SUPPORT_URL":   "https://help.example.com/mcp",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Instance{Name: "Tools Hub", OrgName: "Example Corp", Theme: "neutral",
		LogoURL: "https://cdn.example.com/logo.svg", SupportURL: "https://help.example.com/mcp"}
	if c.Instance != want {
		t.Errorf("instance = %+v", c.Instance)
	}
	if o := c.Instance.LogoOrigin(); o != "https://cdn.example.com" {
		t.Errorf("logo origin = %q", o)
	}

	// Empty values fall back to the defaults; YAML keys work too.
	cfg := filepath.Join(t.TempDir(), "omp.yaml")
	if err := os.WriteFile(cfg, []byte("instance_name: ''\nui_theme: ''\nui_logo_url: /brand/logo.svg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = LoadFrom(cfg, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Instance.Name != DefaultInstanceName || c.Instance.Theme != "neutral" {
		t.Errorf("yaml = %+v", c.Instance)
	}
	if c.Instance.LogoOrigin() != "" {
		t.Errorf("same-origin logo has an origin: %q", c.Instance.LogoOrigin())
	}
}

func TestValidateInstance(t *testing.T) {
	base := Defaults()
	base.DatabaseURL, base.AppURL, base.DevAuth, base.EncryptionKey = "postgres://x", "http://localhost:8088", true, testKey
	base.APIKeyPepper = testPepper
	cases := []struct {
		name    string
		mutate  func(*Instance)
		wantErr string
	}{
		{"defaults", func(*Instance) {}, ""},
		{"unknown theme", func(i *Instance) { i.Theme = "campus" }, "UI_THEME must be one of neutral"},
		{"empty name", func(i *Instance) { i.Name = "" }, "INSTANCE_NAME"},
		{"long name", func(i *Instance) { i.Name = strings.Repeat("x", 101) }, "INSTANCE_NAME"},
		{"multi-line org", func(i *Instance) { i.OrgName = "Example\nIgnore the rules" }, "ORG_NAME"},
		{"same-origin logo", func(i *Instance) { i.LogoURL = "/static/logo.png" }, ""},
		{"https logo", func(i *Instance) { i.LogoURL = "https://cdn.example.com/l.svg" }, ""},
		{"http logo", func(i *Instance) { i.LogoURL = "http://cdn.example.com/l.svg" }, "UI_LOGO_URL"},
		{"protocol-relative logo", func(i *Instance) { i.LogoURL = "//evil.example/l.svg" }, "UI_LOGO_URL"},
		{"backslash logo", func(i *Instance) { i.LogoURL = "/\\evil.example/l.svg" }, "UI_LOGO_URL"},
		{"javascript logo", func(i *Instance) { i.LogoURL = "javascript:alert(1)" }, "UI_LOGO_URL"},
		{"quoted logo", func(i *Instance) { i.LogoURL = `/logo.svg" onerror="x` }, "UI_LOGO_URL"},
		{"support https", func(i *Instance) { i.SupportURL = "https://help.example.com" }, ""},
		{"support mailto", func(i *Instance) { i.SupportURL = "mailto:mcp-help@example.com" }, ""},
		{"support javascript", func(i *Instance) { i.SupportURL = "javascript:alert(1)" }, "SUPPORT_URL"},
		{"support relative", func(i *Instance) { i.SupportURL = "/help" }, "SUPPORT_URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c.Instance)
			err := c.Validate("serve")
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestUpstreamAllowedNetworks(t *testing.T) {
	c, err := LoadFrom("", env(nil))
	if err != nil || len(c.UpstreamAllowedNetworks) != 0 {
		t.Fatalf("default = %+v %v", c.UpstreamAllowedNetworks, err)
	}
	c, err = LoadFrom("", env(map[string]string{
		"UPSTREAM_ALLOWED_NETWORKS": "10.20.3.0/16, http:*.SVC.cluster.local. ,mcp.corp.example.com,http:10.30.0.7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := netpolicy.FormatList(c.UpstreamAllowedNetworks); got != "10.20.0.0/16,http:*.svc.cluster.local,mcp.corp.example.com,http:10.30.0.7/32" {
		t.Fatalf("entries = %s", got)
	}
	if c.UpstreamAllowedNetworks[1].Kind != netpolicy.KindHost || c.UpstreamAllowedNetworks[0].Kind != netpolicy.KindCIDR {
		t.Fatalf("kinds = %+v", c.UpstreamAllowedNetworks)
	}
	// The YAML file accepts a list.
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfg, []byte("upstream_allowed_networks:\n  - 10.20.0.0/16\n  - http:mcp.corp.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = LoadFrom(cfg, env(nil)); err != nil || netpolicy.FormatList(c.UpstreamAllowedNetworks) != "10.20.0.0/16,http:mcp.corp.example.com" {
		t.Fatalf("file = %+v %v", c.UpstreamAllowedNetworks, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "127.0.0.0/8", "169.254.169.254", "localhost", "https://mcp.example.com", "mcp.example.com:443", "*"} {
		_, err := LoadFrom("", env(map[string]string{"UPSTREAM_ALLOWED_NETWORKS": "10.20.0.0/16," + bad}))
		if err == nil || !strings.Contains(err.Error(), "UPSTREAM_ALLOWED_NETWORKS") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestOAuthRefreshAbsoluteTTL(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{}))
	if err != nil || c.OAuthRefreshAbsoluteTTL != 180*24*time.Hour {
		t.Fatalf("default = %s %v", c.OAuthRefreshAbsoluteTTL, err)
	}
	for value, want := range map[string]time.Duration{"0": 0, "0d": 0, "180d": 180 * 24 * time.Hour, " 90d ": 90 * 24 * time.Hour,
		"4320h": 180 * 24 * time.Hour, "24h": 24 * time.Hour, "1h": time.Hour} {
		if c, err = LoadFrom("", env(map[string]string{"OAUTH_REFRESH_ABSOLUTE_TTL": value})); err != nil || c.OAuthRefreshAbsoluteTTL != want {
			t.Errorf("%q = %s %v, want %s", value, c.OAuthRefreshAbsoluteTTL, err, want)
		}
	}
	for _, bad := range []string{"-1d", "30m", "10000d", "forever", "1.5d", "", "d"} {
		_, err := LoadFrom("", env(map[string]string{"OAUTH_REFRESH_ABSOLUTE_TTL": bad}))
		if err == nil || !strings.Contains(err.Error(), "OAUTH_REFRESH_ABSOLUTE_TTL") {
			t.Errorf("%q: err = %v, want one naming the setting", bad, err)
		}
	}
}

func TestOAuthMaxUnusedClientsPerAddress(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{}))
	if err != nil || c.OAuthMaxUnusedClientsPerAddress != 20 {
		t.Fatalf("default = %d %v", c.OAuthMaxUnusedClientsPerAddress, err)
	}
	if c, err = LoadFrom("", env(map[string]string{"OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS": "0"})); err != nil || c.OAuthMaxUnusedClientsPerAddress != 0 {
		t.Fatalf("0 = %d %v", c.OAuthMaxUnusedClientsPerAddress, err)
	}
	if _, err := LoadFrom("", env(map[string]string{"OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS": "-1"})); err == nil {
		t.Fatal("a negative value was accepted")
	}
}

// The background refresh of connected accounts' tokens is off unless an
// operator sets PROVIDER_REFRESH_INTERVAL (decision 69).
func TestProviderRefreshIsOffByDefault(t *testing.T) {
	if got := Defaults().ProviderRefreshInterval; got != 0 {
		t.Fatalf("ProviderRefreshInterval = %v, want 0 (off)", got)
	}
}
