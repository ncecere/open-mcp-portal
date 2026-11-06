package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func smtpBase() Config {
	c := Defaults()
	c.DatabaseURL = "postgres://x"
	c.EncryptionKey, c.APIKeyPepper = testKey, testPepper
	c.AppURL, c.DevAuth = "http://localhost:8088", true
	return c
}

func TestSMTPDefaultsAndLoading(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{}))
	if err != nil || c.SMTP.Enabled() || c.NotificationInterval != 15*time.Second || len(c.NotifyWebhookAllowedNetworks) != 0 {
		t.Fatalf("defaults: %+v %v", c.SMTP, err)
	}
	c, err = LoadFrom("", env(map[string]string{"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "Portal <portal@example.com>", "SMTP_USERNAME": "u",
		"SMTP_PASSWORD": " pw ", "NOTIFICATION_INTERVAL": "30s"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTP.Mode() != SMTPStartTLS || c.SMTP.EffectivePort() != 587 || c.SMTP.Password != "pw" || c.SMTP.Address() != "portal@example.com" || !c.SMTP.Authenticates() || c.NotificationInterval != 30*time.Second {
		t.Errorf("%+v", c.SMTP)
	}
	for mode, port := range map[string]int{"starttls": 587, "tls": 465, "none": 25} {
		s := SMTP{Host: "h", TLS: mode}
		if s.EffectivePort() != port {
			t.Errorf("%s port = %d", mode, s.EffectivePort())
		}
	}
	if (SMTP{Host: "h", TLS: "tls", Port: 2465}).EffectivePort() != 2465 {
		t.Error("explicit port ignored")
	}
}

func TestSMTPValidation(t *testing.T) {
	ok := SMTP{Host: "smtp.example.com", From: "portal@example.com"}
	cases := []struct {
		name string
		s    SMTP
		want string
	}{
		{"off", SMTP{}, ""},
		{"a minimal configuration", ok, ""},
		{"port without host", SMTP{Port: 587}, "SMTP_HOST is not"},
		{"from without host", SMTP{From: "portal@example.com"}, "SMTP_HOST is not"},
		{"username without host", SMTP{Username: "u"}, "SMTP_HOST is not"},
		{"tls mode without host", SMTP{TLS: "tls"}, "SMTP_HOST is not"},
		{"from is required", SMTP{Host: "h"}, "SMTP_FROM is required"},
		{"from must parse", SMTP{Host: "h", From: "not an address"}, "SMTP_FROM is not a valid address"},
		{"from without control characters", SMTP{Host: "h", From: "a@b.example\r\nBcc: x@y.example"}, "control characters"},
		{"username needs password", SMTP{Host: "h", From: "a@b.example", Username: "u"}, "together"},
		{"password needs username", SMTP{Host: "h", From: "a@b.example", Password: "p"}, "together"},
		{"bad mode", SMTP{Host: "h", From: "a@b.example", TLS: "ssl"}, "SMTP_TLS must be"},
		{"bad port", SMTP{Host: "h", From: "a@b.example", Port: 70000}, "SMTP_PORT"},
		{"host with a scheme", SMTP{Host: "smtp://h", From: "a@b.example"}, "SMTP_HOST must be a host name"},
		{"host with a port", SMTP{Host: "h:587", From: "a@b.example"}, "SMTP_HOST must be a host name"},
	}
	for _, c := range cases {
		cfg := smtpBase()
		cfg.SMTP = c.s
		err := cfg.Validate("serve")
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := LoadFrom("", env(map[string]string{"SMTP_PORT": "70000"})); err == nil {
		t.Error("an out-of-range SMTP_PORT loaded")
	}
	if _, err := LoadFrom("", env(map[string]string{"NOTIFICATION_INTERVAL": "1s"})); err == nil {
		t.Error("NOTIFICATION_INTERVAL below 5s loaded")
	}
	if _, err := LoadFrom("", env(map[string]string{"NOTIFICATION_INTERVAL": "11m"})); err == nil {
		t.Error("NOTIFICATION_INTERVAL above 10m loaded")
	}
	// Validate("migrate") never needs email.
	cfg := smtpBase()
	cfg.SMTP = SMTP{Port: 25}
	if err := cfg.Validate("migrate"); err != nil {
		t.Errorf("migrate: %v", err)
	}
}

func TestSMTPPasswordFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "smtp-password")
	if err := os.WriteFile(f, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFrom("", env(map[string]string{"SMTP_HOST": "h", "SMTP_FROM": "a@b.example", "SMTP_USERNAME": "u", "SMTP_PASSWORD_FILE": f}))
	if err != nil || c.SMTP.Password != "from-a-file" {
		t.Fatalf("%q %v", c.SMTP.Password, err)
	}
	// The YAML file takes the same keys.
	y := filepath.Join(t.TempDir(), "omp.yaml")
	if err := os.WriteFile(y, []byte("smtp_host: smtp.example.com\nsmtp_from: a@b.example\nsmtp_tls: tls\nsmtp_port: 2465\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = LoadFrom(y, env(map[string]string{}))
	if err != nil || c.SMTP.Mode() != SMTPImplicit || c.SMTP.Port != 2465 {
		t.Fatalf("%+v %v", c.SMTP, err)
	}
}

// With credentials, plain-text SMTP is refused unless the host is loopback
// or APP_URL is (a developer's machine); without credentials it is allowed
// (an in-cluster relay).
func TestSMTPSafety(t *testing.T) {
	prod := func(s SMTP) Config {
		c := smtpBase()
		c.AppURL, c.DevAuth = "https://mcp.example.com", false
		c.OIDC.Issuer, c.OIDC.ClientID, c.OIDC.ClientSecret = "https://idp", "id", "secret"
		c.EncryptionKey, c.APIKeyPepper = testKey, testPepper
		c.SMTP = s
		return c
	}
	base := SMTP{Host: "relay.example.com", From: "a@b.example", TLS: "none"}
	withCreds := base
	withCreds.Username, withCreds.Password = "u", "p"
	loopback := withCreds
	loopback.Host = "127.0.0.1"
	starttls := withCreds
	starttls.TLS = "starttls"
	for name, c := range map[string]struct {
		s       SMTP
		refused bool
	}{"none with credentials": {withCreds, true}, "none without credentials": {base, false}, "none on loopback": {loopback, false}, "starttls with credentials": {starttls, false}} {
		var found bool
		for _, e := range prod(c.s).SafetyErrors("serve") {
			if strings.Contains(e.Error(), "SMTP_TLS=none") {
				found = true
			}
		}
		if found != c.refused {
			t.Errorf("%s: refused = %v, want %v", name, found, c.refused)
		}
	}
	// A developer's loopback APP_URL is exempt.
	dev := prod(withCreds)
	dev.AppURL, dev.DevAuth = "http://localhost:8088", true
	if errs := dev.SafetyErrors("serve"); len(errs) != 0 {
		t.Errorf("loopback APP_URL: %v", errs)
	}
}

func TestNotifyWebhookAllowedNetworks(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{"NOTIFY_WEBHOOK_ALLOWED_NETWORKS": "10.20.0.0/16,http:*.hooks.internal"}))
	if err != nil || len(c.NotifyWebhookAllowedNetworks) != 2 {
		t.Fatalf("%+v %v", c.NotifyWebhookAllowedNetworks, err)
	}
	// It is separate from the MCP servers' list.
	if len(c.UpstreamAllowedNetworks) != 0 {
		t.Error("NOTIFY_WEBHOOK_ALLOWED_NETWORKS leaked into UPSTREAM_ALLOWED_NETWORKS")
	}
	for _, bad := range []string{"127.0.0.0/8", "169.254.169.254", "not a network!"} {
		if _, err := LoadFrom("", env(map[string]string{"NOTIFY_WEBHOOK_ALLOWED_NETWORKS": bad})); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	c, err = LoadFrom("", env(map[string]string{"UPSTREAM_ALLOWED_NETWORKS": "10.30.0.0/16"}))
	if err != nil || len(c.NotifyWebhookAllowedNetworks) != 0 {
		t.Error("the MCP servers' list must not open webhook destinations")
	}
}

func TestAuditStreamAllowedNetworks(t *testing.T) {
	c, err := LoadFrom("", env(map[string]string{"AUDIT_STREAM_ALLOWED_NETWORKS": "10.20.0.0/16,http:*.audit.internal"}))
	if err != nil || len(c.AuditStreamAllowedNetworks) != 2 || len(c.NotifyWebhookAllowedNetworks) != 0 || len(c.UpstreamAllowedNetworks) != 0 {
		t.Fatalf("audit policy not isolated: %v", err)
	}
	if _, err = LoadFrom("", env(map[string]string{"AUDIT_STREAM_ALLOWED_NETWORKS": "invalid!"})); err == nil {
		t.Fatal("invalid audit policy accepted")
	}
}
