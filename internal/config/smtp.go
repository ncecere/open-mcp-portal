// Email and notification settings (docs/notifications.md, "Configuration").

package config

import (
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

// SMTP modes (SMTP_TLS).
const (
	SMTPStartTLS = "starttls" // upgrade with STARTTLS, required: a server that doesn't offer it fails
	SMTPImplicit = "tls"      // TLS from the first byte
	SMTPPlain    = "none"     // no encryption
)

// SMTP is the operator's mail server. Email is off without Host.
type SMTP struct {
	Host string
	// Port is 0 for the mode's default (587, 465, 25).
	Port     int
	Username string
	Password string // a secret: never logged, shown or returned
	From     string // portal@example.org or Open MCP Portal <portal@example.org>
	// TLS is "" (unset: starttls), starttls, tls or none.
	TLS string
}

// Enabled reports whether email is configured.
func (s SMTP) Enabled() bool { return s.Host != "" }

// Mode is the TLS mode in force.
func (s SMTP) Mode() string {
	if s.TLS == "" {
		return SMTPStartTLS
	}
	return s.TLS
}

// EffectivePort is Port, or the mode's default.
func (s SMTP) EffectivePort() int {
	if s.Port != 0 {
		return s.Port
	}
	switch s.Mode() {
	case SMTPImplicit:
		return 465
	case SMTPPlain:
		return 25
	}
	return 587
}

// Authenticates reports whether a username is set.
func (s SMTP) Authenticates() bool { return s.Username != "" }

// Address is the From address alone (no display name).
func (s SMTP) Address() string {
	a, err := mail.ParseAddress(s.From)
	if err != nil {
		return s.From
	}
	return a.Address
}

// anySet reports whether any SMTP_* setting other than the host is set.
func (s SMTP) anySet() bool {
	return s.Port != 0 || s.Username != "" || s.Password != "" || s.From != "" || s.TLS != ""
}

// Validate checks the settings: a half configuration must not silently mean
// "off".
func (s SMTP) validate() []error {
	var errs []error
	if !s.Enabled() {
		if s.anySet() {
			errs = append(errs, errors.New("SMTP_* settings are set but SMTP_HOST is not: set SMTP_HOST to turn email on, or remove them"))
		}
		return errs
	}
	if strings.ContainsAny(s.Host, "/:@ \t\r\n") {
		errs = append(errs, errors.New("SMTP_HOST must be a host name or address without a scheme or port (use SMTP_PORT)"))
	}
	if s.TLS != "" && s.TLS != SMTPStartTLS && s.TLS != SMTPImplicit && s.TLS != SMTPPlain {
		errs = append(errs, errors.New("SMTP_TLS must be starttls, tls or none"))
	}
	if s.Port != 0 && (s.Port < 1 || s.Port > 65535) {
		errs = append(errs, errors.New("SMTP_PORT must be from 1 to 65535"))
	}
	if (s.Username == "") != (s.Password == "") {
		errs = append(errs, errors.New("SMTP_USERNAME and SMTP_PASSWORD must be set together or not at all"))
	}
	switch {
	case s.From == "":
		errs = append(errs, errors.New("SMTP_FROM is required with SMTP_HOST (portal@example.org or Open MCP Portal <portal@example.org>)"))
	case strings.ContainsAny(s.From, "\r\n\x00") || hasControl(s.From):
		errs = append(errs, errors.New("SMTP_FROM must not contain control characters"))
	default:
		if _, err := mail.ParseAddress(s.From); err != nil {
			errs = append(errs, fmt.Errorf("SMTP_FROM is not a valid address: %w", err))
		}
	}
	return errs
}

// unencryptedWithCredentials: the password would cross the network in plain
// text.
func (s SMTP) unencryptedWithCredentials() bool {
	return s.Enabled() && s.Mode() == SMTPPlain && s.Username != "" && !isLoopbackHost(s.Host)
}

func init() {
	settings = append(settings,
		setting{key: "SMTP_HOST", apply: str(func(c *Config) *string { return &c.SMTP.Host })},
		setting{key: "SMTP_PORT", apply: func(c *Config, v string) error {
			v = strings.TrimSpace(v)
			if v == "" {
				c.SMTP.Port = 0
				return nil
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("must be an integer from 1 to 65535")
			}
			c.SMTP.Port = n
			return nil
		}},
		setting{key: "SMTP_USERNAME", apply: str(func(c *Config) *string { return &c.SMTP.Username })},
		setting{key: "SMTP_PASSWORD", secret: true, apply: func(c *Config, v string) error { c.SMTP.Password = strings.TrimSpace(v); return nil }},
		setting{key: "SMTP_FROM", apply: str(func(c *Config) *string { return &c.SMTP.From })},
		setting{key: "SMTP_TLS", apply: func(c *Config, v string) error {
			c.SMTP.TLS = strings.ToLower(strings.TrimSpace(v))
			return nil
		}},
		setting{key: "AUDIT_STREAM_ALLOWED_NETWORKS", apply: func(c *Config, v string) error {
			entries, err := netpolicy.ParseList(v)
			if err != nil {
				return err
			}
			c.AuditStreamAllowedNetworks = entries
			return nil
		}},
		setting{key: "NOTIFY_WEBHOOK_ALLOWED_NETWORKS", apply: func(c *Config, v string) error {
			entries, err := netpolicy.ParseList(v)
			if err != nil {
				return err
			}
			c.NotifyWebhookAllowedNetworks = entries
			return nil
		}},
		setting{key: "NOTIFICATION_INTERVAL", apply: duration(func(c *Config) *time.Duration { return &c.NotificationInterval }, 5*time.Second, 10*time.Minute)},
	)
}

// validateNotifications checks the email and notification settings.
func (c Config) validateNotifications() []error { return c.SMTP.validate() }
