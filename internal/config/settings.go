// The settings table: every environment variable (and YAML key) with its
// parser and bounds.

package config

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

type setting struct {
	key    string // environment variable name; YAML key is strings.ToLower(key)
	secret bool   // may also be supplied via KEY_FILE
	apply  func(*Config, string) error
}

func str(dst func(*Config) *string) func(*Config, string) error {
	return func(c *Config, v string) error { *dst(c) = strings.TrimSpace(v); return nil }
}

func boolean(dst func(*Config) *bool) func(*Config, string) error {
	return func(c *Config, v string) error {
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("must be true or false")
		}
		*dst(c) = b
		return nil
	}
}

func integer(dst func(*Config) *int, min, max int) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < min || n > max {
			return fmt.Errorf("must be an integer from %d to %d", min, max)
		}
		*dst(c) = n
		return nil
	}
}

func duration(dst func(*Config) *time.Duration, min, max time.Duration) func(*Config, string) error {
	return func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil || d < min || d > max {
			return fmt.Errorf("must be a duration from %s to %s", min, max)
		}
		*dst(c) = d
		return nil
	}
}

// daysOrDuration is a duration that also takes whole days ("180d"), where
// "0" turns the limit off; otherwise it must be from min to max.
func daysOrDuration(dst func(*Config) *time.Duration, min, max time.Duration) func(*Config, string) error {
	return func(c *Config, v string) error {
		v = strings.TrimSpace(v)
		var d time.Duration
		var err error
		if n, ok := strings.CutSuffix(v, "d"); ok {
			var days int
			if days, err = strconv.Atoi(n); err == nil && days >= 0 && days <= 100*365 {
				d = time.Duration(days) * 24 * time.Hour
			} else {
				err = errors.New("bad days")
			}
		} else {
			d, err = time.ParseDuration(v)
		}
		if err != nil || (d != 0 && (d < min || d > max)) {
			return fmt.Errorf("must be 0 (no limit) or a duration from %s to %s, such as 180d or 4320h", min, max)
		}
		*dst(c) = d
		return nil
	}
}

func list(dst func(*Config) *[]string, lower bool) func(*Config, string) error {
	return func(c *Config, v string) error {
		var out []string
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if lower {
				part = strings.ToLower(part)
			}
			if part != "" {
				out = append(out, part)
			}
		}
		*dst(c) = out
		return nil
	}
}

func trustedProxies(c *Config, v string) error {
	var out []netip.Prefix
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q", part)
		}
		out = append(out, p.Masked())
	}
	c.TrustedProxies = out
	return nil
}

// upstreamAllowedNetworks reads UPSTREAM_ALLOWED_NETWORKS (netpolicy.ParseList).
func upstreamAllowedNetworks(c *Config, v string) error {
	entries, err := netpolicy.ParseList(v)
	if err != nil {
		return err
	}
	c.UpstreamAllowedNetworks = entries
	return nil
}

var settings = []setting{
	{key: "APP_URL", apply: str(func(c *Config) *string { return &c.AppURL })},
	{key: "LISTEN_ADDR", apply: str(func(c *Config) *string { return &c.ListenAddr })},
	{key: "DATABASE_URL", secret: true, apply: str(func(c *Config) *string { return &c.DatabaseURL })},
	{key: "DATABASE_MIGRATE_URL", secret: true, apply: str(func(c *Config) *string { return &c.DatabaseMigrateURL })},
	{key: "DB_RUNTIME_ROLE", apply: func(c *Config, v string) error { c.DBRuntimeRole = v; return nil }},
	{key: "DB_REQUIRE_SPLIT_ROLES", apply: boolean(func(c *Config) *bool { return &c.DBRequireSplitRoles })},
	{key: "MIGRATE_ON_START", apply: boolean(func(c *Config) *bool { return &c.MigrateOnStart })},
	{key: "INSTANCE_NAME", apply: func(c *Config, v string) error {
		c.Instance.Name = cmp.Or(strings.TrimSpace(v), DefaultInstanceName)
		return nil
	}},
	{key: "ORG_NAME", apply: str(func(c *Config) *string { return &c.Instance.OrgName })},
	{key: "UI_THEME", apply: func(c *Config, v string) error {
		c.Instance.Theme = cmp.Or(strings.ToLower(strings.TrimSpace(v)), "neutral")
		return nil
	}},
	{key: "UI_LOGO_URL", apply: str(func(c *Config) *string { return &c.Instance.LogoURL })},
	{key: "SUPPORT_URL", apply: str(func(c *Config) *string { return &c.Instance.SupportURL })},
	{key: "LOG_LEVEL", apply: str(func(c *Config) *string { return &c.LogLevel })},
	{key: "LOG_FORMAT", apply: str(func(c *Config) *string { return &c.LogFormat })},
	{key: "TEAM_REQUEST_URL", apply: str(func(c *Config) *string { return &c.TeamRequestURL })},
	{key: "DEV_AUTH", apply: boolean(func(c *Config) *bool { return &c.DevAuth })},
	{key: "OIDC_ISSUER", apply: str(func(c *Config) *string { return &c.OIDC.Issuer })},
	{key: "OIDC_CLIENT_ID", apply: str(func(c *Config) *string { return &c.OIDC.ClientID })},
	{key: "OIDC_CLIENT_SECRET", secret: true, apply: str(func(c *Config) *string { return &c.OIDC.ClientSecret })},
	{key: "OIDC_SCOPES", apply: list(func(c *Config) *[]string { return &c.OIDC.Scopes }, false)},
	{key: "OIDC_EMAIL_CLAIM", apply: str(func(c *Config) *string { return &c.OIDC.EmailClaim })},
	{key: "OIDC_GROUPS_CLAIM", apply: str(func(c *Config) *string { return &c.OIDC.GroupsClaim })},
	{key: "OIDC_REQUIRE_VERIFIED_EMAIL", apply: boolean(func(c *Config) *bool { return &c.OIDC.RequireVerifiedEmail })},
	{key: "OIDC_ALLOWED_EMAIL_DOMAINS", apply: list(func(c *Config) *[]string { return &c.OIDC.AllowedEmailDomains }, true)},
	{key: "BOOTSTRAP_ADMIN_SUBJECT", apply: str(func(c *Config) *string { return &c.OIDC.BootstrapAdminSubject })},
	{key: "ENCRYPTION_KEY", secret: true, apply: str(func(c *Config) *string { return &c.EncryptionKey })},
	{key: "ENCRYPTION_KEY_PREVIOUS", secret: true, apply: str(func(c *Config) *string { return &c.EncryptionKeyPrevious })},
	{key: "API_KEY_PEPPER", secret: true, apply: str(func(c *Config) *string { return &c.APIKeyPepper })},
	{key: "API_KEY_PEPPER_PREVIOUS", secret: true, apply: str(func(c *Config) *string { return &c.APIKeyPepperPrevious })},
	{key: "METRICS_ADDR", apply: str(func(c *Config) *string { return &c.MetricsAddr })},
	{key: "METRICS_MAX_OBJECTS", apply: integer(func(c *Config) *int { return &c.MetricsMaxObjects }, 10, 10_000)},
	{key: "OTEL_TRACES_EXPORTER", apply: lowerStr(func(c *Config) *string { return &c.Tracing.Exporter })},
	{key: "OTEL_EXPORTER_OTLP_ENDPOINT", apply: str(func(c *Config) *string { return &c.Tracing.Endpoint })},
	{key: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", apply: str(func(c *Config) *string { return &c.Tracing.TracesEndpoint })},
	{key: "OTEL_EXPORTER_OTLP_PROTOCOL", apply: lowerStr(func(c *Config) *string { return &c.Tracing.Protocol })},
	{key: "OTEL_EXPORTER_OTLP_HEADERS", secret: true, apply: str(func(c *Config) *string { return &c.Tracing.Headers })},
	{key: "OTEL_SERVICE_NAME", apply: str(func(c *Config) *string { return &c.Tracing.ServiceName })},
	{key: "OTEL_TRACES_SAMPLER", apply: lowerStr(func(c *Config) *string { return &c.Tracing.Sampler })},
	{key: "OTEL_TRACES_SAMPLER_ARG", apply: samplerArg(func(c *Config) *float64 { return &c.Tracing.SamplerArg })},
	{key: "TRACE_LINK_TEMPLATE", apply: str(func(c *Config) *string { return &c.Tracing.LinkTemplate })},
	{key: "RETENTION_INTERVAL", apply: duration(func(c *Config) *time.Duration { return &c.RetentionInterval }, time.Minute, 24*time.Hour)},
	{key: "RETENTION_BATCH_SIZE", apply: integer(func(c *Config) *int { return &c.RetentionBatchSize }, 10, 100_000)},
	{key: "OAUTH_MAX_REGISTERED_CLIENTS", apply: integer(func(c *Config) *int { return &c.OAuthMaxRegisteredClients }, 0, 1_000_000)},
	{key: "OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS", apply: integer(func(c *Config) *int { return &c.OAuthMaxUnusedClientsPerAddress }, 0, 1_000_000)},
	{key: "OAUTH_REFRESH_ABSOLUTE_TTL", apply: daysOrDuration(func(c *Config) *time.Duration { return &c.OAuthRefreshAbsoluteTTL }, time.Hour, 10*365*24*time.Hour)},
	{key: "HEALTH_CHECK_INTERVAL", apply: duration(func(c *Config) *time.Duration { return &c.HealthCheckInterval }, 0, 24*time.Hour)},
	{key: "PROVIDER_REFRESH_INTERVAL", apply: duration(func(c *Config) *time.Duration { return &c.ProviderRefreshInterval }, 0, 24*time.Hour)},
	{key: "TASKS_MAX_TTL", apply: duration(func(c *Config) *time.Duration { return &c.TasksMaxTTL }, mcptasks.MinMaxTTL, mcptasks.MaxMaxTTL)},
	{key: "TASKS_MAX_OPEN_PER_PRINCIPAL", apply: integer(func(c *Config) *int { return &c.TasksMaxOpenPerPrincipal }, mcptasks.MinMaxOpen, mcptasks.MaxMaxOpen)},
	{key: "SIGNING_KEY_PREPUBLISH", apply: duration(func(c *Config) *time.Duration { return &c.SigningKeyPrepublish }, 0, 7*24*time.Hour)},
	{key: "SESSION_IDLE_TIMEOUT", apply: duration(func(c *Config) *time.Duration { return &c.SessionIdleTimeout }, 0, 30*24*time.Hour)},
	{key: "SESSION_TTL", apply: duration(func(c *Config) *time.Duration { return &c.SessionTTL }, 5*time.Minute, 30*24*time.Hour)},
	{key: "TRUSTED_PROXIES", apply: trustedProxies},
	{key: "UPSTREAM_ALLOWED_NETWORKS", apply: upstreamAllowedNetworks},
	{key: "REQUESTS_PER_MINUTE", apply: integer(func(c *Config) *int { return &c.RequestsPerMinute }, 1, 1_000_000)},
	{key: "LOGIN_ATTEMPTS_PER_MINUTE", apply: integer(func(c *Config) *int { return &c.LoginAttemptsPerMinute }, 1, 10_000)},
	{key: "SHUTDOWN_DELAY", apply: duration(func(c *Config) *time.Duration { return &c.ShutdownDelay }, 0, 5*time.Minute)},
	{key: "SHUTDOWN_TIMEOUT", apply: duration(func(c *Config) *time.Duration { return &c.ShutdownTimeout }, time.Second, 30*time.Minute)},
}
