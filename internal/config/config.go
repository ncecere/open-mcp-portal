// Package config resolves runtime configuration.
//
// Precedence: built-in defaults, then the optional YAML file named by
// OMP_CONFIG_FILE, then environment variables. Secret-bearing settings can
// also be read from a file named by the matching *_FILE variable (or
// *_file YAML key), which is how Kubernetes Secrets are mounted.
//
// The YAML file is flat: keys are the lower-case environment variable names,
// for example `app_url: https://mcp.example.com`. Unknown keys are rejected.
package config

import (
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

type Config struct {
	// AppURL is the public origin (scheme://host[:port]) used for cookies,
	// OIDC redirects and Origin checks.
	AppURL              string
	ListenAddr          string // HTTP listener (LISTEN_ADDR)
	DatabaseURL         string
	DatabaseMigrateURL  string
	DBRuntimeRole       string
	DBRequireSplitRoles bool
	MigrateOnStart      bool

	LogLevel  string
	LogFormat string

	// Instance is this deployment's identity: names, theme and links shown
	// in the UI.
	Instance Instance

	// TeamRequestURL links users to the team request form (for example a
	// service desk request). Optional.
	TeamRequestURL string

	DevAuth            bool
	OIDC               OIDC
	SessionTTL         time.Duration
	SessionIdleTimeout time.Duration

	// EncryptionKey (32 bytes, base64) encrypts secrets stored in the
	// database, such as MCP server header values. EncryptionKeyPrevious is
	// the key being rotated away from: values sealed with it still decrypt.
	EncryptionKey         string
	EncryptionKeyPrevious string

	// APIKeyPepper (32 bytes, base64) keys the HMAC under which personal
	// API keys are stored; the keys themselves never are.
	// APIKeyPepperPrevious is the pepper being rotated away from: keys and
	// tokens digested with it are still accepted (keys are re-digested on
	// use).
	APIKeyPepper         string
	APIKeyPepperPrevious string

	// MetricsAddr serves Prometheus metrics at /metrics on its own listener
	// ("" = off). MetricsMaxObjects bounds the gateway, server and provider
	// slugs used as label values.
	MetricsAddr       string
	MetricsMaxObjects int

	// RetentionInterval is how often the retention loop runs (one replica
	// at a time); RetentionBatchSize is how many rows one transaction
	// deletes.
	RetentionInterval  time.Duration
	RetentionBatchSize int

	// OAuthMaxRegisteredClients caps the live clients registered with
	// Dynamic Client Registration at /oauth/register (0: no cap).
	OAuthMaxRegisteredClients int
	// OAuthMaxUnusedClientsPerAddress caps the registrations one source
	// address can hold that have received no tokens yet (0: no cap).
	OAuthMaxUnusedClientsPerAddress int
	// OAuthRefreshAbsoluteTTL is how long after the person last signed an
	// app in its refresh tokens stop working, however often they are used
	// (0: no limit).
	OAuthRefreshAbsoluteTTL time.Duration

	// HealthCheckInterval is how often enabled MCP servers are re-tested
	// (0: never; one replica at a time).
	HealthCheckInterval time.Duration

	// ProviderRefreshInterval is how often a background pass refreshes the
	// access tokens of connected accounts that are about to expire and were
	// used lately, which finds a revoked grant before a call does (0: never,
	// the default; one replica at a time).
	ProviderRefreshInterval time.Duration

	// TasksMaxTTL is the longest a relayed task handle lives in this portal,
	// whatever the upstream's own lifetime says (1m to 24h, default 24h), and
	// TasksMaxOpenPerPrincipal how many unfinished tasks (reserved, working or
	// input required) one person or service account may hold across all its
	// keys and gateways (1 to 1000, default 100). Invalid values fail startup;
	// neither can ever mean unlimited (docs/mcp-tasks.md).
	TasksMaxTTL              time.Duration
	TasksMaxOpenPerPrincipal int

	// Tracing is OpenTelemetry tracing, off unless an OTLP endpoint is set
	// (tracing.go; docs/deploy.md "Tracing").
	Tracing Tracing

	// SMTP is the operator's mail server for notification email (off
	// without SMTP_HOST); NotificationInterval is the dispatcher's tick
	// (docs/notifications.md).
	SMTP                 SMTP
	NotificationInterval time.Duration
	// NotifyWebhookAllowedNetworks are the only internal networks and hosts
	// webhook destinations may use (NOTIFY_WEBHOOK_ALLOWED_NETWORKS, set by
	// the operator, default empty). Webhook URLs never use the MCP servers'
	// allowlist (UPSTREAM_ALLOWED_NETWORKS and Admin > Internal networks):
	// otherwise any team owner could make the portal POST into the internal
	// network. Without entries, webhooks go to public https addresses only.
	NotifyWebhookAllowedNetworks []netpolicy.Entry

	// SigningKeyPrepublish is how long a new identity signing key is
	// published in the JWKS before it starts signing.
	SigningKeyPrepublish time.Duration

	// TrustedProxies are the ingress CIDRs allowed to set X-Forwarded-For.
	TrustedProxies []netip.Prefix

	// UpstreamAllowedNetworks are the deployment's entries in the allowlist
	// of internal networks and hosts MCP servers may use
	// (UPSTREAM_ALLOWED_NETWORKS), shown read-only next to the platform
	// admins' entries.
	UpstreamAllowedNetworks []netpolicy.Entry

	// RequestsPerMinute limits each signed-in person's /v1 requests;
	// LoginAttemptsPerMinute limits sign-in attempts per client address.
	// Both are counted in PostgreSQL, shared by every replica.
	RequestsPerMinute      int
	LoginAttemptsPerMinute int
	ShutdownDelay          time.Duration
	ShutdownTimeout        time.Duration
}

// Themes are the UI themes. Only the neutral theme ships; branding comes
// from INSTANCE_NAME, ORG_NAME and UI_LOGO_URL.
var Themes = []string{"neutral"}

// Instance is the identity of one deployment. Nothing in the product names
// an organisation; each install configures its own.
type Instance struct {
	Name       string // product name in the UI and page titles
	OrgName    string // optional organisation name
	Theme      string // one of Themes; applied as <html data-brand>
	LogoURL    string // optional https URL or same-origin path
	SupportURL string // optional help link (http(s) or mailto:)
}

// DefaultInstanceName is the product name used when INSTANCE_NAME is unset.
const DefaultInstanceName = "Open MCP Portal"

type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	EmailClaim   string
	// GroupsClaim names the claim holding the person's IdP groups (for
	// gateway group grants); "" stores none.
	GroupsClaim           string
	RequireVerifiedEmail  bool
	AllowedEmailDomains   []string
	BootstrapAdminSubject string
}

// Enabled reports whether an OIDC provider is configured.
func (o OIDC) Enabled() bool { return o.Issuer != "" }

// SecureCookies reports whether the app is served over HTTPS.
func (c Config) SecureCookies() bool { return strings.HasPrefix(c.AppURL, "https://") }

// Defaults returns the built-in configuration.
func Defaults() Config {
	return Config{
		ListenAddr: ":8088",
		LogLevel:   "info",
		LogFormat:  "json",
		Instance:   Instance{Name: DefaultInstanceName, Theme: "neutral"},
		OIDC: OIDC{
			Scopes:               []string{"openid", "profile", "email"},
			EmailClaim:           "email",
			GroupsClaim:          "groups",
			RequireVerifiedEmail: true,
		},
		SessionTTL:                      12 * time.Hour,
		HealthCheckInterval:             5 * time.Minute,
		NotificationInterval:            15 * time.Second,
		SigningKeyPrepublish:            24 * time.Hour,
		MetricsMaxObjects:               200,
		Tracing:                         Tracing{Sampler: DefaultTracesSampler, SamplerArg: DefaultSamplerArg, ServiceName: DefaultTraceServiceName},
		TasksMaxTTL:                     mcptasks.DefaultMaxTTL,
		TasksMaxOpenPerPrincipal:        mcptasks.DefaultMaxOpen,
		RetentionInterval:               15 * time.Minute,
		RetentionBatchSize:              1000,
		OAuthMaxRegisteredClients:       1000,
		OAuthMaxUnusedClientsPerAddress: 20,
		OAuthRefreshAbsoluteTTL:         180 * 24 * time.Hour,
		RequestsPerMinute:               600,
		LoginAttemptsPerMinute:          20,
		ShutdownDelay:                   5 * time.Second,
		ShutdownTimeout:                 60 * time.Second,
	}
}

// MigrationURL is used only by migration, never doctor or key rotation.
func (c Config) MigrationURL() string {
	if c.DatabaseMigrateURL != "" {
		return c.DatabaseMigrateURL
	}
	return c.DatabaseURL
}

// LogoOrigin is the origin of an absolute UI_LOGO_URL (for the Content
// Security Policy's img-src), or "" for a same-origin path or no logo.
func (in Instance) LogoOrigin() string {
	if in.LogoURL == "" || strings.HasPrefix(in.LogoURL, "/") {
		return ""
	}
	u, err := url.Parse(in.LogoURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
