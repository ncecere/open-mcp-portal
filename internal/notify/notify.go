// Package notify tells the right people, in the portal or elsewhere, when
// something needs them (docs/notifications.md; decision 56): a server is
// down or changed, a review is waiting or decided, a sign-in lapsed, a key
// is about to expire. Three channels: the in-app inbox, email through the
// operator's SMTP server and webhooks (signed JSON, or Slack-compatible).
// Notifications never block or change anything they report on.
//
// The portal's own changes and loops emit events (Emit, the hooks of
// registry and providers); a leader-elected dispatcher (Service.Loop) fans
// them out to recipients resolved from live roles, then delivers the email
// and webhook rows of the outbox with retries. Delivery is at least once.
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Events (docs/notifications.md): stable names.
const (
	ServerUnhealthy          = "server.unhealthy"
	ServerRecovered          = "server.recovered"
	CapabilityChanged        = "capability.changed"
	PublishRequested         = "publish.requested"
	PublishDecided           = "publish.decided"
	ConnectionNeedsReconsent = "connection.needs_reconsent"
	UpstreamSigninLapsed     = "upstream_signin.lapsed"
	KeyExpiring              = "key.expiring"
	// Test is the type of a destination's test payload; it is not an event.
	Test = "test"
)

// Events lists every event in the order the API shows them.
var Events = []string{ServerUnhealthy, ServerRecovered, CapabilityChanged, PublishRequested, PublishDecided,
	ConnectionNeedsReconsent, UpstreamSigninLapsed, KeyExpiring}

// ValidEvent reports whether e is one of the eight events.
func ValidEvent(e string) bool {
	for _, x := range Events {
		if x == e {
			return true
		}
	}
	return false
}

// Channels.
const (
	ChannelInApp   = "in_app"
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
)

// Key kinds of key.expiring.
const (
	KeyPersonal       = "personal"
	KeyServiceAccount = "service_account"
	KeyPublisherToken = "publisher_token"
	KeyPlatformToken  = "platform_token"
	// KeyServerCertificate is a server's mTLS client certificate (decision 74):
	// the team's owners, admins and editors are told 14 days ahead.
	KeyServerCertificate = "server_certificate"
	// ServerCertWarnDays is how long before expiry a server's client certificate warns.
	ServerCertWarnDays = 14
)

// Limits and schedule (docs/notifications.md, "Delivery").
const (
	// MaxFanOut is how many events one run fans out.
	MaxFanOut = 200
	// MaxSend is how many due outbox rows one run sends, and Parallel how
	// many at a time.
	MaxSend  = 50
	Parallel = 8
	// PerTarget is the most deliveries one destination (or person) gets in a run.
	PerTarget = 3
	// MaxAttempts is how many times a delivery is tried.
	MaxAttempts = 6
	// ExpireAfter is how long a delivery may stay undelivered.
	ExpireAfter = 24 * time.Hour
	// StopAfter is how many failed attempts in a row stop a destination.
	StopAfter = 20
	// EmailsPerHour is the most emails one person gets in an hour.
	EmailsPerHour = 30
	// MaxPayload bounds an event's data (the envelope adds a few hundred
	// bytes, so the body stays under 8 KiB).
	MaxPayload = 7000
	// MaxDestinations per team and for the platform.
	MaxDestinations = 10
	// KeyWarnDays is how long before expiry key.expiring fires.
	KeyWarnDays = 7
	// lease is how long a claimed delivery is left to its run.
	lease = 120
)

// retryDelays are the waits after the first, second, ... failed attempt.
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}

// lockKey is the dispatcher's advisory lock.
const lockKey = "omp.notifications"

// Service is the notification service: the dispatcher and the API's
// operations.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	box  *secrets.Box
	// Client reaches webhook URLs behind the same address guard as MCP
	// servers (its allowlist and development allowance apply).
	client *upstream.Client
	cfg    Config
	log    *slog.Logger
	now    func() time.Time

	// mail sends email (the SMTP client; tests replace it).
	mail Mailer
	// Observe is told a delivery's outcome (channel, event, outcome).
	Observe func(channel, event, outcome string)
	// ObserveLeader is told whether this replica led the latest run.
	ObserveLeader func(leader bool)
}

// Config is what the service needs from the deployment.
type Config struct {
	SMTP         config.SMTP
	AppURL       string
	InstanceName string
	// Interval is the dispatcher's tick.
	Interval time.Duration
	// Version is sent in the webhooks' User-Agent.
	Version string
}

// New returns a Service. client dials webhook URLs; box seals their URLs and
// secrets.
func New(pool *pgxpool.Pool, box *secrets.Box, client *upstream.Client, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	s := &Service{pool: pool, q: dbgen.New(pool), box: box, client: client, cfg: cfg, log: log, now: time.Now}
	s.mail = &SMTPMailer{Config: cfg.SMTP}
	return s
}

// SetMailer replaces the mail sender (tests).
func (s *Service) SetMailer(m Mailer) { s.mail = m }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// EmailAvailable reports whether SMTP is configured.
func (s *Service) EmailAvailable() bool { return s.cfg.SMTP.Enabled() }

func (s *Service) observe(channel, event, outcome string) {
	if s.Observe != nil {
		s.Observe(channel, event, outcome)
	}
}

// Loop runs the dispatcher at start and every interval until ctx is
// cancelled (one replica at a time: Run takes an advisory lock).
func (s *Service) Loop(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		if sum, err := s.Run(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("notification dispatcher failed", "err", err)
		} else if sum.Led && (sum.FannedOut+sum.Sent+sum.Failed+sum.Retried+sum.Skipped > 0) {
			s.log.Debug("notifications", "fannedOut", sum.FannedOut, "sent", sum.Sent, "retry", sum.Retried, "failed", sum.Failed, "skipped", sum.Skipped)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
