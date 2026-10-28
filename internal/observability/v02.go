package observability

import "github.com/prometheus/client_golang/prometheus"

// Metrics of notifications and automation tokens (docs/notifications.md,
// docs/automation-tokens.md). Labels are fixed lists only: channels, event
// types, outcomes and authentication results; never a person, team,
// destination or token.
var (
	NotificationsEmitted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_notifications_emitted_total",
		Help: "Notification events emitted (new ones, not deduplicated repeats), by event type.",
	}, []string{"event"})
	NotificationEmitErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "omp_notification_emit_errors_total",
		Help: "Events that could not be emitted (logged; the change they report on was not affected).",
	})
	NotificationDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_notification_deliveries_total",
		Help: "Delivery attempts by channel (in_app, email, webhook), event type and outcome (sent, retry, failed, skipped).",
	}, []string{"channel", "event", "outcome"})
	AutomationTokenAuth = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omp_automation_token_auth_total",
		Help: "Bearer authentications on /v1 by result (ok, unknown, expired, revoked, creator_not_admin, bad_shape, mcp_credential, rate_limited, ambiguous, session_required, not_allowed, other_team).",
	}, []string{"result"})
)

func v02Collectors() []prometheus.Collector {
	return []prometheus.Collector{NotificationsEmitted, NotificationEmitErrors, NotificationDeliveries, AutomationTokenAuth}
}
