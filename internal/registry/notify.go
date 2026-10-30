package registry

import (
	"context"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Notifier is told about the registry's changes and checks that people may
// want to hear about (internal/notify implements it; docs/notifications.md).
// Calls are made with the queries of the change's transaction (or the pool)
// and never fail it: a notification can't stop what it reports on.
type Notifier interface {
	// ServerChecked: a health check of the server was stored.
	ServerChecked(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID)
	// CapabilitiesRefreshed: a refresh stored the server's capabilities.
	CapabilitiesRefreshed(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID)
	// PublishRequested: the server entered review (reason new, url_changed,
	// upstream_auth_changed or requirement_changed).
	PublishRequested(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, reason string, a authz.Actor)
	// PublishDecided: a platform admin approved or rejected the server.
	PublishDecided(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, approved bool, a authz.Actor)
	// ServerDeprecated: the server left the active lifecycle; the owners of
	// the gateways that select it are told (once per gateway and deprecation).
	ServerDeprecated(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID)
	// ReviewDue: a published server's re-review is overdue (returned: it was
	// sent back to review). It reports whether anyone was newly told: false
	// when the same due date was told before.
	ReviewDue(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, returned bool) bool
	// SunsetSoon: a deprecated server's sunset is near. gateway nil tells the
	// server's team, otherwise the owners of that gateway.
	SunsetSoon(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, gateway *dbgen.Gateway) bool
	// Deprecated tells the owners of a gateway that selects a deprecated server.
	Deprecated(ctx context.Context, q *dbgen.Queries, sv dbgen.McpServer, gateway dbgen.Gateway) bool
}

type noNotifier struct{}

func (noNotifier) ServerChecked(context.Context, *dbgen.Queries, uuid.UUID)         {}
func (noNotifier) CapabilitiesRefreshed(context.Context, *dbgen.Queries, uuid.UUID) {}
func (noNotifier) PublishRequested(context.Context, *dbgen.Queries, uuid.UUID, string, authz.Actor) {
}
func (noNotifier) PublishDecided(context.Context, *dbgen.Queries, uuid.UUID, bool, authz.Actor) {}
func (noNotifier) ServerDeprecated(context.Context, *dbgen.Queries, uuid.UUID)                  {}
func (noNotifier) ReviewDue(context.Context, *dbgen.Queries, dbgen.McpServer, bool) bool {
	return false
}
func (noNotifier) SunsetSoon(context.Context, *dbgen.Queries, dbgen.McpServer, *dbgen.Gateway) bool {
	return false
}
func (noNotifier) Deprecated(context.Context, *dbgen.Queries, dbgen.McpServer, dbgen.Gateway) bool {
	return false
}

// SetNotifier installs the notification hooks.
func (s *Service) SetNotifier(n Notifier) { s.notify = n }

func (s *Service) notifier() Notifier {
	if s.notify == nil {
		return noNotifier{}
	}
	return s.notify
}
