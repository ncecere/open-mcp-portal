package httpapi

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/overview"
)

// The v0.2 pilot-readiness operations: the admin overview and team
// attention (docs/admin-overview.md), notifications (docs/notifications.md)
// and automation tokens (docs/automation-tokens.md).

func (a *api) v02Routes() []route {
	const (
		teamDest  = "/v1/teams/{team}/notification-destinations"
		adminDest = "/v1/admin/notification-destinations"
	)
	routes := []route{
		{"GET", "/v1/admin/overview", a.admin(a.adminGetOverview)},
		{"GET", "/v1/teams/{team}/attention", a.session(a.getTeamAttention)},

		{"GET", "/v1/me/notifications", a.session(a.listMyNotifications)},
		{"GET", "/v1/me/notifications/unread-count", a.session(a.getMyUnreadNotificationCount)},
		{"POST", "/v1/me/notifications/read-all", a.session(a.markAllMyNotificationsRead)},
		{"POST", "/v1/me/notifications/{notificationId}/read", a.session(a.markMyNotificationRead)},
		{"GET", "/v1/me/notification-preferences", a.session(a.getMyNotificationPreferences)},
		{"PUT", "/v1/me/notification-preferences", a.session(a.updateMyNotificationPreferences)},

		{"GET", "/v1/admin/settings/notifications", a.admin(a.adminGetNotificationSettings)},
		{"POST", "/v1/admin/settings/notifications/test-email", a.admin(a.adminTestEmail)},

		{"GET", "/v1/token", a.tokenOnly(a.getToken)},
		{"GET", "/v1/admin/automation-tokens", a.admin(a.adminListAutomationTokens)},
		{"POST", "/v1/admin/automation-tokens", a.admin(a.adminCreateAutomationToken)},
		{"DELETE", "/v1/admin/automation-tokens/{tokenId}", a.admin(a.adminRevokeAutomationToken)},
		{"GET", "/v1/teams/{team}/automation-tokens", a.session(a.listTeamAutomationTokens)},
		{"POST", "/v1/teams/{team}/automation-tokens", a.session(a.createTeamAutomationToken)},
		{"DELETE", "/v1/teams/{team}/automation-tokens/{tokenId}", a.session(a.revokeTeamAutomationToken)},
	}
	dest := func(base string, wrap func(http.HandlerFunc) http.Handler, scope func(*http.Request) notify.Scope) []route {
		return []route{
			{"GET", base, wrap(a.listDestinations(scope))},
			{"POST", base, wrap(a.createDestination(scope))},
			{"GET", base + "/{destinationId}", wrap(a.getDestination(scope))},
			{"PATCH", base + "/{destinationId}", wrap(a.updateDestination(scope))},
			{"DELETE", base + "/{destinationId}", wrap(a.deleteDestination(scope))},
			{"POST", base + "/{destinationId}/test", wrap(a.testDestination(scope))},
			{"POST", base + "/{destinationId}/rotate-secret", wrap(a.rotateDestinationSecret(scope))},
			{"GET", base + "/{destinationId}/deliveries", wrap(a.listDeliveries(scope))},
		}
	}
	teamScope := func(r *http.Request) notify.Scope { return notify.Scope{TeamRef: r.PathValue("team")} }
	platformScope := func(*http.Request) notify.Scope { return notify.Scope{} }
	routes = append(routes, dest(teamDest, a.session, teamScope)...)
	return append(routes, dest(adminDest, a.admin, platformScope)...)
}

func teamRef(id uuid.UUID, slug, name string) *apitypes.TeamRef {
	return &apitypes.TeamRef{Id: id, Slug: slug, Name: name}
}

// ---- overview and attention

func toAPIItems(items []overview.Item) []apitypes.AttentionItem {
	out := make([]apitypes.AttentionItem, len(items))
	for i, it := range items {
		o := apitypes.AttentionItem{Kind: apitypes.AttentionKind(it.Kind), Severity: apitypes.AttentionSeverity(it.Severity), Summary: it.Summary,
			Count: it.Count, At: it.At, Detail: nonEmpty(it.Detail)}
		if it.Subject != nil {
			o.Subject = &apitypes.AttentionSubject{Id: it.Subject.ID, Name: it.Subject.Name, Slug: nonEmpty(it.Subject.Slug)}
		}
		if it.Team != nil {
			o.Team = teamRef(it.Team.ID, it.Team.Slug, it.Team.Name)
		}
		if it.Link != nil {
			l := &apitypes.LinkTarget{Type: apitypes.LinkTargetType(it.Link.Type), Id: nonEmpty(it.Link.ID), TeamSlug: nonEmpty(it.Link.TeamSlug)}
			o.Link = l
		}
		out[i] = o
	}
	return out
}

func (a *api) adminGetOverview(w http.ResponseWriter, r *http.Request) {
	o, err := a.Overview.Admin(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.AdminOverview{
		GeneratedAt: o.GeneratedAt,
		Counts: apitypes.OverviewCounts{Users: o.Counts.Users, Teams: o.Counts.Teams, Servers: o.Counts.Servers, PublishedServers: o.Counts.PublishedServers,
			Gateways: o.Counts.Gateways, ServiceAccounts: o.Counts.ServiceAccounts, AutomationTokens: o.Counts.AutomationTokens},
		Last24h: apitypes.OverviewActivity{Calls: o.Last24h.Calls, Errors: o.Last24h.Errors, RateLimited: o.Last24h.RateLimited,
			ErrorRate: o.Last24h.ErrorRate, RolledUpTo: o.Last24h.RolledUpTo},
		Attention: toAPIItems(o.Attention), Totals: o.Totals, Truncated: o.Truncated,
	})
}

func (a *api) getTeamAttention(w http.ResponseWriter, r *http.Request) {
	t, err := a.Overview.Team(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.TeamAttention{GeneratedAt: t.GeneratedAt, Attention: toAPIItems(t.Attention), Totals: t.Totals, Truncated: t.Truncated})
}

// ---- inbox and preferences

// ---- destinations

// ---- automation tokens
