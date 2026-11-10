// Package overview computes the admin overview and the team attention card
// (docs/admin-overview.md; decision 57): what needs whom, from the data the
// portal already has. It is read-only, computed per request, and adds no
// background work. Each kind is one indexed query with a LIMIT of
// PerKind; the exact total comes with the rows.
package overview

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// PerKind is the most items listed per kind; Totals stay exact.
const PerKind = 20

// Kinds of attention items.
const (
	ServerFailing              = "server_failing"
	UpstreamSigninLapsed       = "upstream_signin_lapsed"
	ReviewPending              = "review_pending"
	ApprovalPending            = "approval_pending"
	AccessRequestsPending      = "access_requests_pending"
	CapabilitiesChanged        = "capabilities_changed"
	PersonalKeysExpiring       = "personal_keys_expiring"
	ServiceAccountKeysExpiring = "service_account_keys_expiring"
	AutomationTokensExpiring   = "automation_tokens_expiring"
	ConnectionsReconsent       = "connections_reconsent"
	GatewaysDisabled           = "gateways_disabled"
	RateLimited                = "rate_limited"
	NotificationFailures       = "notification_failures"
	ServerCertExpiring         = "server_certificate_expiring"
	ReviewDue                  = "review_due"
	ServerOwnerless            = "server_ownerless"
	ServerTransferPending      = "server_transfer_pending"
	ServerUnlabelled           = "server_unlabelled"
)

// Severities.
const (
	Critical = "critical"
	Warning  = "warning"
	Info     = "info"
)

// Thresholds.
const (
	// CriticalAfter is how long a failing server stays a warning.
	CriticalAfter = 24 * time.Hour
	// ReviewWarnAfter is how long a pending review stays info.
	ReviewWarnAfter = 3 * 24 * time.Hour
	// ExpiryWarnWithin is how close an expiry is a warning (info before).
	ExpiryWarnWithin = 3 * 24 * time.Hour
)

// Link targets (docs/admin-overview.md, "Link targets").
const (
	LinkServer                   = "server"
	LinkApproval                 = "approval"
	LinkAccessRequests           = "access_requests"
	LinkServers                  = "servers"
	LinkReviewQueue              = "review_queue"
	LinkGateways                 = "gateways"
	LinkServiceAccounts          = "service_accounts"
	LinkAutomationTokens         = "automation_tokens"
	LinkTeamAutomationTokens     = "team_automation_tokens"
	LinkAuthProviders            = "auth_providers"
	LinkUsage                    = "usage"
	LinkNotificationSettings     = "notification_settings"
	LinkTeamNotificationSettings = "team_notification_settings"
)

// Link is where the web app goes for an item.
type Link struct {
	Type     string
	ID       string
	TeamSlug string
}

// Subject is the server an item is about.
type Subject struct{ ID, Name, Slug string }

// TeamRef is a team as named in items.
type TeamRef struct {
	ID         uuid.UUID
	Slug, Name string
}

// Item is one thing that needs attention.
type Item struct {
	Kind     string
	Severity string
	Summary  string
	Detail   string
	Count    *int64
	At       *time.Time
	Subject  *Subject
	Team     *TeamRef
	Link     *Link
}

// Counts are the platform's headline numbers.
type Counts struct {
	Users, Teams, Servers, PublishedServers, Gateways, ServiceAccounts, AutomationTokens int64
}

// Activity is the last 24 hourly rollup buckets.
type Activity struct {
	Calls, Errors, RateLimited int64
	// ErrorRate is errors/calls from 0 to 1 (nil without calls).
	ErrorRate  *float64
	RolledUpTo *time.Time
}

// Admin is the platform overview.
type Admin struct {
	GeneratedAt time.Time
	Counts      Counts
	Last24h     Activity
	Attention   []Item
	Totals      map[string]int64
	Truncated   bool
}

// Team is a team's attention card.
type Team struct {
	GeneratedAt time.Time
	Attention   []Item
	Totals      map[string]int64
	Truncated   bool
}

// Service computes overviews.
type Service struct {
	// Approvals is optional for legacy compositions. It must return only the
	// current human's eligible metadata and an exact total, never platform totals.
	Approvals func(context.Context, authz.Actor, *uuid.UUID, int32) ([]approvals.AttentionItem, int64, error)
	q         *dbgen.Queries
	now       func() time.Time
}

// New returns a Service.
func New(pool *pgxpool.Pool) *Service {
	return &Service{q: dbgen.New(pool), now: time.Now}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

var errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")

// Admin is the platform overview (platform admins and auditors).
func (s *Service) Admin(ctx context.Context, a authz.Actor) (Admin, error) {
	if !a.CanReadPlatform() {
		return Admin{}, apperr.Forbidden("Only platform admins and auditors can see the overview")
	}
	now := s.now()
	out := Admin{GeneratedAt: now}
	cnt, err := s.q.OverviewCounts(ctx)
	if err != nil {
		return out, err
	}
	out.Counts = Counts{Users: cnt.Users, Teams: cnt.Teams, Servers: cnt.Servers, PublishedServers: cnt.PublishedServers, Gateways: cnt.Gateways,
		ServiceAccounts: cnt.ServiceAccounts, AutomationTokens: cnt.AutomationTokens}
	act, err := s.q.OverviewActivity(ctx)
	if err != nil {
		return out, err
	}
	out.Last24h = Activity{Calls: act.Calls, Errors: act.Errors, RateLimited: act.RateLimited}
	if act.Calls > 0 {
		rate := float64(act.Errors) / float64(act.Calls)
		out.Last24h.ErrorRate = &rate
	}
	st, err := s.q.GetUsageRollupState(ctx)
	if err != nil {
		return out, err
	}
	out.Last24h.RolledUpTo = st.RolledUpTo

	c := newCollector(now)
	if err := s.serverKinds(ctx, c, uuid.NullUUID{}); err != nil {
		return out, err
	}
	pk, err := s.q.AttentionPersonalKeys(ctx)
	if err != nil {
		return out, err
	}
	if pk.Keys > 0 {
		c.add(PersonalKeysExpiring, pk.Keys, 1, Item{Kind: PersonalKeysExpiring, Severity: expirySeverity(now, pk.Earliest), Count: i64(pk.Keys), At: realTime(pk.Earliest),
			Summary: fmt.Sprintf("%s expire within 14 days", plural(pk.Keys, "personal API key", "personal API keys"))})
	}
	if err := s.keyKinds(ctx, c, uuid.NullUUID{}, true); err != nil {
		return out, err
	}
	conns, err := s.q.AttentionConnections(ctx)
	if err != nil {
		return out, err
	}
	if conns > 0 {
		c.add(ConnectionsReconsent, conns, 1, Item{Kind: ConnectionsReconsent, Severity: Info, Count: i64(conns),
			Summary: fmt.Sprintf("%s need to be connected again", plural(conns, "person's connection", "people's connections")), Link: &Link{Type: LinkAuthProviders}})
	}
	gws, err := s.q.AttentionDisabledGateways(ctx)
	if err != nil {
		return out, err
	}
	if gws > 0 {
		c.add(GatewaysDisabled, gws, 1, Item{Kind: GatewaysDisabled, Severity: Info, Count: i64(gws),
			Summary: fmt.Sprintf("%s switched off", plural(gws, "gateway is", "gateways are")), Link: &Link{Type: LinkGateways}})
	}
	if out.Last24h.RateLimited > 0 {
		c.add(RateLimited, out.Last24h.RateLimited, 1, Item{Kind: RateLimited, Severity: Info, Count: i64(out.Last24h.RateLimited),
			Summary: fmt.Sprintf("%s refused by a rate limit in the last 24 hours", plural(out.Last24h.RateLimited, "call", "calls")), Link: &Link{Type: LinkUsage}})
	}
	if err := s.notificationKind(ctx, c, uuid.NullUUID{}, "", "", uuid.Nil); err != nil {
		return out, err
	}
	if err := s.approvalKind(ctx, c, a, nil); err != nil {
		return out, err
	}
	if !a.IsToken() && a.UserID != uuid.Nil {
		n, err := s.q.CountActionableAccessRequests(ctx, a.UserID)
		if err != nil {
			return out, err
		}
		if n > 0 {
			c.add(AccessRequestsPending, n, 1, Item{Kind: AccessRequestsPending, Severity: Info, Count: i64(n),
				Summary: fmt.Sprintf("%d gateway access requests need your review", n), Link: &Link{Type: LinkAccessRequests}})
		}
	}
	out.Attention, out.Totals, out.Truncated = c.sorted(), c.totals, c.truncated
	return out, nil
}

// Team is a team's attention card: members see the team's servers, review
// state and capability changes; owners and admins (and platform staff)
// also key and token expiries and notification failures. An archived team
// has no items; people outside the team get 404.
func (s *Service) Team(ctx context.Context, a authz.Actor, ref string) (Team, error) {
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return Team{}, err
	}
	role, err := teams.MemberRole(ctx, s.q, t.ID, a.UserID)
	if err != nil {
		return Team{}, err
	}
	if role == "" && !a.CanReadPlatform() {
		return Team{}, errTeamNotFound
	}
	now := s.now()
	out := Team{GeneratedAt: now, Attention: []Item{}, Totals: map[string]int64{}}
	if t.Status != teams.StatusActive {
		return out, nil
	}
	team := uuid.NullUUID{UUID: t.ID, Valid: true}
	c := newCollector(now)
	if err := s.serverKinds(ctx, c, team); err != nil {
		return out, err
	}
	for i := range c.items {
		if c.items[i].Kind == ReviewPending {
			c.items[i].Link = &Link{Type: LinkServers, TeamSlug: t.Slug}
			c.items[i].Team = teamRef(t.ID, t.Slug, t.Name)
		}
	}
	if authz.RoleAtLeast(role, authz.RoleOwner) && !a.IsToken() {
		// Only an owner can accept a transfer, so only an owner is asked to.
		tr, err := s.q.AttentionPendingTransfers(ctx, t.ID)
		if err != nil {
			return out, err
		}
		if tr.Pending > 0 {
			c.add(ServerTransferPending, tr.Pending, 1, Item{Kind: ServerTransferPending, Severity: Info, Count: i64(tr.Pending), At: realTime(tr.Oldest),
				Summary: fmt.Sprintf("%s waiting for your team's owners to accept", plural(tr.Pending, "server transfer is", "server transfers are")),
				Team:    teamRef(t.ID, t.Slug, t.Name), Link: &Link{Type: LinkServers, TeamSlug: t.Slug}})
		}
	}
	if a.CanReadPlatform() || authz.RoleAtLeast(role, authz.RoleAdmin) {
		if err := s.keyKinds(ctx, c, team, false); err != nil {
			return out, err
		}
		if err := s.notificationKind(ctx, c, team, t.Slug, t.Name, t.ID); err != nil {
			return out, err
		}
	}
	if err := s.approvalKind(ctx, c, a, &t.ID); err != nil {
		return out, err
	}
	out.Attention, out.Totals, out.Truncated = c.sorted(), c.totals, c.truncated
	return out, nil
}
