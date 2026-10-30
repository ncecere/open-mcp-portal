// Package overview computes the admin overview and the team attention card
// (docs/admin-overview.md; decision 57): what needs whom, from the data the
// portal already has. It is read-only, computed per request, and adds no
// background work. Each kind is one indexed query with a LIMIT of
// PerKind; the exact total comes with the rows.
package overview

import (
	"context"
	"fmt"
	"slices"
	"strings"
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

// collector gathers items and exact totals.
type collector struct {
	now       time.Time
	items     []Item
	totals    map[string]int64
	truncated bool
}

func newCollector(now time.Time) *collector { return &collector{now: now, totals: map[string]int64{}} }

// add records items of one kind with the kind's exact total (the number of
// servers, or the sum of counts): a kind with a total larger than its listed
// rows is truncated.
func (c *collector) add(kind string, total int64, listed int, items ...Item) {
	if total <= 0 {
		return
	}
	c.totals[kind] = total
	if int64(listed) < total {
		c.truncated = true
	}
	c.items = append(c.items, items...)
}

func (c *collector) sorted() []Item {
	rank := map[string]int{Critical: 0, Warning: 1, Info: 2}
	out := slices.Clone(c.items)
	slices.SortStableFunc(out, func(x, y Item) int {
		if d := rank[x.Severity] - rank[y.Severity]; d != 0 {
			return d
		}
		switch {
		case x.At != nil && y.At == nil:
			return -1
		case x.At == nil && y.At != nil:
			return 1
		case x.At != nil && y.At != nil && !x.At.Equal(*y.At):
			return x.At.Compare(*y.At)
		}
		return strings.Compare(sortName(x), sortName(y))
	})
	if out == nil {
		out = []Item{}
	}
	return out
}

func sortName(i Item) string {
	if i.Subject != nil {
		return strings.ToLower(i.Subject.Name)
	}
	if i.Team != nil {
		return strings.ToLower(i.Team.Name)
	}
	return i.Summary
}

func since(now, at time.Time) string {
	d := now.Sub(at)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", max(int(d.Minutes()), 1))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func expirySeverity(now, earliest time.Time) string {
	if earliest.Sub(now) <= ExpiryWarnWithin {
		return Warning
	}
	return Info
}

func i64(n int64) *int64 { return &n }

// realTime is t, or nil for the epoch the queries use for "none" (an
// aggregate over no rows).
func realTime(t time.Time) *time.Time {
	if t.Unix() <= 0 {
		return nil
	}
	return &t
}

func teamRef(id uuid.UUID, slug, name string) *TeamRef {
	return &TeamRef{ID: id, Slug: slug, Name: name}
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// serverKinds adds the kinds about servers, for the platform (published
// servers only) or one team (any publish state).
func (s *Service) serverKinds(ctx context.Context, c *collector, team uuid.NullUUID) error {
	published := !team.Valid
	failing, err := s.q.AttentionFailingServers(ctx, dbgen.AttentionFailingServersParams{PublishedOnly: published, TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	var items []Item
	var total int64
	for _, r := range failing {
		total = r.Total
		at := r.StatusSince
		sev := Warning
		if c.now.Sub(at) > CriticalAfter {
			sev = Critical
		}
		items = append(items, Item{Kind: ServerFailing, Severity: sev, At: &at,
			Summary: fmt.Sprintf("%s (%s) has been failing for %s", r.Name, r.TeamName, since(c.now, at)),
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}})
	}
	c.add(ServerFailing, total, len(items), items...)

	lapsed, err := s.q.AttentionLapsedSignins(ctx, dbgen.AttentionLapsedSigninsParams{PublishedOnly: published, TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total = nil, 0
	for _, r := range lapsed {
		total = r.Total
		it := Item{Kind: UpstreamSigninLapsed, Severity: Warning, Summary: fmt.Sprintf("The sign-in that reads %s (%s) has lapsed", r.Name, r.TeamName),
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}}
		it.At = realTime(r.LapsedAt)
		items = append(items, it)
	}
	c.add(UpstreamSigninLapsed, total, len(items), items...)

	pending, err := s.q.AttentionPendingReviews(ctx, team)
	if err != nil {
		return err
	}
	if pending.Pending > 0 {
		oldest := realTime(pending.Oldest)
		it := Item{Kind: ReviewPending, Severity: Info, Count: i64(pending.Pending), At: oldest,
			Summary: fmt.Sprintf("%s waiting for a platform review", plural(pending.Pending, "server", "servers")), Link: &Link{Type: LinkReviewQueue}}
		if oldest != nil && c.now.Sub(*oldest) > ReviewWarnAfter {
			it.Severity = Warning
		}
		if team.Valid {
			it.Link = nil // set by the caller: it needs the team's slug
		}
		c.add(ReviewPending, pending.Pending, 1, it)
	}

	changed, err := s.q.AttentionChangedCapabilities(ctx, dbgen.AttentionChangedCapabilitiesParams{TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total = nil, 0
	for _, r := range changed {
		total = r.Total
		items = append(items, Item{Kind: CapabilitiesChanged, Severity: Warning, Count: i64(r.Held),
			Summary: fmt.Sprintf("%s (%s) has %s held back from the catalog", r.Name, r.TeamName, plural(r.Held, "changed or new capability", "changed or new capabilities")),
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}})
	}
	c.add(CapabilitiesChanged, total, len(items), items...)

	certs, err := s.q.AttentionExpiringCertificates(ctx, dbgen.AttentionExpiringCertificatesParams{PublishedOnly: published, TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total = nil, 0
	for _, r := range certs {
		total = r.Total
		if r.ClientNotAfter == nil {
			continue
		}
		at := *r.ClientNotAfter
		sev, summary := expirySeverity(c.now, at), fmt.Sprintf("The client certificate of %s (%s) expires in %s", r.Name, r.TeamName, since(at, c.now))
		if !at.After(c.now) {
			sev, summary = Critical, fmt.Sprintf("The client certificate of %s (%s) has expired: the server refuses it", r.Name, r.TeamName)
		}
		items = append(items, Item{Kind: ServerCertExpiring, Severity: sev, At: &at, Summary: summary,
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}})
	}
	c.add(ServerCertExpiring, total, len(items), items...)

	// Governance (decision 88): published servers whose re-review is overdue,
	// and ones nobody is accountable for.
	due, err := s.q.AttentionReviewDue(ctx, dbgen.AttentionReviewDueParams{Now: c.now, TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total = nil, 0
	for _, r := range due {
		total = r.Total
		at := *r.ReviewDueAt
		items = append(items, Item{Kind: ReviewDue, Severity: Warning, At: &at,
			Summary: fmt.Sprintf("The review of %s (%s) has been overdue for %s", r.Name, r.TeamName, since(c.now, at)),
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}})
	}
	c.add(ReviewDue, total, len(items), items...)

	ownerless, err := s.q.AttentionOwnerlessServers(ctx, dbgen.AttentionOwnerlessServersParams{TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total = nil, 0
	for _, r := range ownerless {
		total = r.Total
		why := "has no owner"
		if r.OwnerLeft {
			why = "has no accountable owner any more"
		}
		items = append(items, Item{Kind: ServerOwnerless, Severity: Warning, Summary: fmt.Sprintf("%s (%s) %s", r.Name, r.TeamName, why),
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}})
	}
	c.add(ServerOwnerless, total, len(items), items...)

	// A published server whose sensitivity label nobody confirmed: internal is
	// only the column's default until a team's owner or admin sends a label.
	// Informational: nothing is blocked, unpublished or re-reviewed for it.
	unlabelled, err := s.q.AttentionUnlabelledServers(ctx, dbgen.AttentionUnlabelledServersParams{TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total = nil, 0
	for _, r := range unlabelled {
		total = r.Total
		items = append(items, Item{Kind: ServerUnlabelled, Severity: Info,
			Summary: fmt.Sprintf("%s (%s) is published with the sensitivity label %q that nobody has confirmed", r.Name, r.TeamName, r.Sensitivity),
			Subject: &Subject{ID: r.ID.String(), Name: r.Name, Slug: r.Slug}, Team: teamRef(r.TeamID, r.TeamSlug, r.TeamName),
			Link: &Link{Type: LinkServer, ID: r.ID.String(), TeamSlug: r.TeamSlug}})
	}
	c.add(ServerUnlabelled, total, len(items), items...)
	return nil
}

// keyKinds adds the expiries of service account keys and automation
// tokens. includePlatform: the platform view (platform tokens too).
func (s *Service) keyKinds(ctx context.Context, c *collector, team uuid.NullUUID, includePlatform bool) error {
	sa, err := s.q.AttentionServiceAccountKeys(ctx, dbgen.AttentionServiceAccountKeysParams{TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	var items []Item
	var total, groups int64
	for _, r := range sa {
		total, groups = r.Total, r.Groups
		at := r.Earliest
		items = append(items, Item{Kind: ServiceAccountKeysExpiring, Severity: expirySeverity(c.now, at), Count: i64(r.Keys), At: &at,
			Summary: fmt.Sprintf("%s of team %s expire within 14 days", plural(r.Keys, "service account key", "service account keys"), r.TeamName),
			Team:    teamRef(r.TeamID, r.TeamSlug, r.TeamName), Link: &Link{Type: LinkServiceAccounts, TeamSlug: r.TeamSlug}})
	}
	c.add(ServiceAccountKeysExpiring, total, int(min(groups, int64(len(items)))), items...)
	if groups > int64(len(items)) {
		c.truncated = true
	}

	tok, err := s.q.AttentionAutomationTokens(ctx, dbgen.AttentionAutomationTokensParams{IncludePlatform: includePlatform, TeamID: team, PageSize: PerKind})
	if err != nil {
		return err
	}
	items, total, groups = nil, 0, 0
	for _, r := range tok {
		total, groups = r.Total, r.Groups
		at := r.Earliest
		it := Item{Kind: AutomationTokensExpiring, Severity: expirySeverity(c.now, at), Count: i64(r.Tokens), At: &at}
		if r.TeamSlug == "" {
			it.Summary = fmt.Sprintf("%s expire within 14 days", plural(r.Tokens, "platform token", "platform tokens"))
			it.Link = &Link{Type: LinkAutomationTokens}
		} else {
			it.Summary = fmt.Sprintf("%s of team %s expire within 14 days", plural(r.Tokens, "publisher token", "publisher tokens"), r.TeamName)
			it.Team = teamRef(r.TeamID.UUID, r.TeamSlug, r.TeamName)
			it.Link = &Link{Type: LinkTeamAutomationTokens, TeamSlug: r.TeamSlug}
		}
		items = append(items, it)
	}
	c.add(AutomationTokensExpiring, total, int(min(groups, int64(len(items)))), items...)
	if groups > int64(len(items)) {
		c.truncated = true
	}
	return nil
}

// notificationKind adds the failing webhook destinations (and, for the
// platform, failed email).
func (s *Service) notificationKind(ctx context.Context, c *collector, team uuid.NullUUID, slug string, name string, teamID uuid.UUID) error {
	d, err := s.q.AttentionFailingDestinations(ctx, team)
	if err != nil {
		return err
	}
	n, latest := d.Destinations, realTime(d.Latest)
	if !team.Valid {
		e, err := s.q.AttentionEmailFailure(ctx)
		if err != nil {
			return err
		}
		if t := realTime(e); t != nil {
			n++
			if latest == nil || t.After(*latest) {
				latest = t
			}
		}
	}
	if n == 0 {
		return nil
	}
	it := Item{Kind: NotificationFailures, Severity: Warning, Count: i64(n), At: latest,
		Summary: fmt.Sprintf("%s failing", plural(n, "notification channel is", "notification channels are"))}
	if team.Valid {
		it.Summary = fmt.Sprintf("%s failing", plural(n, "webhook destination is", "webhook destinations are"))
		it.Team = teamRef(teamID, slug, name)
		it.Link = &Link{Type: LinkTeamNotificationSettings, TeamSlug: slug}
	} else {
		it.Link = &Link{Type: LinkNotificationSettings}
	}
	c.add(NotificationFailures, n, 1, it)
	return nil
}

// approvalKind adds private, human-only pending approval hints.
func (s *Service) approvalKind(ctx context.Context, c *collector, a authz.Actor, team *uuid.UUID) error {
	if s.Approvals == nil || a.IsToken() || (a.Kind != "" && a.Kind != authz.KindUser) {
		return nil
	}
	rows, total, err := s.Approvals(ctx, a, team, PerKind)
	if err != nil {
		return err
	}
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		at := r.CreatedAt
		items = append(items, Item{Kind: ApprovalPending, Severity: Info,
			Summary: "Tool call needs your approval", Detail: r.ExposedName, At: &at,
			Link: &Link{Type: LinkApproval, ID: r.ID.String()}})
	}
	c.add(ApprovalPending, total, len(items), items...)
	return nil
}

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
