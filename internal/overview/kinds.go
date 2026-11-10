package overview

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

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
