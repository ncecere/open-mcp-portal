package registry

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// ReplacementRef is the server a retiring one points to.
type ReplacementRef struct {
	ID                 uuid.UUID
	Slug, Name         string
	TeamSlug, TeamName string
	// Published: it is in the catalog (anyone may be shown it).
	Published bool
	teamID    uuid.UUID
}

// TransferRef is a server's open transfer, as its team sees it.
type TransferRef struct {
	ID                     uuid.UUID
	ToTeamSlug, ToTeamName string
	RequestedAt            time.Time
	Revision               int64
}

// GovernanceView is a server's governance as the API shows it.
type GovernanceView struct {
	OwnerUserID uuid.NullUUID
	OwnerName   string
	// Ownerless: nobody accountable now (none named, or the owner is no longer
	// an active editor or above of the team).
	Ownerless     bool
	OncallContact *string
	Sensitivity   string
	// SensitivityConfirmed: an owner or admin of the team sent the label (even
	// the default one). Until then internal is only the column's default.
	SensitivityConfirmed bool
	// LastReviewedAt is the latest approval; ReviewDueAt the next one due.
	LastReviewedAt, ReviewDueAt *time.Time
	ReviewOverdue               bool
	// Lifecycle is as it is now (a deprecated server past its sunset date is
	// sunset).
	Lifecycle              string
	DeprecatedAt, SunsetAt *time.Time
	Replacement            *ReplacementRef
	PendingTransfer        *TransferRef
}

// Visible returns the replacement when the viewer may be shown it: published,
// or of the viewer's own team (teamID uuid.Nil: only published ones).
func (r *ReplacementRef) Visible(teamID uuid.UUID) *ReplacementRef {
	if r == nil || (!r.Published && (teamID == uuid.Nil || r.teamID != teamID)) {
		return nil
	}
	return r
}

// governanceViews completes server views with their governance. Owner names
// and eligibility, replacements and open transfers are read for the whole page
// at once.
func governanceViews(ctx context.Context, q *dbgen.Queries, out []ServerView, index map[uuid.UUID]int, now time.Time) error {
	ids := make([]uuid.UUID, 0, len(out))
	for _, v := range out {
		ids = append(ids, v.Server.ID)
	}
	owners, err := q.GovernanceOwnerViews(ctx, ids)
	if err != nil {
		return err
	}
	ownerOf := make(map[uuid.UUID]dbgen.GovernanceOwnerViewsRow, len(owners))
	for _, o := range owners {
		ownerOf[o.ServerID] = o
	}
	repls, err := q.GovernanceReplacementViews(ctx, ids)
	if err != nil {
		return err
	}
	pend, err := q.GovernancePendingTransfers(ctx, ids)
	if err != nil {
		return err
	}
	for i := range out {
		sv := out[i].Server
		g := GovernanceView{OwnerUserID: sv.OwnerUserID, OncallContact: sv.OncallContact, Sensitivity: sv.Sensitivity,
			SensitivityConfirmed: sv.SensitivityConfirmedAt != nil, LastReviewedAt: sv.LastReviewedAt, ReviewDueAt: sv.ReviewDueAt, ReviewOverdue: ReviewOverdue(sv, now),
			Lifecycle: EffectiveLifecycle(sv, now), DeprecatedAt: sv.DeprecatedAt, SunsetAt: sv.SunsetAt, Ownerless: true}
		if o, ok := ownerOf[sv.ID]; ok {
			g.OwnerName, g.Ownerless = o.OwnerName, !o.Eligible
		}
		out[i].Governance = g
	}
	for _, r := range repls {
		out[index[r.ServerID]].Governance.Replacement = &ReplacementRef{ID: r.ReplacementID, Slug: r.Slug, Name: r.Name, TeamSlug: r.TeamSlug,
			TeamName: r.TeamName, Published: r.PublishState == StatePublished, teamID: r.TeamID}
	}
	for _, t := range pend {
		out[index[t.ServerID]].Governance.PendingTransfer = &TransferRef{ID: t.ID, ToTeamSlug: t.ToTeamSlug, ToTeamName: t.ToTeamName,
			RequestedAt: t.RequestedAt, Revision: t.Revision}
	}
	return nil
}

// clock is the service's clock.
func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// SetClock replaces the clock of the governance loop and of what it reads
// (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// creatorOwner names the person who registers a server as its owner: they are
// an editor or above of the team (the create rule), and a person is
// accountable where a token is not.
func creatorOwner(a authz.Actor) uuid.NullUUID {
	if a.IsToken() || a.UserID == uuid.Nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: a.UserID, Valid: true}
}
