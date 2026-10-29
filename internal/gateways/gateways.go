// Package gateways manages gateways (SPEC.md §5, §7 phase 3;
// docs/phase3-gateways.md): curated collections of tools and prompts served
// at /mcp/{slug}, their selections, and who may use them.
//
// A team gateway belongs to a team: its owners and admins edit it, its
// members (and platform admins and auditors) read it, and only its members
// use it, each capability optionally limited to a minimum team role. It may
// select the tools and prompts of the team's own enabled servers, and the
// approved ones of published servers. A platform gateway belongs to the
// platform: platform admins edit it and grant it to teams, people or SSO
// groups; it selects approved capabilities of published servers only.
//
// Whether a selected capability is served is computed live
// (Availability), so unpublishing a server or changing a tool takes effect
// at once. Every mutation authorizes, changes and writes its audit entry in
// one transaction.
package gateways

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Owner kinds.
const (
	OwnerTeam     = "team"
	OwnerPlatform = "platform"
)

var (
	errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")
	errNoGateway    = apperr.NotFound("gateway_not_found", "Gateway not found")
	errSlugTaken    = apperr.Conflict("slug_taken", "Another gateway already uses that slug")
	errTeamArchived = apperr.Conflict("team_archived", "This team is archived and read-only")
	errAdminOnly    = apperr.Forbidden("Only platform admins can do this")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errTeamGateway  = apperr.New(http.StatusForbidden, "team_gateway",
		"Team gateways are managed by their team; platform admins can only switch them off or on")
	slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)
)

// Service manages gateways.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	appURL string
	log    *slog.Logger
	// Limits checks a gateway's own rate limit against the ceiling (nil: no
	// check).
	Limits *limits.Service
	// AccessNotice emits private notices in the request transaction. Notification
	// failure must not roll back an authoritative access decision.
	AccessNotice func(context.Context, *dbgen.Queries, dbgen.AccessRequest, bool)
	// ServiceConnectionReady checks live shared-credential policy without
	// decrypting or refreshing tokens, for accurate service-account views.
	ServiceConnectionReady func(context.Context, *registry.Requirement, uuid.UUID, uuid.UUID, uuid.UUID, string) (bool, error)
}

// New returns a Service; appURL (APP_URL) makes the gateways' endpoint URLs.
func New(pool *pgxpool.Pool, appURL string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{pool: pool, q: q, appURL: appURL, log: log}
}

// URL is a gateway's MCP endpoint.
func (s *Service) URL(slug string) string { return s.appURL + "/mcp/" + slug }

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// View is a gateway as the API shows it.
type View struct {
	Gateway            dbgen.Gateway
	TeamSlug, TeamName string // team gateways
	// CapabilityCount are the selected capabilities, UnavailableCount the
	// ones not served now, GrantCount a platform gateway's grants.
	CapabilityCount, UnavailableCount, GrantCount int64
}

func views(ctx context.Context, q *dbgen.Queries, rows []dbgen.ListGatewaysRow) ([]View, error) {
	out := make([]View, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(rows))
	index := make(map[uuid.UUID]int, len(rows))
	for i, r := range rows {
		ids[i], index[r.Gateway.ID] = r.Gateway.ID, i
		out[i] = View{Gateway: r.Gateway, TeamSlug: r.TeamSlug, TeamName: r.TeamName}
	}
	stats, err := q.GatewayStats(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, st := range stats {
		v := &out[index[st.GatewayID]]
		v.CapabilityCount, v.UnavailableCount, v.GrantCount = st.CapabilityCount, st.UnavailableCount, st.GrantCount
	}
	return out, nil
}

func view(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (View, error) {
	r, err := q.GetGatewayView(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return View{}, errNoGateway
	} else if err != nil {
		return View{}, err
	}
	vs, err := views(ctx, q, []dbgen.ListGatewaysRow{{Gateway: r.Gateway, TeamSlug: r.TeamSlug, TeamName: r.TeamName}})
	if err != nil {
		return View{}, err
	}
	return vs[0], nil
}

// ListParams filter and page gateway lists by (name, id).
type ListParams struct {
	Search    *string // raw; LIKE-escaped here
	OwnerKind *string // admin list
	Team      string  // admin list: a team slug or ID ("" for all)
	AfterName *string
	AfterID   *uuid.UUID
	Limit     int32
}

func (p ListParams) query() dbgen.ListGatewaysParams {
	out := dbgen.ListGatewaysParams{OwnerKind: p.OwnerKind, AfterName: p.AfterName, PageSize: p.Limit}
	if p.Search != nil {
		escaped := store.EscapeLike(*p.Search)
		out.Search = &escaped
	}
	if p.AfterID != nil {
		out.AfterID = uuid.NullUUID{UUID: *p.AfterID, Valid: true}
	}
	return out
}

// teamAccess is a team as seen by an actor.
type teamAccess struct {
	team dbgen.Team
	role string // "" when not a member
}

// access resolves a team the actor may see: members, and platform admins
// and auditors. Others get 404, so a team's existence is not revealed.
func access(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string) (teamAccess, error) {
	t, err := teams.Resolve(ctx, q, ref)
	if err != nil {
		return teamAccess{}, err
	}
	role, err := teams.MemberRole(ctx, q, t.ID, a.UserID)
	if err != nil {
		return teamAccess{}, err
	}
	if role == "" && !a.CanReadPlatform() {
		return teamAccess{}, errTeamNotFound
	}
	return teamAccess{team: t, role: role}, nil
}

// writable: owners and admins of an active team.
func (ta teamAccess) writable() error {
	if err := authz.CheckGatewayEdit(ta.role); err != nil {
		return err
	}
	if ta.team.Status != teams.StatusActive {
		return errTeamArchived
	}
	return nil
}

func getGateway(ctx context.Context, q *dbgen.Queries, id uuid.UUID, lock bool) (dbgen.Gateway, error) {
	var (
		g   dbgen.Gateway
		err error
	)
	if lock {
		g, err = q.LockGateway(ctx, id)
	} else {
		g, err = q.GetGateway(ctx, id)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return g, errNoGateway
	}
	return g, err
}

// teamGateway returns one of the team's gateways (404 for any other).
func teamGateway(ctx context.Context, q *dbgen.Queries, teamID, id uuid.UUID, lock bool) (dbgen.Gateway, error) {
	g, err := getGateway(ctx, q, id, lock)
	if err == nil && (g.OwnerKind != OwnerTeam || g.TeamID.UUID != teamID) {
		return g, errNoGateway
	}
	return g, err
}

// CreateInput creates a gateway.
type CreateInput struct {
	Slug, Name, Description string
	Enabled                 bool
	// CapturePayloads records calls' contents; RateLimit is the gateway's
	// own limit per minute (nil: inherit).
	CapturePayloads bool
	RateLimit       *int64
}

// UpdateInput holds optional changes; the slug never changes.
type UpdateInput struct {
	Name, Description *string
	Enabled           *bool
	CapturePayloads   *bool
	// SetRateLimit changes the gateway's own limit to RateLimit (nil:
	// inherit); false keeps it.
	SetRateLimit bool
	RateLimit    *int64
}

func checkFields(name, description string) error {
	if n := utf8.RuneCountInString(strings.TrimSpace(name)); n < 1 || n > 100 {
		return apperr.Invalid("invalid_name", "Name must be 1-100 characters")
	}
	if utf8.RuneCountInString(description) > 2000 {
		return apperr.Invalid("invalid_description", "Description must be at most 2000 characters")
	}
	return nil
}

// snapshot is a gateway's audited configuration.
func snapshot(g dbgen.Gateway) map[string]any {
	return map[string]any{"slug": g.Slug, "name": g.Name, "description": g.Description, "ownerKind": g.OwnerKind, "enabled": g.Enabled,
		"capturePayloads": g.CapturePayloads, "rateLimitPerMinute": g.RateLimitPerMinute}
}

// checkLimit refuses a gateway limit above the ceiling (422 invalid_limit).
func (s *Service) checkLimit(ctx context.Context, q *dbgen.Queries, v *int64) error {
	if s.Limits == nil {
		return nil
	}
	return s.Limits.CheckGatewayValue(ctx, q, v)
}

func teamOf(g dbgen.Gateway) uuid.UUID {
	if g.TeamID.Valid {
		return g.TeamID.UUID
	}
	return uuid.Nil
}

// create inserts a gateway and audits gateway.create.
func (s *Service) create(ctx context.Context, q *dbgen.Queries, a authz.Actor, kind string, teamID uuid.NullUUID, in CreateInput) (uuid.UUID, error) {
	in.Slug, in.Name = strings.TrimSpace(in.Slug), strings.TrimSpace(in.Name)
	if !slugRE.MatchString(in.Slug) {
		return uuid.Nil, apperr.Invalid("invalid_slug",
			"Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if err := checkFields(in.Name, in.Description); err != nil {
		return uuid.Nil, err
	}
	if err := s.checkLimit(ctx, q, in.RateLimit); err != nil {
		return uuid.Nil, err
	}
	g, err := q.InsertGateway(ctx, dbgen.InsertGatewayParams{
		ID: uuid.New(), Slug: in.Slug, Name: in.Name, Description: in.Description, OwnerKind: kind, TeamID: teamID,
		Enabled: in.Enabled, CapturePayloads: in.CapturePayloads, RateLimitPerMinute: in.RateLimit, CreatedBy: by(a),
	})
	if apperr.IsUniqueViolation(err, "gateways_slug_key") {
		return uuid.Nil, errSlugTaken
	} else if err != nil {
		return uuid.Nil, err
	}
	e := a.Audit("gateway.create", "gateway", g.ID.String())
	e.TeamID, e.After = teamOf(g), snapshot(g)
	return g.ID, audit.Record(ctx, q, e)
}

// update applies in to cur (locked) and audits gateway.update.
func (s *Service) update(ctx context.Context, q *dbgen.Queries, a authz.Actor, cur dbgen.Gateway, in UpdateInput, expectedRevision int64) error {
	if cur.Revision != expectedRevision {
		return apperr.Stale()
	}
	p := dbgen.UpdateGatewayParams{ID: cur.ID, Name: cur.Name, Description: cur.Description, Enabled: cur.Enabled,
		CapturePayloads: cur.CapturePayloads, RateLimitPerMinute: cur.RateLimitPerMinute, UpdatedBy: by(a)}
	if in.CapturePayloads != nil {
		p.CapturePayloads = *in.CapturePayloads
	}
	if in.SetRateLimit && !sameLimit(in.RateLimit, cur.RateLimitPerMinute) {
		if err := s.checkLimit(ctx, q, in.RateLimit); err != nil {
			return err
		}
		p.RateLimitPerMinute = in.RateLimit
	}
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		p.Description = *in.Description
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if err := checkFields(p.Name, p.Description); err != nil {
		return err
	}
	row, err := q.UpdateGateway(ctx, p)
	if err != nil {
		return err
	}
	e := a.Audit("gateway.update", "gateway", cur.ID.String())
	e.TeamID, e.Before, e.After = teamOf(cur), snapshot(cur), snapshot(row)
	return audit.Record(ctx, q, e)
}

func sameLimit(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// remove deletes a gateway (its selection and grants go with it; its call
// records stay) and audits gateway.delete.
func remove(ctx context.Context, q *dbgen.Queries, a authz.Actor, cur dbgen.Gateway) error {
	if err := q.DeleteGateway(ctx, cur.ID); err != nil {
		return err
	}
	e := a.Audit("gateway.delete", "gateway", cur.ID.String())
	e.TeamID, e.Before = teamOf(cur), snapshot(cur)
	return audit.Record(ctx, q, e)
}

// ListTeam lists a team's gateways (members; platform admins and auditors).
func (s *Service) ListTeam(ctx context.Context, a authz.Actor, ref string, p ListParams) ([]View, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	qp := p.query()
	qp.TeamID, qp.OwnerKind = uuid.NullUUID{UUID: ta.team.ID, Valid: true}, nil
	rows, err := s.q.ListGateways(ctx, qp)
	if err != nil {
		return nil, err
	}
	return views(ctx, s.q, rows)
}

// GetTeam returns one of a team's gateways.
func (s *Service) GetTeam(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (View, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return View{}, err
	}
	if _, err := teamGateway(ctx, s.q, ta.team.ID, id, false); err != nil {
		return View{}, err
	}
	return view(ctx, s.q, id)
}

// CreateTeam creates a team gateway (team owners and admins).
func (s *Service) CreateTeam(ctx context.Context, a authz.Actor, ref string, in CreateInput) (View, error) {
	var id uuid.UUID
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		id, err = s.create(ctx, q, a, OwnerTeam, uuid.NullUUID{UUID: ta.team.ID, Valid: true}, in)
		return err
	})
	if err != nil {
		return View{}, err
	}
	return view(ctx, s.q, id)
}

// UpdateTeam changes a team gateway's name, description or switch (team
// owners and admins).
func (s *Service) UpdateTeam(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (View, error) {
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		cur, err := teamGateway(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		return s.update(ctx, q, a, cur, in, expectedRevision)
	})
	if err != nil {
		return View{}, err
	}
	return view(ctx, s.q, id)
}

// DeleteTeam deletes a team gateway (team owners and admins).
func (s *Service) DeleteTeam(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		cur, err := teamGateway(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		return remove(ctx, q, a, cur)
	})
}

// AdminList lists every gateway (platform admins and auditors). An unknown
// team filter lists nothing.
func (s *Service) AdminList(ctx context.Context, a authz.Actor, p ListParams) ([]View, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	qp := p.query()
	if p.Team != "" {
		t, err := teams.Resolve(ctx, s.q, p.Team)
		if e, ok := apperr.As(err); ok && e.Status == http.StatusNotFound {
			return []View{}, nil
		} else if err != nil {
			return nil, err
		}
		qp.TeamID = uuid.NullUUID{UUID: t.ID, Valid: true}
	}
	rows, err := s.q.ListGateways(ctx, qp)
	if err != nil {
		return nil, err
	}
	return views(ctx, s.q, rows)
}

// AdminGet returns any gateway (platform admins and auditors).
func (s *Service) AdminGet(ctx context.Context, a authz.Actor, id uuid.UUID) (View, error) {
	if !a.CanReadPlatform() {
		return View{}, errPlatformRead
	}
	return view(ctx, s.q, id)
}

// AdminCreate creates a platform gateway (platform admins).
func (s *Service) AdminCreate(ctx context.Context, a authz.Actor, in CreateInput) (View, error) {
	if !a.IsPlatformAdmin() {
		return View{}, errAdminOnly
	}
	var id uuid.UUID
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		var err error
		id, err = s.create(ctx, q, a, OwnerPlatform, uuid.NullUUID{}, in)
		return err
	})
	if err != nil {
		return View{}, err
	}
	return view(ctx, s.q, id)
}

// AdminUpdate changes a platform gateway (platform admins). On a team
// gateway only the switch may change (403 team_gateway otherwise).
func (s *Service) AdminUpdate(ctx context.Context, a authz.Actor, id uuid.UUID, in UpdateInput, expectedRevision int64) (View, error) {
	if !a.IsPlatformAdmin() {
		return View{}, errAdminOnly
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		if cur.OwnerKind == OwnerTeam &&
			((in.Name != nil && strings.TrimSpace(*in.Name) != cur.Name) || (in.Description != nil && *in.Description != cur.Description) ||
				(in.CapturePayloads != nil && *in.CapturePayloads != cur.CapturePayloads) ||
				(in.SetRateLimit && !sameLimit(in.RateLimit, cur.RateLimitPerMinute))) {
			return errTeamGateway
		}
		return s.update(ctx, q, a, cur, in, expectedRevision)
	})
	if err != nil {
		return View{}, err
	}
	return view(ctx, s.q, id)
}

// AdminDelete deletes a platform gateway (platform admins); team gateways
// are deleted by their team (403 team_gateway).
func (s *Service) AdminDelete(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		if cur.OwnerKind != OwnerPlatform {
			return errTeamGateway
		}
		return remove(ctx, q, a, cur)
	})
}
