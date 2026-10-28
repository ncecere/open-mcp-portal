package gateways

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Selections: which tools, prompts, resources and resource templates a
// gateway exposes, and whether each is served right now.

// Selection limits.
const (
	MaxSelection = 200
	// DefaultOptionPage and MaxOptionPage bound a page of gateway-options.
	DefaultOptionPage = 100
	MaxOptionPage     = 500
)

// Why a selected capability isn't served (the API's GatewayUnavailableReason).
const (
	ReasonServerDisabled = "server_disabled"
	ReasonNotPublished   = "not_published"
	ReasonNotApproved    = "not_approved"
	ReasonChanged        = "changed"
	ReasonGone           = "gone"
	ReasonCurationStale  = "curation_stale"
	// ReasonTeamArchived: the server's team, or a team gateway's own team,
	// is archived. Nothing is changed on archive, so unarchiving restores it.
	ReasonTeamArchived = "team_archived"
)

// Option sources.
const (
	SourceTeam    = "team"
	SourceCatalog = "catalog"
)

// Selectable reports whether a capability kind may be selected: tools,
// prompts, resources and resource templates (templates also need
// TemplateSupported).
func Selectable(kind string) bool {
	switch kind {
	case upstream.KindTool, upstream.KindPrompt, upstream.KindResource, upstream.KindResourceTemplate:
		return true
	}
	return false
}

// ExposedName is the name clients see: {serverSlug}__{name}. Server slugs
// have no underscores, so the first "__" always ends the slug.
func ExposedName(serverSlug, name string) string { return serverSlug + "__" + name }

// Archived says which teams involved in serving a capability are archived:
// a team gateway's own team, and the team that owns the server.
type Archived struct {
	GatewayTeam, ServerTeam bool
}

// Availability says whether a gateway serves a selected capability now,
// and why not: it must be listed, of a selectable kind, neither the server's
// team nor a team gateway's own team archived, its server enabled, and
// either a server of the team gateway's own team, or published with the
// current definition approved. GatewayStats (SQL) mirrors this rule.
func Availability(g dbgen.Gateway, c dbgen.McpCapability, s dbgen.McpServer, archived Archived) (bool, string) {
	switch {
	case c.GoneAt != nil || !Selectable(c.Kind):
		return false, ReasonGone
	case archived.GatewayTeam || archived.ServerTeam:
		return false, ReasonTeamArchived
	case !s.Enabled:
		return false, ReasonServerDisabled
	case g.OwnerKind == OwnerTeam && g.TeamID.Valid && s.TeamID == g.TeamID.UUID:
		return true, ""
	case s.PublishState != registry.StatePublished:
		return false, ReasonNotPublished
	case c.ApprovedFingerprint == nil:
		return false, ReasonNotApproved
	case *c.ApprovedFingerprint != c.Fingerprint:
		return false, ReasonChanged
	}
	return true, ""
}

// Selected is one selected capability.
type Selected struct {
	Capability         dbgen.McpCapability
	Server             dbgen.McpServer
	TeamSlug, TeamName string // the server's team
	MinRole            *string
	// ExposedName is the name (tools, prompts) or URI (resources,
	// templates) clients see.
	ExposedName         string
	Curation            *curation.Policy
	CurationStale       bool
	EffectiveDefinition json.RawMessage
	BaseFingerprint     *string
	CuratedBy           uuid.NullUUID
	CuratedAt           *time.Time
	Available           bool
	Reason              string // when not Available
	// Requires is the capability's effective user-authorization
	// requirement (nil: calls get no provider token).
	Requires *registry.Requirement
}

// Selection is a gateway's selection with its revision.
type Selection struct {
	Revision int64
	Items    []Selected
}

// gatewayTeamArchived reports whether g is a team gateway whose team is
// archived.
func gatewayTeamArchived(ctx context.Context, q *dbgen.Queries, g dbgen.Gateway) (bool, error) {
	if g.OwnerKind != OwnerTeam || !g.TeamID.Valid {
		return false, nil
	}
	t, err := q.GetTeamByID(ctx, g.TeamID.UUID)
	if err != nil {
		return false, err
	}
	return t.Status != teams.StatusActive, nil
}

func selection(ctx context.Context, q *dbgen.Queries, g dbgen.Gateway) ([]Selected, error) {
	ownArchived, err := gatewayTeamArchived(ctx, q, g)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListGatewaySelection(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	ps, err := registry.LoadProviders(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]Selected, len(rows))
	for i, r := range rows {
		ok, reason := Availability(g, r.McpCapability, r.McpServer,
			Archived{GatewayTeam: ownArchived, ServerTeam: r.TeamStatus != teams.StatusActive})
		out[i] = Selected{Capability: r.McpCapability, Server: r.McpServer, TeamSlug: r.TeamSlug, TeamName: r.TeamName,
			MinRole: r.GatewayCapability.MinTeamRole, ExposedName: Exposed(r.McpCapability.Kind, r.McpServer.Slug, r.McpCapability.Name), Available: ok, Reason: reason,
			Requires: registry.EffectiveFor(r.McpServer, r.McpCapability, ps)}
		applyCuration(&out[i], r.GatewayCapability)
	}
	return out, nil
}

// Option is a capability a gateway may select.
type Option struct {
	dbgen.ListGatewayOptionsRow
	Source      string
	ExposedName string
	// Requires is the effective user-authorization requirement (nil: none).
	Requires *registry.Requirement
}

func checkKind(kind *string) error {
	if kind != nil && !Selectable(*kind) {
		return apperr.Invalid("invalid_kind", "kind must be tool, prompt, resource or resource_template")
	}
	return nil
}

// OptionParams filter and page gateway-options by (server name, server ID,
// name, ID).
type OptionParams struct {
	Search, Kind *string
	Server       *uuid.UUID
	After        *OptionCursor
	// Limit is the page size (the caller asks for one more to see whether
	// another page follows).
	Limit int32
}

// OptionCursor is the sort key of the last option of a page.
type OptionCursor struct {
	ServerName string
	ServerID   uuid.UUID
	Name       string
	ID         uuid.UUID
}

// options lists what a gateway of teamID (uuid.Nil: a platform gateway) may
// select; ids narrows to those capabilities (and ignores p).
func options(ctx context.Context, q *dbgen.Queries, teamID uuid.UUID, p OptionParams, ids []uuid.UUID) ([]Option, error) {
	qp := dbgen.ListGatewayOptionsParams{Kind: p.Kind, PageSize: p.Limit, Ids: []uuid.UUID{}}
	if qp.PageSize <= 0 {
		qp.PageSize = DefaultOptionPage
	}
	if teamID != uuid.Nil {
		qp.TeamID = uuid.NullUUID{UUID: teamID, Valid: true}
	}
	if p.Server != nil {
		qp.ServerID = uuid.NullUUID{UUID: *p.Server, Valid: true}
	}
	if p.Search != nil {
		escaped := store.EscapeLike(*p.Search)
		qp.Search = &escaped
	}
	if a := p.After; a != nil {
		qp.AfterServerName, qp.AfterServerID = &a.ServerName, uuid.NullUUID{UUID: a.ServerID, Valid: true}
		qp.AfterName, qp.AfterID = &a.Name, uuid.NullUUID{UUID: a.ID, Valid: true}
	}
	if ids != nil {
		qp = dbgen.ListGatewayOptionsParams{TeamID: qp.TeamID, ByIds: true, Ids: ids, PageSize: int32(len(ids))}
	}
	rows, err := q.ListGatewayOptions(ctx, qp)
	if err != nil {
		return nil, err
	}
	ps, err := registry.LoadProviders(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]Option, len(rows))
	for i, r := range rows {
		src := SourceCatalog
		if teamID != uuid.Nil && r.ServerTeamID == teamID {
			src = SourceTeam
		}
		out[i] = Option{ListGatewayOptionsRow: r, Source: src, ExposedName: Exposed(r.Kind, r.ServerSlug, r.Name),
			Requires: registry.Effective(registry.ServerOf{ID: r.ServerID, AuthMode: r.ServerAuthMode, Provider: r.ServerAuthProviderID,
				Scopes: r.ServerAuthScopes}, r.RequirementMode, r.RequirementScopes, ps)}
	}
	return out, nil
}

// Cursor is the option's sort key, to continue after it.
func (o Option) Cursor() OptionCursor {
	return OptionCursor{ServerName: o.ServerName, ServerID: o.ServerID, Name: o.Name, ID: o.ID}
}

// TeamSelection returns a team gateway's selection (members; platform
// admins and auditors).
func (s *Service) TeamSelection(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (Selection, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return Selection{}, err
	}
	g, err := teamGateway(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return Selection{}, err
	}
	items, err := selection(ctx, s.q, g)
	return Selection{Revision: g.Revision, Items: items}, err
}

// AdminSelection returns any gateway's selection (platform admins and
// auditors).
func (s *Service) AdminSelection(ctx context.Context, a authz.Actor, id uuid.UUID) (Selection, error) {
	if !a.CanReadPlatform() {
		return Selection{}, errPlatformRead
	}
	g, err := getGateway(ctx, s.q, id, false)
	if err != nil {
		return Selection{}, err
	}
	items, err := selection(ctx, s.q, g)
	return Selection{Revision: g.Revision, Items: items}, err
}

// TeamOptions lists what the team's gateways may select (team owners and
// admins).
func (s *Service) TeamOptions(ctx context.Context, a authz.Actor, ref string, p OptionParams) ([]Option, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	if err := authz.CheckGatewayEdit(ta.role); err != nil {
		return nil, err
	}
	if err := checkKind(p.Kind); err != nil {
		return nil, err
	}
	return options(ctx, s.q, ta.team.ID, p, nil)
}

// AdminOptions lists what platform gateways may select (platform admins
// and auditors).
func (s *Service) AdminOptions(ctx context.Context, a authz.Actor, p OptionParams) ([]Option, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if err := checkKind(p.Kind); err != nil {
		return nil, err
	}
	return options(ctx, s.q, uuid.Nil, p, nil)
}

// SelectionInput is one capability of a new selection.
type SelectionInput struct {
	CapabilityID uuid.UUID
	MinRole      *string
	// nil: preserve; JSON null: clear; object: replace.
	Curation            json.RawMessage
	ExpectedFingerprint *string
}

// SetTeamSelection replaces a team gateway's selection (team owners and
// admins); expectedRevision is the gateway's.
func (s *Service) SetTeamSelection(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, items []SelectionInput, expectedRevision int64) (Selection, error) {
	var out Selection
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		g, err := teamGateway(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		out, err = setSelection(ctx, q, a, g, items, expectedRevision)
		return err
	})
	return out, err
}

// AdminSetSelection replaces a platform gateway's selection (platform
// admins; 403 team_gateway for a team gateway).
func (s *Service) AdminSetSelection(ctx context.Context, a authz.Actor, id uuid.UUID, items []SelectionInput, expectedRevision int64) (Selection, error) {
	if !a.IsPlatformAdmin() {
		return Selection{}, errAdminOnly
	}
	var out Selection
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		g, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		if g.OwnerKind != OwnerPlatform {
			return errTeamGateway
		}
		out, err = setSelection(ctx, q, a, g, items, expectedRevision)
		return err
	})
	return out, err
}

// Why a capability can't be selected (capability_not_selectable's
// details.reasons).
const (
	// NotSelectableUnsupportedTemplate: a resource template with RFC 6570
	// expressions other than {var} and {+var}.
	NotSelectableUnsupportedTemplate = "unsupported_template"
	// NotSelectableNotOffered: anything else gateway-options doesn't offer
	// (another team's private server, not approved, gone, unknown).
	NotSelectableNotOffered = "not_offered"
)

// notSelectable is 422 capability_not_selectable for refused, saying why
// for each (details.reasons).
func notSelectable(ctx context.Context, q *dbgen.Queries, refused []uuid.UUID) error {
	reasons := map[string]string{}
	msg := "Some capabilities can't be selected for this gateway: another team's private server, not approved, gone, or unknown"
	for _, id := range refused {
		reasons[id.String()] = NotSelectableNotOffered
		c, err := q.GetCapability(ctx, id)
		if err == nil && c.Kind == upstream.KindResourceTemplate && !TemplateSupported(c.Name) {
			reasons[id.String()] = NotSelectableUnsupportedTemplate
			msg = "Some capabilities can't be selected for this gateway. Resource templates may only use {var} and {+var} expressions"
		}
	}
	return unprocessable("capability_not_selectable", msg, map[string]any{"capabilityIds": refused, "reasons": reasons})
}

func unprocessable(code, msg string, details any) error {
	e := apperr.New(http.StatusUnprocessableEntity, code, msg)
	e.Details = details
	return e
}

// audited is a selection as the audit log records it.
func audited(items []Selected) []map[string]any {
	out := make([]map[string]any, len(items))
	for i, it := range items {
		m := map[string]any{"exposedName": it.ExposedName, "kind": it.Capability.Kind}
		if it.Curation != nil {
			m["curation"] = curation.Summary(it.Curation)
		}
		if it.MinRole != nil {
			m["minRole"] = *it.MinRole
		}
		out[i] = m
	}
	return out
}

// setSelection validates and stores a gateway's new selection (g is
// locked). New capabilities must be offered by the gateway's options;
// capabilities already selected may stay even when they aren't served right
// now (a catalog server that left the catalog), since every call re-checks
// them. minRole is for team gateways only, and exposed names and URIs must
// be distinct (case-insensitively, across every kind). Audited as
// gateway.capabilities_set.
func setSelection(ctx context.Context, q *dbgen.Queries, a authz.Actor, g dbgen.Gateway, items []SelectionInput, expectedRevision int64) (Selection, error) {
	if g.Revision != expectedRevision {
		return Selection{}, apperr.Stale()
	}
	if len(items) > MaxSelection {
		return Selection{}, unprocessable("too_many", "A gateway can select at most 200 capabilities", map[string]any{"max": MaxSelection})
	}
	before, err := selection(ctx, q, g)
	if err != nil {
		return Selection{}, err
	}
	current := make(map[uuid.UUID]Selected, len(before))
	for _, it := range before {
		current[it.Capability.ID] = it
	}
	seen := map[uuid.UUID]bool{}
	var added []uuid.UUID
	for _, it := range items {
		if seen[it.CapabilityID] {
			return Selection{}, apperr.Invalid("duplicate_capability", "Each capability can be selected once")
		}
		seen[it.CapabilityID] = true
		if it.MinRole != nil {
			if g.OwnerKind != OwnerTeam {
				return Selection{}, unprocessable("min_role_not_allowed", "Platform gateways have no minimum team role",
					map[string]any{"capabilityIds": []uuid.UUID{it.CapabilityID}})
			}
			if !authz.ValidTeamRole(*it.MinRole) {
				return Selection{}, apperr.Invalid("invalid_role", "minRole must be owner, admin, editor or member")
			}
		}
		if _, ok := current[it.CapabilityID]; !ok {
			added = append(added, it.CapabilityID)
		}
	}
	names := map[uuid.UUID]string{}
	kinds := map[uuid.UUID]string{}
	for id, it := range current {
		kinds[id] = it.Capability.Kind
		names[id] = Exposed(it.Capability.Kind, it.Server.Slug, it.Capability.Name)
	}
	if len(added) > 0 {
		offered, err := options(ctx, q, teamOf(g), OptionParams{}, added)
		if err != nil {
			return Selection{}, err
		}
		ok := map[uuid.UUID]bool{}
		for _, o := range offered {
			ok[o.ID], names[o.ID], kinds[o.ID] = true, o.ExposedName, o.Kind
		}
		refused := []uuid.UUID{}
		for _, id := range added {
			if !ok[id] {
				refused = append(refused, id)
			}
		}
		if len(refused) > 0 {
			return Selection{}, notSelectable(ctx, q, refused)
		}
	}
	policies, err := prepareCurations(ctx, q, a, items, current, names)
	if err != nil {
		return Selection{}, err
	}
	exposed := map[string]string{}
	keep := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		n := strings.ToLower(names[it.CapabilityID])
		if previous, clash := exposed[n]; clash {
			if previous == upstream.KindTool && kinds[it.CapabilityID] == upstream.KindTool {
				return Selection{}, apperr.Conflict("name_taken", "Two selected tools expose the same name")
			}
			return Selection{}, unprocessable("name_clash", "Two selected capabilities expose the same name or URI", map[string]any{"exposedName": names[it.CapabilityID]})
		}
		exposed[n] = kinds[it.CapabilityID]
		keep = append(keep, it.CapabilityID)
	}
	if err := q.RemoveGatewayCapabilitiesExcept(ctx, dbgen.RemoveGatewayCapabilitiesExceptParams{GatewayID: g.ID, Keep: keep}); err != nil {
		return Selection{}, err
	}
	for _, it := range items {
		if err := q.UpsertGatewayCapability(ctx, dbgen.UpsertGatewayCapabilityParams{
			GatewayID: g.ID, CapabilityID: it.CapabilityID, MinTeamRole: it.MinRole, AddedBy: by(a),
		}); err != nil {
			return Selection{}, err
		}
	}
	for id, p := range policies {
		p.GatewayID, p.CapabilityID = g.ID, id
		if err := q.SetGatewayCapabilityCuration(ctx, p); err != nil {
			return Selection{}, err
		}
	}
	row, err := q.BumpGatewayRevision(ctx, dbgen.BumpGatewayRevisionParams{ID: g.ID, UpdatedBy: by(a)})
	if err != nil {
		return Selection{}, err
	}
	after, err := selection(ctx, q, row)
	if err != nil {
		return Selection{}, err
	}
	e := a.Audit("gateway.capabilities_set", "gateway", g.ID.String())
	e.TeamID, e.Before, e.After = teamOf(g), map[string]any{"capabilities": audited(before)}, map[string]any{"capabilities": audited(after)}
	e.Metadata = map[string]any{"name": g.Name, "added": len(added), "removed": len(before) + len(added) - len(items), "count": len(items)}
	if err := audit.Record(ctx, q, e); err != nil {
		return Selection{}, err
	}
	return Selection{Revision: row.Revision, Items: after}, nil
}
