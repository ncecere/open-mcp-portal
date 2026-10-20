package providers

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The per-provider access list (decision 69, issue #27, threat model H-5):
// a platform admin restricts a platform provider to named teams and
// servers. An open provider (every provider that existed before the list,
// and any an admin opens) may be required by any team's server, as before.
// A restricted one may be required only by a server of a listed team or a
// listed server, and a new provider starts restricted with an empty list,
// so nobody may use it until an admin says who.
//
// It is checked when a requirement is saved (registry.checkRequirement),
// when a person allows a server to use their account (a consent link, My
// connections), and on every call (Service.Credential), so removing a team
// stops delivery on the next call, for an agent's relayed call too. A
// server-bound provider (kind mcp_server, an oauth server's own sign-in)
// has no list.

// Access modes (auth_providers.access_mode).
const (
	AccessOpen       = "open"
	AccessRestricted = "restricted"
)

// MaxAccessEntries bounds the teams, and the servers, a list may name.
const MaxAccessEntries = 500

// ErrProviderNotAllowed: the provider is restricted and neither the
// server's team nor the server is on its list: the call is refused.
var ErrProviderNotAllowed = errors.New("providers: the auth provider is not open to this server")

var (
	errAccessMode  = apperr.Invalid("invalid_access_mode", "accessMode must be open or restricted")
	errAccessTeams = apperr.New(http.StatusUnprocessableEntity, "team_not_found", "A listed team doesn't exist")
	errAccessSrv   = apperr.New(http.StatusUnprocessableEntity, "server_not_found", "A listed server doesn't exist")
	errAccessMany  = apperr.New(http.StatusUnprocessableEntity, "too_many_entries", "A list names at most 500 teams and 500 servers")
)

// AccessTeam is a team on a provider's list.
type AccessTeam struct {
	ID         uuid.UUID
	Slug, Name string
}

// Access is a provider's access list: the mode, who is listed, and the
// servers that require the provider but are not permitted now (their calls
// are refused).
type Access struct {
	Provider dbgen.AuthProvider
	Mode     string
	Teams    []AccessTeam
	Servers  []ServerRef
	// Blocked lists up to 20 servers (BlockedCount in all) that require the
	// provider though the list excludes them.
	Blocked      []ServerRef
	BlockedCount int64
}

// AccessInput replaces a provider's access list.
type AccessInput struct {
	Mode               string
	TeamIDs, ServerIDs []uuid.UUID
}

func (s *Service) access(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider) (Access, error) {
	teams, err := q.ListAuthProviderTeams(ctx, p.ID)
	if err != nil {
		return Access{}, err
	}
	servers, err := q.ListAuthProviderServers(ctx, p.ID)
	if err != nil {
		return Access{}, err
	}
	out := Access{Provider: p, Mode: p.AccessMode, Teams: make([]AccessTeam, len(teams)), Servers: make([]ServerRef, len(servers)),
		Blocked: []ServerRef{}}
	for i, t := range teams {
		out.Teams[i] = AccessTeam{ID: t.TeamID, Slug: t.TeamSlug, Name: t.TeamName}
	}
	for i, sv := range servers {
		out.Servers[i] = ServerRef{ID: sv.ServerID, Slug: sv.ServerSlug, Name: sv.ServerName, TeamSlug: sv.TeamSlug, TeamName: sv.TeamName}
	}
	blocked, err := q.ServersOutsideProviderAccess(ctx, dbgen.ServersOutsideProviderAccessParams{ProviderID: p.ID, PageSize: 1000})
	if err != nil {
		return Access{}, err
	}
	out.BlockedCount = int64(len(blocked))
	for i, b := range blocked {
		if i == 20 {
			break
		}
		out.Blocked = append(out.Blocked, ServerRef{ID: b.ID, Slug: b.Slug, Name: b.Name, TeamSlug: b.TeamSlug})
	}
	return out, nil
}

// AdminAccess returns a provider's access list (platform admins and
// auditors).
func (s *Service) AdminAccess(ctx context.Context, a authz.Actor, id uuid.UUID) (Access, error) {
	if !a.CanReadPlatform() {
		return Access{}, errPlatformRead
	}
	p, err := getPlatformProvider(ctx, s.q, id, false)
	if err != nil {
		return Access{}, err
	}
	return s.access(ctx, s.q, p)
}

func accessSnapshot(ac Access) map[string]any {
	teams := make([]map[string]any, len(ac.Teams))
	for i, t := range ac.Teams {
		teams[i] = map[string]any{"id": t.ID.String(), "slug": t.Slug, "name": t.Name}
	}
	servers := make([]map[string]any, len(ac.Servers))
	for i, sv := range ac.Servers {
		servers[i] = map[string]any{"id": sv.ID.String(), "slug": sv.Slug, "name": sv.Name, "teamSlug": sv.TeamSlug}
	}
	return map[string]any{"accessMode": ac.Mode, "teams": teams, "servers": servers}
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// SetAccess replaces a provider's access list (platform admins; a browser
// session only, decision 58). The provider's revision must match and moves.
// 422 team_not_found or server_not_found for an ID that doesn't exist.
// Audited as auth_provider.access_update with the list before and after
// (metadata.blockedServers: servers that require the provider and are
// excluded now).
func (s *Service) SetAccess(ctx context.Context, a authz.Actor, id uuid.UUID, in AccessInput, expectedRevision int64) (Access, error) {
	if !a.IsPlatformAdmin() {
		return Access{}, errAdminOnly
	}
	if in.Mode != AccessOpen && in.Mode != AccessRestricted {
		return Access{}, errAccessMode
	}
	teams, servers := dedupe(in.TeamIDs), dedupe(in.ServerIDs)
	if len(teams) > MaxAccessEntries || len(servers) > MaxAccessEntries {
		return Access{}, errAccessMany
	}
	var out Access
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := getPlatformProvider(ctx, q, id, true)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		if n, err := q.CountExistingTeams(ctx, teams); err != nil {
			return err
		} else if n != int64(len(teams)) {
			return errAccessTeams
		}
		if n, err := q.CountExistingServers(ctx, servers); err != nil {
			return err
		} else if n != int64(len(servers)) {
			return errAccessSrv
		}
		before, err := s.access(ctx, q, cur)
		if err != nil {
			return err
		}
		row, err := q.SetAuthProviderAccessMode(ctx, dbgen.SetAuthProviderAccessModeParams{ID: id, AccessMode: in.Mode, UpdatedBy: by(a)})
		if err != nil {
			return err
		}
		if err := q.ClearAuthProviderTeams(ctx, id); err != nil {
			return err
		}
		if err := q.ClearAuthProviderServers(ctx, id); err != nil {
			return err
		}
		if err := q.AddAuthProviderTeams(ctx, dbgen.AddAuthProviderTeamsParams{ProviderID: id, TeamIds: teams, AddedBy: by(a)}); err != nil {
			return err
		}
		if err := q.AddAuthProviderServers(ctx, dbgen.AddAuthProviderServersParams{ProviderID: id, ServerIds: servers, AddedBy: by(a)}); err != nil {
			return err
		}
		if out, err = s.access(ctx, q, row); err != nil {
			return err
		}
		e := a.Audit("auth_provider.access_update", "auth_provider", id.String())
		e.Before, e.After = accessSnapshot(before), accessSnapshot(out)
		e.Metadata = map[string]any{"name": row.Name, "blockedServers": out.BlockedCount}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// allowsServer reports whether the provider's access list permits the
// server (its team or itself): an open provider permits every server.
func allowsServer(ctx context.Context, q *dbgen.Queries, providerID, serverID uuid.UUID) (bool, error) {
	ok, err := q.ProviderAllowsServer(ctx, dbgen.ProviderAllowsServerParams{ProviderID: providerID, ServerID: serverID})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return false, nil
	}
	return ok, err
}

// accessIndex is every restricted provider's list, read once for a
// listing: providers absent from restricted are open.
type accessIndex struct {
	restricted map[uuid.UUID]bool
	entries    map[uuid.UUID]map[uuid.UUID]bool // provider -> team or server IDs
}

func (s *Service) loadAccess(ctx context.Context) (*accessIndex, error) {
	rows, err := s.q.ListProviderAccessEntries(ctx)
	if err != nil {
		return nil, err
	}
	ix := &accessIndex{restricted: map[uuid.UUID]bool{}, entries: map[uuid.UUID]map[uuid.UUID]bool{}}
	for _, r := range rows {
		ix.restricted[r.ProviderID] = true
		if r.Kind == "restricted" {
			continue
		}
		if ix.entries[r.ProviderID] == nil {
			ix.entries[r.ProviderID] = map[uuid.UUID]bool{}
		}
		ix.entries[r.ProviderID][r.TargetID] = true
	}
	return ix, nil
}

// allows reports whether the provider's list permits a server of team.
func (ix *accessIndex) allows(providerID, teamID, serverID uuid.UUID) bool {
	if !ix.restricted[providerID] {
		return true
	}
	return ix.entries[providerID][teamID] || ix.entries[providerID][serverID]
}

// Pickable lists the enabled platform providers a server of the team may
// require (open ones, and restricted ones that list the team, or serverID
// when it is not uuid.Nil), by name: the requirement picker. It is a
// convenience: the save and every call check again.
func (s *Service) Pickable(ctx context.Context, teamID, serverID uuid.UUID) ([]registry.Provider, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	ix, err := s.loadAccess(ctx)
	if err != nil {
		return nil, err
	}
	if serverID != uuid.Nil {
		// A server of another team counts for nothing here.
		if sv, err := s.q.GetMCPServer(ctx, serverID); err != nil || sv.TeamID != teamID {
			serverID = uuid.Nil
		}
	}
	out := make([]registry.Provider, 0, len(all))
	for _, p := range all {
		if ix.allows(p.ID, teamID, serverID) {
			out = append(out, p)
		}
	}
	return out, nil
}
