package providers

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

var errNoServiceConnection = apperr.NotFound("connection_not_found", "Service connection not found")

// ServiceTokenAAD is deliberately disjoint from personal connection AAD.
func ServiceTokenAAD(id uuid.UUID, field string) []byte {
	return []byte("service_connection:" + id.String() + ":" + field)
}
func ServiceStateAAD(digest string) []byte { return []byte("service_connection_auth_state:" + digest) }
func (s *Service) serviceSeal(id uuid.UUID, field, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return s.box.Seal([]byte(value), ServiceTokenAAD(id, field))
}
func (s *Service) serviceOpen(id uuid.UUID, field string, value []byte) (string, error) {
	if len(value) == 0 {
		return "", nil
	}
	b, e := s.box.Open(value, ServiceTokenAAD(id, field))
	return string(b), e
}

// ServiceGrant is exactly the destination and scope set reviewed by the admin.
type ServiceGrant struct {
	ServerID uuid.UUID `json:"serverId"`
	Origin   string    `json:"origin"`
	Scopes   []string  `json:"scopes"`
}

// ServiceConnectionView never exposes ciphertexts or authentication state.
type ServiceConnectionView struct {
	ID           uuid.UUID      `json:"id"`
	TeamID       uuid.UUID      `json:"teamId"`
	ProviderID   uuid.UUID      `json:"providerId"`
	ProviderName string         `json:"providerName"`
	Name         string         `json:"name"`
	AccountLabel *string        `json:"accountLabel"`
	Status       string         `json:"status"`
	Scopes       []string       `json:"scopes"`
	Revision     int64          `json:"revision"`
	Accounts     []uuid.UUID    `json:"accounts"`
	Servers      []ServiceGrant `json:"servers"`
}

func serviceConflict(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return apperr.Conflict("connection_conflict", "This name or account/provider assignment is already in use")
	}
	return err
}
func serviceAccess(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string, write bool) (dbgen.Team, error) {
	if a.IsToken() {
		return dbgen.Team{}, apperr.Forbidden("Use a browser session")
	}
	t, err := teams.Resolve(ctx, q, ref)
	if err != nil {
		return t, err
	}
	role, err := teams.MemberRole(ctx, q, t.ID, a.UserID)
	if err != nil {
		return t, err
	}
	if role == "" {
		return t, apperr.NotFound("team_not_found", "Team not found")
	}
	if write {
		ok, err := q.ServiceConnectionAdminActive(ctx, dbgen.ServiceConnectionAdminActiveParams{UserID: a.UserID, TeamID: t.ID})
		if err != nil {
			return t, err
		}
		if !ok {
			return t, apperr.Forbidden("Only active team owners and admins can manage shared connections")
		}
	}
	return t, nil
}
func (s *Service) serviceView(ctx context.Context, q *dbgen.Queries, c dbgen.ServiceConnection) (ServiceConnectionView, error) {
	p, err := q.GetAuthProvider(ctx, c.ProviderID)
	if err != nil {
		return ServiceConnectionView{}, err
	}
	v := ServiceConnectionView{ID: c.ID, TeamID: c.TeamID, ProviderID: p.ID, ProviderName: p.Name, Name: c.Name, AccountLabel: c.AccountLabel, Status: c.Status, Scopes: nonNil(c.Scopes), Revision: c.Revision, Accounts: []uuid.UUID{}, Servers: []ServiceGrant{}}
	active := false
	if c.ConnectedBy.Valid {
		active, err = q.ServiceConnectionAdminActive(ctx, dbgen.ServiceConnectionAdminActiveParams{UserID: c.ConnectedBy.UUID, TeamID: c.TeamID})
		if err != nil {
			return v, err
		}
	}
	if !active {
		v.Status = "lapsed"
	}
	ids, err := q.ListServiceConnectionAccounts(ctx, c.ID)
	if err != nil {
		return v, err
	}
	if ids != nil {
		v.Accounts = ids
	}
	grants, err := q.ListServiceConnectionGrants(ctx, c.ID)
	if err != nil {
		return v, err
	}
	for _, g := range grants {
		v.Servers = append(v.Servers, ServiceGrant{ServerID: g.ServerID, Origin: g.Origin, Scopes: nonNil(g.Scopes)})
	}
	return v, nil
}
func (s *Service) ListServiceConnections(ctx context.Context, a authz.Actor, team string, after uuid.NullUUID, limit int32) ([]ServiceConnectionView, error) {
	var tid uuid.NullUUID
	if team != "" {
		t, e := serviceAccess(ctx, s.q, a, team, false)
		if e != nil {
			return nil, e
		}
		tid = uuid.NullUUID{UUID: t.ID, Valid: true}
	} else if a.IsToken() || !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if limit < 1 || limit > 201 {
		limit = 50
	}
	rows, e := s.q.ListServiceConnections(ctx, dbgen.ListServiceConnectionsParams{TeamID: tid, AfterID: after, PageSize: limit})
	if e != nil {
		return nil, e
	}
	out := make([]ServiceConnectionView, 0, len(rows))
	for _, c := range rows {
		v, e := s.serviceView(ctx, s.q, c)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func serviceAudit(ctx context.Context, q *dbgen.Queries, a authz.Actor, c dbgen.ServiceConnection, action string, metadata map[string]any) error {
	e := a.Audit("service_connection."+action, "service_connection", c.ID.String())
	e.TeamID = c.TeamID
	e.Metadata = metadata
	return audit.Record(ctx, q, e)
}
func serviceOwned(c dbgen.ServiceConnection, t dbgen.Team, err error) error {
	if errors.Is(err, pgx.ErrNoRows) || err == nil && c.TeamID != t.ID {
		return errNoServiceConnection
	}
	return err
}
func serviceRevision(c dbgen.ServiceConnection, rev int64) error {
	if c.Revision != rev {
		return apperr.New(http.StatusPreconditionFailed, "revision_mismatch", "Reload the connection and try again")
	}
	return nil
}

// UpdateServiceConnection replaces both lists in one audited transaction. DB
// uniqueness is authoritative even when two admins assign concurrently.
func (s *Service) UpdateServiceConnection(ctx context.Context, a authz.Actor, team string, id uuid.UUID, rev int64, accounts []uuid.UUID, grants []ServiceGrant) (ServiceConnectionView, error) {
	var out ServiceConnectionView
	if len(accounts) > 500 || len(grants) > 500 {
		return out, apperr.Invalid("invalid_assignment", "At most 500 accounts and servers")
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, e := serviceAccess(ctx, q, a, team, true)
		if e != nil {
			return e
		}
		c, e := q.GetServiceConnection(ctx, id)
		if e = serviceOwned(c, t, e); e != nil {
			return e
		}
		// Registry changes lock the server before invalidating its connection
		// configuration. Match that order, sorting destinations across edits.
		grants = slices.Clone(grants)
		slices.SortFunc(grants, func(a, b ServiceGrant) int { return strings.Compare(a.ServerID.String(), b.ServerID.String()) })
		for _, g := range grants {
			if _, e = q.LockMCPServer(ctx, g.ServerID); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apperr.NotFound("server_not_found", "Server not found")
				}
				return e
			}
		}
		c, e = q.LockServiceConnection(ctx, id)
		if e = serviceOwned(c, t, e); e != nil {
			return e
		}
		// All destination and connection waits precede authority and proof
		// reads. Never carry a pre-wait role, provider or scope snapshot into
		// this write (including when the connection, not the server, waited).
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		if e = serviceRevision(c, rev); e != nil {
			return e
		}
		before, e := s.serviceView(ctx, q, c)
		if e != nil {
			return e
		}
		if e = q.ClearServiceConnectionAccounts(ctx, id); e != nil {
			return e
		}
		for _, aid := range accounts {
			if _, e = q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: aid, TeamID: t.ID}); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return apperr.NotFound("service_account_not_found", "Service account not found")
				}
				return e
			}
			if e = q.InsertServiceConnectionAccount(ctx, dbgen.InsertServiceConnectionAccountParams{ConnectionID: id, TeamID: t.ID, ProviderID: c.ProviderID, ServiceAccountID: aid}); e != nil {
				return e
			}
		}
		if e = q.ClearServiceConnectionGrants(ctx, id); e != nil {
			return e
		}
		for _, g := range grants {
			if e = q.InsertServiceConnectionGrant(ctx, dbgen.InsertServiceConnectionGrantParams{ConnectionID: id, ServerID: g.ServerID, Origin: g.Origin, Scopes: nonNil(g.Scopes), GrantedBy: by(a)}); e != nil {
				return e
			}
		}
		c, e = q.AdvanceServiceConnection(ctx, id)
		if e != nil {
			return e
		}
		if e = q.DeleteServiceConnectionAuthStates(ctx, id); e != nil {
			return e
		}
		// Assignment uniqueness/FK checks may also have queued. A refusal
		// rolls back the entire replacement and its revision/state changes.
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		if e = serviceAudit(ctx, q, a, c, "update", map[string]any{"name": c.Name, "before": before, "accounts": accounts, "servers": grants}); e != nil {
			return e
		}
		// Even assignment and audit FK checks can wait. Validate the live
		// authority and destination proof after every potentially waiting
		// write, rolling back the replacement and audit together on refusal.
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		p, e := q.GetAuthProvider(ctx, c.ProviderID)
		if e != nil {
			return e
		}
		if len(grants) > 0 && (!p.Enabled || s.linkUsable(ctx, p) != nil) {
			return errNoProvider
		}
		for _, g := range grants {
			if e = s.validateServiceGrant(ctx, q, a, p, g); e != nil {
				return e
			}
		}
		out, e = s.serviceView(ctx, q, c)
		return e
	})
	return out, serviceConflict(err)
}

// validateServiceGrant is metadata-only. The caller must hold every sorted
// destination lock and the connection lock before any of these live reads.
func (s *Service) validateServiceGrant(ctx context.Context, q *dbgen.Queries, a authz.Actor, p dbgen.AuthProvider, g ServiceGrant) error {
	if s.Reachable == nil {
		return apperr.NotFound("server_not_found", "Server not found")
	}
	u, e := q.GetUser(ctx, a.UserID)
	if e != nil {
		return e
	}
	reachable, e := s.Reachable(ctx, u)
	if e != nil {
		return e
	}
	visible := false
	var required []string
	for _, r := range reachable {
		if r.Server.ID == g.ServerID {
			visible = true
			for _, n := range r.Needs {
				if n.Provider.ID == p.ID {
					required = union(required, n.Scopes)
				}
			}
		}
	}
	if !visible {
		return apperr.NotFound("server_not_found", "Server not found")
	}
	sv, e := q.GetMCPServer(ctx, g.ServerID)
	if e != nil {
		return e
	}
	if p.Kind == KindMCPServer {
		if !p.ServerID.Valid || p.ServerID.UUID != sv.ID {
			return apperr.NotFound("server_not_found", "Server not found")
		}
		required = p.DefaultScopes
	} else {
		ok, e := allowsServer(ctx, q, p.ID, sv.ID)
		if e != nil {
			return e
		}
		if !ok {
			return apperr.New(http.StatusUnprocessableEntity, "provider_not_allowed", "The destination server is not on the provider's access list")
		}
		if !sv.AuthProviderID.Valid || sv.AuthProviderID.UUID != p.ID {
			return apperr.Conflict("server_changed", "The server no longer requires this provider")
		}
	}
	scopes, e := normalizeScopes(g.Scopes)
	if e != nil {
		return e
	}
	if g.Origin != registry.OriginOf(sv.URL) || !Covers(scopes, required) || !Covers(required, scopes) {
		return apperr.Conflict("server_changed", "Review the current server origin and scopes")
	}
	return nil
}
func (s *Service) RevokeServiceConnection(ctx context.Context, a authz.Actor, team string, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, e := serviceAccess(ctx, q, a, team, true)
		if e != nil {
			return e
		}
		c, e := q.LockServiceConnection(ctx, id)
		if e = serviceOwned(c, t, e); e != nil {
			return e
		}
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		if e = q.DeleteServiceConnection(ctx, id); e != nil {
			return e
		}
		p, e := q.GetAuthProvider(ctx, c.ProviderID)
		if e != nil {
			return e
		}
		result := any(revokeNotSupported)
		if p.RevocationUrl != nil {
			token, _ := s.serviceOpen(c.ID, "refresh", c.RefreshTokenCipher)
			hint := "refresh_token"
			if token == "" {
				token, _ = s.serviceOpen(c.ID, "access", c.AccessTokenCipher)
				hint = "access_token"
			}
			result = token != "" && s.revoke(ctx, p, token, hint)
		}
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		if e = serviceAudit(ctx, q, a, c, "revoke", map[string]any{"name": c.Name, "providerRevoked": result}); e != nil {
			return e
		}
		_, e = serviceAccess(ctx, q, a, team, true)
		return e
	})
}
func serviceName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return "", apperr.Invalid("invalid_name", "Use a name of 1 to 100 characters")
	}
	return name, nil
}
