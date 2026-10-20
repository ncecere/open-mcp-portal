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
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Allowing a server from My connections (decision 68, issue #60): the same
// grant the consent link's confirm step records, without a link. An agent's
// call never returns one (decision 66), so the person allows the server
// here, before or after the agent asks. The server must be one the person
// may use through a gateway now (gateways.ReachableServers, the rule calls
// use), must require this connection's provider, and the connection must
// already cover what it asks; the grant is bound to the server's current
// origin and the scopes the server's capabilities require, and the request
// names the origin and scopes the person was shown, so a server that moved
// or asks for more since the list was loaded is refused.

var (
	errServerNotFound = apperr.NotFound("server_not_found", "That server isn't one you can use, or it doesn't exist")
	errNotRequired    = apperr.New(http.StatusUnprocessableEntity, "server_does_not_require_provider",
		"That server doesn't require this account")
	errAllowChanged = apperr.Conflict("server_changed",
		"The server's address or the access it needs changed since this list was loaded. Reload and review it again.")
	errAllowShown = apperr.New(http.StatusBadRequest, "invalid_allow",
		"Send the server's ID with the address and scopes you were shown")
)

// Allowable is a server a person may allow to use a connection: it requires
// the connection's provider and is visible to the person.
type Allowable struct {
	Server ServerRef
	// Origin is the server's origin now: what an allowance is bound to.
	Origin string
	// Scopes are what the server's capabilities, as the person may use
	// them, ask of the account.
	Scopes []string
	// Covered: the connection is active and has all of Scopes, so allowing
	// needs no round trip to the provider.
	Covered bool
	// Allowed: already allowed at this origin for these scopes.
	Allowed bool
}

// platformConnection loads one of the caller's connections to a platform
// provider.
func (s *Service) platformConnection(ctx context.Context, q *dbgen.Queries, userID, id uuid.UUID) (dbgen.ProviderConnection, dbgen.AuthProvider, error) {
	c, err := q.GetProviderConnectionByID(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && c.UserID != userID) {
		return c, dbgen.AuthProvider{}, errNoConnection
	} else if err != nil {
		return c, dbgen.AuthProvider{}, err
	}
	p, err := getProvider(ctx, q, c.ProviderID, false)
	if err != nil {
		return c, p, err
	}
	if p.Kind == KindMCPServer {
		return c, p, errNotPlatform
	}
	if !p.Enabled {
		return c, p, errNoProvider
	}
	return c, p, nil
}

// ListAllowable lists the servers the caller may allow to use one of their
// connections (404 connection_not_found for another person's), by server
// name. Servers already allowed at their current origin for all they ask
// are included, marked Allowed.
func (s *Service) ListAllowable(ctx context.Context, a authz.Actor, connectionID uuid.UUID) ([]Allowable, error) {
	if s.Reachable == nil {
		return []Allowable{}, nil
	}
	c, p, err := s.platformConnection(ctx, s.q, a.UserID, connectionID)
	if err != nil {
		return nil, err
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return nil, err
	}
	reach, err := s.Reachable(ctx, u)
	if err != nil {
		return nil, err
	}
	grants, err := s.q.ListProviderServerGrantsForUser(ctx, a.UserID)
	if err != nil {
		return nil, err
	}
	ix, err := s.loadAccess(ctx)
	if err != nil {
		return nil, err
	}
	out := []Allowable{}
	for _, r := range reach {
		i := slices.IndexFunc(r.Needs, func(n gateways.ProviderNeed) bool { return n.Provider.ID == p.ID })
		if i < 0 || !ix.allows(p.ID, r.Server.TeamID, r.Server.ID) {
			// Not a server of this account's provider, or one the provider's
			// access list excludes: it could not receive the token, so it
			// is not offered (decision 69).
			continue
		}
		scopes, origin := nonNil(r.Needs[i].Scopes), registry.OriginOf(r.Server.URL)
		al := Allowable{Server: ServerRef{ID: r.Server.ID, Slug: r.Server.Slug, Name: r.Server.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName},
			Origin: origin, Scopes: scopes, Covered: c.Status == StatusActive && Covers(c.Scopes, scopes)}
		for _, g := range grants {
			if g.ConnectionID == c.ID && g.ServerID == r.Server.ID && g.Origin == origin && Covers(g.Scopes, scopes) {
				al.Allowed = true
			}
		}
		out = append(out, al)
	}
	return out, nil
}

// AllowInput is what the person was shown and agreed to.
type AllowInput struct {
	ServerID uuid.UUID
	// Origin and Scopes are the server's origin and the scopes it asked for,
	// as the list showed them.
	Origin string
	Scopes []string
}

// AllowServer records the grant for a server on one of the caller's
// connections, as ConfirmRequest does for a link. Refusals: 404
// connection_not_found (another person's), 404 server_not_found (no such
// server, or one the person may not use), 422 server_does_not_require_provider,
// 409 connect_required (the connection isn't active or lacks the server's
// scopes: the details name them, for the provider round trip), 409
// server_changed (the origin or scopes differ from what was shown).
func (s *Service) AllowServer(ctx context.Context, a authz.Actor, connectionID uuid.UUID, in AllowInput) (Confirmed, error) {
	if in.Origin == "" {
		return Confirmed{}, errAllowShown
	}
	c, p, err := s.platformConnection(ctx, s.q, a.UserID, connectionID)
	if err != nil {
		return Confirmed{}, err
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return Confirmed{}, err
	}
	var reach []gateways.ReachableServer
	if s.Reachable != nil {
		if reach, err = s.Reachable(ctx, u); err != nil {
			return Confirmed{}, err
		}
	}
	// Not visible and not existing answer the same.
	ri := slices.IndexFunc(reach, func(r gateways.ReachableServer) bool { return r.Server.ID == in.ServerID })
	if ri < 0 {
		return Confirmed{}, errServerNotFound
	}
	need := slices.IndexFunc(reach[ri].Needs, func(n gateways.ProviderNeed) bool { return n.Provider.ID == p.ID })
	if need < 0 {
		return Confirmed{}, errNotRequired
	}
	if ok, err := allowsServer(ctx, s.q, p.ID, in.ServerID); err != nil {
		return Confirmed{}, err
	} else if !ok {
		return Confirmed{}, registry.ErrProviderNotAllowed
	}
	required := nonNil(reach[ri].Needs[need].Scopes)
	if registry.OriginOf(reach[ri].Server.URL) != in.Origin || !Covers(in.Scopes, required) {
		return Confirmed{}, errAllowChanged
	}
	var out Confirmed
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// The server's row is locked, so an edit of its address or provider
		// (which deletes its grants) is before or after this, never between.
		sv, err := q.LockMCPServer(ctx, in.ServerID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errServerNotFound
		} else if err != nil {
			return err
		}
		if registry.OriginOf(sv.URL) != in.Origin {
			return errAllowChanged
		}
		if sv.AuthProviderID != (uuid.NullUUID{UUID: p.ID, Valid: true}) {
			return errAllowChanged
		}
		conn, err := q.LockProviderConnectionByID(ctx, c.ID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoConnection
		} else if err != nil {
			return err
		}
		if conn.Status != StatusActive || !Covers(conn.Scopes, required) {
			e := *errConnectFirst
			e.Details = map[string]any{"providerId": p.ID.String(), "scopes": required}
			return &e
		}
		g, err := s.recordGrant(ctx, q, a, u, p, conn, sv, required, false)
		if err != nil {
			return err
		}
		ref, err := s.refOf(ctx, q, p)
		if err != nil {
			return err
		}
		sr, err := q.GetServerRef(ctx, sv.ID)
		if err != nil {
			return err
		}
		out = Confirmed{Provider: ref, Scopes: nonNil(g.Scopes),
			Server: ServerRef{ID: sr.ID, Slug: sr.Slug, Name: sr.Name, TeamSlug: sr.TeamSlug, TeamName: sr.TeamName}}
		return nil
	})
	return out, err
}

// RevokeServer takes back the caller's allowance of one server on one of
// their connections (404 connection_not_found for another person's, 404
// server_grant_not_found when there is none). The connection stays; the next call
// of that server gets server_not_allowed again. Audited as
// provider_connection.server_revoke.
func (s *Service) RevokeServer(ctx context.Context, a authz.Actor, connectionID, serverID uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		c, err := q.LockProviderConnectionByID(ctx, connectionID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && c.UserID != a.UserID) {
			return errNoConnection
		} else if err != nil {
			return err
		}
		g, err := q.LockProviderServerGrant(ctx, dbgen.LockProviderServerGrantParams{ConnectionID: c.ID, ServerID: serverID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoGrant
		} else if err != nil {
			return err
		}
		if _, err := q.DeleteProviderServerGrant(ctx, dbgen.DeleteProviderServerGrantParams{ConnectionID: c.ID, ServerID: serverID}); err != nil {
			return err
		}
		p, err := q.GetAuthProvider(ctx, c.ProviderID)
		if err != nil {
			return err
		}
		u, err := q.GetUser(ctx, a.UserID)
		if err != nil {
			return err
		}
		sr, err := q.GetServerRef(ctx, serverID)
		if err != nil {
			return err
		}
		e := a.Audit("provider_connection.server_revoke", "provider_connection", c.ID.String())
		e.Metadata = map[string]any{"name": displayName(u) + " · " + p.Name, "provider": p.Slug, "userId": u.ID.String(),
			"serverId": serverID.String(), "server": sr.Name, "origin": g.Origin, "scopes": nonNil(g.Scopes)}
		return audit.Record(ctx, q, e)
	})
}

var errNoGrant = apperr.NotFound("server_grant_not_found", "That server isn't allowed to use this account")
