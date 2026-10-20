package providers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Server grants (F-3, decision 60): a person's connection to a platform
// provider is sent only to a server the person allowed to use it, at the
// origin (scheme, host, port) the server had when they allowed it, and for
// the scopes they were shown. A consent link is made for one server and
// origin, and can allow only that one. The registry deletes a server's
// grants when its origin or provider changes or it is deleted; a
// connection's disconnect, a provider's delete and a user's delete delete
// theirs by cascade. oauth-mode (server-bound) providers have no grants.

var (
	errServerChanged = apperr.New(http.StatusGone, "connect_request_server_changed",
		"The server's address or required account changed after this link was made. Run the tool again.")
	errConnectFirst = apperr.Conflict("connect_required",
		"Your account isn't connected with the access this server needs; continue to the provider first")
	errNotPlatform = apperr.Conflict("not_platform_provider", "This link is for an MCP server's own sign-in; there is nothing to allow")
)

// ServerGrant is a server a person allowed to use a connection.
type ServerGrant struct {
	Server      ServerRef
	Origin      string
	Scopes      []string
	ConsentedAt time.Time
}

func serverGrantOf(g dbgen.ListProviderServerGrantsForUserRow) ServerGrant {
	return ServerGrant{Server: ServerRef{ID: g.ServerID, Slug: g.ServerSlug, Name: g.ServerName, TeamSlug: g.TeamSlug, TeamName: g.TeamName},
		Origin: g.Origin, Scopes: nonNil(g.Scopes), ConsentedAt: g.ConsentedAt}
}

// requestServer is the server a platform provider's consent link was made
// for, as it is now. A link without one (made before the upgrade), for a
// server that is gone, that has moved to another origin or that no longer
// requires the provider can't be used (the person runs the tool again).
func requestServer(ctx context.Context, q *dbgen.Queries, r dbgen.ProviderConnectRequest) (dbgen.McpServer, error) {
	if !r.ServerID.Valid || r.ServerOrigin == nil {
		return dbgen.McpServer{}, errRequestExpired
	}
	sv, err := q.GetMCPServer(ctx, r.ServerID.UUID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return sv, errRequestExpired
	} else if err != nil {
		return sv, err
	}
	if registry.OriginOf(sv.URL) != *r.ServerOrigin || sv.AuthProviderID != (uuid.NullUUID{UUID: r.ProviderID, Valid: true}) {
		return sv, errServerChanged
	}
	return sv, nil
}

// recordGrant stores (or widens) the person's grant for a server on their
// connection, at the server's current origin: the scopes shown to them,
// added to those already allowed at the same origin. Audited as
// provider_connection.server_allow (no token).
func (s *Service) recordGrant(ctx context.Context, q *dbgen.Queries, a authz.Actor, u dbgen.User, p dbgen.AuthProvider,
	conn dbgen.ProviderConnection, sv dbgen.McpServer, scopes []string, viaRequest bool) (dbgen.ProviderServerGrant, error) {
	// A person cannot allow a server the provider's access list excludes
	// (decision 69); the check is here so every way of allowing one passes it.
	if ok, err := allowsServer(ctx, q, p.ID, sv.ID); err != nil {
		return dbgen.ProviderServerGrant{}, err
	} else if !ok {
		return dbgen.ProviderServerGrant{}, registry.ErrProviderNotAllowed
	}
	origin := registry.OriginOf(sv.URL)
	merged := nonNil(scopes)
	cur, err := q.LockProviderServerGrant(ctx, dbgen.LockProviderServerGrantParams{ConnectionID: conn.ID, ServerID: sv.ID})
	switch {
	case err == nil && cur.Origin == origin:
		merged = union(cur.Scopes, scopes)
	case err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound):
		return dbgen.ProviderServerGrant{}, err
	}
	g, err := q.UpsertProviderServerGrant(ctx, dbgen.UpsertProviderServerGrantParams{ConnectionID: conn.ID, ServerID: sv.ID, Origin: origin, Scopes: merged})
	if err != nil {
		return g, err
	}
	e := a.Audit("provider_connection.server_allow", "provider_connection", conn.ID.String())
	e.Metadata = map[string]any{"name": displayName(u) + " · " + p.Name, "provider": p.Slug, "userId": u.ID.String(), "serverId": sv.ID.String(),
		"server": sv.Name, "origin": origin, "scopes": merged, "viaRequest": viaRequest}
	return g, audit.Record(ctx, q, e)
}

// Confirmed is what allowing a server did.
type Confirmed struct {
	Provider ProviderRef
	Server   ServerRef
	Scopes   []string
}

// ConfirmRequest answers a consent link whose only missing piece is the
// server's grant: the person is connected with scopes that cover the link,
// so no round trip to the provider is made. The grant is recorded for the
// server (and origin) the link was made for, for the scopes it names, and
// the link is used up. Not connected, or scopes missing now: 409
// connect_required (the person goes to the provider). Another person's link
// is 404, an expired or used one 410, as for GetRequest.
func (s *Service) ConfirmRequest(ctx context.Context, a authz.Actor, id string) (Confirmed, error) {
	r, err := s.loadRequest(ctx, s.q, a.UserID, id)
	if err != nil {
		return Confirmed{}, err
	}
	p, err := getProvider(ctx, s.q, r.ProviderID, false)
	if err != nil {
		return Confirmed{}, err
	}
	if !p.Enabled {
		return Confirmed{}, errNoProvider
	}
	if p.Kind == KindMCPServer {
		return Confirmed{}, errNotPlatform
	}
	var out Confirmed
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		sv, err := requestServer(ctx, q, r)
		if err != nil {
			return err
		}
		c, err := q.LockProviderConnection(ctx, dbgen.LockProviderConnectionParams{UserID: a.UserID, ProviderID: p.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errConnectFirst
		} else if err != nil {
			return err
		}
		if c.Status != StatusActive || !Covers(c.Scopes, r.RequiredScopes) {
			return errConnectFirst
		}
		// Single use, also against a second tab answering at once.
		if n, err := q.MarkConnectRequestUsed(ctx, r.IDDigest); err != nil {
			return err
		} else if n == 0 {
			return errRequestExpired
		}
		u, err := q.GetUser(ctx, a.UserID)
		if err != nil {
			return err
		}
		g, err := s.recordGrant(ctx, q, a, u, p, c, sv, nonNil(r.RequiredScopes), true)
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

// Ready answers, for one person, whether a call of a capability would be
// forwarded with their token now (the "connected" mark of My gateways): an
// active connection covering the scopes and, for a platform provider, a
// grant for the capability's server at the origin its URL has now, and the
// provider's access list permits the server.
type Ready func(req *registry.Requirement, server dbgen.McpServer) bool

// ReadyFor loads what Ready needs for a person.
func (s *Service) ReadyFor(ctx context.Context, userID uuid.UUID) (Ready, error) {
	rows, err := s.q.ListProviderConnectionsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	grants, err := s.q.ListProviderServerGrantsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	ix, err := s.loadAccess(ctx)
	if err != nil {
		return nil, err
	}
	return func(req *registry.Requirement, server dbgen.McpServer) bool {
		if req == nil || !req.Provider.Enabled {
			return false
		}
		serverID, serverURL := server.ID, server.URL
		if !req.Provider.ServerBound() && !ix.allows(req.Provider.ID, server.TeamID, serverID) {
			return false
		}
		for _, r := range rows {
			c := r.ProviderConnection
			if c.ProviderID != req.Provider.ID || c.Status != StatusActive || !Covers(c.Scopes, req.Scopes) {
				continue
			}
			if req.Provider.ServerBound() {
				return true
			}
			for _, g := range grants {
				if g.ConnectionID == c.ID && g.ServerID == serverID && g.Origin == registry.OriginOf(serverURL) && Covers(g.Scopes, req.Scopes) {
					return true
				}
			}
		}
		return false
	}, nil
}
