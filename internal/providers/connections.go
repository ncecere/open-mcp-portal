package providers

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Connections: one per person and provider (decision 29). Tokens are sealed
// and bound to the connection's ID and their kind. needs_reconsent erases
// them but keeps the row, scopes and label; disconnecting deletes the row
// and revokes the tokens at the provider where it can.

// Connection statuses.
const (
	StatusActive         = "active"
	StatusNeedsReconsent = "needs_reconsent"
)

var (
	errNoConnection = apperr.NotFound("connection_not_found", "Connection not found")
	errNoUser       = apperr.NotFound("user_not_found", "User not found")
)

// TokenAAD binds a sealed token to its connection and kind ("access" or
// "refresh").
func TokenAAD(connectionID uuid.UUID, kind string) []byte {
	return []byte("provider_connection:" + connectionID.String() + ":" + kind)
}

func (s *Service) seal(id uuid.UUID, kind, token string) ([]byte, error) {
	if token == "" {
		return nil, nil
	}
	return s.box.Seal([]byte(token), TokenAAD(id, kind))
}

func (s *Service) open(id uuid.UUID, kind string, ct []byte) (string, error) {
	if ct == nil {
		return "", nil
	}
	b, err := s.box.Open(ct, TokenAAD(id, kind))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ProviderRef names a connection's provider: a platform provider, or an
// MCP server's own sign-in (Kind mcp_server, Server set).
type ProviderRef struct {
	ID              uuid.UUID
	Slug, Name      string
	Preset, LogoURL *string
	Kind            string
	Server          *ServerRef
}

// ServerRef names the MCP server of a server-bound provider.
type ServerRef struct {
	ID                   uuid.UUID
	Slug, Name, TeamSlug string
	// TeamName is set where the team is shown by name (grants, consent).
	TeamName string
}

// Connection is a person's connection as listed: never a token.
type Connection struct {
	Connection dbgen.ProviderConnection
	Provider   ProviderRef
	// Servers are the MCP servers the person allowed to use this
	// connection (a platform provider's grants, F-3); none for a
	// server-bound provider, whose connection is for its server.
	Servers []ServerGrant
	// NarrowsScopes: calls get a token refreshed with only the scopes the
	// call needs, never this connection's stored token (decision 69). False
	// means the token a server receives holds every scope granted.
	NarrowsScopes bool
}

// Refreshable reports whether a refresh token is held.
func (c Connection) Refreshable() bool { return c.Connection.RefreshTokenCipher != nil }

func (s *Service) list(ctx context.Context, userID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListProviderConnectionsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	grants, err := s.q.ListProviderServerGrantsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = Connection{Connection: r.ProviderConnection, Provider: ProviderRef{ID: r.ProviderConnection.ProviderID,
			Slug: r.ProviderSlug, Name: r.ProviderName, Preset: r.ProviderPreset, LogoURL: r.ProviderLogoUrl, Kind: r.ProviderKind},
			Servers: []ServerGrant{}, NarrowsScopes: r.ProviderNarrows && r.ProviderKind != KindMCPServer && r.ProviderConnection.RefreshTokenCipher != nil}
		for _, g := range grants {
			if g.ConnectionID == r.ProviderConnection.ID {
				out[i].Servers = append(out[i].Servers, serverGrantOf(g))
			}
		}
		if r.ServerID.Valid {
			out[i].Provider.Server = &ServerRef{ID: r.ServerID.UUID, Slug: deref(r.ServerSlug), Name: deref(r.ServerName),
				TeamSlug: deref(r.ServerTeamSlug)}
		}
	}
	return out, nil
}

// ListMyConnections lists the caller's connections, by provider name.
func (s *Service) ListMyConnections(ctx context.Context, a authz.Actor) ([]Connection, error) {
	return s.list(ctx, a.UserID)
}

// AdminListConnections lists a person's connections (platform admins and auditors);
// 404 for an unknown person.
func (s *Service) AdminListConnections(ctx context.Context, a authz.Actor, userID uuid.UUID) ([]Connection, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if _, err := s.q.GetUser(ctx, userID); errors.Is(store.NotFound(err), store.ErrNotFound) {
		return nil, errNoUser
	} else if err != nil {
		return nil, err
	}
	return s.list(ctx, userID)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Covers reports whether granted includes every required scope.
func Covers(granted, required []string) bool {
	for _, r := range required {
		if !contains(granted, r) {
			return false
		}
	}
	return true
}

// Revocation results (providerRevoked in the audit).
const revokeNotSupported = "not_supported"

func revokeResult(p dbgen.AuthProvider, ok bool) any {
	if p.RevocationUrl == nil {
		return revokeNotSupported
	}
	return ok
}

// revokeAtProvider revokes a connection's tokens at the provider (best
// effort): the refresh token, else the access token. The result is true,
// false or "not_supported".
func (s *Service) revokeAtProvider(ctx context.Context, p dbgen.AuthProvider, c dbgen.ProviderConnection) any {
	if p.RevocationUrl == nil {
		return revokeNotSupported
	}
	token, hint := "", ""
	if rt, err := s.open(c.ID, "refresh", c.RefreshTokenCipher); err == nil && rt != "" {
		token, hint = rt, "refresh_token"
	} else if at, err := s.open(c.ID, "access", c.AccessTokenCipher); err == nil && at != "" {
		token, hint = at, "access_token"
	}
	if token == "" {
		return false
	}
	return s.revoke(ctx, p, token, hint)
}

// revokeAll revokes connections at the provider, four at a time and at most
// a minute in all; unfinished ones count as not revoked.
func (s *Service) revokeAll(ctx context.Context, p dbgen.AuthProvider, conns []dbgen.ProviderConnection) map[uuid.UUID]any {
	out := map[uuid.UUID]any{}
	if p.RevocationUrl == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	var mu sync.Mutex
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, c := range conns {
		if c.AccessTokenCipher == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c dbgen.ProviderConnection) {
			defer func() { <-sem; wg.Done() }()
			r := s.revokeAtProvider(ctx, p, c)
			mu.Lock()
			out[c.ID] = r
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return out
}

// RevokeMine disconnects one of the caller's accounts (reason user).
func (s *Service) RevokeMine(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	return s.disconnect(ctx, a, a.UserID, id, "user")
}

// AdminRevoke disconnects a person's account (platform admins; reason
// admin).
func (s *Service) AdminRevoke(ctx context.Context, a authz.Actor, userID, id uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return s.disconnect(ctx, a, userID, id, "admin")
}

// disconnect erases a connection's tokens and deletes it, then revokes the
// tokens at the provider (best effort, within the transaction so the audit
// records the result). Audited as provider_connection.revoke.
func (s *Service) disconnect(ctx context.Context, a authz.Actor, userID, id uuid.UUID, reason string) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		c, err := q.LockProviderConnectionByID(ctx, id)
		if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && c.UserID != userID) {
			return errNoConnection
		} else if err != nil {
			return err
		}
		p, err := q.GetAuthProvider(ctx, c.ProviderID)
		if err != nil {
			return err
		}
		u, err := q.GetUser(ctx, c.UserID)
		if err != nil {
			return err
		}
		if err := q.DeleteProviderConnection(ctx, id); err != nil {
			return err
		}
		result := any(false)
		if c.AccessTokenCipher != nil {
			result = s.revokeAtProvider(ctx, p, c)
		} else if p.RevocationUrl == nil {
			result = revokeNotSupported
		}
		e := a.Audit("provider_connection.revoke", "provider_connection", id.String())
		e.Before = connectionSnapshot(c)
		e.Metadata = map[string]any{"name": displayName(u) + " · " + p.Name, "reason": reason, "providerRevoked": result,
			"userId": c.UserID.String(), "provider": p.Slug}
		return audit.Record(ctx, q, e)
	})
}
