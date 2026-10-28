package providers

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

const (
	ServiceConnectionMissing        = "service_connection_missing"
	ServiceConnectionNotAllowed     = "service_connection_not_allowed"
	ServiceConnectionNeedsReconsent = "service_connection_needs_reconsent"
	ServiceConnectionLapsed         = "service_connection_lapsed"
)

// ServiceCredentialError is a link-free refusal. It never creates consent state.
type ServiceCredentialError struct{ Reason string }

func (e *ServiceCredentialError) Error() string { return "providers: " + e.Reason }
func serviceRefused(reason string) error        { return &ServiceCredentialError{Reason: reason} }

// ServiceCallContext names the genuine account and exact destination, not a
// relayed person. The account/team are reloaded, never trusted as authorization.
type ServiceCallContext struct {
	Account      dbgen.ServiceAccount
	Team         dbgen.Team
	ServerID     uuid.UUID
	ServerOrigin string
	ServerURL    string
}

func (s *Service) serviceAuthorized(ctx context.Context, q *dbgen.Queries, req *registry.Requirement, cc ServiceCallContext, c dbgen.ServiceConnection) (dbgen.AuthProvider, error) {
	p, e := q.GetAuthProvider(ctx, req.Provider.ID)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && !p.Enabled {
		return p, ErrProviderDisabled
	}
	if e != nil {
		return p, e
	}
	if s.linkUsable(ctx, p) != nil {
		return p, ErrProviderDisabled
	}
	sv, e := q.GetMCPServer(ctx, cc.ServerID)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return p, e
	}
	if !sv.Enabled || sv.TeamID != c.TeamID && sv.PublishState != "published" {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if cc.ServerOrigin == "" || cc.ServerOrigin != registry.OriginOf(sv.URL) || cc.ServerURL != sv.URL {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if p.Kind == KindMCPServer {
		if !p.ServerID.Valid || p.ServerID.UUID != sv.ID || sv.AuthMode != "oauth" || deref(p.Resource) != cc.ServerURL {
			return p, serviceRefused(ServiceConnectionNotAllowed)
		}
	} else {
		allowed, e := allowsServer(ctx, q, p.ID, sv.ID)
		if e != nil {
			return p, e
		}
		if !allowed {
			return p, ErrProviderNotAllowed
		}
		if !sv.AuthProviderID.Valid || sv.AuthProviderID.UUID != p.ID {
			return p, serviceRefused(ServiceConnectionNotAllowed)
		}
	}
	t, e := q.GetTeamByID(ctx, cc.Team.ID)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return p, e
	}
	if t.Status != "active" {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	account, e := q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: cc.Account.ID, TeamID: t.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return p, e
	}
	if !account.ServiceAccount.Enabled {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	assignment, e := q.GetServiceConnectionAssignment(ctx, dbgen.GetServiceConnectionAssignmentParams{ServiceAccountID: cc.Account.ID, ProviderID: p.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return p, serviceRefused(ServiceConnectionMissing)
	}
	if e != nil {
		return p, e
	}
	if c.ID != assignment || c.TeamID != t.ID || c.ProviderID != p.ID {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	active := false
	if c.ConnectedBy.Valid {
		active, e = q.ServiceConnectionAdminActive(ctx, dbgen.ServiceConnectionAdminActiveParams{UserID: c.ConnectedBy.UUID, TeamID: c.TeamID})
		if e != nil {
			return p, e
		}
	}
	if !active {
		return p, serviceRefused(ServiceConnectionLapsed)
	}
	if c.Status != StatusActive || !Covers(c.Scopes, req.Scopes) {
		return p, serviceRefused(ServiceConnectionNeedsReconsent)
	}
	g, e := q.GetServiceConnectionGrant(ctx, dbgen.GetServiceConnectionGrantParams{ConnectionID: c.ID, ServerID: sv.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	if e != nil {
		return p, e
	}
	if g.Origin != cc.ServerOrigin || !Covers(g.Scopes, req.Scopes) {
		return p, serviceRefused(ServiceConnectionNotAllowed)
	}
	return p, nil
}
func serviceNarrowKey(c dbgen.ServiceConnection, scopes []string) narrowKey {
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	return narrowKey{owner: "service", conn: c.ID, connected: c.Generation, scopes: strings.Join(sorted, " ")}
}
func (s *Service) serviceReconsent(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, c dbgen.ServiceConnection, reason string) error {
	if e := q.MarkServiceConnectionReconsent(ctx, dbgen.MarkServiceConnectionReconsentParams{ID: c.ID, LastErrorClass: &reason}); e != nil {
		return e
	}
	if n, ok := s.Notify.(interface {
		ServiceConnectionReconsent(context.Context, *dbgen.Queries, uuid.UUID, uuid.UUID, string, string, int64)
	}); ok {
		n.ServiceConnectionReconsent(ctx, q, c.ID, c.TeamID, p.Slug, p.Name, c.Generation)
	}
	return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, TeamID: c.TeamID, Action: "service_connection.refresh_failed", TargetType: "service_connection", TargetID: c.ID.String(), Metadata: map[string]any{"reason": reason, "provider": p.Slug}})
}

// ServiceCredential authorizes before every decryption/cache hit, after waiting
// for the cross-replica lock, and after refresh (including shrunken scopes).
func (s *Service) ServiceCredential(ctx context.Context, req *registry.Requirement, cc ServiceCallContext) (Credential, error) {
	return s.serviceCredential(ctx, req, cc, nil, false)
}

// ServiceUpstreamRejected pins retry to the original connection and generation.
func (s *Service) ServiceUpstreamRejected(ctx context.Context, req *registry.Requirement, cc ServiceCallContext, used Credential, mayRefresh bool) (Credential, error) {
	return s.serviceCredential(ctx, req, cc, &used, mayRefresh)
}
func (s *Service) serviceCredential(ctx context.Context, req *registry.Requirement, cc ServiceCallContext, used *Credential, mayRefresh bool) (Credential, error) {
	var out Credential
	var outcome error
	var pending *narrowEntry
	var key narrowKey
	// Check provider policy even when no assignment exists, preserving disabled
	// and access-list errors instead of concealing them as missing consent.
	p, e := s.q.GetAuthProvider(ctx, req.Provider.ID)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && !p.Enabled {
		return out, ErrProviderDisabled
	}
	if e != nil {
		return out, e
	}
	if s.linkUsable(ctx, p) != nil {
		return out, ErrProviderDisabled
	}
	if p.Kind != KindMCPServer {
		ok, e := allowsServer(ctx, s.q, p.ID, cc.ServerID)
		if e != nil {
			return out, e
		}
		if !ok {
			return out, ErrProviderNotAllowed
		}
	}
	id, e := s.q.GetServiceConnectionAssignment(ctx, dbgen.GetServiceConnectionAssignmentParams{ServiceAccountID: cc.Account.ID, ProviderID: p.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return out, serviceRefused(ServiceConnectionMissing)
	}
	if e != nil {
		return out, e
	}
	if used != nil && id != used.ServiceConnectionID {
		return out, serviceRefused(ServiceConnectionNotAllowed)
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		c, e := q.LockServiceConnection(ctx, id)
		if errors.Is(e, pgx.ErrNoRows) {
			outcome = serviceRefused(ServiceConnectionMissing)
			return nil
		}
		if e != nil {
			return e
		}
		if used != nil && c.Generation != used.ServiceGeneration {
			outcome = serviceRefused(ServiceConnectionNeedsReconsent)
			return nil
		}
		p, e = s.serviceAuthorized(ctx, q, req, cc, c)
		if e != nil {
			outcome = e
			return nil
		}
		narrowed := p.NarrowOnRefresh && p.Kind != KindMCPServer && len(c.RefreshTokenCipher) > 0 && len(req.Scopes) > 0
		key = serviceNarrowKey(c, req.Scopes)
		if narrowed && used == nil {
			if token, ok := s.narrow.get(key, s.now()); ok {
				out = serviceCredentialOf(p, c, token, true)
				return q.TouchServiceConnection(ctx, c.ID)
			}
		}
		refresh := narrowed || c.ExpiresAt != nil && c.ExpiresAt.Before(s.now().Add(RefreshAhead))
		if used != nil {
			current, e := s.serviceOpen(c.ID, "access", c.AccessTokenCipher)
			if e != nil {
				return e
			}
			if !mayRefresh {
				outcome = serviceRefused(ServiceConnectionNeedsReconsent)
				if current == used.AccessToken {
					return s.serviceReconsent(ctx, q, p, c, "upstream_rejected")
				}
				return nil
			}
			refresh = current == used.AccessToken
		}
		if refresh {
			rt, e := s.serviceOpen(c.ID, "refresh", c.RefreshTokenCipher)
			if e != nil || rt == "" {
				outcome = serviceRefused(ServiceConnectionNeedsReconsent)
				return s.serviceReconsent(ctx, q, p, c, "expired")
			}
			var tok tokenSet
			var ee *endpointError
			if narrowed {
				tok, ee = s.refreshScoped(ctx, p, rt, req.Scopes)
			} else {
				tok, ee = s.refresh(ctx, p, rt)
			}
			observeRefresh(p.Slug, endpointOutcome(ee))
			if ee != nil {
				if ee.Unavailable || narrowed && ee.Code == "invalid_scope" {
					outcome = &UnavailableError{Provider: registry.ProviderOf(p), Code: "refresh_failed"}
					return nil
				}
				outcome = serviceRefused(ServiceConnectionNeedsReconsent)
				return s.serviceReconsent(ctx, q, p, c, ee.Code)
			}
			access, e := s.serviceSeal(c.ID, "access", tok.Access)
			if e != nil {
				return e
			}
			rtct := c.RefreshTokenCipher
			if tok.Refresh != "" {
				rtct, e = s.serviceSeal(c.ID, "refresh", tok.Refresh)
				if e != nil {
					return e
				}
			}
			if narrowed {
				if e = q.RotateServiceConnectionRefresh(ctx, dbgen.RotateServiceConnectionRefreshParams{ID: c.ID, RefreshTokenCipher: rtct}); e != nil {
					return e
				}
				if tok.HasScope && !Covers(tok.Scopes, req.Scopes) {
					outcome = serviceRefused(ServiceConnectionNeedsReconsent)
					return nil
				}
				ttl := narrowNoExpiry
				if tok.ExpiresIn > 0 {
					ttl = time.Duration(tok.ExpiresIn)*time.Second - RefreshAhead
				}
				if ttl > 0 {
					pending = &narrowEntry{token: tok.Access, expires: s.now().Add(ttl)}
				}
				out = serviceCredentialOf(p, c, tok.Access, true)
			} else {
				scopes := c.Scopes
				if tok.HasScope {
					scopes = tok.Scopes
				}
				var expires *time.Time
				if tok.ExpiresIn > 0 {
					t := s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
					expires = &t
				}
				c, e = q.RefreshServiceConnectionTokens(ctx, dbgen.RefreshServiceConnectionTokensParams{ID: c.ID, Scopes: nonNil(scopes), AccessTokenCipher: access, RefreshTokenCipher: rtct, ExpiresAt: expires})
				if e != nil {
					return e
				}
			}
			// Live policy is checked again after the outbound exchange, before any
			// credential can escape and even when this request waited for a lock.
			if _, e = s.serviceAuthorized(ctx, q, req, cc, c); e != nil {
				pending = nil
				outcome = e
				return nil
			}
		}
		if out.AccessToken == "" {
			token, e := s.serviceOpen(c.ID, "access", c.AccessTokenCipher)
			if e != nil || token == "" {
				outcome = serviceRefused(ServiceConnectionNeedsReconsent)
				return s.serviceReconsent(ctx, q, p, c, "config")
			}
			out = serviceCredentialOf(p, c, token, false)
		}
		return q.TouchServiceConnection(ctx, c.ID)
	})
	if err != nil {
		return Credential{}, err
	}
	if outcome != nil {
		return Credential{}, outcome
	}
	// Never publish a token whose rotated refresh token failed to commit.
	if pending != nil {
		s.narrow.put(key, pending.token, pending.expires, s.now())
	}
	return out, nil
}
func serviceCredentialOf(p dbgen.AuthProvider, c dbgen.ServiceConnection, token string, narrowed bool) Credential {
	return Credential{Provider: registry.ProviderOf(p), AccessToken: token, Resource: deref(p.Resource), Refreshable: len(c.RefreshTokenCipher) > 0, Narrowed: narrowed, ServiceConnectionID: c.ID, ServiceGeneration: c.Generation}
}
