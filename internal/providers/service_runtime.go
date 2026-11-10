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

// Policy refusals may commit a completed refresh rotation while withholding
// the credential. Database failures must instead abort the transaction.
func servicePolicyRefusal(err error) bool {
	var refused *ServiceCredentialError
	return errors.Is(err, ErrProviderDisabled) || errors.Is(err, ErrProviderNotAllowed) || errors.As(err, &refused)
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

// serviceIssue is one serviceCredential call: what was asked, and what the
// transaction holding the connection's row lock decided. A step that sets
// outcome ends the transaction body: the transaction still commits (a completed
// refresh rotation, a reconsent mark) and the credential is withheld.
type serviceIssue struct {
	req        *registry.Requirement
	cc         ServiceCallContext
	used       *Credential // the credential the upstream rejected (nil: a first call)
	mayRefresh bool

	out     Credential
	outcome error
	pending *narrowEntry // a narrowed token to cache once the transaction commits
	key     narrowKey
}

// policyOutcome records a policy refusal as the outcome and lets the
// transaction commit; any other error is returned to abort it.
func (r *serviceIssue) policyOutcome(e error) error {
	if !servicePolicyRefusal(e) {
		return e
	}
	r.outcome = e
	return nil
}

func (s *Service) serviceCredential(ctx context.Context, req *registry.Requirement, cc ServiceCallContext, used *Credential, mayRefresh bool) (Credential, error) {
	id, e := s.serviceAssignment(ctx, req, cc, used)
	if e != nil {
		return Credential{}, e
	}
	r := &serviceIssue{req: req, cc: cc, used: used, mayRefresh: mayRefresh}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		return s.serviceIssueLocked(ctx, q, id, r)
	})
	if err != nil {
		return Credential{}, err
	}
	if r.outcome != nil {
		return Credential{}, r.outcome
	}
	// Never publish a token whose rotated refresh token failed to commit.
	if r.pending != nil {
		s.narrow.put(r.key, r.pending.token, r.pending.expires, s.now())
	}
	return r.out, nil
}

// serviceAssignment names the account's assigned connection for the provider,
// before any transaction.
func (s *Service) serviceAssignment(ctx context.Context, req *registry.Requirement, cc ServiceCallContext, used *Credential) (uuid.UUID, error) {
	// Check provider policy even when no assignment exists, preserving disabled
	// and access-list errors instead of concealing them as missing consent.
	p, e := s.q.GetAuthProvider(ctx, req.Provider.ID)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && !p.Enabled {
		return uuid.Nil, ErrProviderDisabled
	}
	if e != nil {
		return uuid.Nil, e
	}
	if s.linkUsable(ctx, p) != nil {
		return uuid.Nil, ErrProviderDisabled
	}
	if p.Kind != KindMCPServer {
		ok, e := allowsServer(ctx, s.q, p.ID, cc.ServerID)
		if e != nil {
			return uuid.Nil, e
		}
		if !ok {
			return uuid.Nil, ErrProviderNotAllowed
		}
	}
	id, e := s.q.GetServiceConnectionAssignment(ctx, dbgen.GetServiceConnectionAssignmentParams{ServiceAccountID: cc.Account.ID, ProviderID: p.ID})
	if errors.Is(e, pgx.ErrNoRows) {
		return uuid.Nil, serviceRefused(ServiceConnectionMissing)
	}
	if e != nil {
		return uuid.Nil, e
	}
	if used != nil && id != used.ServiceConnectionID {
		return uuid.Nil, serviceRefused(ServiceConnectionNotAllowed)
	}
	return id, nil
}

// serviceIssueLocked is the transaction body of serviceCredential: it locks
// the connection, authorizes, refreshes when needed (inside this transaction,
// under the row lock) and leaves the credential in r.out or a refusal in
// r.outcome.
func (s *Service) serviceIssueLocked(ctx context.Context, q *dbgen.Queries, id uuid.UUID, r *serviceIssue) error {
	c, e := q.LockServiceConnection(ctx, id)
	if errors.Is(e, pgx.ErrNoRows) {
		r.outcome = serviceRefused(ServiceConnectionMissing)
		return nil
	}
	if e != nil {
		return e
	}
	if r.used != nil && c.Generation != r.used.ServiceGeneration {
		r.outcome = serviceRefused(ServiceConnectionNeedsReconsent)
		return nil
	}
	p, e := s.serviceAuthorized(ctx, q, r.req, r.cc, c)
	if e != nil {
		return r.policyOutcome(e)
	}
	narrowed := p.NarrowOnRefresh && p.Kind != KindMCPServer && len(c.RefreshTokenCipher) > 0 && len(r.req.Scopes) > 0
	r.key = serviceNarrowKey(c, r.req.Scopes)
	if narrowed && r.used == nil {
		if token, ok := s.narrow.get(r.key, s.now()); ok {
			r.out = serviceCredentialOf(p, c, token, true)
			return q.TouchServiceConnection(ctx, c.ID)
		}
	}
	refresh := narrowed || c.ExpiresAt != nil && c.ExpiresAt.Before(s.now().Add(RefreshAhead))
	if r.used != nil {
		refresh, e = s.serviceRejectedRefresh(ctx, q, p, c, r)
		if e != nil || r.outcome != nil {
			return e
		}
	}
	if refresh {
		c, e = s.serviceRefresh(ctx, q, p, c, narrowed, r)
		if e != nil || r.outcome != nil {
			return e
		}
	}
	if r.out.AccessToken == "" {
		token, e := s.serviceOpen(c.ID, "access", c.AccessTokenCipher)
		if e != nil || token == "" {
			r.outcome = serviceRefused(ServiceConnectionNeedsReconsent)
			return s.serviceReconsent(ctx, q, p, c, "config")
		}
		r.out = serviceCredentialOf(p, c, token, false)
	}
	return q.TouchServiceConnection(ctx, c.ID)
}

// serviceRejectedRefresh decides what follows the upstream rejecting r.used:
// a refresh only when it is allowed and the stored access token is still the
// rejected one (otherwise another call already replaced it). When a refresh is
// not allowed it refuses, marking the connection for reconsent if the rejected
// token is still the stored one.
func (s *Service) serviceRejectedRefresh(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, c dbgen.ServiceConnection, r *serviceIssue) (bool, error) {
	current, e := s.serviceOpen(c.ID, "access", c.AccessTokenCipher)
	if e != nil {
		return false, e
	}
	if !r.mayRefresh {
		r.outcome = serviceRefused(ServiceConnectionNeedsReconsent)
		if current == r.used.AccessToken {
			return false, s.serviceReconsent(ctx, q, p, c, "upstream_rejected")
		}
		return false, nil
	}
	return current == r.used.AccessToken, nil
}

// serviceRefresh exchanges the refresh token inside the caller's transaction,
// stores the result, authorizes again and returns the connection as it now is.
// A narrowed exchange leaves its token in r.out and r.pending.
func (s *Service) serviceRefresh(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, c dbgen.ServiceConnection, narrowed bool, r *serviceIssue) (dbgen.ServiceConnection, error) {
	rt, e := s.serviceOpen(c.ID, "refresh", c.RefreshTokenCipher)
	if e != nil || rt == "" {
		r.outcome = serviceRefused(ServiceConnectionNeedsReconsent)
		return c, s.serviceReconsent(ctx, q, p, c, "expired")
	}
	var scopes []string
	if narrowed {
		scopes = r.req.Scopes
	}
	tok, ee, e := s.refreshInTransaction(ctx, q, p, rt, scopes)
	if e != nil {
		return c, e
	}
	observeRefresh(p.Slug, endpointOutcome(ee))
	if ee != nil {
		if ee.Unavailable || narrowed && ee.Code == "invalid_scope" {
			r.outcome = &UnavailableError{Provider: registry.ProviderOf(p), Code: "refresh_failed"}
			return c, nil
		}
		r.outcome = serviceRefused(ServiceConnectionNeedsReconsent)
		return c, s.serviceReconsent(ctx, q, p, c, ee.Code)
	}
	access, e := s.serviceSeal(c.ID, "access", tok.Access)
	if e != nil {
		return c, e
	}
	rtct := c.RefreshTokenCipher
	if tok.Refresh != "" {
		rtct, e = s.serviceSeal(c.ID, "refresh", tok.Refresh)
		if e != nil {
			return c, e
		}
	}
	if narrowed {
		e = s.serviceKeepNarrowed(ctx, q, p, c, tok, rtct, r)
	} else {
		c, e = s.serviceStoreRefreshed(ctx, q, c, tok, access, rtct)
	}
	if e != nil || r.outcome != nil {
		return c, e
	}
	// Live policy is checked again after the outbound exchange, before any
	// credential can escape and even when this request waited for a lock.
	if _, e = s.serviceAuthorized(ctx, q, r.req, r.cc, c); e != nil {
		r.pending = nil
		return c, r.policyOutcome(e)
	}
	return c, nil
}

// serviceKeepNarrowed stores only the rotated refresh token: a narrowed access
// token is never stored, it goes to r.out and (as r.pending) to the cache.
func (s *Service) serviceKeepNarrowed(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, c dbgen.ServiceConnection, tok tokenSet, rtct []byte, r *serviceIssue) error {
	if e := q.RotateServiceConnectionRefresh(ctx, dbgen.RotateServiceConnectionRefreshParams{ID: c.ID, RefreshTokenCipher: rtct}); e != nil {
		return e
	}
	if tok.HasScope && !Covers(tok.Scopes, r.req.Scopes) {
		r.outcome = serviceRefused(ServiceConnectionNeedsReconsent)
		return nil
	}
	ttl := narrowNoExpiry
	if tok.ExpiresIn > 0 {
		ttl = time.Duration(tok.ExpiresIn)*time.Second - RefreshAhead
	}
	if ttl > 0 {
		r.pending = &narrowEntry{token: tok.Access, expires: s.now().Add(ttl)}
	}
	r.out = serviceCredentialOf(p, c, tok.Access, true)
	return nil
}

// serviceStoreRefreshed stores the refreshed tokens, scopes and expiry as the
// connection's own and returns the updated row.
func (s *Service) serviceStoreRefreshed(ctx context.Context, q *dbgen.Queries, c dbgen.ServiceConnection, tok tokenSet, access, rtct []byte) (dbgen.ServiceConnection, error) {
	scopes := c.Scopes
	if tok.HasScope {
		scopes = tok.Scopes
	}
	var expires *time.Time
	if tok.ExpiresIn > 0 {
		t := s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		expires = &t
	}
	return q.RefreshServiceConnectionTokens(ctx, dbgen.RefreshServiceConnectionTokensParams{ID: c.ID, Scopes: nonNil(scopes), AccessTokenCipher: access, RefreshTokenCipher: rtct, ExpiresAt: expires})
}

func serviceCredentialOf(p dbgen.AuthProvider, c dbgen.ServiceConnection, token string, narrowed bool) Credential {
	return Credential{Provider: registry.ProviderOf(p), AccessToken: token, Resource: deref(p.Resource), Refreshable: len(c.RefreshTokenCipher) > 0, Narrowed: narrowed, ServiceConnectionID: c.ID, ServiceGeneration: c.Generation}
}
