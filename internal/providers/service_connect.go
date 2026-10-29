package providers

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// lockServiceSession takes USER KEY SHARE before SESSION -> CONNECTION -> STATE.
// Suspension takes USER FOR UPDATE before deleting sessions; acquiring this user
// lock before any session lock also prevents later user audit/FK checks forming
// a cycle. SessionID is the session row UUID, not its cookie.
func (s *Service) lockServiceSession(ctx context.Context, q *dbgen.Queries, user uuid.UUID, session string) error {
	id, e := uuid.Parse(session)
	if e != nil {
		return apperr.Forbidden("Use a live browser session")
	}
	status, e := q.LockServiceConsentUser(ctx, user)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && status != auth.StatusActive {
		return apperr.Forbidden("Use a live browser session")
	}
	if e != nil {
		return e
	}
	since := time.Time{}
	if s.SessionIdleTimeout > 0 {
		since = s.now().Add(-s.SessionIdleTimeout)
	}
	_, e = q.LockServiceConsentSession(ctx, dbgen.LockServiceConsentSessionParams{ID: id, UserID: user, AsOf: s.now(), IdleSince: since})
	if errors.Is(e, pgx.ErrNoRows) {
		return apperr.Forbidden("Use a live browser session")
	}
	return e
}
func (s *Service) StartServiceConnection(ctx context.Context, a authz.Actor, team string, provider uuid.UUID, name string, scopes []string, session string) (Started, error) {
	var out Started
	name, e := serviceName(name)
	if e != nil {
		return out, e
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if e := s.lockServiceSession(ctx, q, a.UserID, session); e != nil {
			return e
		}
		t, e := serviceAccess(ctx, q, a, team, true)
		if e != nil {
			return e
		}
		if e = q.LockServiceConnectionTeam(ctx, t.ID.String()); e != nil {
			return e
		}
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		n, e := q.CountTeamServiceConnections(ctx, t.ID)
		if e != nil {
			return e
		}
		if n >= 200 {
			return apperr.Conflict("connection_limit", "A team may have at most 200 shared connections")
		}
		p, e := q.GetAuthProvider(ctx, provider)
		if e != nil || !p.Enabled {
			return errNoProvider
		}
		if p.Kind == KindMCPServer {
			// A bound provider may be connected only for a reachable destination.
			u, e := q.GetUser(ctx, a.UserID)
			if e != nil {
				return e
			}
			visible := false
			if s.Reachable != nil {
				rs, e := s.Reachable(ctx, u)
				if e != nil {
					return e
				}
				for _, r := range rs {
					if p.ServerID.Valid && r.Server.ID == p.ServerID.UUID {
						visible = true
					}
				}
			}
			if !visible {
				return errNoProvider
			}
		}
		if scopes == nil {
			scopes = p.DefaultScopes
		}
		scopes, e = normalizeScopes(scopes)
		if e != nil {
			return e
		}
		c, e := q.InsertServiceConnection(ctx, dbgen.InsertServiceConnectionParams{TeamID: t.ID, ProviderID: p.ID, Name: name, Scopes: nonNil(scopes), ConnectedBy: by(a)})
		if e != nil {
			return e
		}
		if e = serviceAudit(ctx, q, a, c, "create", map[string]any{"name": name, "providerId": p.ID, "shared": true}); e != nil {
			return e
		}
		out, e = s.beginService(ctx, q, a, p, c, session)
		if e != nil {
			return e
		}
		_, e = serviceAccess(ctx, q, a, team, true)
		return e
	})
	return out, serviceConflict(err)
}
func (s *Service) ReconnectServiceConnection(ctx context.Context, a authz.Actor, team string, id uuid.UUID, rev int64, session string) (Started, error) {
	var out Started
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if e := s.lockServiceSession(ctx, q, a.UserID, session); e != nil {
			return e
		}
		t, e := serviceAccess(ctx, q, a, team, true)
		if e != nil {
			return e
		}
		c, e := q.LockServiceConnection(ctx, id)
		if e = serviceOwned(c, t, e); e != nil {
			return e
		}
		// Session-first, connection-next; only then trust live team authority.
		if _, e = serviceAccess(ctx, q, a, team, true); e != nil {
			return e
		}
		if e = serviceRevision(c, rev); e != nil {
			return e
		}
		p, e := q.GetAuthProvider(ctx, c.ProviderID)
		if e != nil || !p.Enabled {
			return errNoProvider
		}
		c, e = q.AdvanceServiceConnection(ctx, id)
		if e != nil {
			return e
		}
		if e = q.DeleteServiceConnectionAuthStates(ctx, id); e != nil {
			return e
		}
		if e = serviceAudit(ctx, q, a, c, "reconnect", map[string]any{"name": c.Name}); e != nil {
			return e
		}
		out, e = s.beginService(ctx, q, a, p, c, session)
		if e != nil {
			return e
		}
		_, e = serviceAccess(ctx, q, a, team, true)
		return e
	})
	return out, err
}
func (s *Service) beginService(ctx context.Context, q *dbgen.Queries, a authz.Actor, p dbgen.AuthProvider, c dbgen.ServiceConnection, session string) (Started, error) {
	client, e := clientOfWith(ctx, q, p)
	if errors.Is(e, errLinkMismatch) || errors.Is(e, pgx.ErrNoRows) {
		return Started{}, errNoProvider
	}
	if e != nil {
		return Started{}, e
	}
	if !p.Enabled {
		return Started{}, errNoProvider
	}
	state := randomID()
	digest := auth.Digest(state)
	expires := s.now().Add(StateTTL)
	var challenge string
	var ct []byte
	if p.Pkce || p.Kind == KindMCPServer {
		v, ch := pkcePair()
		challenge = ch
		ct, e = s.box.Seal([]byte(v), ServiceStateAAD(digest))
		if e != nil {
			return Started{}, e
		}
	}
	scopes := union(c.Scopes, p.DefaultScopes)
	grants, e := q.ListServiceConnectionGrants(ctx, c.ID)
	if e != nil {
		return Started{}, e
	}
	for _, g := range grants {
		scopes = union(scopes, g.Scopes)
	}
	e = q.InsertServiceConnectionAuthState(ctx, dbgen.InsertServiceConnectionAuthStateParams{StateDigest: digest, UserID: a.UserID, SessionDigest: auth.Digest(session), ConnectionID: c.ID, Revision: c.Revision, Generation: c.Generation, ProviderID: p.ID, ProviderRevision: p.Revision, ClientRevision: client.Revision, Scopes: scopes, CodeVerifierCipher: ct, Resource: p.Resource, ExpiresAt: expires})
	if e != nil {
		return Started{}, e
	}
	return Started{AuthorizeURL: s.authorizeURL(p, client, state, challenge, scopes), Scopes: scopes, ExpiresAt: expires}, nil
}
func (s *Service) validateServiceCallback(ctx context.Context, q *dbgen.Queries, st dbgen.ServiceConnectionAuthState, in CallbackInput) (dbgen.ServiceConnection, dbgen.AuthProvider, error) {
	var zero dbgen.ServiceConnection
	var zp dbgen.AuthProvider
	if in.SessionID == "" || auth.Digest(in.SessionID) != st.SessionDigest || in.User.ID != st.UserID || in.User.Status != auth.StatusActive || !s.now().Before(st.ExpiresAt) {
		return zero, zp, errNoServiceConnection
	}
	if e := s.lockServiceSession(ctx, q, st.UserID, in.SessionID); e != nil {
		return zero, zp, e
	}
	c, e := q.LockServiceConnection(ctx, st.ConnectionID)
	if e != nil {
		return c, zp, e
	}
	if c.Revision != st.Revision || c.Generation != st.Generation || c.ProviderID != st.ProviderID {
		return c, zp, errNoServiceConnection
	}
	ok, e := q.ServiceConnectionAdminActive(ctx, dbgen.ServiceConnectionAdminActiveParams{UserID: st.UserID, TeamID: c.TeamID})
	if e != nil {
		return c, zp, e
	}
	if !ok {
		return c, zp, errNoServiceConnection
	}
	p, e := q.GetAuthProvider(ctx, st.ProviderID)
	if e != nil {
		return c, p, e
	}
	client, e := clientOfWith(ctx, q, p)
	if errors.Is(e, errLinkMismatch) || errors.Is(e, pgx.ErrNoRows) {
		return c, p, errNoServiceConnection
	}
	if e != nil {
		return c, p, e
	}
	if !p.Enabled || p.Revision != st.ProviderRevision || client.Revision != st.ClientRevision || deref(p.Resource) != deref(st.Resource) {
		return c, p, errNoServiceConnection
	}
	if p.Kind == KindMCPServer {
		sv, e := q.GetMCPServer(ctx, p.ServerID.UUID)
		if e != nil {
			return c, p, e
		}
		if sv.AuthMode != "oauth" || deref(p.Resource) != sv.URL || in.Iss != "" && in.Iss != deref(p.Issuer) || in.Iss == "" && p.IssParamSupported && in.Error == "" {
			return c, p, errNoServiceConnection
		}
	}
	return c, p, nil
}

// serviceDone adds only a display hint; it conveys no team or credential authority.
func serviceDone(provider, result string, missing []string) string {
	return done(provider, result, missing) + "&context=service"
}

// serviceCallback consumes its own state before exchange and revalidates under
// user/session-first locks before committing; never calls the personal store adapter.
func (s *Service) serviceCallback(ctx context.Context, st dbgen.ServiceConnectionAuthState, in CallbackInput) (string, error) {
	var p dbgen.AuthProvider
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// Lock user then browser even for one-time state consumption.
		if e := s.lockServiceSession(ctx, q, st.UserID, in.SessionID); e != nil {
			return e
		}
		// Connection-before-state agrees with update/revoke's invalidation
		// order; taking state first could deadlock against a list update.
		if _, e := q.LockServiceConnection(ctx, st.ConnectionID); e != nil {
			return e
		}
		taken, e := q.TakeServiceConnectionAuthState(ctx, st.StateDigest)
		if e != nil {
			return e
		}
		st = taken
		_, p, e = s.validateServiceCallback(ctx, q, st, in)
		return e
	})
	if err != nil { // consume invalid states as well, never leaving reusable consent
		_, _ = s.q.TakeServiceConnectionAuthState(ctx, st.StateDigest)
		return serviceDone("", ResultExpired, nil), nil
	}
	if in.Error != "" {
		return serviceDone(p.Slug, ResultDenied, nil), nil
	}
	if in.Code == "" || len(in.Code) > 4096 {
		return serviceDone(p.Slug, ResultError, nil), nil
	}
	verifier := ""
	if st.CodeVerifierCipher != nil {
		b, e := s.box.Open(st.CodeVerifierCipher, ServiceStateAAD(st.StateDigest))
		if e != nil {
			return serviceDone(p.Slug, ResultError, nil), nil
		}
		verifier = string(b)
	}
	tok, ee := s.exchange(ctx, p, in.Code, verifier)
	if ee != nil {
		return serviceDone(p.Slug, ResultError, nil), nil
	}
	label := s.accountLabel(ctx, p, tok.Access)
	granted := st.Scopes
	if tok.HasScope {
		granted = tok.Scopes
	}
	var expires *time.Time
	if tok.ExpiresIn > 0 {
		t := s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		expires = &t
	}
	a := authz.Actor{UserID: in.User.ID, PlatformRole: in.User.PlatformRole, RequestID: in.RequestID, ClientIP: in.ClientIP}
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		c, _, e := s.validateServiceCallback(ctx, q, st, in)
		if e != nil {
			return e
		}
		access, e := s.serviceSeal(c.ID, "access", tok.Access)
		if e != nil {
			return e
		}
		refresh, e := s.serviceSeal(c.ID, "refresh", tok.Refresh)
		if e != nil {
			return e
		}
		// A new authorization may select another upstream account (or be
		// completed by another admin). Never attach the old account's refresh
		// token when the new authorization did not return one. Runtime
		// refresh rotation, unlike authorization, retains the same grant.
		c, e = q.StoreServiceConnectionTokens(ctx, dbgen.StoreServiceConnectionTokensParams{ID: c.ID, Scopes: nonNil(granted), AccountLabel: &label, AccessTokenCipher: access, RefreshTokenCipher: refresh, ExpiresAt: expires, ConnectedBy: by(a)})
		if e != nil {
			return e
		}
		return serviceAudit(ctx, q, a, c, "connect", map[string]any{"name": c.Name, "accountLabel": label, "scopes": granted, "shared": true})
	})
	if err != nil {
		// Consent may have been revoked while exchange was in flight. Do not
		// keep even an orphaned upstream credential when revocation exists.
		token, hint := tok.Refresh, "refresh_token"
		if token == "" {
			token, hint = tok.Access, "access_token"
		}
		if p.RevocationUrl != nil && token != "" {
			_ = s.revoke(ctx, p, token, hint)
		}
		return serviceDone(p.Slug, ResultExpired, nil), nil
	}
	var missing []string
	for _, scope := range st.Scopes {
		if !contains(granted, scope) {
			missing = append(missing, scope)
		}
	}
	if len(missing) > 0 {
		return serviceDone(p.Slug, ResultMissingScopes, missing), nil
	}
	return serviceDone(p.Slug, ResultConnected, nil), nil
}
