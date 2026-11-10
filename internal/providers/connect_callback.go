package providers

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// CallbackInput is the provider's redirect back, with the browser's
// session (SessionID "" when signed out) and its person.
type CallbackInput struct {
	State, Code, Error string
	// Iss is the authorization response's iss parameter (RFC 9207; "":
	// absent).
	Iss                 string
	SessionID           string
	User                dbgen.User
	RequestID, ClientIP string
}

// done is the web app's result page.
func done(provider, result string, missing []string) string {
	q := url.Values{"result": {result}}
	if provider != "" {
		q.Set("provider", provider)
	}
	for _, m := range missing {
		q.Add("missing", m)
	}
	return DonePath + "?" + q.Encode()
}

// Callback completes connecting and returns the same-origin path to send
// the browser to: the request's return path, or the web app's result page.
// The state is deleted before anything else is checked; it must belong to
// this browser session (OAuth CSRF), and names the provider whose token
// endpoint receives the code (mix-up). Audited as
// provider_connection.create.
func (s *Service) Callback(ctx context.Context, in CallbackInput) (string, error) {
	if in.State == "" || len(in.State) > 200 {
		return done("", ResultExpired, nil), nil
	}
	// Service states live in a separate namespace. An older replica sees an
	// unknown personal state and refuses; it can never store personal tokens.
	if serviceState, err := s.q.GetServiceConnectionAuthState(ctx, auth.Digest(in.State)); err == nil {
		return s.serviceCallback(ctx, serviceState, in)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	st, err := s.q.TakeProviderAuthState(ctx, auth.Digest(in.State))
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return done("", ResultExpired, nil), nil
	} else if err != nil {
		return "", err
	}
	p, err := s.q.GetAuthProvider(ctx, st.ProviderID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return done("", ResultExpired, nil), nil
	} else if err != nil {
		return "", err
	}
	if !s.now().Before(st.ExpiresAt) {
		return done(p.Slug, ResultExpired, nil), nil
	}
	if in.SessionID == "" || auth.Digest(in.SessionID) != st.SessionDigest || in.User.ID != st.UserID || in.User.Status != auth.StatusActive {
		return done(p.Slug, ResultWrongPerson, nil), nil
	}
	if p.Kind == KindMCPServer {
		// Mix-up (RFC 9207): the response must come from the server's own
		// issuer; and the server's resource must not have changed meanwhile.
		switch {
		case deref(st.Resource) != deref(p.Resource):
			return done(p.Slug, ResultError, nil), nil
		case in.Iss != "" && in.Iss != deref(p.Issuer):
			return done(p.Slug, ResultError, nil), nil
		case in.Iss == "" && p.IssParamSupported && in.Error == "":
			return done(p.Slug, ResultError, nil), nil
		}
		if s.linkUsable(ctx, p) != nil {
			return done(p.Slug, ResultError, nil), nil
		}
	}
	if in.Error != "" {
		return done(p.Slug, ResultDenied, nil), nil
	}
	if !p.Enabled || in.Code == "" || len(in.Code) > 4096 {
		return done(p.Slug, ResultError, nil), nil
	}
	verifier := ""
	if st.CodeVerifierCipher != nil {
		b, err := s.box.Open(st.CodeVerifierCipher, stateAAD(st.StateDigest))
		if err != nil {
			return done(p.Slug, ResultError, nil), nil
		}
		verifier = string(b)
	}
	tok, ee := s.exchange(ctx, p, in.Code, verifier)
	if ee != nil {
		s.Log.InfoContext(ctx, "auth provider code exchange failed", "provider", p.Slug, "error", ee.Code, "status", ee.Status)
		return done(p.Slug, ResultError, nil), nil
	}
	granted := nonNil(st.Scopes)
	if tok.HasScope {
		granted = tok.Scopes
	}
	label := s.accountLabel(ctx, p, tok.Access)
	var expires *time.Time
	if tok.ExpiresIn > 0 {
		t := s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		expires = &t
	}
	actor := authz.Actor{UserID: in.User.ID, PlatformRole: in.User.PlatformRole, RequestID: in.RequestID, ClientIP: in.ClientIP}
	setup, grantSkipped, notAllowed := false, false, false
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		row, viaRequest, err := s.store(ctx, q, actor, in.User, p, st, tok, granted, label, expires, in.SessionID)
		if err != nil {
			return err
		}
		if !st.SetupServerID.Valid {
			// The consent link also allows the server it was made for, when
			// this callback used it up and the provider granted what it asks.
			if viaRequest && p.Kind != KindMCPServer {
				grantSkipped, notAllowed, err = s.grantFromRequest(ctx, q, actor, in.User, p, row, st, granted)
			}
			return err
		}
		// The setup sign-in counts only for an editor (or above) of the
		// server's team, checked again now.
		sv, err := q.GetMCPServer(ctx, st.SetupServerID.UUID)
		if err != nil {
			return err
		}
		role, err := teams.MemberRole(ctx, q, sv.TeamID, in.User.ID)
		if err != nil || authz.CheckServerEdit(role) != nil {
			return err
		}
		if _, err := registry.SetSetupConnection(ctx, q, actor, sv.ID, displayName(in.User)); err != nil {
			return err
		}
		setup = true
		return nil
	})
	if errors.Is(err, errPersonalConsentEnded) {
		return done(p.Slug, ResultExpired, nil), nil
	}
	if err != nil {
		return "", err
	}
	if setup && s.Registry != nil {
		// Capabilities are read at once with the new setup connection.
		if err := s.Registry.RefreshAsSetup(context.WithoutCancel(ctx), actor, st.SetupServerID.UUID); err != nil {
			s.Log.WarnContext(ctx, "reading capabilities after the setup sign-in failed", "server", st.SetupServerID.UUID, "err", err)
		}
	}
	var missing []string
	for _, m := range st.RequiredScopes {
		if !contains(granted, m) {
			missing = append(missing, m)
		}
	}
	switch {
	case len(missing) > 0:
		return done(p.Slug, ResultMissingScopes, missing), nil
	case notAllowed:
		// Connected, but the provider's access list excludes the link's
		// server: nothing was allowed, and asking again will not help.
		return done(p.Slug, ResultNotAllowed, nil), nil
	case grantSkipped:
		// Connected, but the link's server moved or went meanwhile: nothing
		// was allowed; the next call asks again.
		return done(p.Slug, ResultExpired, nil), nil
	case st.ReturnTo != nil && SafeReturnPath(*st.ReturnTo):
		return *st.ReturnTo, nil
	}
	return done(p.Slug, ResultConnected, nil), nil
}

// grantFromRequest allows, after a connect that used the link up, the server
// the link was made for (at the origin it was made for), for the scopes the
// link names, when the provider granted them all. skipped: the link's server
// is gone or changed, so nothing was allowed; notAllowed: the provider's
// access list excludes the server, so nothing was allowed either.
func (s *Service) grantFromRequest(ctx context.Context, q *dbgen.Queries, a authz.Actor, u dbgen.User, p dbgen.AuthProvider,
	conn dbgen.ProviderConnection, st dbgen.ProviderAuthState, granted []string) (skipped, notAllowed bool, err error) {
	r, err := q.GetConnectRequest(ctx, *st.RequestDigest)
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && (r.UserID != u.ID || r.ProviderID != p.ID)) {
		return false, false, nil
	} else if err != nil {
		return false, false, err
	}
	if !Covers(granted, r.RequiredScopes) {
		return false, false, nil // reported as missing scopes
	}
	sv, err := requestServer(ctx, q, r)
	if errors.Is(err, errServerChanged) || errors.Is(err, errRequestExpired) {
		return true, false, nil
	} else if err != nil {
		return false, false, err
	}
	if ok, err := allowsServer(ctx, q, p.ID, sv.ID); err != nil {
		return false, false, err
	} else if !ok {
		return false, true, nil
	}
	_, err = s.recordGrant(ctx, q, a, u, p, conn, sv, nonNil(r.RequiredScopes), true)
	return false, false, err
}

// store saves new tokens as the person's active connection and uses up the
// request (viaRequest: this call did).
func (s *Service) store(ctx context.Context, q *dbgen.Queries, a authz.Actor, u dbgen.User, p dbgen.AuthProvider, st dbgen.ProviderAuthState,
	tok tokenSet, granted []string, label string, expires *time.Time, sessionID string) (dbgen.ProviderConnection, bool, error) {
	var row0 dbgen.ProviderConnection
	var labelPtr *string
	if label != "" {
		labelPtr = &label
	}
	cur, err := q.LockProviderConnection(ctx, dbgen.LockProviderConnectionParams{UserID: u.ID, ProviderID: p.ID})
	reconnect := err == nil
	if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return row0, false, err
	}
	if err := s.lockPersonalSession(ctx, q, u.ID, sessionID); err != nil {
		return row0, false, err
	}
	id := uuid.New()
	if reconnect {
		id = cur.ID
	}
	access, err := s.seal(id, "access", tok.Access)
	if err != nil {
		return row0, false, err
	}
	refresh, err := s.seal(id, "refresh", tok.Refresh)
	if err != nil {
		return row0, false, err
	}
	if reconnect && refresh == nil && cur.Status == StatusActive && cur.RefreshTokenCipher != nil {
		// Some providers (Google) only send a refresh token on first consent;
		// the one held stays valid.
		refresh = cur.RefreshTokenCipher
	}
	var row dbgen.ProviderConnection
	if reconnect {
		row, err = q.ReconnectProviderConnection(ctx, dbgen.ReconnectProviderConnectionParams{ID: id, Scopes: granted, AccountLabel: labelPtr,
			AccessTokenCipher: access, RefreshTokenCipher: refresh, ExpiresAt: expires})
	} else {
		row, err = q.InsertProviderConnection(ctx, dbgen.InsertProviderConnectionParams{ID: id, UserID: u.ID, ProviderID: p.ID, Scopes: granted,
			AccountLabel: labelPtr, AccessTokenCipher: access, RefreshTokenCipher: refresh, ExpiresAt: expires})
	}
	if err != nil {
		return row0, false, err
	}
	viaRequest := false
	if st.RequestDigest != nil {
		n, err := q.MarkConnectRequestUsed(ctx, *st.RequestDigest)
		if err != nil {
			return row0, false, err
		}
		viaRequest = n > 0
	}
	e := a.Audit("provider_connection.create", "provider_connection", row.ID.String())
	if reconnect {
		e.Before = connectionSnapshot(cur)
	}
	e.After = connectionSnapshot(row)
	e.Metadata = map[string]any{"name": displayName(u) + " · " + p.Name, "scopes": granted, "reconnect": reconnect,
		"viaRequest": viaRequest, "provider": p.Slug}
	return row, viaRequest, audit.Record(ctx, q, e)
}
