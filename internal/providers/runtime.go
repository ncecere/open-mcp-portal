package providers

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The runtime (decisions 27-29): a call of a capability with an effective
// requirement gets the person's access token for that provider, refreshed
// when it expires within a minute, or a consent link when there is no
// usable connection.

// RefreshAhead: a token expiring sooner than this is refreshed first.
const RefreshAhead = time.Minute

// Why a call needs consent (the connect request's reason, and the call
// record's error class).
const (
	ReasonNotConnected   = "not_connected"
	ReasonMissingScopes  = "missing_scopes"
	ReasonNeedsReconsent = "needs_reconsent"
	// ReasonServerNotAllowed: the person is connected with scopes that
	// cover the call, but hasn't allowed this server (at its current
	// origin, for these scopes) to use the connection (F-3).
	ReasonServerNotAllowed = "server_not_allowed"
)

// CallContext is the call that needs a credential.
type CallContext struct {
	User         dbgen.User
	Gateway      dbgen.Gateway
	CapabilityID uuid.UUID
	// ServerID and ServerOrigin are the server the capability belongs to and
	// the origin (registry.OriginOf) of the URL the call goes to: consent is
	// bound to both.
	ServerID     uuid.UUID
	ServerOrigin string
	// Kind, ExposedName and Title describe the capability to the person.
	Kind, ExposedName, Title string
	// NoConsent: the call is an agent's, with no browser to open a link in
	// (decision 66, #57). A missing, lapsed or too narrow connection, or a
	// server the person hasn't allowed, still answers *ConsentNeeded, but no
	// consent link is made: nothing is stored, and RequestID and URL stay
	// empty.
	NoConsent bool
}

// Credential is what a call carries: the provider and the bare access
// token. The token goes only to the server whose capability requires it and
// that the person allowed, at the origin they allowed it (a platform
// provider's grant, F-3).
// For an oauth server's own sign-in (Provider.Kind mcp_server) Resource is
// the only URL the token may be sent to, and Refreshable says a refresh
// token is held (an upstream 401 gets one refresh and retry).
type Credential struct {
	Provider    registry.Provider
	AccessToken string
	Resource    string
	Refreshable bool
}

// ConsentNeeded: the person must connect (or reconnect) an account; URL is
// the consent link (the web app's /connect/{provider}?request=ID).
type ConsentNeeded struct {
	Reason, RequestID, URL string
	Provider               registry.Provider
	Scopes                 []string
}

func (e *ConsentNeeded) Error() string { return "providers: consent needed (" + e.Reason + ")" }

// ErrProviderDisabled: a platform admin turned the provider off (or it is
// gone): calls that need it are refused.
var ErrProviderDisabled = errors.New("providers: the auth provider is turned off")

// UnavailableError: the provider's token endpoint failed (network, 5xx,
// timeout); the connection is kept and the call isn't forwarded.
type UnavailableError struct {
	Provider registry.Provider
	Code     string
}

func (e *UnavailableError) Error() string { return "providers: provider unavailable (" + e.Code + ")" }

// errReconsent is a refresh that ended the connection's tokens.
var errReconsent = errors.New("providers: reconsent")

// Credential returns the person's token for a call that requires req, or
// a *ConsentNeeded (a consent link was made or reused), ErrProviderDisabled
// or an *UnavailableError. Nothing is sent anywhere but the provider's own
// token endpoint.
func (s *Service) Credential(ctx context.Context, req *registry.Requirement, cc CallContext) (Credential, error) {
	p, err := s.q.GetAuthProvider(ctx, req.Provider.ID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Credential{}, ErrProviderDisabled
	} else if err != nil {
		return Credential{}, err
	}
	if !p.Enabled {
		return Credential{}, ErrProviderDisabled
	}
	if p.Kind == KindMCPServer && s.linkUsable(ctx, p) != nil {
		// The platform provider whose client the server uses is off.
		return Credential{}, ErrProviderDisabled
	}
	prov := registry.ProviderOf(p)
	c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: cc.User.ID, ProviderID: p.ID})
	switch {
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonNotConnected)
	case err != nil:
		return Credential{}, err
	case c.Status != StatusActive:
		return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonNeedsReconsent)
	case !Covers(c.Scopes, req.Scopes):
		return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonMissingScopes)
	}
	if p.Kind != KindMCPServer {
		// A platform provider's token goes only to a server the person
		// allowed, at the origin they allowed it (an oauth server's own
		// connection is for that server already).
		ok, err := s.serverAllowed(ctx, c, req.Scopes, cc)
		if err != nil {
			return Credential{}, err
		} else if !ok {
			return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonServerNotAllowed)
		}
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(s.now().Add(RefreshAhead)) {
		c, err = s.refreshConnection(ctx, p, c)
		observeRefresh(p.Slug, err)
		if errors.Is(err, errReconsent) {
			return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonNeedsReconsent)
		} else if err != nil {
			return Credential{}, err
		}
	}
	token, err := s.open(c.ID, "access", c.AccessTokenCipher)
	if err != nil || token == "" {
		// Sealed with a key this installation no longer has.
		s.Log.WarnContext(ctx, "provider token unreadable; asking to reconnect", "provider", p.Slug)
		if err := s.markReconsent(ctx, s.q, p, c, "config"); err != nil {
			return Credential{}, err
		}
		return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonNeedsReconsent)
	}
	if err := s.q.TouchProviderConnection(ctx, c.ID); err != nil {
		s.Log.WarnContext(ctx, "could not record a connection's use", "err", err)
	}
	return Credential{Provider: prov, AccessToken: token, Resource: deref(p.Resource), Refreshable: c.RefreshTokenCipher != nil}, nil
}

// serverAllowed reports whether the person allowed the call's server to use
// connection c: a grant whose origin is the origin the call goes to and whose
// scopes cover the requirement.
func (s *Service) serverAllowed(ctx context.Context, c dbgen.ProviderConnection, scopes []string, cc CallContext) (bool, error) {
	g, err := s.q.GetProviderServerGrant(ctx, dbgen.GetProviderServerGrantParams{ConnectionID: c.ID, ServerID: cc.ServerID})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return cc.ServerOrigin != "" && g.Origin == cc.ServerOrigin && Covers(g.Scopes, scopes), nil
}

// ErrInsufficientScope: an oauth server asked for scopes the person
// already holds, or for scopes outside what was reviewed (the server's
// scopes and its scopes_supported). Step-up isn't offered: that would loop.
var ErrInsufficientScope = errors.New("providers: insufficient scope that consent can't fix")

// UpstreamRejected handles an oauth server's 401 to a call made with used
// (docs/phase7-upstream-oauth.md, runtime step 5). With mayRefresh and a
// refresh token, the token is refreshed once (under the row lock; a token
// another request already replaced is used as is) and the new credential
// returned for one retry. Otherwise the tokens are erased (needs_reconsent,
// provider_connection.refresh_failed with reason upstream_rejected) and a
// *ConsentNeeded returned.
func (s *Service) UpstreamRejected(ctx context.Context, req *registry.Requirement, cc CallContext, used Credential, mayRefresh bool) (Credential, error) {
	p, err := s.q.GetAuthProvider(ctx, req.Provider.ID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Credential{}, ErrProviderDisabled
	} else if err != nil {
		return Credential{}, err
	}
	prov := registry.ProviderOf(p)
	var out Credential
	var outcome error
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		c, err := q.LockProviderConnection(ctx, dbgen.LockProviderConnectionParams{UserID: cc.User.ID, ProviderID: p.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			outcome = errReconsent
			return nil
		} else if err != nil {
			return err
		}
		if c.Status != StatusActive {
			outcome = errReconsent
			return nil
		}
		current, err := s.open(c.ID, "access", c.AccessTokenCipher)
		if err == nil && mayRefresh && current != "" && current != used.AccessToken {
			// Another request refreshed it meanwhile.
			out = Credential{Provider: prov, AccessToken: current, Resource: deref(p.Resource), Refreshable: c.RefreshTokenCipher != nil}
			return nil
		}
		rt, err := s.open(c.ID, "refresh", c.RefreshTokenCipher)
		if !mayRefresh || err != nil || rt == "" {
			outcome = errReconsent
			return s.markReconsent(ctx, q, p, c, "upstream_rejected")
		}
		tok, ee := s.refresh(ctx, p, rt)
		observeRefresh(p.Slug, endpointOutcome(ee))
		if ee != nil {
			if ee.Unavailable {
				outcome = &UnavailableError{Provider: prov, Code: ee.Code}
				return nil
			}
			outcome = errReconsent
			return s.markReconsent(ctx, q, p, c, "upstream_rejected")
		}
		row, err := s.storeRefreshed(ctx, q, c, tok)
		if err != nil {
			return err
		}
		access, err := s.open(row.ID, "access", row.AccessTokenCipher)
		if err != nil {
			return err
		}
		out = Credential{Provider: prov, AccessToken: access, Resource: deref(p.Resource), Refreshable: row.RefreshTokenCipher != nil}
		return nil
	})
	switch {
	case err != nil:
		return Credential{}, err
	case errors.Is(outcome, errReconsent):
		return Credential{}, s.needConsent(ctx, prov, req.Scopes, cc, ReasonNeedsReconsent)
	case outcome != nil:
		return Credential{}, outcome
	}
	return out, nil
}

func endpointOutcome(ee *endpointError) error {
	switch {
	case ee == nil:
		return nil
	case ee.Unavailable:
		return &UnavailableError{Code: ee.Code}
	}
	return errReconsent
}

// StepUp handles an oauth server's 403 insufficient_scope for challenged
// scopes: a consent link asking for the granted scopes and the challenged
// ones (missing_scopes), or ErrInsufficientScope when the person already
// holds them all or one is outside the reviewed scopes and scopes_supported.
func (s *Service) StepUp(ctx context.Context, req *registry.Requirement, cc CallContext, challenged []string) error {
	p, err := s.q.GetAuthProvider(ctx, req.Provider.ID)
	if err != nil {
		return err
	}
	granted := []string{}
	if c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: cc.User.ID, ProviderID: p.ID}); err == nil {
		if c.Status == StatusActive {
			granted = nonNil(c.Scopes)
		}
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return err
	}
	reviewed := union(nonNil(p.DefaultScopes), nonNil(p.ScopesSupported))
	if len(challenged) == 0 || Covers(granted, challenged) {
		return ErrInsufficientScope
	}
	for _, sc := range challenged {
		if !contains(reviewed, sc) {
			return ErrInsufficientScope
		}
	}
	return s.needConsent(ctx, registry.ProviderOf(p), union(granted, req.Scopes, challenged), cc, ReasonMissingScopes)
}

// SetupToken is the setup connection's access token for reading an oauth
// server's capabilities (registry.OAuthHooks), refreshed first when it
// expires soon. An unusable one is a *registry.SetupError.
func (s *Service) SetupToken(ctx context.Context, sv dbgen.McpServer, p dbgen.AuthProvider) (string, string, error) {
	st, err := registry.SetupStatus(ctx, s.q, sv, p.ID)
	if err != nil {
		return "", "", err
	}
	if st.Status != registry.SetupActive {
		return "", "", &registry.SetupError{Status: st.Status}
	}
	c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: st.PersonID.UUID, ProviderID: p.ID})
	if err != nil {
		return "", "", err
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(s.now().Add(RefreshAhead)) {
		c, err = s.refreshConnection(ctx, p, c)
		observeRefresh(p.Slug, err)
		var down *UnavailableError
		switch {
		case errors.Is(err, errReconsent):
			return "", "", &registry.SetupError{Status: registry.SetupNeedsReconsent}
		case errors.As(err, &down):
			return "", "", errors.New("the authorization server couldn't be reached to renew the sign-in (" + down.Code + ")")
		case err != nil:
			return "", "", err
		}
	}
	token, err := s.open(c.ID, "access", c.AccessTokenCipher)
	if err != nil || token == "" {
		if err := s.markReconsent(ctx, s.q, p, c, "config"); err != nil {
			return "", "", err
		}
		return "", "", &registry.SetupError{Status: registry.SetupNeedsReconsent}
	}
	return token, *st.PersonName, nil
}

// RevokeConnections revokes every connection to a server-bound provider at
// its authorization server (registry.OAuthHooks; best effort, bounded).
func (s *Service) RevokeConnections(ctx context.Context, p dbgen.AuthProvider) map[uuid.UUID]any {
	conns, err := s.q.ListProviderConnectionsForProvider(ctx, p.ID)
	if err != nil {
		s.Log.WarnContext(ctx, "listing a server's connections to revoke failed", "err", err)
		return map[uuid.UUID]any{}
	}
	return s.revokeAll(ctx, p, conns)
}

// DeleteConnections deletes every connection to a server-bound provider in
// the caller's transaction (registry.OAuthHooks). Audited as
// provider_connection.revoke ("person · server", the reason and the
// revocation result) per connection.
func (s *Service) DeleteConnections(ctx context.Context, q *dbgen.Queries, a authz.Actor, p dbgen.AuthProvider, results map[uuid.UUID]any, reason string) error {
	all, err := q.ListProviderConnectionsForProvider(ctx, p.ID)
	if err != nil {
		return err
	}
	names, err := s.userNames(ctx, q, all)
	if err != nil {
		return err
	}
	for _, c := range all {
		if err := q.DeleteProviderConnection(ctx, c.ID); err != nil {
			return err
		}
		result, ok := results[c.ID]
		if !ok {
			result = revokeResult(p, false)
		}
		e := a.Audit("provider_connection.revoke", "provider_connection", c.ID.String())
		e.Before = connectionSnapshot(c)
		e.Metadata = map[string]any{"name": names[c.UserID] + " · " + p.Name, "reason": reason, "providerRevoked": result,
			"userId": c.UserID.String(), "provider": p.Slug}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
	}
	return nil
}

// observeRefresh counts a refresh (omp_provider_token_refresh_total).
func observeRefresh(provider string, err error) {
	var down *UnavailableError
	switch {
	case err == nil:
		observability.ObserveProviderRefresh(provider, "ok")
	case errors.Is(err, errReconsent):
		observability.ObserveProviderRefresh(provider, "refused")
	case errors.As(err, &down):
		observability.ObserveProviderRefresh(provider, "unavailable")
	}
}

// refreshConnection refreshes a connection's access token while holding its
// row lock, so replicas never use a (rotating) refresh token twice: a
// replica that waited finds the token already refreshed. A refused refresh
// (invalid_grant, 400, 401) or an expired token without a refresh token
// erases the tokens (needs_reconsent; errReconsent); a provider that can't
// be reached keeps the connection (*UnavailableError).
func (s *Service) refreshConnection(ctx context.Context, p dbgen.AuthProvider, conn dbgen.ProviderConnection) (dbgen.ProviderConnection, error) {
	var out dbgen.ProviderConnection
	var outcome error
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		c, err := q.LockProviderConnectionByID(ctx, conn.ID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			outcome = errReconsent
			return nil
		} else if err != nil {
			return err
		}
		switch {
		case c.Status != StatusActive:
			outcome = errReconsent
			return nil
		case c.ExpiresAt == nil || !c.ExpiresAt.Before(s.now().Add(RefreshAhead)):
			out = c // another request refreshed it meanwhile
			return nil
		}
		rt, err := s.open(c.ID, "refresh", c.RefreshTokenCipher)
		if err != nil || rt == "" {
			outcome = errReconsent
			return s.markReconsent(ctx, q, p, c, "expired")
		}
		tok, ee := s.refresh(ctx, p, rt)
		if ee != nil {
			if ee.Unavailable {
				s.Log.InfoContext(ctx, "auth provider refresh failed", "provider", p.Slug, "error", ee.Code, "status", ee.Status)
				outcome = &UnavailableError{Provider: registry.ProviderOf(p), Code: ee.Code}
				return nil
			}
			outcome = errReconsent
			return s.markReconsent(ctx, q, p, c, ee.Code)
		}
		out, err = s.storeRefreshed(ctx, q, c, tok)
		return err
	})
	if err != nil {
		return out, err
	}
	return out, outcome
}

// storeRefreshed saves a refresh's answer (a rotated refresh token replaces
// the old one).
func (s *Service) storeRefreshed(ctx context.Context, q *dbgen.Queries, c dbgen.ProviderConnection, tok tokenSet) (dbgen.ProviderConnection, error) {
	access, err := s.seal(c.ID, "access", tok.Access)
	if err != nil {
		return c, err
	}
	refresh := c.RefreshTokenCipher
	if tok.Refresh != "" {
		if refresh, err = s.seal(c.ID, "refresh", tok.Refresh); err != nil {
			return c, err
		}
	}
	scopes := nonNil(c.Scopes)
	if tok.HasScope && len(tok.Scopes) > 0 {
		scopes = tok.Scopes
	}
	var expires *time.Time
	if tok.ExpiresIn > 0 {
		t := s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		expires = &t
	}
	return q.SetProviderConnectionRefreshed(ctx, dbgen.SetProviderConnectionRefreshedParams{
		ID: c.ID, AccessTokenCipher: access, RefreshTokenCipher: refresh, ExpiresAt: expires, Scopes: scopes,
	})
}

// markReconsent erases a connection's tokens. Audited as
// provider_connection.refresh_failed by the system, with the reason.
func (s *Service) markReconsent(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider, c dbgen.ProviderConnection, reason string) error {
	if err := q.MarkProviderConnectionReconsent(ctx, dbgen.MarkProviderConnectionReconsentParams{ID: c.ID, ErrorClass: &reason}); err != nil {
		return err
	}
	if s.Notify != nil {
		s.Notify.ConnectionReconsent(ctx, q, c.ID, reason)
	}
	name := p.Name
	if u, err := q.GetUser(ctx, c.UserID); err == nil {
		name = displayName(u) + " · " + p.Name
	}
	return audit.Record(ctx, q, audit.Entry{
		ActorKind: audit.ActorSystem, Action: "provider_connection.refresh_failed", TargetType: "provider_connection",
		TargetID: c.ID.String(), Before: connectionSnapshot(c),
		Metadata: map[string]any{"name": name, "reason": reason, "provider": p.Slug, "userId": c.UserID.String()},
	})
}

// needConsent makes (or reuses, for the same person, capability and
// scopes) a consent link and returns it as a *ConsentNeeded.
func (s *Service) needConsent(ctx context.Context, p registry.Provider, scopes []string, cc CallContext, reason string) error {
	if cc.NoConsent {
		return &ConsentNeeded{Reason: reason, Provider: p, Scopes: slices.Clone(scopes)}
	}
	id, err := s.request(ctx, p, scopes, cc, reason)
	if err != nil {
		return err
	}
	return &ConsentNeeded{Reason: reason, RequestID: id, URL: s.ConnectURL(p.Slug, id), Provider: p, Scopes: slices.Clone(scopes)}
}

// request returns the ID of an open consent link for the call, making one
// when none stays valid for at least two more minutes. A person has at most
// MaxOpenRequests open; the oldest is dropped.
func (s *Service) request(ctx context.Context, p registry.Provider, scopes []string, cc CallContext, reason string) (string, error) {
	scopes = nonNil(scopes)
	var id string
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		open, err := q.FindOpenConnectRequest(ctx, dbgen.FindOpenConnectRequestParams{UserID: cc.User.ID, ProviderID: p.ID,
			GatewayID: cc.Gateway.ID, CapabilityID: cc.CapabilityID, RequiredScopes: scopes, ValidUntil: s.now().Add(2 * time.Minute),
			ServerID: uuid.NullUUID{UUID: cc.ServerID, Valid: true}, ServerOrigin: &cc.ServerOrigin})
		if err == nil {
			if b, err := s.box.Open(open.IDCipher, requestAAD(open.IDDigest)); err == nil {
				id = string(b)
				return nil
			}
		} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		id = randomID()
		digest := requestDigest(id)
		ct, err := s.box.Seal([]byte(id), requestAAD(digest))
		if err != nil {
			return err
		}
		title := []rune(cc.Title)
		if len(title) > 200 {
			title = title[:200]
		}
		if _, err := q.InsertConnectRequest(ctx, dbgen.InsertConnectRequestParams{
			IDDigest: digest, IDCipher: ct, UserID: cc.User.ID, ProviderID: p.ID, RequiredScopes: scopes, Reason: reason,
			GatewayID: cc.Gateway.ID, GatewaySlug: cc.Gateway.Slug, GatewayName: cc.Gateway.Name, CapabilityID: cc.CapabilityID,
			CapabilityKind: cc.Kind, ExposedName: cc.ExposedName, CapabilityTitle: string(title), ExpiresAt: s.now().Add(RequestTTL),
			ServerID: uuid.NullUUID{UUID: cc.ServerID, Valid: true}, ServerOrigin: &cc.ServerOrigin,
		}); err != nil {
			return err
		}
		if _, err := q.TrimOpenConnectRequests(ctx, dbgen.TrimOpenConnectRequestsParams{UserID: cc.User.ID, Keep: MaxOpenRequests}); err != nil {
			return err
		}
		_, err = q.DeleteStaleConnectRequests(ctx, s.now().Add(-requestKeep))
		return err
	})
	return id, err
}
