package oauth

import (
	"context"
	"errors"
	"net/url"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// AuthorizeRequest is an authorization request (RFC 6749 §4.1.1 with PKCE,
// RFC 7636, and a resource indicator, RFC 8707).
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	State               string
	Scope               string
	ScopePresent        bool
}

// Bounds.
const (
	// maxStateLen bounds state (echoed back to the client).
	maxStateLen = 1000
	// MaxQueryLen bounds an authorization request's query string.
	MaxQueryLen = 8000
)

// pkceChallenge is an S256 challenge: base64url of a SHA-256, unpadded.
var pkceChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// RequestFromQuery reads an authorization request from a query string. A
// parameter given twice is refused (RFC 6749 §3.1), before anything is
// known about the client, so as a page.
func RequestFromQuery(q url.Values) (AuthorizeRequest, error) {
	for k, v := range q {
		if len(v) > 1 {
			return AuthorizeRequest{}, pageError("invalid_request", "The request repeats the "+k+" parameter.")
		}
	}
	return AuthorizeRequest{
		ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), ResponseType: q.Get("response_type"),
		CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
		Resource: q.Get("resource"), State: q.Get("state"), Scope: q.Get("scope"), ScopePresent: q.Has("scope"),
	}, nil
}

// Check validates a request. The client and its redirect URI come first:
// until both are known to be good an error is shown as a page (ShowPage),
// never sent anywhere, so the endpoint can't be an open redirect. Other
// errors go back to the client's redirect URI. The resource must have the
// shape <APP_URL>/mcp/{slug}; whether it names a gateway the person may use
// is checked once they are signed in (Gateway), so the endpoint doesn't
// tell anyone which gateways exist.
func (s *Service) Check(ctx context.Context, r AuthorizeRequest) (Client, error) {
	c, err := s.ResolveClient(ctx, r.ClientID)
	if err != nil {
		return Client{}, err
	}
	if r.RedirectURI == "" {
		return Client{}, pageError("invalid_request", "The request has no redirect_uri.")
	}
	if !matchRedirect(c.RedirectURIs, r.RedirectURI) {
		return Client{}, pageError("invalid_request", "The redirect_uri isn't one the client registered.")
	}
	if len(r.State) > maxStateLen {
		return Client{}, pageError("invalid_request", "The state parameter is too long.")
	}
	_, resourceOK := s.resourceSlug(r.Resource)
	switch {
	case r.ResponseType != "code":
		return c, oauthError("unsupported_response_type", "Only response_type=code is supported.")
	case r.CodeChallenge == "":
		return c, oauthError("invalid_request", "PKCE is required: send code_challenge with code_challenge_method=S256.")
	case r.CodeChallengeMethod != "S256":
		return c, oauthError("invalid_request", "Only the S256 code_challenge_method is supported.")
	case !pkceChallenge.MatchString(r.CodeChallenge):
		return c, oauthError("invalid_request", "The code_challenge isn't an S256 challenge.")
	case r.Resource == "":
		return c, oauthError("invalid_target", "The resource parameter is required: the gateway's URL, "+s.issuer+"/mcp/{gateway}.")
	case !resourceOK:
		return c, oauthError("invalid_target", "The resource must be a gateway's URL, "+s.issuer+"/mcp/{gateway}.")
	}
	if _, err := r.ToolScope(); err != nil {
		return c, err
	}
	return c, nil
}

// ToolScope is the requested ceiling; no parameter preserves unclassified tools.
func (r AuthorizeRequest) ToolScope() (*toolscope.Scope, error) {
	s, err := toolscope.OAuth(r.Scope, r.ScopePresent)
	if err != nil {
		return nil, oauthError("invalid_scope", "Supported scopes are omp:read, omp:write and omp:destructive.")
	}
	return s, nil
}

// errNoGateway is the answer for a resource that isn't a gateway the
// person may use now (unknown, switched off, its team archived, or no
// access): all alike.
func errNoGateway() *Error {
	return oauthError("invalid_target", "The resource isn't a gateway you can use.")
}

// Gateway returns the gateway a checked request's resource names, when the
// person may use it now; otherwise errNoGateway (an OAuth error).
func (s *Service) Gateway(ctx context.Context, u dbgen.User, r AuthorizeRequest) (dbgen.Gateway, error) {
	slug, ok := s.resourceSlug(r.Resource)
	if !ok {
		return dbgen.Gateway{}, errNoGateway()
	}
	g, err := s.gateways.Resolve(ctx, slug)
	if e, ok := apperr.As(err); ok && e.Status == 404 {
		return g, errNoGateway()
	} else if err != nil {
		return g, err
	}
	why, err := s.gateways.Unserved(ctx, g)
	if err != nil {
		return g, err
	}
	c, err := s.gateways.CallerOf(ctx, g, u)
	if err != nil {
		return g, err
	}
	if why != "" || !c.Allowed() {
		return g, errNoGateway()
	}
	return g, nil
}

// redirect is the redirect URI with params, the state and the issuer (RFC
// 9207). Call it only for a request that passed the page checks.
func (s *Service) redirect(r AuthorizeRequest, params url.Values) string {
	u, err := url.Parse(r.RedirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if r.State != "" {
		q.Set("state", r.State)
	}
	q.Set("iss", s.issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// ErrorRedirect is where to send an error that isn't shown as a page.
func (s *Service) ErrorRedirect(r AuthorizeRequest, e *Error) string {
	return s.redirect(r, url.Values{"error": {e.Code}, "error_description": {e.Description}})
}

// DenyRedirect is where to send the person who said no.
func (s *Service) DenyRedirect(r AuthorizeRequest) string {
	return s.ErrorRedirect(r, oauthError("access_denied", "The person declined."))
}

// Remembered reports whether the person has already allowed the client on
// the gateway (an active grant), so the consent page can be skipped.
func (s *Service) Remembered(ctx context.Context, userID uuid.UUID, clientID string, gatewayID uuid.UUID) (bool, error) {
	_, err := s.q.GetActiveOAuthGrant(ctx, dbgen.GetActiveOAuthGrantParams{UserID: userID, ClientID: clientID, GatewayID: gatewayID})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ConsentState is what the portal knows about one person, client and
// gateway when an authorization request arrives.
type ConsentState struct {
	// Trusted: a metadata-document client on the admins' trusted list.
	Trusted bool
	// Remembered: the person already allowed the client on the gateway.
	Remembered bool
	// Notice: a trusted client asking for the first time with a loopback
	// redirect (decision 62). The person sees a short notice and confirms
	// once; a trusted client with an https redirect never does.
	Notice    bool
	Expansion bool
}

// Silent reports whether the request can go straight back with a code: the
// client is trusted or already allowed, and no first-use notice is due.
func (c ConsentState) Silent() bool { return (c.Trusted || c.Remembered) && !c.Notice && !c.Expansion }

// How is how the person's answer is recorded when they allow the request
// on the consent page: a confirmation of the notice for a trusted client's
// first loopback sign-in, else a consent.
func (c ConsentState) How() string {
	if c.Notice {
		return ConsentConfirmed
	}
	return ConsentAllowed
}

// ConsentState reads the state for a checked request's client and gateway.
func (s *Service) ConsentState(ctx context.Context, userID uuid.UUID, c Client, gatewayID uuid.UUID, redirectURI string, requested *toolscope.Scope) (ConsentState, error) {
	trusted, err := s.Trusted(ctx, c)
	if err != nil {
		return ConsentState{}, err
	}
	gr, err := s.q.GetActiveOAuthGrant(ctx, dbgen.GetActiveOAuthGrantParams{UserID: userID, ClientID: c.ID, GatewayID: gatewayID})
	remembered := err == nil
	if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return ConsentState{}, err
	}
	expansion := remembered && !toolscope.Subset(requested, toolscope.OAuthStored(gr.ToolScope))
	return ConsentState{Trusted: trusted, Remembered: remembered, Notice: trusted && !remembered && loopbackRedirect(redirectURI), Expansion: expansion}, nil
}

// How consent was given (audit metadata of oauth.consent and
// oauth.grant_confirmed).
const (
	ConsentAllowed = "allowed" // the person allowed it on the consent page
	ConsentTrusted = "trusted" // a trusted client: no consent screen
	// ConsentConfirmed: the person confirmed the first-use notice of a
	// trusted client with a loopback redirect (audited oauth.grant_confirmed).
	ConsentConfirmed = "confirmed"
)

// Approve records the person's consent for a checked request's client on
// the gateway (a grant, audited as oauth.consent the first time, or as
// oauth.grant_confirmed when they confirmed the notice of a trusted client)
// and
// returns the redirect with a new authorization code: single use, CodeTTL,
// bound to the grant, client, redirect URI, PKCE challenge and resource.
func (s *Service) Approve(ctx context.Context, a authz.Actor, c Client, g dbgen.Gateway, r AuthorizeRequest, how string, chosen ...*toolscope.Scope) (string, error) {
	requested, err := r.ToolScope()
	if err != nil {
		return "", err
	}
	scope := requested
	if len(chosen) > 0 {
		scope = chosen[0]
	}
	if scope != nil && len(scope.Tools) > 0 || !toolscope.Subset(scope, requested) {
		return "", oauthError("invalid_scope", "Consent may narrow but not widen the requested classes.")
	}
	// Canonicalize direct callers as well as the HTTP decoder.
	scope, err = toolscope.Parse(toolscope.JSON(scope))
	if err != nil {
		return "", err
	}
	code := newToken(codePrefix)
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// Serializes first creation and replacement, including silent flows that
		// raced with a human narrowing. The grant itself is immutable.
		if _, err := q.GetUserForUpdate(ctx, a.UserID); err != nil {
			return err
		}
		gr, err := s.grantFor(ctx, q, a, c, g, how, scope)
		if err != nil {
			return err
		}
		if err := q.DeleteExpiredOAuthCodes(ctx); err != nil {
			return err
		}
		if c.Kind == KindRegistered {
			if err := q.TouchOAuthClient(ctx, c.ID); err != nil {
				return err
			}
		}
		return q.InsertOAuthCode(ctx, dbgen.InsertOAuthCodeParams{
			CodeHash: s.digest(code), GrantID: gr.ID, ClientID: c.ID, RedirectUri: r.RedirectURI,
			CodeChallenge: r.CodeChallenge, Resource: gr.Resource, ExpiresAt: s.now().Add(CodeTTL),
		})
	})
	if err != nil {
		return "", err
	}
	return s.redirect(r, url.Values{"code": {code}}), nil
}

// grantFor returns the person's active grant for the client on the
// gateway, creating it (and auditing the consent) when there is none.
func (s *Service) grantFor(ctx context.Context, q *dbgen.Queries, a authz.Actor, c Client, g dbgen.Gateway, how string, scope *toolscope.Scope) (dbgen.OauthGrant, error) {
	gr, err := q.GetActiveOAuthGrant(ctx, dbgen.GetActiveOAuthGrantParams{UserID: a.UserID, ClientID: c.ID, GatewayID: g.ID})
	if err == nil {
		gr, err = q.LockOAuthGrant(ctx, gr.ID)
		if err != nil {
			return gr, err
		}
		if gr.RevokedAt == nil {
			old := toolscope.OAuthStored(gr.ToolScope)
			if how == ConsentTrusted && !toolscope.Subset(scope, old) {
				return gr, apperr.Conflict("consent_required", "The requested scope needs confirmation.")
			}
			if toolscope.Equal(scope, old) {
				return gr, q.RenewOAuthGrant(ctx, gr.ID)
			}
			if err = s.revokeGrant(ctx, q, a, gr.ID, ReasonScopeChanged); err != nil {
				return gr, err
			}
		}
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return gr, err
	}
	gr, err = q.InsertOAuthGrant(ctx, dbgen.InsertOAuthGrantParams{
		UserID: a.UserID, GatewayID: g.ID, ClientID: c.ID, ClientKind: c.Kind, ClientName: c.Name, ClientUri: ptr(c.URI),
		LogoUri: ptr(c.LogoURI), Resource: s.Resource(g.Slug), ToolScope: toolscope.JSON(scope),
	})
	if apperr.IsUniqueViolation(err, "oauth_grants_active_key") {
		// Allowed twice at once: the other request's grant serves.
		return gr, apperr.Conflict("consent_conflict", "This app was just connected. Try again.")
	} else if err != nil {
		return gr, err
	}
	action := "oauth.consent"
	if how == ConsentConfirmed {
		action = "oauth.grant_confirmed"
	}
	e := a.Audit(action, "oauth_grant", gr.ID.String())
	if g.TeamID.Valid {
		e.TeamID = g.TeamID.UUID
	}
	e.After = grantSnapshot(gr, g)
	e.Metadata = map[string]any{"how": how, "name": gr.ClientName + " · " + g.Name}
	return gr, audit.Record(ctx, q, e)
}

func grantSnapshot(gr dbgen.OauthGrant, g dbgen.Gateway) map[string]any {
	return map[string]any{"clientId": gr.ClientID, "clientKind": gr.ClientKind, "clientName": gr.ClientName, "clientUri": gr.ClientUri,
		"gatewayId": g.ID.String(), "gatewaySlug": g.Slug, "resource": gr.Resource, "userId": gr.UserID, "toolScope": toolscope.OAuthStored(gr.ToolScope)}
}
