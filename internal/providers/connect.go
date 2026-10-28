package providers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/safepath"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Connecting an account: consent links (connect requests) that calls answer
// with, the start of an authorization (state + PKCE, bound to the browser
// session), and the provider's redirect back to /connect/callback.

// Lifetimes and limits.
const (
	// RequestTTL is a consent link's life; StateTTL an authorization's.
	RequestTTL = 10 * time.Minute
	StateTTL   = 10 * time.Minute
	// MaxOpenRequests per person; the oldest open one is dropped.
	MaxOpenRequests = 20
	// requestKeep: expired and used requests answer 410 this long, then
	// they are deleted.
	requestKeep = 24 * time.Hour
	// MaxReturnTo bounds a return path.
	MaxReturnTo = 2000
	idBytes     = 32
)

// The web app's result page and its results.
const (
	DonePath            = "/connect/done"
	ResultConnected     = "connected"
	ResultMissingScopes = "missing_scopes"
	ResultDenied        = "denied"
	ResultExpired       = "expired"
	// ResultNotAllowed: connected, but the provider's access list excludes
	// the server the link was for (decision 69).
	ResultNotAllowed  = "not_allowed"
	ResultWrongPerson = "wrong_person"
	ResultError       = "error"
)

var (
	errNoRequest      = apperr.NotFound("connect_request_not_found", "This link was made for someone else, or doesn't exist")
	errRequestExpired = apperr.New(http.StatusGone, "connect_request_expired", "This link expired. Run the tool again.")
	requestIDRE       = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func randomID() string {
	b := make([]byte, idBytes)
	_, _ = rand.Read(b) // crypto/rand never fails on supported platforms
	return base64.RawURLEncoding.EncodeToString(b)
}

// requestDigest is a request ID's stored key: base64url SHA-256.
func requestDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func requestAAD(digest string) []byte { return []byte("provider_connect_request:" + digest) }

func stateAAD(digest string) []byte { return []byte("provider_auth_state:" + digest) }

// ConnectURL is the web app's consent page for a request.
func (s *Service) ConnectURL(providerSlug, requestID string) string {
	return s.appURL + "/connect/" + providerSlug + "?request=" + requestID
}

// SafeReturnPath reports whether p is a path on this site: one leading
// slash, no "//", backslash, scheme or control character, at most
// MaxReturnTo characters; the same for every percent-decoding of p, and an
// encoded slash or backslash is refused outright (internal/safepath, shared
// with the sign-in's next).
func SafeReturnPath(p string) bool { return safepath.Local(p, MaxReturnTo) }

// union appends to a the scopes of the others it lacks, in order.
func union(lists ...[]string) []string {
	out := []string{}
	for _, l := range lists {
		for _, s := range l {
			if !contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// RequestView is a consent link as its person's confirm page sees it.
type RequestView struct {
	Request  dbgen.ProviderConnectRequest
	ID       string
	Provider ProviderRef
	// Granted are the active connection's scopes (empty without one), and
	// AccountLabel its account; RequestScopes what will be asked for.
	Granted, RequestScopes []string
	AccountLabel           *string
	// Reason is why connecting is needed now (ReasonNotConnected,
	// ReasonNeedsReconsent, ReasonMissingScopes or ReasonServerNotAllowed),
	// from the connection and the server's grant as
	// it is now; the stored reason only when it already covers the request.
	Reason string
	// The gateway as it is now (or as it was, when deleted).
	GatewaySlug, GatewayName string
	GatewayExists            bool
	// Server is the MCP server the link was made for, with its team: the
	// one the person is asked to allow (nil for an oauth server's own
	// sign-in, which is the server's alone).
	Server *ServerRef
	// AuthorizationServerHost is an oauth server's authorization server
	// host ("": a platform provider), for "act as you at github.com".
	AuthorizationServerHost string
}

// loadRequest finds a request of a person: 404 for an unknown ID or another
// person's, 410 once expired or used.
func (s *Service) loadRequest(ctx context.Context, q *dbgen.Queries, userID uuid.UUID, id string) (dbgen.ProviderConnectRequest, error) {
	if !requestIDRE.MatchString(id) {
		return dbgen.ProviderConnectRequest{}, errNoRequest
	}
	r, err := q.GetConnectRequest(ctx, requestDigest(id))
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && r.UserID != userID) {
		return r, errNoRequest
	} else if err != nil {
		return r, err
	}
	if r.UsedAt != nil || !s.now().Before(r.ExpiresAt) {
		return r, errRequestExpired
	}
	return r, nil
}

// GetRequest returns a consent link for the person it was made for.
func (s *Service) GetRequest(ctx context.Context, a authz.Actor, id string) (RequestView, error) {
	r, err := s.loadRequest(ctx, s.q, a.UserID, id)
	if err != nil {
		return RequestView{}, err
	}
	p, err := getProvider(ctx, s.q, r.ProviderID, false)
	if err != nil {
		return RequestView{}, err
	}
	ref, err := s.refOf(ctx, s.q, p)
	if err != nil {
		return RequestView{}, err
	}
	v := RequestView{Request: r, ID: id, Provider: ref, Granted: []string{}, GatewaySlug: r.GatewaySlug, GatewayName: r.GatewayName,
		Reason: ReasonNotConnected}
	var sv dbgen.McpServer
	if p.Kind != KindMCPServer {
		// The server this link allows, as it is now: a link for another
		// origin (or provider) than the server has now is no longer valid.
		if sv, err = requestServer(ctx, s.q, r); err != nil {
			return RequestView{}, err
		}
		sr, err := s.q.GetServerRef(ctx, sv.ID)
		if err != nil {
			return RequestView{}, err
		}
		v.Server = &ServerRef{ID: sr.ID, Slug: sr.Slug, Name: sr.Name, TeamSlug: sr.TeamSlug, TeamName: sr.TeamName}
	}
	if p.Kind == KindMCPServer {
		as := deref(p.AuthorizationServer)
		if as == "" {
			as = p.AuthorizationUrl
		}
		if u, err := url.Parse(as); err == nil {
			v.AuthorizationServerHost = u.Hostname()
		}
	}
	if c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: a.UserID, ProviderID: p.ID}); err == nil {
		v.AccountLabel = c.AccountLabel
		switch {
		case c.Status != StatusActive:
			v.Reason = ReasonNeedsReconsent
		case !Covers(c.Scopes, r.RequiredScopes):
			v.Granted, v.Reason = nonNil(c.Scopes), ReasonMissingScopes
		case p.Kind != KindMCPServer && !s.hasGrant(ctx, c, sv, r.RequiredScopes):
			v.Granted, v.Reason = nonNil(c.Scopes), ReasonServerNotAllowed
		default:
			// Connected since the link was made: nothing is missing now.
			v.Granted, v.Reason = nonNil(c.Scopes), r.Reason
		}
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return RequestView{}, err
	}
	v.RequestScopes = union(v.Granted, r.RequiredScopes)
	if g, err := s.q.GetGateway(ctx, r.GatewayID); err == nil {
		v.GatewaySlug, v.GatewayName, v.GatewayExists = g.Slug, g.Name, true
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return RequestView{}, err
	}
	return v, nil
}

// hasGrant: the person's connection is allowed for the server at its
// current origin, for scopes (a lookup failure counts as not allowed).
func (s *Service) hasGrant(ctx context.Context, c dbgen.ProviderConnection, sv dbgen.McpServer, scopes []string) bool {
	g, err := s.q.GetProviderServerGrant(ctx, dbgen.GetProviderServerGrantParams{ConnectionID: c.ID, ServerID: sv.ID})
	return err == nil && g.Origin == registry.OriginOf(sv.URL) && Covers(g.Scopes, scopes)
}

func (s *Service) refOf(ctx context.Context, q *dbgen.Queries, p dbgen.AuthProvider) (ProviderRef, error) {
	out := ProviderRef{ID: p.ID, Slug: p.Slug, Name: p.Name, Preset: p.Preset, LogoURL: p.LogoUrl, Kind: p.Kind}
	if p.ServerID.Valid {
		r, err := q.GetServerRef(ctx, p.ServerID.UUID)
		if err != nil {
			return out, err
		}
		out.Server = &ServerRef{ID: r.ID, Slug: r.Slug, Name: r.Name, TeamSlug: r.TeamSlug}
	}
	return out, nil
}

// StartInput begins connecting. SessionID is the caller's browser session.
type StartInput struct {
	ProviderID uuid.UUID
	RequestID  *string
	ReturnTo   *string
	Scopes     *[]string
	SessionID  string
	// ServerBoundAllowed: the caller may start a sign-in to an oauth
	// server's own provider without a consent link (they can use one of the
	// server's capabilities through a gateway now; checked by the caller).
	ServerBoundAllowed bool
}

// Started says where to send the browser.
type Started struct {
	AuthorizeURL string
	Scopes       []string
	ExpiresAt    time.Time
}

func pkcePair() (verifier, challenge string) {
	verifier = randomID()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// Start begins connecting (or reconnecting) an account: it stores a
// single-use state bound to the browser session, the person, the provider
// and the request, and returns the provider's authorization URL, built from
// the stored settings only. The scopes asked for are the union of the
// connection's granted scopes (when active), the caller's scopes (or the
// provider's default scopes when neither scopes nor a request is given) and
// the request's required scopes.
func (s *Service) Start(ctx context.Context, a authz.Actor, in StartInput) (Started, error) {
	if in.SessionID == "" {
		return Started{}, apperr.New(http.StatusForbidden, "session_required", "Connect accounts from the web app")
	}
	if in.ReturnTo != nil && !SafeReturnPath(*in.ReturnTo) {
		return Started{}, apperr.Invalid("invalid_return_to", "returnTo must be a path on this site")
	}
	var extra []string
	if in.Scopes != nil {
		var err error
		if extra, err = normalizeScopes(*in.Scopes); err != nil {
			return Started{}, err
		}
	}
	p, err := getProvider(ctx, s.q, in.ProviderID, false)
	if err != nil {
		return Started{}, err
	}
	if !p.Enabled {
		return Started{}, errNoProvider
	}
	if p.Kind == KindMCPServer {
		if in.RequestID == nil && !in.ServerBoundAllowed {
			return Started{}, errNoProvider
		}
		if err := s.linkUsable(ctx, p); err != nil {
			return Started{}, errNoProvider
		}
	}
	var requestDig *string
	var required []string
	if in.RequestID != nil {
		r, err := s.loadRequest(ctx, s.q, a.UserID, *in.RequestID)
		if err != nil {
			return Started{}, err
		}
		if r.ProviderID != p.ID {
			return Started{}, apperr.Conflict("provider_mismatch", "This link is for another provider")
		}
		if p.Kind != KindMCPServer {
			// The link is for one server at one origin; if either changed it
			// can't be used to connect either.
			if _, err := requestServer(ctx, s.q, r); err != nil {
				return Started{}, err
			}
		}
		d := r.IDDigest
		requestDig, required = &d, nonNil(r.RequiredScopes)
	}
	granted := []string{}
	if c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: a.UserID, ProviderID: p.ID}); err == nil {
		if c.Status == StatusActive {
			granted = nonNil(c.Scopes)
		}
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Started{}, err
	}
	asked := extra
	if in.Scopes == nil && in.RequestID == nil {
		asked = nonNil(p.DefaultScopes)
	}
	scopes := union(granted, asked, required)
	mustHave := union(required, extra)
	if in.Scopes == nil && in.RequestID == nil {
		mustHave = asked
	}
	return s.begin(ctx, a, p, in.SessionID, scopes, mustHave, requestDig, in.ReturnTo, uuid.NullUUID{})
}

// begin stores a single-use state bound to the session, person, provider,
// request (or the server being set up) and resource, and returns the
// authorization URL.
func (s *Service) begin(ctx context.Context, a authz.Actor, p dbgen.AuthProvider, sessionID string, scopes, mustHave []string,
	requestDig, returnTo *string, setupServer uuid.NullUUID) (Started, error) {
	client, err := s.clientOf(ctx, p)
	if err != nil {
		return Started{}, err
	}
	state := randomID()
	digest := auth.Digest(state)
	expires := s.now().Add(StateTTL)
	var verifier, challenge string
	var verifierCT []byte
	// PKCE S256 is required by the MCP spec for oauth servers.
	if p.Pkce || p.Kind == KindMCPServer {
		verifier, challenge = pkcePair()
		if verifierCT, err = s.box.Seal([]byte(verifier), stateAAD(digest)); err != nil {
			return Started{}, err
		}
	}
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := q.DeleteExpiredProviderAuthStates(ctx); err != nil {
			return err
		}
		return q.InsertProviderAuthState(ctx, dbgen.InsertProviderAuthStateParams{
			StateDigest: digest, UserID: a.UserID, SessionDigest: auth.Digest(sessionID), ProviderID: p.ID, Scopes: scopes,
			RequiredScopes: mustHave, CodeVerifierCipher: verifierCT, RequestDigest: requestDig, ReturnTo: returnTo, ExpiresAt: expires,
			SetupServerID: setupServer, Resource: p.Resource,
		})
	})
	if err != nil {
		return Started{}, err
	}
	return Started{AuthorizeURL: s.authorizeURL(p, client, state, challenge, scopes), Scopes: scopes, ExpiresAt: expires}, nil
}

// linkUsable: an oauth server registered with platform_provider can sign in
// only while the platform provider is on and its endpoints still match.
func (s *Service) linkUsable(ctx context.Context, p dbgen.AuthProvider) error {
	if !p.LinkProviderID.Valid {
		return nil
	}
	l, err := s.q.GetAuthProvider(ctx, p.LinkProviderID.UUID)
	if err != nil {
		return err
	}
	if !l.Enabled || l.AuthorizationUrl != p.AuthorizationUrl || l.TokenUrl != p.TokenUrl {
		return errLinkMismatch
	}
	return nil
}

var errLinkMismatch = apperr.New(http.StatusUnprocessableEntity, "provider_mismatch",
	"The platform provider this server signs in with is turned off or no longer matches its authorization server")

// SetupStart begins the setup sign-in of an oauth server
// (authorizeTeamMcpServerSetup): the caller's own connection to the
// server's provider, with the server's scopes. After the callback it
// becomes the server's setup connection and capabilities are read with it.
// The caller checked the server (editors and above, oauth mode).
func (s *Service) SetupStart(ctx context.Context, a authz.Actor, sv dbgen.McpServer, p dbgen.AuthProvider, teamSlug string,
	returnTo *string, sessionID string) (Started, error) {
	if sessionID == "" {
		return Started{}, apperr.New(http.StatusForbidden, "session_required", "Sign in from the web app")
	}
	if returnTo != nil && !SafeReturnPath(*returnTo) {
		return Started{}, apperr.Invalid("invalid_return_to", "returnTo must be a path on this site")
	}
	if returnTo == nil {
		def := "/teams/" + teamSlug + "/servers/" + sv.ID.String() + "?setup=connected"
		returnTo = &def
	}
	if err := s.linkUsable(ctx, p); err != nil {
		return Started{}, err
	}
	granted := []string{}
	if c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: a.UserID, ProviderID: p.ID}); err == nil {
		if c.Status == StatusActive {
			granted = nonNil(c.Scopes)
		}
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Started{}, err
	}
	want := nonNil(p.DefaultScopes)
	return s.begin(ctx, a, p, sessionID, union(granted, want), want, nil, returnTo, uuid.NullUUID{UUID: sv.ID, Valid: true})
}

func normalizeScopes(in []string) ([]string, error) { return registry.NormalizeScopes(in) }

// authorizeURL builds the provider's authorization request from its stored
// settings; client is the provider whose client is used (clientOf).
func (s *Service) authorizeURL(p, client dbgen.AuthProvider, state, challenge string, scopes []string) string {
	q := url.Values{}
	for k, v := range extraParams(client.ExtraAuthorizeParams) {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", client.ClientID)
	q.Set("redirect_uri", s.RedirectURI())
	q.Set("state", state)
	if len(scopes) > 0 {
		q.Set(client.ScopeParam, strings.Join(scopes, client.ScopeSeparator))
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	if p.Kind == KindMCPServer && p.SendResource && p.Resource != nil {
		// RFC 8707: the token is for this MCP server only (the MCP spec).
		q.Set("resource", *p.Resource)
	}
	return p.AuthorizationUrl + "?" + q.Encode()
}

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
		row, viaRequest, err := s.store(ctx, q, actor, in.User, p, st, tok, granted, label, expires)
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
	tok tokenSet, granted []string, label string, expires *time.Time) (dbgen.ProviderConnection, bool, error) {
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

// Cleanup deletes expired authorization states, and connect requests a day
// after they expired. Safe on every replica.
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	n, err := s.q.DeleteExpiredProviderAuthStates(ctx)
	if err != nil {
		return n, err
	}
	serviceN, err := s.q.DeleteExpiredServiceConnectionAuthStates(ctx)
	if err != nil {
		return n, err
	}
	n += serviceN
	m, err := s.q.DeleteStaleConnectRequests(ctx, s.now().Add(-requestKeep))
	return n + m, err
}
