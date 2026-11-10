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
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/safepath"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
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
	return linkUsableWith(ctx, s.q, p)
}

func linkUsableWith(ctx context.Context, q store.EndpointReader, p dbgen.AuthProvider) error {
	_, err := clientOfWith(ctx, q, p)
	return err
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
