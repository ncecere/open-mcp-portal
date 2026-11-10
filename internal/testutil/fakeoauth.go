package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// FakeOAuth is a third-party OAuth 2.0 provider (the authorization code
// grant with optional PKCE S256, refresh with rotation, RFC 7009
// revocation and a userinfo endpoint) for tests of delegated credentials
// and for local development (cmd/fakeoauth). Its knobs make it misbehave the
// ways real providers do: narrower grants, no scope in the answer,
// form-encoded or Slack-style answers, refused or failing refreshes, a
// failing userinfo endpoint.
//
// Endpoints: GET /authorize (a page with Approve and Deny, or straight back
// with AutoApprove), POST /token, POST /revoke, GET /userinfo.
type FakeOAuth struct {
	*httptest.Server

	// ClientID and ClientSecret are the registered client's (the secret may
	// come in the form or as HTTP Basic).
	ClientID, ClientSecret string

	mu sync.Mutex
	// AutoApprove sends the browser straight back with a code (tests);
	// otherwise /authorize shows a page with Approve and Deny.
	AutoApprove bool
	// Deny answers every authorization with error=access_denied.
	Deny bool
	// AccessTTL is an access token's life (0: no expires_in).
	AccessTTL time.Duration
	// IssueRefresh issues refresh tokens; RotateRefresh replaces one on
	// every use (the old one then fails with invalid_grant).
	IssueRefresh, RotateRefresh bool
	// GrantScopes, when set, is what every authorization grants (else what
	// was asked); OmitScope leaves scope out of token answers.
	GrantScopes []string
	OmitScope   bool
	// FailRefresh: "" (work), "invalid_grant" (400) or "unavailable" (503).
	FailRefresh string
	// RefreshGrantedScopes simulates an authorization server shrinking consent.
	RefreshGrantedScopes []string
	// BeforeCodeExchange coordinates callback races without timing sleeps.
	BeforeCodeExchange func()
	// BeforeRevoke coordinates revocation races outside the fake's mutex.
	BeforeRevoke func()
	FailRevoke   bool
	// FormEncoded answers the token endpoint form-encoded (like GitHub
	// without Accept: application/json); Slack answers like Slack's
	// oauth.v2.access with the user token under authed_user.
	FormEncoded, Slack bool
	// FailUserinfo makes /userinfo answer 500.
	FailUserinfo bool
	// RefreshDelay delays refresh answers (concurrency tests).
	RefreshDelay time.Duration
	// BeforeToken is called outside the lock with the grant type, before a
	// token is issued. Tests can block renewal without timing-based sleeps.
	BeforeToken func(string)
	// HonourRefreshScope makes a refresh request's scope parameter narrow the
	// new access token (RFC 6749 section 6, as Microsoft's endpoint does): the
	// token holds only those scopes, a scope outside the grant is
	// invalid_scope, and the refresh token issued with it keeps the whole
	// grant. Off (the default, as most providers behave), scope on refresh is
	// ignored and the token holds everything granted.
	HonourRefreshScope bool
	// Login is what /userinfo calls the account.
	Login string

	// Authorization server metadata (Phase 7, an MCP server's own
	// authorization server). IssuerPath is the issuer's path ("": the
	// root; "/login/oauth" imitates GitHub, whose metadata is served only at
	// the RFC 8414 path-insertion URL). MetadataAt serves it elsewhere
	// instead: "oidc-insert" (/.well-known/openid-configuration{path}),
	// "oidc-append" ({issuer}/.well-known/openid-configuration) or "none".
	IssuerPath, MetadataAt string
	// MetadataIssuer overrides the metadata's issuer (issuer_mismatch).
	MetadataIssuer string
	// DCR serves /register (RFC 7591) and lists it; CIMD says client ID
	// metadata documents are supported (any URL client ID is accepted).
	DCR, CIMD bool
	// NoPKCE leaves S256 out of the metadata.
	NoPKCE bool
	// ScopesSupported are listed in the metadata.
	ScopesSupported []string
	// IssParam sends iss with authorization responses and says so in the
	// metadata (RFC 9207); WrongIss sends another issuer, OmitIss none.
	IssParam, WrongIss, OmitIss bool
	// RejectResource refuses requests with a resource parameter
	// (invalid_target), as authorization servers without RFC 8707 do.
	RejectResource bool

	// The client credentials grant (decision 73: a server that authenticates
	// the portal itself). It is on by default, with the same client and secret
	// (HTTP Basic or in the form) and AccessTTL as the other grants, and no
	// refresh token. NoClientCredentials turns it off (unsupported_grant_type,
	// and the metadata doesn't list it). MachineScopes, when set, are the
	// scopes the client may ask for (any other: invalid_scope); a request
	// without scope is granted all of them, else the grant is what was asked.
	// FailClientCredentials: "" (work), "invalid_client" (401 whatever the
	// credentials), "unavailable" (503), "invalid_response" (200 without an
	// access token) or "wrong_type" (token_type DPoP). EnforceExpiry makes
	// an access token stop being active (Introspect) AccessTTL after it was
	// issued. TokenDelay delays client credentials answers (concurrency tests).
	NoClientCredentials   bool
	MachineScopes         []string
	FailClientCredentials string
	EnforceExpiry         bool
	TokenDelay            time.Duration

	codes   map[string]fakeCode
	expires map[string]time.Time // access token -> expiry (EnforceExpiry)
	// machine records every client credentials request.
	machine []ClientCredentialsRequest
	access  map[string]fakeGrant // token -> grant
	refresh map[string]fakeGrant
	clients map[string]string // registered client ID -> secret
	// registrations are the bodies of every /register request.
	registrations []map[string]any
	revoked       []string
	refreshScopes []string // the scope parameter of every refresh request ("" when absent)
	issued        []string
	issuedRT      []string
	lastAuth      url.Values
	resources     []string
	tokens        int
	refreshs      int
	authorizes    int
}

type fakeCode struct {
	redirectURI, challenge, resource, clientID string
	scopes                                     []string
}

// fakeGrant is what a token was issued for.
type fakeGrant struct {
	scopes             []string
	resource, clientID string
}

// ClientCredentialsRequest is one client credentials grant request as the
// fake received it. ClientAuth is "basic", "post" or "none"; ClientSecret is
// what the client sent (the test checks it is the secret it stored).
type ClientCredentialsRequest struct {
	ClientAuth, ClientID, ClientSecret string
	Scope, Audience, Resource          string
	// Authorized says the client credentials were right.
	Authorized bool
}

// Introspection is what the fake says about a token (its /introspect).
type Introspection struct {
	Active   bool     `json:"active"`
	Scopes   []string `json:"scopes,omitempty"`
	Resource string   `json:"resource,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
}

// NewFakeOAuth starts a fake provider on a loopback address (closed with the
// test), auto-approving, with one-hour access tokens and rotating refresh
// tokens.
func NewFakeOAuth(t testing.TB) *FakeOAuth {
	f, h := NewFakeOAuthHandler("fake-client", "fake-secret-0123456789")
	f.AutoApprove = true
	f.Server = httptest.NewServer(h)
	t.Cleanup(f.Close)
	return f
}

// NewFakeOAuthHandler builds a fake provider without starting a server.
func NewFakeOAuthHandler(clientID, clientSecret string) (*FakeOAuth, http.Handler) {
	f := &FakeOAuth{ClientID: clientID, ClientSecret: clientSecret, AccessTTL: time.Hour, IssueRefresh: true, RotateRefresh: true,
		Login: "octocat", codes: map[string]fakeCode{}, access: map[string]fakeGrant{}, refresh: map[string]fakeGrant{},
		clients: map[string]string{}, expires: map[string]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("POST /revoke", f.revoke)
	mux.HandleFunc("GET /userinfo", f.userinfo)
	mux.HandleFunc("POST /register", f.register)
	mux.HandleFunc("POST /introspect", f.introspectHTTP)
	mux.HandleFunc("GET /.well-known/", f.metadata)
	mux.HandleFunc("GET /{path...}", f.metadata)
	return f, mux
}

// base is the fake's own URL as a request reached it.
func base(r *http.Request) string { return "http://" + r.Host }

// Issuer is the authorization server's identifier (the fake's URL and
// IssuerPath).
func (f *FakeOAuth) Issuer() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.URL + f.IssuerPath
}

// Registrations are the bodies of the /register requests received.
func (f *FakeOAuth) Registrations() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.registrations...)
}

// RegisteredClients are the client IDs registered through /register.
func (f *FakeOAuth) RegisteredClients() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for id := range f.clients {
		out = append(out, id)
	}
	return out
}

// RegisteredSecrets are the client secrets issued through /register.
func (f *FakeOAuth) RegisteredSecrets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, s := range f.clients {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Introspect says whether a token is current, and for what.
func (f *FakeOAuth) Introspect(token string) Introspection {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.access[token]
	if !ok {
		return Introspection{}
	}
	if exp, has := f.expires[token]; has && f.EnforceExpiry && !time.Now().Before(exp) {
		return Introspection{}
	}
	return Introspection{Active: true, Scopes: append([]string{}, g.scopes...), Resource: g.resource, ClientID: g.clientID}
}

func (f *FakeOAuth) introspectHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f.Introspect(r.PostForm.Get("token")))
}

// Invalidate ends an access token without the client knowing (a person
// revoking the app at the provider).
func (f *FakeOAuth) Invalidate(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.access, token)
}

// InvalidateAll ends every access token (and, with refreshToo, refresh
// token).
func (f *FakeOAuth) InvalidateAll(refreshToo bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access = map[string]fakeGrant{}
	if refreshToo {
		f.refresh = map[string]fakeGrant{}
	}
}

// Resources are the resource parameters of token requests, in order ("":
// absent).
func (f *FakeOAuth) Resources() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.resources...)
}

// Set changes knobs under the fake's lock.
func (f *FakeOAuth) Set(change func(f *FakeOAuth)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func fakeToken(prefix string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// LastAuthorize is the query of the latest authorization request.
func (f *FakeOAuth) LastAuthorize() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuth
}

// Issued are the access tokens issued so far, oldest first.
func (f *FakeOAuth) Issued() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.issued...)
}

// IssuedRefresh are the refresh tokens issued so far, oldest first.
func (f *FakeOAuth) IssuedRefresh() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.issuedRT...)
}

// Revoked are the tokens revoked so far.
func (f *FakeOAuth) Revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

// TokenRequests and RefreshRequests count token endpoint requests (all, and
// refresh_token grants).
func (f *FakeOAuth) TokenRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens
}

// AuthorizeRequests counts requests that reached the authorization endpoint.
func (f *FakeOAuth) AuthorizeRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authorizes
}

// RefreshScopes are the scope parameters of the refresh requests so far, in
// order ("" for one without scope).
func (f *FakeOAuth) RefreshScopes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.refreshScopes...)
}

func (f *FakeOAuth) RefreshRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshs
}

// Valid reports whether an access token is current (issued and not
// revoked).
func (f *FakeOAuth) Valid(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.access[token]
	return ok
}
