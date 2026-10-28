package testutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
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

// metadata serves RFC 8414 / OpenID Connect metadata where MetadataAt says.
func (f *FakeOAuth) metadata(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	path, at, iss := f.IssuerPath, f.MetadataAt, f.MetadataIssuer
	dcr, cimd, noPKCE, issParam, noCC := f.DCR, f.CIMD, f.NoPKCE, f.IssParam, f.NoClientCredentials
	scopes := append([]string{}, f.ScopesSupported...)
	f.mu.Unlock()
	want := "/.well-known/oauth-authorization-server" + path
	switch at {
	case "oidc-insert":
		want = "/.well-known/openid-configuration" + path
	case "oidc-append":
		want = path + "/.well-known/openid-configuration"
	case "none":
		want = ""
	}
	if r.URL.Path != want || want == "" {
		http.NotFound(w, r)
		return
	}
	b := base(r)
	if iss == "" {
		iss = b + path
	}
	methods := []string{"S256"}
	if noPKCE {
		methods = []string{"plain"}
	}
	grants := []string{"authorization_code", "refresh_token"}
	if !noCC {
		grants = append(grants, "client_credentials")
	}
	md := map[string]any{"issuer": iss, "authorization_endpoint": b + "/authorize", "token_endpoint": b + "/token",
		"revocation_endpoint": b + "/revoke", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": methods,
		"grant_types_supported":                 grants,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"scopes_supported":                      scopes, "authorization_response_iss_parameter_supported": issParam}
	if dcr {
		md["registration_endpoint"] = b + "/register"
	}
	if cimd {
		md["client_id_metadata_document_supported"] = true
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(md)
}

// register is RFC 7591 dynamic client registration.
func (f *FakeOAuth) register(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	on := f.DCR
	f.mu.Unlock()
	if !on {
		http.NotFound(w, r)
		return
	}
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		Method       string   `json:"token_endpoint_auth_method"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	var whole map[string]any
	_ = json.Unmarshal(raw, &whole)
	f.mu.Lock()
	f.registrations = append(f.registrations, whole)
	f.mu.Unlock()
	if err := json.Unmarshal(raw, &in); err != nil || len(in.RedirectURIs) == 0 {
		f.fail(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	id, secret := fakeToken("dcr_"), ""
	if in.Method != "none" {
		secret = fakeToken("dcrs_")
	} else {
		in.Method = "none"
	}
	f.mu.Lock()
	f.clients[id] = secret
	f.mu.Unlock()
	out := map[string]any{"client_id": id, "token_endpoint_auth_method": in.Method, "redirect_uris": in.RedirectURIs,
		"client_id_issued_at": time.Now().Unix()}
	if secret != "" {
		out["client_secret"], out["client_secret_expires_at"] = secret, 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
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

// knownClient reports whether a client ID may authorize: the configured
// one, a registered one, or (with CIMD) a URL.
func (f *FakeOAuth) knownClient(id string) bool {
	if id == f.ClientID {
		return true
	}
	if _, ok := f.clients[id]; ok {
		return true
	}
	return f.CIMD && (strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://"))
}

var fakeConsentPage = template.Must(template.New("consent").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Fake OAuth provider</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;line-height:1.5}
a{display:inline-block;margin-right:1rem;padding:.5rem 1rem;border:1px solid #888;border-radius:.4rem;text-decoration:none}</style></head>
<body><h1>Fake OAuth provider</h1><p>An app ({{.Client}}) asks for these scopes:</p><ul>{{range .Scopes}}<li><code>{{.}}</code></li>{{else}}<li>(none)</li>{{end}}</ul>
<p><a href="{{.Approve}}">Approve</a><a href="{{.Deny}}">Deny</a></p></body></html>`))

func (f *FakeOAuth) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, state := q.Get("redirect_uri"), q.Get("state")
	f.mu.Lock()
	f.authorizes++
	known := f.knownClient(q.Get("client_id"))
	f.mu.Unlock()
	if q.Get("response_type") != "code" || !known || redirect == "" || state == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if m := q.Get("code_challenge_method"); q.Get("code_challenge") != "" && m != "S256" {
		http.Error(w, "only S256", http.StatusBadRequest)
		return
	}
	scopes := strings.FieldsFunc(q.Get("scope")+","+q.Get("user_scope"), func(r rune) bool { return r == ' ' || r == ',' })
	f.mu.Lock()
	f.lastAuth = q
	auto, deny := f.AutoApprove, f.Deny
	if f.GrantScopes != nil {
		scopes = append([]string(nil), f.GrantScopes...)
	}
	issParam, wrongIss, omitIss, rejectResource, issuer := f.IssParam, f.WrongIss, f.OmitIss, f.RejectResource, base(r)+f.IssuerPath
	f.mu.Unlock()
	back, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	answer := func(v url.Values) string {
		if issParam && !omitIss {
			v.Set("iss", issuer)
			if wrongIss {
				v.Set("iss", "https://evil.example/login/oauth")
			}
		}
		u := *back
		u.RawQuery = v.Encode()
		return u.String()
	}
	denied := answer(url.Values{"error": {"access_denied"}, "state": {state}})
	if rejectResource && q.Get("resource") != "" {
		http.Redirect(w, r, answer(url.Values{"error": {"invalid_target"}, "state": {state}}), http.StatusFound)
		return
	}
	if deny || q.Get("decision") == "deny" {
		http.Redirect(w, r, denied, http.StatusFound)
		return
	}
	if !auto && q.Get("decision") != "approve" {
		approve := *r.URL
		aq := approve.Query()
		aq.Set("decision", "approve")
		approve.RawQuery = aq.Encode()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = fakeConsentPage.Execute(w, map[string]any{"Client": f.ClientID, "Scopes": scopes, "Approve": approve.String(), "Deny": denied})
		return
	}
	code := fakeToken("fcode_")
	f.mu.Lock()
	f.codes[code] = fakeCode{redirectURI: redirect, challenge: q.Get("code_challenge"), scopes: scopes, resource: q.Get("resource"),
		clientID: q.Get("client_id")}
	f.mu.Unlock()
	http.Redirect(w, r, answer(url.Values{"code": {code}, "state": {state}}), http.StatusFound)
}

// clientOK authenticates the client of a token or revocation request and
// returns its ID.
func (f *FakeOAuth) clientOK(r *http.Request) (string, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if want, ok := f.clients[id]; ok {
		return id, want == "" || secret == want
	}
	if f.CIMD && id != f.ClientID && (strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://")) {
		return id, true // a public client identified by its metadata document
	}
	return id, id == f.ClientID && (f.ClientSecret == "" || secret == f.ClientSecret)
}

func (f *FakeOAuth) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "fake provider says no"})
}

func (f *FakeOAuth) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	f.mu.Lock()
	f.tokens++
	f.resources = append(f.resources, r.PostForm.Get("resource"))
	rejectResource, beforeToken := f.RejectResource, f.BeforeToken
	f.mu.Unlock()
	if beforeToken != nil {
		beforeToken(r.PostForm.Get("grant_type"))
	}
	clientID, ok := f.clientOK(r)
	if r.PostForm.Get("grant_type") == "client_credentials" {
		f.recordClientCredentials(r, clientID, ok)
	}
	if !ok {
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if rejectResource && r.PostForm.Get("resource") != "" {
		f.fail(w, http.StatusBadRequest, "invalid_target")
		return
	}
	var scopes []string
	resource := r.PostForm.Get("resource")
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.mu.Lock()
		hook := f.BeforeCodeExchange
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		f.mu.Lock()
		c, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		if !ok || c.redirectURI != r.PostForm.Get("redirect_uri") || c.clientID != clientID ||
			(c.resource != "" && resource != "" && c.resource != resource) {
			f.fail(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		if resource == "" {
			resource = c.resource
		}
		if c.challenge != "" {
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
				f.fail(w, http.StatusBadRequest, "invalid_grant")
				return
			}
		}
		scopes = c.scopes
	case "refresh_token":
		f.mu.Lock()
		f.refreshs++
		f.refreshScopes = append(f.refreshScopes, r.PostForm.Get("scope"))
		delay, failMode := f.RefreshDelay, f.FailRefresh
		f.mu.Unlock()
		time.Sleep(delay)
		switch failMode {
		case "invalid_grant", "invalid_scope":
			f.fail(w, http.StatusBadRequest, failMode)
			return
		case "unavailable":
			http.Error(w, "upstream down", http.StatusServiceUnavailable)
			return
		}
		f.mu.Lock()
		rt := r.PostForm.Get("refresh_token")
		g, ok := f.refresh[rt]
		if ok && f.RotateRefresh {
			delete(f.refresh, rt)
		}
		f.mu.Unlock()
		if !ok || g.clientID != clientID {
			f.fail(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		scopes = g.scopes
		if resource == "" {
			resource = g.resource
		}
		f.mu.Lock()
		honour := f.HonourRefreshScope
		if f.RefreshGrantedScopes != nil {
			scopes = slices.Clone(f.RefreshGrantedScopes)
		}
		f.mu.Unlock()
		if want := strings.FieldsFunc(r.PostForm.Get("scope"), func(r rune) bool { return r == ' ' || r == ',' }); honour && len(want) > 0 {
			for _, sc := range want {
				if !slices.Contains(g.scopes, sc) {
					f.fail(w, http.StatusBadRequest, "invalid_scope")
					return
				}
			}
			f.issue(w, r, fakeGrant{scopes: want, resource: resource, clientID: clientID}, g)
			return
		}
	case "client_credentials":
		f.clientCredentials(w, r, clientID, resource)
		return
	default:
		f.fail(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	g := fakeGrant{scopes: scopes, resource: resource, clientID: clientID}
	f.issue(w, r, g, g)
}

// issue answers with a new access token for g (and a refresh token for rg,
// which differs from g when a refresh narrowed the access token).
func (f *FakeOAuth) issue(w http.ResponseWriter, r *http.Request, g, rg fakeGrant) {
	scopes := g.scopes
	f.mu.Lock()
	access := fakeToken("fat_")
	f.access[access] = g
	if f.AccessTTL > 0 {
		f.expires[access] = time.Now().Add(f.AccessTTL)
	}
	f.issued = append(f.issued, access)
	out := map[string]any{"access_token": access, "token_type": "bearer"}
	if f.AccessTTL > 0 {
		out["expires_in"] = int64(f.AccessTTL / time.Second)
	}
	refresh := ""
	if f.IssueRefresh {
		refresh = r.PostForm.Get("refresh_token")
		if refresh == "" || f.RotateRefresh {
			refresh = fakeToken("frt_")
		}
		f.refresh[refresh] = rg
		f.issuedRT = append(f.issuedRT, refresh)
		out["refresh_token"] = refresh
	}
	if !f.OmitScope {
		out["scope"] = strings.Join(scopes, " ")
	}
	form, slack := f.FormEncoded, f.Slack
	f.mu.Unlock()
	switch {
	case slack:
		if s, ok := out["scope"].(string); ok {
			out["scope"] = strings.ReplaceAll(s, " ", ",")
		}
		out["token_type"] = "user"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "access_token": "xoxb-bot-not-for-people", "token_type": "bot",
			"authed_user": out})
	case form:
		v := url.Values{}
		for k, val := range out {
			v.Set(k, fmt.Sprint(val))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte(v.Encode()))
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (f *FakeOAuth) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if _, ok := f.clientOK(r); !ok {
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	token := r.PostForm.Get("token")
	f.mu.Lock()
	f.revoked = append(f.revoked, token)
	delete(f.access, token)
	if _, ok := f.refresh[token]; ok {
		delete(f.refresh, token)
		// Revoking a refresh token ends its access tokens too (as Google does).
		for k := range f.access {
			delete(f.access, k)
		}
	}
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (f *FakeOAuth) userinfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	failing, login := f.FailUserinfo, f.Login
	_, ok := f.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	f.mu.Unlock()
	switch {
	case failing:
		http.Error(w, "userinfo down", http.StatusInternalServerError)
	case !ok:
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"login": login, "sub": "fake-" + login})
	}
}

// TokenDigest is the hex SHA-256 prefix of a token that the fake MCP
// server's provider_token tool reports (never the token itself).
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

// recordClientCredentials notes a client credentials request.
func (f *FakeOAuth) recordClientCredentials(r *http.Request, clientID string, ok bool) {
	method := "none"
	secret := r.PostForm.Get("client_secret")
	if _, sec, basic := r.BasicAuth(); basic {
		method = "basic"
		secret, _ = url.QueryUnescape(sec)
	} else if secret != "" {
		method = "post"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.machine = append(f.machine, ClientCredentialsRequest{ClientAuth: method, ClientID: clientID, ClientSecret: secret,
		Scope: r.PostForm.Get("scope"), Audience: r.PostForm.Get("audience"), Resource: r.PostForm.Get("resource"), Authorized: ok})
}

// ClientCredentialsRequests are the client credentials grant requests so
// far, in order.
func (f *FakeOAuth) ClientCredentialsRequests() []ClientCredentialsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ClientCredentialsRequest(nil), f.machine...)
}

// clientCredentials answers the client credentials grant for an authenticated
// client: an access token (no refresh token) for the scopes asked for.
func (f *FakeOAuth) clientCredentials(w http.ResponseWriter, r *http.Request, clientID, resource string) {
	f.mu.Lock()
	off, fail, allowed, delay := f.NoClientCredentials, f.FailClientCredentials, append([]string(nil), f.MachineScopes...), f.TokenDelay
	f.mu.Unlock()
	time.Sleep(delay)
	switch {
	case off:
		f.fail(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	case fail == "invalid_client":
		f.fail(w, http.StatusUnauthorized, "invalid_client")
		return
	case fail == "unavailable":
		http.Error(w, "authorization server down", http.StatusServiceUnavailable)
		return
	case fail == "invalid_response":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"bearer"}`))
		return
	}
	want := strings.Fields(r.PostForm.Get("scope"))
	for _, sc := range want {
		if len(allowed) > 0 && !slices.Contains(allowed, sc) {
			f.fail(w, http.StatusBadRequest, "invalid_scope")
			return
		}
	}
	if len(want) == 0 {
		want = allowed
	}
	if want == nil {
		want = []string{}
	}
	f.mu.Lock()
	access := fakeToken("fmt_")
	f.access[access] = fakeGrant{scopes: want, resource: resource, clientID: clientID}
	if f.AccessTTL > 0 {
		f.expires[access] = time.Now().Add(f.AccessTTL)
	}
	f.issued = append(f.issued, access)
	out := map[string]any{"access_token": access, "token_type": "bearer"}
	if fail == "wrong_type" {
		out["token_type"] = "DPoP"
	}
	if f.AccessTTL > 0 {
		out["expires_in"] = int64(f.AccessTTL / time.Second)
	}
	if !f.OmitScope {
		out["scope"] = strings.Join(want, " ")
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
