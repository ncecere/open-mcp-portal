// OAuth sign-in for MCP clients (docs/phase4-client-auth.md,
// docs/connect-clients.md): the protocol endpoints of the authorization
// server in internal/oauth. Like /mcp they speak a protocol (OAuth 2.1, RFC
// 8414, RFC 9728, RFC 7591, RFC 7009), so they are outside api/openapi.yaml
// and the contract test skips them. Always on.

package httpapi

import (
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"strconv"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
)

const (
	// maxOAuthBody bounds token, revocation and registration requests.
	maxOAuthBody = 16 << 10
	// Per-address rates (per minute) of the protocol endpoints.
	oauthRatePerMinute    = 60
	registerRatePerMinute = 10
	// oauthConsentPath is the web app's consent page.
	oauthConsentPath = "/oauth/consent"
)

// oauthRoutes serve the protocol endpoints.
func (a *api) oauthRoutes() []route {
	on := func(name string, perMinute int, h http.HandlerFunc) http.Handler {
		return a.oauthGate(name, perMinute, h)
	}
	return []route{
		{"GET", "/.well-known/oauth-protected-resource/mcp/{slug}", http.HandlerFunc(a.oauthResourceMetadata)},
		{"GET", "/.well-known/oauth-authorization-server", http.HandlerFunc(a.oauthServerMetadata)},
		{"GET", "/oauth/authorize", on("authorize", oauthRatePerMinute, a.oauthAuthorize)},
		{"POST", "/oauth/token", on("token", oauthRatePerMinute, a.oauthToken)},
		{"POST", "/oauth/revoke", on("revoke", oauthRatePerMinute, a.oauthRevoke)},
		{"POST", "/oauth/register", on("register", registerRatePerMinute, a.oauthRegister)},
		// Without these, a GET would fall through to the web app.
		{"GET", "/oauth/token", http.HandlerFunc(oauthPostOnly)},
		{"GET", "/oauth/revoke", http.HandlerFunc(oauthPostOnly)},
		{"GET", "/oauth/register", http.HandlerFunc(oauthPostOnly)},
	}
}

// oauthPostOnly answers a GET on an endpoint that only takes POST (405).
func oauthPostOnly(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	oauthJSONError(w, http.StatusMethodNotAllowed, "invalid_request", "This endpoint only accepts POST.")
}

// oauthGate applies the endpoint's per-address rate.
func (a *api) oauthGate(name string, perMinute int, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r, a.Config.TrustedProxies)
		ok, wait, err := ratelimit.Allow(r.Context(), a.limiter, ratelimit.Bucket("oauth:"+name, ip), perMinute)
		if err != nil {
			a.oauthFail(w, r, err)
			return
		}
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfter(wait)))
			oauthJSONError(w, http.StatusTooManyRequests, "slow_down", "Too many requests. Try again shortly.")
			return
		}
		h(w, r)
	})
}

// oauthJSON writes a protocol response: plain JSON, never cached.
func oauthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthJSONError writes an OAuth error response (RFC 6749 §5.2).
func oauthJSONError(w http.ResponseWriter, status int, code, description string) {
	oauthJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// oauthFail writes err: an OAuth error as itself, anything else as a
// logged server_error.
func (a *api) oauthFail(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		oauthJSONError(w, oe.Status, oe.Code, oe.Description)
		return
	}
	a.Log.ErrorContext(r.Context(), "oauth", "err", err, "request_id", httpx.RequestID(r.Context()))
	oauthJSONError(w, http.StatusInternalServerError, "server_error", "Something went wrong. Try again shortly.")
}

// oauthResourceMetadata is a gateway's protected resource metadata (RFC
// 9728), at the address its 401 names. It is served for any slug, without
// looking the gateway up, so it doesn't tell anyone which gateways exist.
func (a *api) oauthResourceMetadata(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !oauth.ValidSlug(slug) {
		httpx.Error(w, http.StatusNotFound, "not_found", "Not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                 a.OAuth.Resource(slug),
		"authorization_servers":    []string{a.OAuth.Issuer()},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            a.Config.Instance.Name,
		"scopes_supported":         []string{"omp:read", "omp:write", "omp:destructive"},
	})
}

// oauthServerMetadata is the authorization server metadata (RFC 8414). It
// lists registration_endpoint unless an admin turned open client
// registration off.
func (a *api) oauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	iss := a.OAuth.Issuer()
	open, err := a.OAuth.OpenRegistration(r.Context())
	if err != nil {
		a.oauthFail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	doc := map[string]any{
		"issuer":                                         iss,
		"scopes_supported":                               []string{"omp:read", "omp:write", "omp:destructive"},
		"authorization_endpoint":                         iss + "/oauth/authorize",
		"token_endpoint":                                 iss + "/oauth/token",
		"revocation_endpoint":                            iss + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	}
	if open {
		doc["registration_endpoint"] = iss + "/oauth/register"
	}
	_ = json.NewEncoder(w).Encode(doc)
}

// oauthAuthorize is the authorization endpoint. Nothing about the request
// is looked at before the person is signed in: without a browser session it
// sends them to sign in and back here, so an anonymous caller can't make the
// portal fetch a client's metadata document or learn why one failed
// (threat model H-3). The only anonymous refusal is a request that is
// malformed on its face (too long, or a repeated parameter), the same page
// for both, with no reason.
//
// Signed in, a request whose client or redirect URI isn't good gets a page
// (never a redirect); other errors go back to the client. The resource must
// be a gateway they may use now; then a client they already allowed on that
// gateway, or a trusted client, goes straight back with a code, and anyone
// else (and a trusted client asking for the first time with a loopback
// redirect, decision 62) goes to the consent page of the web app with the
// same request.
func (a *api) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	user, ok, err := a.Auth.SessionUser(r)
	if err != nil {
		a.oauthPage(w, r, err)
		return
	}
	if !ok {
		a.oauthAnonymous(w, r)
		return
	}
	if user.Status != auth.StatusActive {
		a.oauthPage(w, r, &oauth.Error{Code: "access_denied", Description: "This account is suspended."})
		return
	}
	if len(r.URL.RawQuery) > oauth.MaxQueryLen {
		a.oauthPage(w, r, &oauth.Error{Code: "invalid_request", Description: "The request is too long."})
		return
	}
	req, err := oauth.RequestFromQuery(r.URL.Query())
	if err != nil {
		a.oauthPage(w, r, err)
		return
	}
	ctx := oauth.WithSource(r.Context(), httpx.ClientIP(r, a.Config.TrustedProxies))
	c, err := a.OAuth.Check(ctx, req)
	var oe *oauth.Error
	if errors.As(err, &oe) && !oe.ShowPage() {
		http.Redirect(w, r, a.OAuth.ErrorRedirect(req, oe), http.StatusFound)
		return
	} else if err != nil {
		a.oauthPage(w, r, err)
		return
	}
	g, err := a.OAuth.Gateway(r.Context(), user, req)
	if errors.As(err, &oe) {
		http.Redirect(w, r, a.OAuth.ErrorRedirect(req, oe), http.StatusFound)
		return
	} else if err != nil {
		a.oauthPage(w, r, err)
		return
	}
	requested, _ := req.ToolScope() // Check already validated it after the redirect URI.
	state, err := a.OAuth.ConsentState(r.Context(), user.ID, c, g.ID, req.RedirectURI, requested)
	if err != nil {
		a.oauthPage(w, r, err)
		return
	}
	if !state.Silent() {
		http.Redirect(w, r, oauthConsentPath+"?"+r.URL.RawQuery, http.StatusFound)
		return
	}
	actor := auth.Identity{User: user}.Actor(httpx.RequestID(r.Context()), httpx.ClientIP(r, a.Config.TrustedProxies))
	to, err := a.OAuth.Approve(r.Context(), actor, c, g, req, oauth.ConsentTrusted)
	if e, ok := apperr.As(err); ok && e.Code == "consent_required" {
		http.Redirect(w, r, oauthConsentPath+"?"+r.URL.RawQuery, http.StatusFound)
		return
	}
	if err != nil {
		a.oauthPage(w, r, err)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

// oauthAnonymous answers an authorization request without a session: sign
// in first, and come back with the whole query. The client is not resolved
// (no fetch, no reason); a request too long to come back, or repeating a
// parameter, gets the generic page.
func (a *api) oauthAnonymous(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > oauth.MaxQueryLen {
		a.oauthGenericPage(w, r)
		return
	}
	for _, v := range r.URL.Query() {
		if len(v) > 1 {
			a.oauthGenericPage(w, r)
			return
		}
	}
	http.Redirect(w, r, a.Auth.LoginURL("/oauth/authorize?"+r.URL.RawQuery), http.StatusFound)
}

// oauthPageTmpl is the authorization error page. It follows the person's
// color mode like the web app: /color-mode.js (the app's own pre-paint
// script, same origin) sets <html data-theme> from their choice in this
// browser, else the system's; without it, the system's setting applies.
var oauthPageTmpl = template.Must(template.New("oauth").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<script src="/color-mode.js"></script>
<title>Can't connect this app · {{.Instance}}</title>
<style>:root{color-scheme:light;--bg:#fff;--fg:#1f2328;--muted:#59636e;--code:#eff1f3}
:root[data-theme=dark]{color-scheme:dark;--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--code:#262c36}
@media (prefers-color-scheme:dark){:root:not([data-theme]){color-scheme:dark;--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--code:#262c36}}
html{background:var(--bg)}body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;line-height:1.5;color:var(--fg);background:var(--bg)}
h1{font-size:1.4rem}small{color:var(--muted)}code{background:var(--code);padding:0 .25rem}</style></head>
<body><main><h1>Can't connect this app</h1><p>{{.Message}}</p>
<p>Nothing was shared with the app. Close this page and try connecting again, or ask the app's maker.</p>
{{if .Code}}<p><small>Error: <code>{{.Code}}</code></small></p>{{end}}</main></body></html>`))

// oauthPage shows an authorization error to the person (400; 500 for a
// failure of ours, logged).
func (a *api) oauthPage(w http.ResponseWriter, r *http.Request, err error) {
	status, code, msg := http.StatusBadRequest, "invalid_request", "The app's request isn't valid."
	var oe *oauth.Error
	if errors.As(err, &oe) {
		code, msg = oe.Code, oe.Description
		if oe.Status != 0 {
			status = oe.Status
		}
	} else {
		a.Log.ErrorContext(r.Context(), "oauth authorize", "err", err, "request_id", httpx.RequestID(r.Context()))
		status, code, msg = http.StatusInternalServerError, "server_error", "Something went wrong. Try again shortly."
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = oauthPageTmpl.Execute(w, map[string]string{"Instance": a.Config.Instance.Name, "Message": msg, "Code": code})
}

// oauthGenericPage is the page for an anonymous caller: the same for every
// failure, naming no reason and no error code.
func (a *api) oauthGenericPage(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusBadRequest)
	_ = oauthPageTmpl.Execute(w, map[string]string{"Instance": a.Config.Instance.Name, "Message": "The app's request isn't valid.", "Code": ""})
}

// oauthForm reads a form-encoded protocol request (bounded).
func oauthForm(w http.ResponseWriter, r *http.Request) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/x-www-form-urlencoded" {
		oauthJSONError(w, http.StatusBadRequest, "invalid_request", "Send the request as application/x-www-form-urlencoded.")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if err := r.ParseForm(); err != nil {
		oauthJSONError(w, http.StatusBadRequest, "invalid_request", "The request body couldn't be read.")
		return false
	}
	return true
}

// formClientID is the client_id in the form, or the user of a Basic
// Authorization header (clients that send it there with an empty secret).
func formClientID(r *http.Request) string {
	if id := r.PostForm.Get("client_id"); id != "" {
		return id
	}
	if user, _, ok := r.BasicAuth(); ok {
		return user
	}
	return ""
}

// oauthToken is the token endpoint.
func (a *api) oauthToken(w http.ResponseWriter, r *http.Request) {
	if !oauthForm(w, r) {
		return
	}
	f := r.PostForm
	if len(f["scope"]) > 1 {
		oauthJSONError(w, http.StatusBadRequest, "invalid_request", "The scope parameter must appear at most once.")
		return
	}
	out, err := a.OAuth.Token(r.Context(), oauth.TokenRequest{
		GrantType: f.Get("grant_type"), ClientID: formClientID(r), Code: f.Get("code"), RedirectURI: f.Get("redirect_uri"),
		CodeVerifier: f.Get("code_verifier"), RefreshToken: f.Get("refresh_token"), Resource: f.Get("resource"),
		RequestID: httpx.RequestID(r.Context()), ClientIP: httpx.ClientIP(r, a.Config.TrustedProxies), Scope: f.Get("scope"), ScopePresent: f.Has("scope"),
	})
	if err != nil {
		a.oauthFail(w, r, err)
		return
	}
	oauthJSON(w, http.StatusOK, out)
}

// oauthRevoke is the revocation endpoint (RFC 7009): 200 whatever the token.
func (a *api) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if !oauthForm(w, r) {
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		oauthJSONError(w, http.StatusBadRequest, "invalid_request", "Send the token to revoke.")
		return
	}
	err := a.OAuth.Revoke(r.Context(), token, formClientID(r), httpx.RequestID(r.Context()), httpx.ClientIP(r, a.Config.TrustedProxies))
	if err != nil {
		a.oauthFail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// oauthRegister is Dynamic Client Registration (RFC 7591) for clients that
// can't use a metadata document: public clients only. MCP 2026-07-28
// deprecates it in favor of Client ID Metadata Documents (which the
// authorization server metadata advertises) but keeps it for clients that
// need it; the specification defines no metadata field to mark it
// deprecated, so none is sent. application_type (web or native) is accepted
// and echoed.
func (a *api) oauthRegister(w http.ResponseWriter, r *http.Request) {
	var in oauth.ClientMetadata
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		oauthJSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Send the client's metadata as a JSON object of at most 16 KiB.")
		return
	}
	reg, err := a.OAuth.Register(r.Context(), in, httpx.RequestID(r.Context()), httpx.ClientIP(r, a.Config.TrustedProxies))
	if err != nil {
		a.oauthFail(w, r, err)
		return
	}
	out := map[string]any{
		"client_id": reg.ID, "client_id_issued_at": reg.IssuedAt, "client_name": reg.Name, "redirect_uris": reg.RedirectURIs,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"},
	}
	if reg.ApplicationType != "" {
		out["application_type"] = reg.ApplicationType
	}
	if reg.URI != "" {
		out["client_uri"] = reg.URI
	}
	if reg.LogoURI != "" {
		out["logo_uri"] = reg.LogoURI
	}
	oauthJSON(w, http.StatusCreated, out)
}
