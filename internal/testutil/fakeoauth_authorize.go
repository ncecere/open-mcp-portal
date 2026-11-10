package testutil

import (
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
