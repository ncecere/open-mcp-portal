package httpapi_test

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
)

// docResponse is what the document server answers on one path.
type docResponse struct {
	status      int
	contentType string
	body        string
	redirect    string
}

// docServer serves client metadata documents over TLS.
type docServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths map[string]docResponse
	hits  map[string]int
}

func newDocServer(t *testing.T) *docServer {
	d := &docServer{paths: map[string]docResponse{}, hits: map[string]int{}}
	d.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		res, ok := d.paths[r.URL.Path]
		d.hits[r.URL.Path]++
		d.mu.Unlock()
		switch {
		case !ok:
			http.NotFound(w, r)
		case res.redirect != "":
			http.Redirect(w, r, res.redirect, http.StatusFound)
		default:
			w.Header().Set("Content-Type", res.contentType)
			w.WriteHeader(res.status)
			_, _ = io.WriteString(w, res.body)
		}
	}))
	t.Cleanup(d.Close)
	return d
}

func (d *docServer) set(path string, r docResponse) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths[path] = r
	return d.URL + path
}

// client publishes a metadata document for a client and returns its ID.
func (d *docServer) client(path, name string, redirects ...string) string {
	id := d.URL + path
	b, _ := json.Marshal(map[string]any{"client_id": id, "client_name": name, "client_uri": "https://assistant.example.com",
		"redirect_uris": redirects, "token_endpoint_auth_method": "none"})
	return d.set(path, docResponse{status: 200, contentType: "application/json", body: string(b)})
}

func (d *docServer) hitCount(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hits[path]
}

// trustDocs makes the app's metadata fetches trust the document server's
// certificate (the address guard stays: the development allowance lets
// them reach 127.0.0.1).
func trustDocs(d *docServer) func(*httpapi.Deps) {
	return func(deps *httpapi.Deps) {
		deps.OAuth.SetMetadataTLS(&tls.Config{RootCAs: d.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
	}
}

// pkce is a verifier and its S256 challenge.
type pkce struct{ verifier, challenge string }

func newPKCE() pkce {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

const testRedirect = "http://127.0.0.1:4567/callback"

// authQuery is an authorization request of a client for a gateway, with
// overrides ("" deletes a parameter).
func authQuery(app *testApp, clientID, slug string, p pkce, over map[string]string) url.Values {
	q := url.Values{"client_id": {clientID}, "redirect_uri": {testRedirect}, "response_type": {"code"}, "code_challenge": {p.challenge},
		"code_challenge_method": {"S256"}, "resource": {app.URL + "/mcp/" + slug}, "state": {"st-1"}}
	for k, v := range over {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q
}

func noFollow(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// authorize calls the authorization endpoint as a browser (s: signed in,
// nil: signed out) without following its redirect.
func authorize(t *testing.T, app *testApp, s *session, q url.Values) (*http.Response, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: noFollow}
	if s != nil {
		c.Jar = s.client.Jar
	}
	res, err := c.Get(app.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

// wantPage checks an authorization error shown as a page, never a redirect.
// The page follows the person's color mode: the app's same-origin
// color-mode script (allowed by its CSP, nothing else is) and dark styles.
func wantPage(t *testing.T, what string, res *http.Response, body, code string) {
	t.Helper()
	if res.StatusCode != 400 || res.Header.Get("Location") != "" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(body, code) {
		t.Errorf("%s = %d %q %s", what, res.StatusCode, res.Header.Get("Location"), body)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(body, `<script src="/color-mode.js"></script>`) || !strings.Contains(body, ":root[data-theme=dark]") ||
		!strings.Contains(body, "prefers-color-scheme:dark") || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("%s: the page doesn't follow the color mode (CSP %q)", what, csp)
	}
}

// wantRedirectError checks an authorization error sent back to the client.
func wantRedirectError(t *testing.T, app *testApp, what string, res *http.Response, code string) {
	t.Helper()
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc == nil || loc.Scheme+"://"+loc.Host+loc.Path != testRedirect || loc.Query().Get("error") != code ||
		loc.Query().Get("iss") != app.URL || loc.Query().Get("state") != "st-1" {
		t.Errorf("%s = %d %q, want error %s", what, res.StatusCode, res.Header.Get("Location"), code)
	}
}

// codeFrom reads the code of a successful authorization redirect.
func codeFrom(t *testing.T, app *testApp, what, location string) string {
	t.Helper()
	loc, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, "http://127.0.0.1:") || loc.Query().Get("code") == "" ||
		loc.Query().Get("iss") != app.URL || loc.Query().Get("error") != "" {
		t.Fatalf("%s: redirect %q", what, location)
	}
	return loc.Query().Get("code")
}

// consent decides on the consent page and returns where the browser goes.
func consent(t *testing.T, s *session, q url.Values, decision string) string {
	t.Helper()
	var out struct {
		RedirectUrl string `json:"redirectUrl"`
	}
	code, ec := s.call("POST", "/v1/oauth/consent", map[string]any{"query": q.Encode(), "decision": decision}, &out, nil)
	mustCode(t, "consent "+decision, code, ec, 200, "")
	return out.RedirectUrl
}

// tokenCall posts to the token endpoint (form-encoded).
func tokenCall(t *testing.T, app *testApp, path string, form url.Values) (int, map[string]any, http.Header) {
	t.Helper()
	res, err := http.PostForm(app.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, res.Header
}

func wantOAuthError(t *testing.T, what string, status int, out map[string]any, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || out["error"] != code {
		t.Errorf("%s = %d %v, want %d %s", what, status, out, wantStatus, code)
	}
}

// exchange redeems a code and returns the access and refresh tokens.
func exchange(t *testing.T, app *testApp, clientID, code string, p pkce, extra url.Values) (string, string) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {p.verifier},
		"redirect_uri": {testRedirect}}
	for k, v := range extra {
		form[k] = v
	}
	status, out, hdr := tokenCall(t, app, "/oauth/token", form)
	access, _ := out["access_token"].(string)
	refresh, _ := out["refresh_token"].(string)
	if status != 200 || !strings.HasPrefix(access, "ompat_") || !strings.HasPrefix(refresh, "omprt_") || out["token_type"] != "Bearer" ||
		out["expires_in"] != float64(3600) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange = %d %v", status, out)
	}
	return access, refresh
}

// connectApp signs a client in to a gateway (allowing it on the consent
// page unless it is remembered or trusted) and returns its tokens.
func connectApp(t *testing.T, app *testApp, s *session, clientID, slug string) (string, string) {
	t.Helper()
	p := newPKCE()
	q := authQuery(app, clientID, slug, p, nil)
	res, _ := authorize(t, app, s, q)
	loc := res.Header.Get("Location")
	if strings.HasPrefix(loc, "/oauth/consent?") {
		loc = consent(t, s, q, "allow")
	}
	return exchange(t, app, clientID, codeFrom(t, app, "connect "+slug, loc), p, nil)
}

// oauthEnv is a runtime environment (team gateway "support", platform
// gateway "shared" granted to blair, both selecting whoami) with a
// document server whose certificate the app trusts.
type oauthEnv struct {
	*rtEnv
	docs *docServer
	logs *syncBuffer
}

func newOAuthEnv(t *testing.T) *oauthEnv {
	docs := newDocServer(t)
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &oauthEnv{rtEnv: newRuntimeEnvHook(t, log, trustDocs(docs)), docs: docs, logs: logs}
}

func getRaw(t *testing.T, u string) (int, http.Header, []byte) {
	t.Helper()
	res, err := (&http.Client{CheckRedirect: noFollow}).Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

func jsonPost(t *testing.T, app *testApp, path string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := http.Post(app.URL+path, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, res.Header
}
