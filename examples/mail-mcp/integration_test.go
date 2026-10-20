package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The whole flow with the real gateway (in process, over a fresh database;
// skipped without Postgres like the other integration tests): a fake OAuth
// provider standing in for Google, this server in front of the fake Gmail,
// a server requirement (provider + gmail.readonly), a team gateway and an
// API key. The first tools/call answers -32042 with a consent link; after
// consent the call reaches this server with a verified identity token
// carrying the provider claim, and Gmail sees the token the provider issued.

const (
	integrationEncryptionKey = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	integrationPepper        = "cGVwcGVyLXBlcHBlci1wZXBwZXItcGVwcGVyLTAxMjM="
	gmailReadonly            = "https://www.googleapis.com/auth/gmail.readonly"
)

type browser struct {
	t      *testing.T
	base   string
	client *http.Client
	csrf   string
}

func newBrowser(t *testing.T, base, account string) *browser {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, base: base, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
	b.must("POST", "/auth/dev", map[string]string{"account": account}, nil, 200)
	var me struct {
		CsrfToken string `json:"csrfToken"`
	}
	b.must("GET", "/v1/me", nil, &me, 200)
	b.csrf = me.CsrfToken
	return b
}

func (b *browser) do(method, path string, body any, headers map[string]string) (int, http.Header, []byte) {
	b.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.base + path
	}
	req, _ := http.NewRequest(method, u, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", b.base)
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, raw
}

// must performs a request, checks the status and decodes {"data": ...}.
func (b *browser) must(method, path string, body, out any, want int, headers ...map[string]string) {
	b.t.Helper()
	var h map[string]string
	if len(headers) > 0 {
		h = headers[0]
	}
	code, _, raw := b.do(method, path, body, h)
	if code != want {
		b.t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, &struct{ Data any }{Data: out}); err != nil {
			b.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
}

func TestGatewayDelegatedGmailEndToEnd(t *testing.T) {
	// The gateway.
	pool, _ := testutil.NewDB(t)
	var handler http.Handler
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(gwSrv.Close)
	cfg := config.Defaults()
	cfg.AppURL, cfg.DevAuth, cfg.DatabaseURL = gwSrv.URL, true, "unused"
	cfg.EncryptionKey, cfg.APIKeyPepper = integrationEncryptionKey, integrationPepper
	cfg.RequestsPerMinute, cfg.LoginAttemptsPerMinute = 100_000, 100_000
	if err := cfg.Validate("serve"); err != nil {
		t.Fatal(err)
	}
	deps, err := app.NewDeps(cfg, pool, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	deps.Health = httpapi.NewHealth(map[string]func(context.Context) error{"postgres": pool.Ping})
	deps.Web, deps.WebBuilt = fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>x</title>")}}, true
	handler = httpapi.NewAPIHandler(deps)

	// "Google" (the fake OAuth provider) and this server in front of the
	// fake Gmail.
	oauth := testutil.NewFakeOAuth(t)
	gmail := NewFakeGmail()
	gmailSrv := httptest.NewServer(gmail)
	t.Cleanup(gmailSrv.Close)
	var mu sync.Mutex
	var calls []CallInfo
	mailMux := http.NewServeMux()
	mailSrv := httptest.NewServer(mailMux)
	t.Cleanup(mailSrv.Close)
	audience := mailSrv.URL + "/mcp"
	ms := &MailServer{Gmail: &Gmail{Base: gmailSrv.URL}, Provider: "google-test", Logf: t.Logf,
		OnCall: func(c CallInfo) { mu.Lock(); calls = append(calls, c); mu.Unlock() }}
	guard := &Guard{Verifier: &Verifier{JWKSURL: gwSrv.URL + "/.well-known/jwks.json", Issuer: gwSrv.URL, Audience: audience}, Logf: t.Logf}
	mailMux.Handle("/mcp", guard.Wrap(ms.Handler()))

	admin := newBrowser(t, gwSrv.URL, "admin")

	// A platform admin adds the provider.
	var provider struct {
		ID       string `json:"id"`
		Slug     string `json:"slug"`
		Revision int    `json:"revision"`
	}
	admin.must("POST", "/v1/admin/auth-providers", map[string]any{
		"slug": "google-test", "name": "Google (test)", "preset": "google", "clientId": oauth.ClientID, "clientSecret": oauth.ClientSecret,
		"authorizationUrl": oauth.URL + "/authorize", "tokenUrl": oauth.URL + "/token", "revocationUrl": oauth.URL + "/revoke",
		"userinfoUrl": oauth.URL + "/userinfo", "defaultScopes": []string{"openid", "email"},
	}, &provider, 201)

	// The team registers the server with its requirement; discovery runs
	// without an identity token.
	var team struct {
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
	}
	admin.must("POST", "/v1/admin/teams", map[string]any{"slug": "mail-team", "name": "Mail team", "ownerEmail": "admin@localhost"}, &team, 201)
	// A new provider is restricted until an admin lists who may use it.
	admin.must("PUT", "/v1/admin/auth-providers/"+provider.ID+"/access", map[string]any{"accessMode": "restricted",
		"teamIds": []string{team.Team.ID}, "serverIds": []string{}}, nil, 200,
		map[string]string{"If-Match": fmt.Sprintf("%q", fmt.Sprint(provider.Revision))})
	var created struct {
		Server struct {
			ID       string `json:"id"`
			Revision int    `json:"revision"`
		} `json:"server"`
		RefreshError any `json:"refreshError"`
	}
	admin.must("POST", "/v1/teams/mail-team/mcp-servers", map[string]any{"slug": "mail", "name": "Mail", "url": audience,
		"requirement": map[string]any{"providerId": provider.ID, "scopes": []string{gmailReadonly}}}, &created, 201)
	if created.RefreshError != nil {
		t.Fatalf("discovery failed: %v", created.RefreshError)
	}
	var caps []struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	admin.must("GET", "/v1/teams/mail-team/mcp-servers/"+created.Server.ID+"/capabilities", nil, &caps, 200)
	if len(caps) != 3 {
		t.Fatalf("capabilities = %+v", caps)
	}

	// A team gateway with the tools, and a personal API key.
	var gw struct {
		ID       string `json:"id"`
		Revision int    `json:"revision"`
	}
	admin.must("POST", "/v1/teams/mail-team/gateways", map[string]any{"slug": "mail", "name": "Mail"}, &gw, 201)
	var items []map[string]any
	for _, c := range caps {
		items = append(items, map[string]any{"capabilityId": c.ID})
	}
	admin.must("PUT", "/v1/teams/mail-team/gateways/"+gw.ID+"/capabilities", map[string]any{"items": items}, nil, 200,
		map[string]string{"If-Match": fmt.Sprintf(`"%d"`, gw.Revision)})
	var key struct {
		Secret string `json:"secret"`
	}
	admin.must("POST", "/v1/me/api-keys", map[string]any{"name": "mail-test"}, &key, 201)

	callMCP := func(name string, args map[string]any) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		req, _ := http.NewRequest("POST", gwSrv.URL+"/mcp/mail", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+key.Secret)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out map[string]any
		if res.StatusCode != 200 || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("tools/call %s = %d %s", name, res.StatusCode, raw)
		}
		return out
	}

	// 1. Not connected yet: -32042 with a consent link; nothing reaches us.
	out := callMCP("mail__search_messages", map[string]any{"query": "from:alice"})
	e, _ := out["error"].(map[string]any)
	if code, _ := e["code"].(float64); code != -32042 {
		t.Fatalf("first call = %v", out)
	}
	link := e["data"].(map[string]any)["elicitations"].([]any)[0].(map[string]any)["url"].(string)
	requestID := link[strings.Index(link, "?request=")+len("?request="):]
	mu.Lock()
	n := len(calls)
	mu.Unlock()
	if n != 0 || len(gmail.TokensSeen()) != 0 {
		t.Fatalf("server reached before consent: %d calls", n)
	}

	// 2. The person consents in the browser (the fake provider approves).
	var started struct {
		AuthorizeURL string `json:"authorizeUrl"`
	}
	admin.must("POST", "/v1/me/connections/start", map[string]any{"providerId": provider.ID, "requestId": requestID}, &started, 200)
	code, h, _ := admin.do("GET", started.AuthorizeURL, nil, nil)
	if code != http.StatusFound {
		t.Fatalf("authorize = %d", code)
	}
	code, h, _ = admin.do("GET", h.Get("Location"), nil, nil)
	if code != http.StatusSeeOther || !strings.Contains(h.Get("Location"), "result=connected") {
		t.Fatalf("callback = %d %s", code, h.Get("Location"))
	}

	// 3. The retry reaches this server and Gmail.
	out = callMCP("mail__search_messages", map[string]any{"query": "from:alice"})
	res, _ := out["result"].(map[string]any)
	if res == nil || res["isError"] == true {
		t.Fatalf("retry = %v", out)
	}
	sc, _ := json.Marshal(res["structuredContent"])
	var found SearchOutput
	_ = json.Unmarshal(sc, &found)
	if len(found.Messages) != 2 || found.Messages[0].Subject != "Re: Quarterly report draft" {
		t.Fatalf("messages = %s", sc)
	}
	mu.Lock()
	got := append([]CallInfo(nil), calls...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("calls = %+v", got)
	}
	c := got[0]
	if c.Err != nil || !c.TokenReceived || c.Identity.Provider != "google-test" || c.Identity.Email != "admin@localhost" ||
		c.Identity.PrincipalType != "user" || c.Identity.Subject == "" || c.Identity.Gateway != "mail" || c.Identity.Tool != "mail__search_messages" {
		t.Fatalf("call = %+v", c)
	}
	issued := oauth.Issued()
	if seen := gmail.TokensSeen(); len(issued) != 1 || len(seen) == 0 || seen[0] != digest(issued[0]) {
		t.Fatalf("Gmail saw %d tokens; provider issued %d", len(seen), len(issued))
	}

	// read_message through the gateway too.
	out = callMCP("mail__read_message", map[string]any{"id": found.Messages[0].ID})
	if res, _ := out["result"].(map[string]any); res == nil || res["isError"] == true {
		t.Fatalf("read = %v", out)
	}
}
