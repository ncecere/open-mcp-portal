package upstream

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A token endpoint for the client credentials grant: it records the requests
// it gets and answers as its knobs say.
type fakeTokenEndpoint struct {
	*httptest.Server
	mu       sync.Mutex
	requests []tokenRequest
	status   int
	body     string // "": a fresh token
	expires  int    // expires_in; 0 leaves it out
	delay    time.Duration
	n        int
}

type tokenRequest struct {
	Auth string
	Form url.Values
}

func newTokenEndpoint(t *testing.T) *fakeTokenEndpoint {
	f := &fakeTokenEndpoint{status: 200, expires: 3600}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.requests = append(f.requests, tokenRequest{Auth: r.Header.Get("Authorization"), Form: r.PostForm})
		f.n++
		n, status, body, exp, delay := f.n, f.status, f.body, f.expires, f.delay
		f.mu.Unlock()
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		out := `{"access_token":"tok-` + string(rune('a'+n-1)) + `","token_type":"Bearer"`
		if exp > 0 {
			out += `,"expires_in":` + strconv.Itoa(exp)
		}
		_, _ = w.Write([]byte(out + `}`))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeTokenEndpoint) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeTokenEndpoint) set(change func(f *fakeTokenEndpoint)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newMachine(t *testing.T, f *fakeTokenEndpoint) (*MachineTokens, MachineConfig, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	m := NewMachineTokens(&Client{AllowPrivate: true})
	m.Now = clk.now
	return m, MachineConfig{ServerID: "srv-1", TokenURL: f.URL + "/token", ClientID: "client one", ClientSecret: "s3cr3t/+&sentinel", Scopes: []string{"read", "write"}}, clk
}

func TestMachineTokenRequestShape(t *testing.T) {
	f := newTokenEndpoint(t)
	m, cfg, _ := newMachine(t, f)
	cfg.Audience, cfg.Resource = "api://orders", "https://orders.example/mcp"

	tok, err := m.Token(context.Background(), cfg)
	if err != nil || tok != "tok-a" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	got := f.requests[0]
	wantBasic := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(cfg.ClientID)+":"+url.QueryEscape(cfg.ClientSecret)))
	if got.Auth != wantBasic {
		t.Errorf("basic auth = %q, want %q", got.Auth, wantBasic)
	}
	if got.Form.Get("grant_type") != "client_credentials" || got.Form.Get("scope") != "read write" || got.Form.Get("audience") != "api://orders" ||
		got.Form.Get("resource") != "https://orders.example/mcp" || got.Form.Get("client_secret") != "" || got.Form.Get("client_id") != "" {
		t.Errorf("form = %v", got.Form)
	}

	// client_secret_post: the credentials are in the form and not in a header.
	cfg.ServerID, cfg.AuthMethod, cfg.Scopes, cfg.Audience, cfg.Resource = "srv-2", MachineAuthPost, nil, "", ""
	if _, err := m.Token(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got = f.requests[1]
	if got.Auth != "" || got.Form.Get("client_id") != cfg.ClientID || got.Form.Get("client_secret") != cfg.ClientSecret ||
		got.Form.Has("scope") || got.Form.Has("audience") || got.Form.Has("resource") {
		t.Errorf("post form = %v auth %q", got.Form, got.Auth)
	}
}

func TestMachineTokenCacheExpiryAndSkew(t *testing.T) {
	f := newTokenEndpoint(t)
	m, cfg, clk := newMachine(t, f)
	f.set(func(f *fakeTokenEndpoint) { f.expires = 300 })
	ctx := context.Background()

	first, _ := m.Token(ctx, cfg)
	clk.advance(3 * time.Minute)
	if again, _ := m.Token(ctx, cfg); again != first || f.count() != 1 {
		t.Fatalf("a token that is still good was fetched again: %q, %d requests", again, f.count())
	}
	// 60 s before its expiry the token is no longer used.
	clk.advance(1*time.Minute + 30*time.Second)
	second, _ := m.Token(ctx, cfg)
	if second == first || f.count() != 2 {
		t.Fatalf("a token inside the margin was reused: %q, %d requests", second, f.count())
	}

	// A token shorter than twice the margin is still used for the first half
	// of its life, not fetched for every call.
	f.set(func(f *fakeTokenEndpoint) { f.expires = 30 })
	m.Forget(cfg.ServerID)
	n := f.count()
	short, _ := m.Token(ctx, cfg)
	clk.advance(10 * time.Second)
	if again, _ := m.Token(ctx, cfg); again != short || f.count() != n+1 {
		t.Fatalf("a 30 s token was not reused for 10 s: %d requests", f.count()-n)
	}
	clk.advance(10 * time.Second)
	if again, _ := m.Token(ctx, cfg); again == short {
		t.Fatal("a 30 s token was used after half its life")
	}

	// No expires_in: five minutes. A string expires_in is read too.
	f.set(func(f *fakeTokenEndpoint) { f.expires = 0 })
	m.Forget(cfg.ServerID)
	n = f.count()
	m.Token(ctx, cfg)
	clk.advance(3 * time.Minute)
	m.Token(ctx, cfg)
	if f.count() != n+1 {
		t.Errorf("a token without expires_in was not cached for the default lifetime")
	}
	clk.advance(2 * time.Minute)
	m.Token(ctx, cfg)
	if f.count() != n+2 {
		t.Errorf("a token without expires_in outlived the default lifetime")
	}
	f.set(func(f *fakeTokenEndpoint) { f.body = `{"access_token":"str-ttl","expires_in":"120"}` })
	m.Forget(cfg.ServerID)
	m.Token(ctx, cfg)
	clk.advance(30 * time.Second)
	n = f.count()
	m.Token(ctx, cfg)
	if f.count() != n {
		t.Errorf("a string expires_in was not read")
	}
}

func TestMachineTokenSingleFlight(t *testing.T) {
	f := newTokenEndpoint(t)
	f.set(func(f *fakeTokenEndpoint) { f.delay = 200 * time.Millisecond })
	m, cfg, _ := newMachine(t, f)
	var wg sync.WaitGroup
	tokens := make([]string, 30)
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], _ = m.Token(context.Background(), cfg)
		}()
	}
	wg.Wait()
	if f.count() != 1 {
		t.Fatalf("%d token requests for 30 concurrent callers, want 1", f.count())
	}
	for _, tok := range tokens {
		if tok != "tok-a" {
			t.Fatalf("tokens = %v", tokens)
		}
	}
	// A caller that gives up doesn't stop the request the others wait for.
	m.Forget(cfg.ServerID)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var wg2 sync.WaitGroup
	var other string
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		other, _ = m.Token(context.Background(), cfg)
	}()
	time.Sleep(5 * time.Millisecond)
	if _, err := m.Token(ctx, cfg); err == nil || !err.Unavailable {
		t.Errorf("a cancelled caller got %v", err)
	}
	wg2.Wait()
	if other == "" || f.count() != 2 {
		t.Errorf("the others' request failed: %q after %d requests", other, f.count())
	}
}

func TestMachineTokenRenew(t *testing.T) {
	f := newTokenEndpoint(t)
	m, cfg, _ := newMachine(t, f)
	ctx := context.Background()
	first, _ := m.Token(ctx, cfg)

	// Many callers rejected the same token: one request, one new token.
	var wg sync.WaitGroup
	got := make([]string, 10)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = m.Renew(ctx, cfg, first)
		}()
	}
	wg.Wait()
	if f.count() != 2 {
		t.Fatalf("%d token requests for ten renewals of one token, want 2 in all", f.count())
	}
	for _, tok := range got {
		if tok == first || tok != "tok-b" {
			t.Fatalf("renewed tokens = %v", got)
		}
	}
	// A renewal of a token that is no longer the cached one gets the cached.
	if tok, _ := m.Renew(ctx, cfg, first); tok != "tok-b" || f.count() != 2 {
		t.Errorf("renewing an old token = %q after %d requests", tok, f.count())
	}
	// Rejecting the new one fetches another.
	if tok, _ := m.Renew(ctx, cfg, "tok-b"); tok != "tok-c" {
		t.Errorf("renewing the current token = %q", tok)
	}
}

func TestMachineTokenConfigChangeNeverReusesAToken(t *testing.T) {
	f := newTokenEndpoint(t)
	m, cfg, _ := newMachine(t, f)
	ctx := context.Background()
	first, _ := m.Token(ctx, cfg)
	for name, change := range map[string]func(c *MachineConfig){
		"secret":   func(c *MachineConfig) { c.ClientSecret = "another" },
		"client":   func(c *MachineConfig) { c.ClientID = "another" },
		"scopes":   func(c *MachineConfig) { c.Scopes = []string{"read"} },
		"audience": func(c *MachineConfig) { c.Audience = "other" },
		"resource": func(c *MachineConfig) { c.Resource = "https://other.example" },
		"endpoint": func(c *MachineConfig) { c.TokenURL += "/v2" },
		"method":   func(c *MachineConfig) { c.AuthMethod = MachineAuthPost },
	} {
		c := cfg
		change(&c)
		if tok, _ := m.Token(ctx, c); tok == first {
			t.Errorf("a changed %s reused the token", name)
		}
	}
}

func TestMachineTokenErrorsAreCodesOnly(t *testing.T) {
	f := newTokenEndpoint(t)
	m, cfg, _ := newMachine(t, f)
	ctx := context.Background()
	for name, c := range map[string]struct {
		status      int
		body        string
		code        string
		unavailable bool
		class       string
	}{
		"invalid_client":      {401, `{"error":"invalid_client","error_description":"bad secret s3cr3t/+&sentinel"}`, "invalid_client", false, ClassAuth},
		"invalid_scope":       {400, `{"error":"invalid_scope"}`, "invalid_scope", false, ClassAuth},
		"unauthorized":        {400, `{"error":"unauthorized_client"}`, "unauthorized_client", false, ClassAuth},
		"not an OAuth code":   {400, `{"error":"has spaces and a secret s3cr3t/+&sentinel"}`, "error", false, ClassAuth},
		"html 404":            {404, `<html>token s3cr3t/+&sentinel</html>`, "http_404", false, ClassAuth},
		"temporarily":         {503, `{"error":"temporarily_unavailable"}`, "server_error", true, ClassUnavailable},
		"5xx":                 {502, `bad gateway s3cr3t/+&sentinel`, "server_error", true, ClassUnavailable},
		"429":                 {429, `{"error":"slow_down"}`, "server_error", true, ClassUnavailable},
		"200 without token":   {200, `{"token_type":"bearer"}`, "invalid_response", true, ClassUnavailable},
		"200 not JSON":        {200, `access_token=abc`, "invalid_response", true, ClassUnavailable},
		"a token with a CRLF": {200, "{\"access_token\":\"abc\\r\\nX-Evil: 1\"}", "invalid_response", true, ClassUnavailable},
		"a DPoP token":        {200, `{"access_token":"abc","token_type":"DPoP"}`, "unsupported_token_type", false, ClassAuth},
		"200 with error":      {200, `{"error":"invalid_client"}`, "invalid_client", false, ClassAuth},
	} {
		f.set(func(f *fakeTokenEndpoint) { f.status, f.body = c.status, c.body })
		m.Forget(cfg.ServerID)
		tok, err := m.Token(ctx, cfg)
		if err == nil || tok != "" {
			t.Errorf("%s: got %q, %v", name, tok, err)
			continue
		}
		if err.Code != c.code || err.Unavailable != c.unavailable {
			t.Errorf("%s: code %q unavailable %v, want %q %v", name, err.Code, err.Unavailable, c.code, c.unavailable)
		}
		ue := err.AsError()
		if ue.Class != c.class {
			t.Errorf("%s: class %q, want %q", name, ue.Class, c.class)
		}
		if (ue.Reason == ReasonMachineAuthUnavailable) != c.unavailable {
			t.Errorf("%s: reason %q", name, ue.Reason)
		}
		for _, text := range []string{err.Error(), ue.Message} {
			if strings.Contains(text, "sentinel") || strings.Contains(text, "spaces") || strings.Contains(text, "html") {
				t.Errorf("%s: %q repeats what the server or the client said", name, text)
			}
		}
	}
	// Nothing was cached for a failure, and the next request works again.
	f.set(func(f *fakeTokenEndpoint) { f.status, f.body = 200, "" })
	if tok, err := m.Token(ctx, cfg); err != nil || tok == "" {
		t.Errorf("after the failures: %q, %v", tok, err)
	}
}

func TestMachineTokenBodyLimitRedirectAndTimeout(t *testing.T) {
	// A body over 64 KiB is unavailable, not read.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"` + strings.Repeat("a", 70<<10) + `"}`))
	}))
	defer big.Close()
	m := NewMachineTokens(&Client{AllowPrivate: true})
	cfg := MachineConfig{ServerID: "s", TokenURL: big.URL + "/token", ClientID: "c", ClientSecret: "x"}
	if _, err := m.Token(context.Background(), cfg); err == nil || err.Code != "too_large" || !err.Unavailable {
		t.Errorf("a huge answer: %v", err)
	}
	// A redirect is never followed (not even to a harmless address).
	var followed atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	cfg.TokenURL = redir.URL + "/token"
	if _, err := m.Token(context.Background(), cfg); err == nil || err.Code != "redirect" || followed.Load() != 0 {
		t.Errorf("a redirect: %v, followed %d", err, followed.Load())
	}
	// A reachable but silent endpoint ends at the deadline of the caller's context.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }))
	defer slow.Close()
	cfg.TokenURL = slow.URL + "/token"
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.Token(ctx, cfg); err == nil || err.AsError().Reason != ReasonMachineAuthUnavailable {
		t.Errorf("a slow endpoint: %v", err)
	}
	// Nothing listens: unreachable.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	cfg.TokenURL = "http://" + addr + "/token"
	if _, err := m.Token(context.Background(), cfg); err == nil || err.Code != "unreachable" || err.AsError().Class != ClassUnavailable {
		t.Errorf("a closed port: %v", err)
	}
}

// A token endpoint on an address the rules refuse is never dialled, and the
// client secret never leaves.
func TestMachineTokenBlockedAddressIsNeverDialled(t *testing.T) {
	var dials atomic.Int64
	var served atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Add(1) }))
	defer srv.Close()
	c := &Client{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "rebind.example.com", "meta.example.com":
				return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
			case "private.example.com":
				return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
			}
			return nil, errors.New("no such host")
		},
	}
	m := NewMachineTokens(c)
	for _, raw := range []string{
		"https://127.0.0.1/token",                 // refused when the URL is checked
		"https://169.254.169.254/latest/token",    // the cloud metadata address
		"https://10.0.0.5/token",                  // a private address
		"https://rebind.example.com/token",        // a public name that resolves to link-local space
		"https://private.example.com/token",       // a public-looking name that resolves to a private address
		"http://token.example.com/token",          // not https
		"https://user:pw@token.example.com/oauth", // userinfo
	} {
		_, err := m.Token(context.Background(), MachineConfig{ServerID: "s", TokenURL: raw, ClientID: "c", ClientSecret: "super-secret-value"})
		if err == nil || err.Code != "not_allowed" || !err.Unavailable || err.AsError().Class != ClassNotAllowed {
			t.Errorf("%s: %v", raw, err)
		}
	}
	if dials.Load() != 0 || served.Load() != 0 {
		t.Errorf("a blocked token endpoint was dialled %d times and served %d requests", dials.Load(), served.Load())
	}
}

func TestMachineTokenAsErrorMessages(t *testing.T) {
	refused := (&MachineError{Code: "invalid_client"}).AsError()
	if refused.Class != ClassAuth || refused.Reason != "" || !strings.Contains(refused.Message, "invalid_client") {
		t.Errorf("refused = %+v", refused)
	}
	down := (&MachineError{Code: "unreachable", Unavailable: true}).AsError()
	if down.Class != ClassUnavailable || down.Reason != ReasonMachineAuthUnavailable {
		t.Errorf("unavailable = %+v", down)
	}
	if e := (&MachineError{Code: "timeout", Unavailable: true}).AsError(); e.Class != ClassTimeout || e.Reason != ReasonMachineAuthUnavailable {
		t.Errorf("timeout = %+v", e)
	}
	if e := (&MachineError{Code: "config", Unavailable: true}).AsError(); e.Class != ClassConfig || e.Reason != "" {
		t.Errorf("config = %+v", e)
	}
}
