package agentidentity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/agentidentity"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

const (
	issuer       = "https://example.com"
	jwksURL      = "https://example.com/.well-known/mcp-identity-jwks.json"
	audience     = "https://portal.example.org"
	personIssuer = "https://login.example.org/application/o/pdp/"
)

// fakeIssuer is an agent platform: it signs tokens with P-256 keys and
// serves the JWKS of the keys it publishes, counting fetches.
type fakeIssuer struct {
	t   *testing.T
	srv *httptest.Server

	mu           sync.Mutex
	keys         map[string]*ecdsa.PrivateKey
	published    []string
	cacheControl string
	contentType  string
	status       int
	redirect     string
	padding      int
	fetches      atomic.Int64
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	f := &fakeIssuer{t: t, keys: map[string]*ecdsa.PrivateKey{}, cacheControl: "public, max-age=300", contentType: "application/jwk-set+json", status: 200}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) serve(w http.ResponseWriter, r *http.Request) {
	f.fetches.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	if f.status != 200 {
		w.WriteHeader(f.status)
		return
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, kid := range f.published {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &f.keys[kid].PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
	}
	body, _ := json.Marshal(set)
	if f.padding > 0 {
		body = []byte(`{"padding":"` + strings.Repeat("x", f.padding) + `",` + string(body[1:]))
	}
	w.Header().Set("Content-Type", f.contentType)
	if f.cacheControl != "" {
		w.Header().Set("Cache-Control", f.cacheControl)
	}
	_, _ = w.Write(body)
}

// addKey creates a key and (when publish) publishes it.
func (f *fakeIssuer) addKey(kid string, publish bool) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[kid] = k
	if publish {
		f.published = append(f.published, kid)
	}
	return k
}

func (f *fakeIssuer) publish(kids ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = kids
}

func (f *fakeIssuer) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// claims is a token's payload; Mutate edits it before signing.
func goodClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": issuer, "aud": audience, "sub": "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21", "principal_type": "agent", "name": "Mail assistant",
		"team":              map[string]any{"id": "6f1c0000", "slug": "personal-1a2b3c4d5e6f", "kind": "personal"},
		"thread_visibility": "private",
		"person":            map[string]any{"iss": personIssuer, "sub": "8c41d2", "email": "ada@example.com"},
		"person_present":    true, "tool": "search_mail", "jti": fmt.Sprintf("jti-%d", jtiCounter.Add(1)),
		"iat": now.Unix(), "nbf": now.Add(-30 * time.Second).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

var jtiCounter atomic.Int64

// sign makes a token: header members in extra override the defaults.
func sign(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any, extra map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader("kid", kid)
	for k, v := range extra {
		opts.WithHeader(jose.HeaderKey(k), v)
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := sg.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

type env struct {
	t      *testing.T
	pool   *pgxpool.Pool
	f      *fakeIssuer
	svc    *agentidentity.Service
	admin  authz.Actor
	now    time.Time
	nowMu  sync.Mutex
	key    *ecdsa.PrivateKey
	policy []netpolicy.Entry
}

func (e *env) clock() time.Time {
	e.nowMu.Lock()
	defer e.nowMu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.nowMu.Lock()
	e.now = e.now.Add(d)
	e.nowMu.Unlock()
}

type staticPolicy struct{ p *netpolicy.Policy }

func (s staticPolicy) Current(context.Context) *netpolicy.Policy { return s.p }

// newService makes a service on pool that reaches the fake issuer's server at
// whatever address host example.com resolves to (resolved), through the real
// address guard.
func (e *env) newService(resolved string, entries []netpolicy.Entry) *agentidentity.Service {
	client := &upstream.Client{
		Networks: staticPolicy{netpolicy.New(entries)},
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host != "example.com" {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr(resolved)}, nil
		},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, e.f.srv.Listener.Addr().String())
		},
	}
	svc := agentidentity.New(e.pool, client, audience, personIssuer, testutil.Logger())
	svc.TLS = &tls.Config{RootCAs: e.f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "example.com"}
	svc.SetClock(e.clock)
	return svc
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	e := &env{t: t, pool: pool, f: newFakeIssuer(t), now: time.Now().Truncate(time.Second)}
	e.key = e.f.addKey("k1", true)
	e.svc = e.newService("93.184.216.34", nil)
	var admin string
	if err := pool.QueryRow(context.Background(), `INSERT INTO users (oidc_issuer, oidc_subject, email, display_name, platform_role)
		VALUES ($1, 'admin', 'admin@example.com', 'Admin', 'platform_admin') RETURNING id::text`, personIssuer).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	e.admin = authz.Actor{PlatformRole: authz.PlatformAdmin}
	e.admin.UserID = mustUUID(t, admin)
	return e
}

// trust adds the fake platform (or edits the fields).
func (e *env) trust() string {
	e.t.Helper()
	name := "Pi Durable Platform"
	v, err := e.svc.Create(context.Background(), e.admin, agentidentity.Input{Name: &name, Issuer: ptr(issuer), Audience: ptr(audience)})
	if err != nil {
		e.t.Fatal(err)
	}
	return v.Platform.ID.String()
}

func (e *env) verify(token string) (agentidentity.Identity, error) {
	return e.svc.Verify(context.Background(), token)
}

func reasonOf(err error) string {
	var r *agentidentity.Rejection
	if errors.As(err, &r) {
		return r.Reason
	}
	if err == nil {
		return ""
	}
	return "error: " + err.Error()
}

func (e *env) token(mutate func(c map[string]any), extra map[string]any) string {
	e.t.Helper()
	c := goodClaims(e.clock())
	if mutate != nil {
		mutate(c)
	}
	return sign(e.t, e.key, "k1", c, extra)
}

func TestVerifyAcceptsThePlatformsToken(t *testing.T) {
	e := newEnv(t)
	e.trust()
	id, err := e.verify(e.token(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if id.AgentID != "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21" || id.AgentName != "Mail assistant" || id.TeamID != "6f1c0000" || id.TeamKind != "personal" ||
		id.ThreadVisibility != "private" || id.Tool != "search_mail" || !id.PersonPresent || id.Person == nil ||
		id.Person.Issuer != personIssuer || id.Person.Subject != "8c41d2" || id.Person.Email != "ada@example.com" || id.Platform.Issuer != issuer {
		t.Fatalf("identity = %+v person %+v", id, id.Person)
	}
	// A token without a person, an audience array, and no nbf.
	id, err = e.verify(e.token(func(c map[string]any) {
		delete(c, "person")
		c["person_present"] = false
		c["aud"] = []string{"https://other.example", audience}
		delete(c, "nbf")
	}, nil))
	if err != nil || id.Person != nil || id.PersonPresent {
		t.Fatalf("no person: %+v %v", id, err)
	}
	// person_present without a person is not a present person.
	id, err = e.verify(e.token(func(c map[string]any) { c["person"] = nil }, nil))
	if err != nil || id.Person != nil || id.PersonPresent {
		t.Fatalf("null person: %+v %v", id, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	e := newEnv(t)
	e.trust()
	now := e.clock()
	otherKey := e.f.addKey("not-published", false)
	cases := []struct {
		name   string
		token  func() string
		reason string
	}{
		{"alg none", func() string {
			return b64(map[string]any{"alg": "none", "kid": "k1", "typ": "JWT"}) + "." + b64(goodClaims(now)) + "."
		}, "algorithm"},
		{"HS256 with the public key as the secret", func() string {
			der, _ := x509.MarshalPKIXPublicKey(&e.key.PublicKey)
			signing := b64(map[string]any{"alg": "HS256", "kid": "k1", "typ": "JWT"}) + "." + b64(goodClaims(now))
			mac := hmac.New(sha256.New, der)
			mac.Write([]byte(signing))
			return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		}, "algorithm"},
		{"RS256", func() string {
			return b64(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + b64(goodClaims(now)) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
		}, "algorithm"},
		{"ES384", func() string {
			return b64(map[string]any{"alg": "ES384", "kid": "k1", "typ": "JWT"}) + "." + b64(goodClaims(now)) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
		}, "algorithm"},
		{"no kid", func() string {
			return b64(map[string]any{"alg": "ES256", "typ": "JWT"}) + "." + b64(goodClaims(now)) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
		}, "key_id"},
		{"another typ", func() string { return e.token(nil, map[string]any{"typ": "at+jwt"}) }, "type"},
		{"no typ", func() string {
			return b64(map[string]any{"alg": "ES256", "kid": "k1"}) + "." + b64(goodClaims(now)) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
		}, "type"},
		{"an embedded key", func() string {
			return e.token(nil, map[string]any{"jwk": map[string]any{"kty": "EC"}})
		}, "malformed"},
		{"crit", func() string { return e.token(nil, map[string]any{"crit": []string{"exp"}}) }, "malformed"},
		{"JSON serialization", func() string { return `{"payload":"e30","signatures":[]}` }, "malformed"},
		{"garbage", func() string { return "not.a.token" }, "malformed"},
		{"empty", func() string { return "" }, "malformed"},
		{"a kid the issuer never published", func() string { return sign(t, otherKey, "not-published", goodClaims(now), nil) }, "unknown_kid"},
		{"a signature by another key under a published kid", func() string { return sign(t, otherKey, "k1", goodClaims(now), nil) }, "signature"},
		{"another issuer", func() string { return e.token(func(c map[string]any) { c["iss"] = "https://evil.example.com" }, nil) }, "untrusted_issuer"},
		{"no issuer", func() string { return e.token(func(c map[string]any) { delete(c, "iss") }, nil) }, "malformed"},
		{"another audience", func() string { return e.token(func(c map[string]any) { c["aud"] = "https://other.example" }, nil) }, "audience"},
		{"no audience", func() string { return e.token(func(c map[string]any) { delete(c, "aud") }, nil) }, "audience"},
		{"an audience array without ours", func() string { return e.token(func(c map[string]any) { c["aud"] = []string{"a", "b"} }, nil) }, "audience"},
		{"an audience that is a prefix of ours", func() string { return e.token(func(c map[string]any) { c["aud"] = audience + "/x" }, nil) }, "audience"},
		{"expired beyond the skew", func() string {
			return e.token(func(c map[string]any) {
				c["exp"] = now.Add(-31 * time.Second).Unix()
				c["iat"] = now.Add(-330 * time.Second).Unix()
			}, nil)
		}, "expired"},
		{"not valid yet (nbf beyond the skew)", func() string {
			return e.token(func(c map[string]any) { c["nbf"] = now.Add(40 * time.Second).Unix() }, nil)
		}, "not_yet_valid"},
		{"issued in the future", func() string {
			return e.token(func(c map[string]any) { c["iat"] = now.Add(40 * time.Second).Unix() }, nil)
		}, "not_yet_valid"},
		{"a lifetime over ten minutes", func() string {
			return e.token(func(c map[string]any) { c["exp"] = now.Add(11 * time.Minute).Unix() }, nil)
		}, "lifetime"},
		{"exp before iat", func() string {
			return e.token(func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }, nil)
		}, "lifetime"},
		{"exp as a string", func() string {
			return e.token(func(c map[string]any) { c["exp"] = fmt.Sprint(now.Add(time.Minute).Unix()) }, nil)
		}, "claims"},
		{"exp too large to be a date", func() string { return e.token(func(c map[string]any) { c["exp"] = 1e20 }, nil) }, "claims"},
		{"negative iat", func() string { return e.token(func(c map[string]any) { c["iat"] = -5 }, nil) }, "claims"},
		{"no exp", func() string { return e.token(func(c map[string]any) { delete(c, "exp") }, nil) }, "claims"},
		{"no principal_type", func() string { return e.token(func(c map[string]any) { delete(c, "principal_type") }, nil) }, "principal_type"},
		{"principal_type user", func() string { return e.token(func(c map[string]any) { c["principal_type"] = "user" }, nil) }, "principal_type"},
		{"principal_type service_account", func() string { return e.token(func(c map[string]any) { c["principal_type"] = "service_account" }, nil) }, "principal_type"},
		{"no jti", func() string { return e.token(func(c map[string]any) { delete(c, "jti") }, nil) }, "claims"},
		{"an empty jti", func() string { return e.token(func(c map[string]any) { c["jti"] = "" }, nil) }, "claims"},
		{"a jti over 128 bytes", func() string { return e.token(func(c map[string]any) { c["jti"] = strings.Repeat("j", 129) }, nil) }, "claims"},
		{"no sub", func() string { return e.token(func(c map[string]any) { delete(c, "sub") }, nil) }, "claims"},
		{"a sub with a control character", func() string { return e.token(func(c map[string]any) { c["sub"] = "a\ngent" }, nil) }, "claims"},
		{"no team", func() string { return e.token(func(c map[string]any) { delete(c, "team") }, nil) }, "claims"},
		{"no team.id", func() string { return e.token(func(c map[string]any) { c["team"] = map[string]any{"slug": "x"} }, nil) }, "claims"},
		{"a person without a sub", func() string {
			return e.token(func(c map[string]any) { c["person"] = map[string]any{"iss": personIssuer} }, nil)
		}, "claims"},
		{"a person that isn't an object", func() string { return e.token(func(c map[string]any) { c["person"] = "ada" }, nil) }, "claims"},
		{"a person from another identity provider", func() string {
			return e.token(func(c map[string]any) {
				c["person"] = map[string]any{"iss": "https://other-idp.example", "sub": "8c41d2"}
			}, nil)
		}, "person_issuer"},
		{"a person whose iss differs only by a trailing slash", func() string {
			return e.token(func(c map[string]any) {
				c["person"] = map[string]any{"iss": strings.TrimSuffix(personIssuer, "/"), "sub": "8c41d2"}
			}, nil)
		}, "person_issuer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reasonOf(func() error { _, err := e.verify(c.token()); return err }()); got != c.reason {
				t.Fatalf("refused as %q, want %q", got, c.reason)
			}
		})
	}
	// Every refused token left nothing behind: a good token still works and
	// no jti was recorded for a refused one.
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM agent_token_jtis`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("jtis after refusals: %d %v", n, err)
	}
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
}

// Within the skew a token is still good; the bounds are exact.
func TestVerifySkew(t *testing.T) {
	e := newEnv(t)
	e.trust()
	now := e.clock()
	for name, mutate := range map[string]func(c map[string]any){
		"expired 20 s ago": func(c map[string]any) {
			c["exp"] = now.Add(-20 * time.Second).Unix()
			c["iat"] = now.Add(-320 * time.Second).Unix()
		},
		"nbf 20 s ahead":    func(c map[string]any) { c["nbf"] = now.Add(20 * time.Second).Unix() },
		"issued 20 s ahead": func(c map[string]any) { c["iat"] = now.Add(20 * time.Second).Unix() },
		"ten minutes":       func(c map[string]any) { c["exp"] = now.Add(10 * time.Minute).Unix(); c["iat"] = now.Unix() },
	} {
		if _, err := e.verify(e.token(mutate, nil)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyDisabledAndUnknownIssuerNeverFetch(t *testing.T) {
	e := newEnv(t)
	// Nothing trusted: refused without any fetch.
	if got := reasonOf(func() error { _, err := e.verify(e.token(nil, nil)); return err }()); got != "untrusted_issuer" {
		t.Fatalf("untrusted: %s", got)
	}
	id := e.trust()
	e.update(id, agentidentity.Input{Enabled: ptr(false)})
	if got := reasonOf(func() error { _, err := e.verify(e.token(nil, nil)); return err }()); got != "disabled_issuer" {
		t.Fatalf("disabled: %s", got)
	}
	if n := e.f.fetches.Load(); n != 0 {
		t.Fatalf("%d fetches for an untrusted and a disabled issuer", n)
	}
	e.update(id, agentidentity.Input{Enabled: ptr(true)})
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
}

func (e *env) update(id string, in agentidentity.Input) {
	e.t.Helper()
	var rev int64
	if err := e.pool.QueryRow(context.Background(), `SELECT revision FROM agent_platforms WHERE id = $1`, id).Scan(&rev); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.Update(context.Background(), e.admin, mustUUID(e.t, id), in, rev); err != nil {
		e.t.Fatal(err)
	}
}

// A jti is used once, across replicas: two services on one database.
func TestVerifyReplay(t *testing.T) {
	e := newEnv(t)
	e.trust()
	tok := e.token(nil, nil)
	if _, err := e.verify(tok); err != nil {
		t.Fatal(err)
	}
	if got := reasonOf(func() error { _, err := e.verify(tok); return err }()); got != "replay" {
		t.Fatalf("second use on the same replica: %s", got)
	}
	// Another replica: its own caches, the same database.
	other := e.newService("93.184.216.34", nil)
	if _, err := other.Verify(context.Background(), tok); reasonOf(err) != "replay" {
		t.Fatalf("second use on another replica: %v", err)
	}
	// A fresh token on the other replica works.
	if _, err := other.Verify(context.Background(), e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
	// Racing replicas: exactly one accepts a token.
	race := e.token(nil, nil)
	svcs := []*agentidentity.Service{e.svc, other, e.newService("93.184.216.34", nil), e.newService("93.184.216.34", nil)}
	var ok atomic.Int64
	var wg sync.WaitGroup
	for _, s := range svcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Verify(context.Background(), race); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d replicas accepted one token", ok.Load())
	}
	// The jti is kept until exp + skew (+ a minute) and then cleaned up.
	var expires time.Time
	if err := e.pool.QueryRow(context.Background(), `SELECT max(expires_at) FROM agent_token_jtis`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if want := e.clock().Add(5*time.Minute + agentidentity.Skew + time.Minute); expires.Sub(want).Abs() > 3*time.Second {
		t.Fatalf("jti kept until %s, want about %s", expires, want)
	}
	if n, err := e.svc.Cleanup(context.Background()); err != nil || n != 0 {
		t.Fatalf("cleanup of live jtis = %d %v", n, err)
	}
	if _, err := e.pool.Exec(context.Background(), `UPDATE agent_token_jtis SET expires_at = now() - interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.Cleanup(context.Background()); err != nil || n < 1 {
		t.Fatalf("cleanup of expired jtis = %d %v", n, err)
	}
}

// An unknown kid refetches the JWKS exactly once; a flood of unknown kids
// costs a bounded number of fetches.
func TestUnknownKidRefetch(t *testing.T) {
	e := newEnv(t)
	e.trust()
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
	if n := e.f.fetches.Load(); n != 1 {
		t.Fatalf("first verification fetched %d times", n)
	}
	ghost := e.f.addKey("ghost", false)
	if got := reasonOf(func() error {
		_, err := e.verify(sign(t, ghost, "ghost", goodClaims(e.clock()), nil))
		return err
	}()); got != "unknown_kid" {
		t.Fatalf("unknown kid: %s", got)
	}
	if n := e.f.fetches.Load(); n != 2 {
		t.Fatalf("an unknown kid caused %d fetches in all, want 2 (one refetch)", n)
	}
	// A flood of tokens with random kids.
	for i := range 200 {
		kid := fmt.Sprintf("flood-%d", i)
		k := e.f.addKey(kid, false)
		if reasonOf(func() error { _, err := e.verify(sign(t, k, kid, goodClaims(e.clock()), nil)); return err }()) != "unknown_kid" {
			t.Fatal("a flood token was not refused as unknown_kid")
		}
	}
	if n := e.f.fetches.Load(); n > 3 {
		t.Fatalf("a flood of 200 unknown kids caused %d fetches (budget: 2 refetches a minute)", n)
	}
	// Known keys keep working from the cache meanwhile.
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
	// A minute later the budget is back.
	e.advance(61 * time.Second)
	before := e.f.fetches.Load()
	k := e.f.addKey("later", false)
	_, _ = e.verify(sign(t, k, "later", goodClaims(e.clock()), nil))
	if e.f.fetches.Load() != before+1 {
		t.Fatalf("after the window the refetch budget wasn't restored: %d -> %d", before, e.f.fetches.Load())
	}
}

func TestKeyRotation(t *testing.T) {
	e := newEnv(t)
	e.trust()
	old := e.key
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
	// The new key is published before it signs: both are in the set.
	k2 := e.f.addKey("k2", true)
	// Signing with it at once: an unknown kid, one refetch, accepted.
	if _, err := e.verify(sign(t, k2, "k2", goodClaims(e.clock()), nil)); err != nil {
		t.Fatalf("new key: %v", err)
	}
	// Both are accepted while both are published.
	if _, err := e.verify(sign(t, old, "k1", goodClaims(e.clock()), nil)); err != nil {
		t.Fatalf("old key while published: %v", err)
	}
	if _, err := e.verify(sign(t, k2, "k2", goodClaims(e.clock()), nil)); err != nil {
		t.Fatalf("new key: %v", err)
	}
	// The old key is withdrawn (a leak): once the cached set expires, tokens
	// it signed are refused.
	e.f.publish("k2")
	e.advance(6 * time.Minute)
	if got := reasonOf(func() error { _, err := e.verify(sign(t, old, "k1", goodClaims(e.clock()), nil)); return err }()); got != "unknown_kid" {
		t.Fatalf("withdrawn key: %s", got)
	}
	if _, err := e.verify(sign(t, k2, "k2", goodClaims(e.clock()), nil)); err != nil {
		t.Fatalf("new key after withdrawing the old: %v", err)
	}
}

func TestJWKSCacheLifetime(t *testing.T) {
	e := newEnv(t)
	e.trust()
	ver := func() {
		t.Helper()
		if _, err := e.verify(e.token(nil, nil)); err != nil {
			t.Fatal(err)
		}
	}
	// Cache-Control max-age=3600 is capped at five minutes.
	e.f.set(func() { e.f.cacheControl = "public, max-age=3600" })
	ver()
	ver()
	if n := e.f.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (cached)", n)
	}
	e.advance(4 * time.Minute)
	ver()
	if n := e.f.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d after 4 minutes, want 1", n)
	}
	e.advance(2 * time.Minute)
	ver()
	if n := e.f.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d after the cap, want 2", n)
	}
	// A shorter max-age is honoured (but never below ten seconds).
	e.f.set(func() { e.f.cacheControl = "max-age=30" })
	e.advance(6 * time.Minute)
	ver() // fetch 3, cached 30 s
	e.advance(20 * time.Second)
	ver()
	if n := e.f.fetches.Load(); n != 3 {
		t.Fatalf("fetches = %d inside max-age=30, want 3", n)
	}
	e.advance(20 * time.Second)
	ver()
	if n := e.f.fetches.Load(); n != 4 {
		t.Fatalf("fetches = %d after max-age=30, want 4", n)
	}
	e.f.set(func() { e.f.cacheControl = "max-age=0" })
	e.advance(time.Minute)
	ver() // fetch 5, cached the 10 s minimum
	ver()
	if n := e.f.fetches.Load(); n != 5 {
		t.Fatalf("fetches = %d with max-age=0, want 5 (minimum lifetime)", n)
	}
}

// Stale-while-error: when the platform can't be reached, the keys last
// fetched keep serving for 15 minutes past their expiry, then nothing
// verifies. Unreachable is not retried for ten seconds.
func TestStaleWhileError(t *testing.T) {
	e := newEnv(t)
	e.trust()
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatal(err)
	}
	e.f.set(func() { e.f.status = 503 })
	e.advance(6 * time.Minute) // expired, the platform is down
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatalf("stale keys within 15 minutes: %v", err)
	}
	n := e.f.fetches.Load()
	for range 20 {
		if _, err := e.verify(e.token(nil, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if e.f.fetches.Load() != n {
		t.Fatalf("fetched again within the failure backoff: %d -> %d", n, e.f.fetches.Load())
	}
	e.advance(11 * time.Second)
	if _, err := e.verify(e.token(nil, nil)); err != nil || e.f.fetches.Load() != n+1 {
		t.Fatalf("retry after the backoff: %v fetches %d", err, e.f.fetches.Load())
	}
	// Past 5 + 15 minutes without a successful fetch: refused.
	e.advance(15 * time.Minute)
	if got := reasonOf(func() error { _, err := e.verify(e.token(nil, nil)); return err }()); got != "jwks_unavailable" {
		t.Fatalf("after the stale window: %s", got)
	}
	// The platform comes back.
	e.f.set(func() { e.f.status = 200 })
	e.advance(11 * time.Second)
	if _, err := e.verify(e.token(nil, nil)); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	// With no keys ever fetched and the platform down: refused.
	e2 := newEnv(t)
	e2.trust()
	e2.f.set(func() { e2.f.status = 500 })
	if got := reasonOf(func() error { _, err := e2.verify(e2.token(nil, nil)); return err }()); got != "jwks_unavailable" {
		t.Fatalf("never fetched: %s", got)
	}
}

func TestJWKSFetchGuard(t *testing.T) {
	ctx := context.Background()
	t.Run("a private address is refused unless allow-listed", func(t *testing.T) {
		e := newEnv(t)
		e.svc = e.newService("10.20.0.5", nil)
		id := e.trust()
		res, err := e.svc.Test(ctx, e.admin, mustUUID(t, id))
		if err != nil || res.OK || res.Error != agentidentity.FetchNotAllowed || e.f.fetches.Load() != 0 {
			t.Fatalf("private: %+v %v fetches %d", res, err, e.f.fetches.Load())
		}
		if got := reasonOf(func() error { _, err := e.verify(e.token(nil, nil)); return err }()); got != "jwks_unavailable" {
			t.Fatalf("verification with a refused fetch: %s", got)
		}
		entries, err := netpolicy.ParseList("10.20.0.0/16")
		if err != nil {
			t.Fatal(err)
		}
		e.svc = e.newService("10.20.0.5", entries)
		if res, err := e.svc.Test(ctx, e.admin, mustUUID(t, id)); err != nil || !res.OK || len(res.KeyIDs) != 1 {
			t.Fatalf("allow-listed: %+v %v", res, err)
		}
	})
	t.Run("loopback, link-local and metadata addresses are never reached", func(t *testing.T) {
		for _, addr := range []string{"127.0.0.1", "169.254.169.254", "::1", "0.0.0.0"} {
			e := newEnv(t)
			entries, _ := netpolicy.ParseList("10.0.0.0/8")
			e.svc = e.newService(addr, entries)
			id := e.trust()
			res, err := e.svc.Test(ctx, e.admin, mustUUID(t, id))
			if err != nil || res.OK || res.Error != agentidentity.FetchNotAllowed || e.f.fetches.Load() != 0 {
				t.Fatalf("%s: %+v %v", addr, res, err)
			}
		}
	})
	t.Run("redirects are refused", func(t *testing.T) {
		e := newEnv(t)
		id := e.trust()
		e.f.set(func() { e.f.redirect = "https://example.com/elsewhere" })
		res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id))
		if res.OK || res.Error != agentidentity.FetchRedirect {
			t.Fatalf("redirect: %+v", res)
		}
	})
	t.Run("a response over 64 KiB is refused", func(t *testing.T) {
		e := newEnv(t)
		id := e.trust()
		e.f.set(func() { e.f.padding = 70 << 10 })
		res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id))
		if res.OK || res.Error != agentidentity.FetchTooLarge {
			t.Fatalf("too large: %+v", res)
		}
		// Just under the cap is fine.
		e.f.set(func() { e.f.padding = 60 << 10 })
		if res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id)); !res.OK {
			t.Fatalf("under the cap: %+v", res)
		}
	})
	t.Run("the content type and status are checked", func(t *testing.T) {
		e := newEnv(t)
		id := e.trust()
		e.f.set(func() { e.f.contentType = "text/html" })
		if res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id)); res.OK || res.Error != agentidentity.FetchContentType {
			t.Fatalf("content type: %+v", res)
		}
		e.f.set(func() { e.f.contentType = "application/json"; e.f.status = 404 })
		if res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id)); res.OK || res.Error != agentidentity.FetchStatus || res.HTTPCode != 404 {
			t.Fatalf("status: %+v", res)
		}
		e.f.set(func() { e.f.status = 200 })
		if res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id)); !res.OK {
			t.Fatalf("application/json: %+v", res)
		}
	})
	t.Run("a set without usable keys is an error, private keys are never trusted", func(t *testing.T) {
		e := newEnv(t)
		id := e.trust()
		e.f.publish() // none
		if res, _ := e.svc.Test(ctx, e.admin, mustUUID(t, id)); res.OK || res.Error != agentidentity.FetchNoKeys {
			t.Fatalf("empty: %+v", res)
		}
	})
	t.Run("the result is stored for the admin page", func(t *testing.T) {
		e := newEnv(t)
		id := e.trust()
		if _, err := e.svc.Test(ctx, e.admin, mustUUID(t, id)); err != nil {
			t.Fatal(err)
		}
		v, err := e.svc.Get(ctx, e.admin, mustUUID(t, id))
		if err != nil || v.Platform.JwksOk == nil || !*v.Platform.JwksOk || len(v.Platform.JwksKeyIds) != 1 || v.Platform.JwksKeyIds[0] != "k1" {
			t.Fatalf("stored result: %+v %v", v.Platform, err)
		}
		e.f.set(func() { e.f.status = 500 })
		_, _ = e.svc.Test(ctx, e.admin, mustUUID(t, id))
		v, _ = e.svc.Get(ctx, e.admin, mustUUID(t, id))
		if v.Platform.JwksOk == nil || *v.Platform.JwksOk || v.Platform.JwksError == nil || *v.Platform.JwksError != "http_status" || len(v.Platform.JwksKeyIds) != 0 {
			t.Fatalf("stored failure: %+v", v.Platform)
		}
	})
}

// The admin operations: platform admins only, never an automation token,
// validated and audited.
func TestPlatformAdministration(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	auditor := authz.Actor{PlatformRole: authz.PlatformAuditor, UserID: e.admin.UserID}
	token := authz.Actor{Kind: authz.KindAutomationToken, PlatformRole: authz.PlatformAdmin, TokenKind: authz.TokenPlatformAdmin, TokenScopes: []string{authz.ScopePlatformWrite}}
	nobody := authz.Actor{PlatformRole: authz.PlatformNone, UserID: e.admin.UserID}
	name := "Pi Durable Platform"
	in := agentidentity.Input{Name: &name, Issuer: ptr(issuer)}
	for who, a := range map[string]authz.Actor{"auditor": auditor, "token": token, "nobody": nobody} {
		if _, err := e.svc.Create(ctx, a, in); err == nil {
			t.Errorf("%s created a platform", who)
		}
	}
	v, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Platform.JwksUrl != jwksURL || v.Platform.Audience != audience || !v.Platform.Enabled {
		t.Fatalf("defaults: %+v", v.Platform)
	}
	id := v.Platform.ID
	for who, a := range map[string]authz.Actor{"auditor": auditor, "token": token, "nobody": nobody} {
		if _, err := e.svc.Update(ctx, a, id, agentidentity.Input{Enabled: ptr(false)}, v.Platform.Revision); err == nil {
			t.Errorf("%s updated a platform", who)
		}
		if err := e.svc.Delete(ctx, a, id); err == nil {
			t.Errorf("%s deleted a platform", who)
		}
		if _, err := e.svc.Test(ctx, a, id); err == nil {
			t.Errorf("%s tested a platform", who)
		}
		if _, err := e.svc.SetRelay(ctx, a, id, id); err == nil {
			t.Errorf("%s set a relay", who)
		}
	}
	if _, err := e.svc.List(ctx, auditor); err != nil {
		t.Errorf("an auditor lists platforms: %v", err)
	}
	if _, err := e.svc.List(ctx, nobody); err == nil {
		t.Error("a person without a platform role listed platforms")
	}
	for name, bad := range map[string]agentidentity.Input{
		"http issuer":              {Issuer: ptr("http://agents.example.com")},
		"issuer with a query":      {Issuer: ptr("https://agents.example.com/?a=b")},
		"issuer with userinfo":     {Issuer: ptr("https://u:p@agents.example.com")},
		"relative issuer":          {Issuer: ptr("agents.example.com")},
		"empty name":               {Name: ptr(" ")},
		"a JWKS URL on http":       {JWKSURL: ptr("http://agents.example.com/jwks")},
		"a loopback JWKS URL":      {JWKSURL: ptr("https://127.0.0.1/jwks")},
		"an audience with a space": {Audience: ptr("two words")},
	} {
		in := bad
		if in.Name == nil {
			in.Name = ptr("Second")
		}
		if in.Issuer == nil {
			in.Issuer = ptr("https://second.example.com")
		}
		if _, err := e.svc.Create(ctx, e.admin, in); err == nil {
			t.Errorf("%s: created", name)
		}
	}
	if _, err := e.svc.Create(ctx, e.admin, agentidentity.Input{Name: ptr("other"), Issuer: ptr(issuer)}); err == nil {
		t.Error("the same issuer was trusted twice")
	}
	if _, err := e.svc.Update(ctx, e.admin, id, agentidentity.Input{Enabled: ptr(false)}, 99); err == nil {
		t.Error("a stale revision updated")
	}
	u, err := e.svc.Update(ctx, e.admin, id, agentidentity.Input{Enabled: ptr(false), Audience: ptr("https://portal.example.org/")}, v.Platform.Revision)
	if err != nil || u.Platform.Enabled || u.Platform.Audience != "https://portal.example.org/" || u.Platform.Revision != v.Platform.Revision+1 {
		t.Fatalf("update: %+v %v", u.Platform, err)
	}
	if err := e.svc.Delete(ctx, e.admin, id); err != nil {
		t.Fatal(err)
	}
	var actions []string
	rows, err := e.pool.Query(ctx, `SELECT action FROM audit_log WHERE action LIKE 'agent_platform.%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	if strings.Join(actions, ",") != "agent_platform.create,agent_platform.update,agent_platform.delete" {
		t.Fatalf("audit = %v", actions)
	}
}

func TestPersonIssuerIsRequiredToBeConfigured(t *testing.T) {
	e := newEnv(t)
	e.trust()
	e.svc.PersonIssuer = ""
	if got := reasonOf(func() error { _, err := e.verify(e.token(nil, nil)); return err }()); got != "person_issuer" {
		t.Fatalf("a person with no configured issuer: %s", got)
	}
	// A token without a person doesn't need one.
	if _, err := e.verify(e.token(func(c map[string]any) { delete(c, "person") }, nil)); err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
