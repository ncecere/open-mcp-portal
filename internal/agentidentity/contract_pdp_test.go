package agentidentity

// Contract test: tokens and JWKS documents produced by Pi Durable Platform's
// REAL signing and JWKS-serving code (see testdata/pdp/README.md) must be
// accepted or refused by this package's verifier exactly as recorded in each
// token's *.expected.json. The fixtures use fixed timestamps; the verifier's
// clock is injected (SetClock), so this keeps passing after the tokens'
// five-minute life is long over.
//
// Needs the test Postgres like the other integration tests (OMP_TEST_DATABASE_URL).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

//go:embed testdata/pdp
var pdpFixtures embed.FS

// The platform and portal the fixtures were generated for.
const (
	pdpIssuer       = "https://agents.example.com"
	pdpPortalAud    = "https://mcp.example.com" // the portal's APP_URL = PDP's identityAudience
	pdpPersonIssuer = "https://login.example.org/application/o/pdp/"
	pdpFetchHost    = "agents.example.com"
)

type pdpCheck struct {
	Name             string `json:"name"`
	At               string `json:"at"`
	JWKS             string `json:"jwks"`
	Accept           bool   `json:"accept"`
	Reason           string `json:"reason"`
	Twice            bool   `json:"twice"`
	PlatformAudience string `json:"platformAudience"`
	PersonIssuer     string `json:"personIssuer"`
	Identity         *struct {
		AgentName     string `json:"agentName"`
		TeamKind      string `json:"teamKind"`
		Visibility    string `json:"visibility"`
		Tool          string `json:"tool"`
		HasPerson     bool   `json:"hasPerson"`
		PersonPresent bool   `json:"personPresent"`
		PersonEmail   string `json:"personEmail"`
	} `json:"identity"`
}

type pdpExpected struct {
	Description string     `json:"description"`
	Checks      []pdpCheck `json:"checks"`
}

type pdpJWKSHeaders struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
}

type pdpPolicy struct{ p *netpolicy.Policy }

func (s pdpPolicy) Current(context.Context) *netpolicy.Policy { return s.p }

// pdpServer serves one recorded PDP JWKS response (body and headers as PDP's
// handler produced them) at PDP's well-known path.
type pdpServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	body []byte
	hdr  pdpJWKSHeaders
	hits []string
}

func newPDPServer(t *testing.T) *pdpServer {
	s := &pdpServer{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits = append(s.hits, r.URL.Path)
		if r.URL.Path != WellKnownJWKS || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		for k, v := range s.hdr.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(s.hdr.Status)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *pdpServer) load(t *testing.T, name string) {
	t.Helper()
	body, err := pdpFixtures.ReadFile("testdata/pdp/jwks/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var h pdpJWKSHeaders
	raw, err := pdpFixtures.ReadFile("testdata/pdp/jwks/" + name + ".headers.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.body, s.hdr = body, h
	s.mu.Unlock()
}

type pdpEnv struct {
	t     *testing.T
	srv   *pdpServer
	admin authz.Actor
	mk    func(personIssuer string, at time.Time) *Service
}

func newPDPEnv(t *testing.T) *pdpEnv {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	e := &pdpEnv{t: t, srv: newPDPServer(t)}
	var admin string
	if err := pool.QueryRow(context.Background(), `INSERT INTO users (oidc_issuer, oidc_subject, email, display_name, platform_role)
		VALUES ($1, 'admin', 'admin@example.com', 'Admin', 'platform_admin') RETURNING id::text`, pdpPersonIssuer).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	e.admin = authz.Actor{PlatformRole: authz.PlatformAdmin}
	e.admin.UserID = uuid.MustParse(admin)
	roots := e.srv.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	e.mk = func(personIssuer string, at time.Time) *Service {
		client := &upstream.Client{
			Networks: pdpPolicy{netpolicy.New(nil)},
			Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
				if host != pdpFetchHost {
					return nil, errors.New("no such host")
				}
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			},
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, e.srv.srv.Listener.Addr().String())
			},
		}
		s := New(pool, client, pdpPortalAud, personIssuer, testutil.Logger())
		// httptest's certificate is for example.com.
		s.TLS = &tls.Config{RootCAs: roots, ServerName: "example.com"}
		s.SetClock(func() time.Time { return at })
		return s
	}
	return e
}

func pdpPtr[T any](v T) *T { return &v }

func pdpReason(err error) string {
	var r *Rejection
	switch {
	case err == nil:
		return ""
	case errors.As(err, &r):
		return r.Reason
	}
	return "error: " + err.Error()
}

func pdpSegment(t *testing.T, tok string, i int, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestPDPContractTokens(t *testing.T) {
	e := newPDPEnv(t)
	entries, err := pdpFixtures.ReadDir("testdata/pdp/tokens")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ent := range entries {
		if !strings.HasSuffix(ent.Name(), ".expected.json") {
			continue
		}
		name := strings.TrimSuffix(ent.Name(), ".expected.json")
		n++
		rawExp, _ := pdpFixtures.ReadFile(path.Join("testdata/pdp/tokens", ent.Name()))
		var exp pdpExpected
		if err := json.Unmarshal(rawExp, &exp); err != nil {
			t.Fatal(err)
		}
		rawTok, err := pdpFixtures.ReadFile("testdata/pdp/tokens/" + name + ".jwt")
		if err != nil {
			t.Fatal(err)
		}
		tok := strings.TrimSpace(string(rawTok))
		for _, ck := range exp.Checks {
			t.Run(name+"/"+ck.Name, func(t *testing.T) {
				at, err := time.Parse(time.RFC3339, ck.At)
				if err != nil {
					t.Fatal(err)
				}
				personIssuer := pdpPersonIssuer
				if ck.PersonIssuer != "" {
					personIssuer = ck.PersonIssuer
				}
				audience := pdpPortalAud
				if ck.PlatformAudience != "" {
					audience = ck.PlatformAudience
				}
				e.srv.load(t, ck.JWKS)
				svc := e.mk(personIssuer, at)
				v, err := svc.Create(context.Background(), e.admin, Input{Name: pdpPtr("Pi Durable Platform"), Issuer: pdpPtr(pdpIssuer), Audience: pdpPtr(audience)})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := svc.Delete(context.Background(), e.admin, v.Platform.ID); err != nil {
						t.Fatal(err)
					}
				}()
				id, err := svc.Verify(context.Background(), tok)
				if got := pdpReason(err); got != ck.Reason {
					t.Fatalf("refused as %q (%v), want %q", got, err, ck.Reason)
				}
				if ck.Twice {
					if got := pdpReason(func() error { _, err := svc.Verify(context.Background(), tok); return err }()); got != "replay" {
						t.Fatalf("second use: %q, want replay", got)
					}
				}
				if !ck.Accept {
					return
				}
				// What the verifier made of the token must be what PDP put in it.
				var c struct {
					Sub, Jti      string
					Iat, Nbf, Exp int64
					Team          struct{ ID, Slug, Kind string }
					Person        *struct{ Iss, Sub, Email string }
				}
				pdpSegment(t, tok, 1, &c)
				if id.AgentID != c.Sub || id.JTI != c.Jti || id.TeamID != c.Team.ID || id.TeamSlug != c.Team.Slug ||
					id.IssuedAt.Unix() != c.Iat || id.NotBefore.Unix() != c.Nbf || id.ExpiresAt.Unix() != c.Exp ||
					id.Platform.Issuer != pdpIssuer {
					t.Fatalf("identity %+v does not match the token's claims %+v", id, c)
				}
				if c.Nbf != c.Iat-30 || c.Exp != c.Iat+300 {
					t.Fatalf("PDP's timing changed: iat %d nbf %d exp %d", c.Iat, c.Nbf, c.Exp)
				}
				want := ck.Identity
				if want == nil {
					t.Fatal("an accepted check has no identity")
				}
				if id.AgentName != want.AgentName || id.TeamKind != want.TeamKind || id.ThreadVisibility != want.Visibility ||
					id.Tool != want.Tool || id.PersonPresent != want.PersonPresent || (id.Person != nil) != want.HasPerson {
					t.Fatalf("identity = %+v, want %+v", id, *want)
				}
				if id.Person != nil {
					if c.Person == nil || id.Person.Issuer != c.Person.Iss || id.Person.Subject != c.Person.Sub || id.Person.Email != want.PersonEmail {
						t.Fatalf("person = %+v, token has %+v, want email %q", id.Person, c.Person, want.PersonEmail)
					}
				}
			})
		}
	}
	if n < 6 {
		t.Fatalf("only %d token fixtures found", n)
	}
}

// Derived refusals: a PDP token altered in transit is refused, whatever PDP
// signed.
func TestPDPContractTampering(t *testing.T) {
	e := newPDPEnv(t)
	raw, err := pdpFixtures.ReadFile("testdata/pdp/tokens/personal_private_email_portalaud.jwt")
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(string(raw))
	parts := strings.Split(tok, ".")
	var claims map[string]any
	pdpSegment(t, tok, 1, &claims)
	claims["person"] = map[string]any{"iss": pdpPersonIssuer, "sub": "someone-else"}
	forged, _ := json.Marshal(claims)
	flip := func(s string) string { // change a base64 character inside the signature (the last one holds padding bits)
		c := byte('A')
		if s[10] == 'A' {
			c = 'B'
		}
		return s[:10] + string(c) + s[11:]
	}
	for name, bad := range map[string]string{
		"payload swapped for another person": parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2],
		"signature bit flipped":              parts[0] + "." + parts[1] + "." + flip(parts[2]),
	} {
		t.Run(name, func(t *testing.T) {
			at := time.Unix(1792497600, 0)
			e.srv.load(t, "jwks-single")
			svc := e.mk(pdpPersonIssuer, at)
			v, err := svc.Create(context.Background(), e.admin, Input{Name: pdpPtr("Pi Durable Platform"), Issuer: pdpPtr(pdpIssuer), Audience: pdpPtr(pdpPortalAud)})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Delete(context.Background(), e.admin, v.Platform.ID) //nolint:errcheck
			if got := pdpReason(func() error { _, err := svc.Verify(context.Background(), bad); return err }()); got != "signature" {
				t.Fatalf("refused as %q, want signature", got)
			}
		})
	}
}

// The JWKS documents exactly as PDP's handler wrote them: the portal's fetch
// (content type, size, cache lifetime) and parser accept every one, each key
// is usable, and each kid is the key's RFC 7638 thumbprint.
func TestPDPContractJWKS(t *testing.T) {
	e := newPDPEnv(t)
	entries, err := pdpFixtures.ReadDir("testdata/pdp/jwks")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".headers.json") || strings.HasPrefix(ent.Name(), "real-http") {
			continue
		}
		name := strings.TrimSuffix(ent.Name(), ".json")
		n++
		t.Run(name, func(t *testing.T) {
			body, _ := pdpFixtures.ReadFile("testdata/pdp/jwks/" + ent.Name())
			var doc struct {
				Keys []map[string]string `json:"keys"`
			}
			if err := json.Unmarshal(body, &doc); err != nil || len(doc.Keys) == 0 {
				t.Fatalf("fixture is not a JWKS: %v", err)
			}
			for _, k := range doc.Keys {
				if k["kty"] != "EC" || k["crv"] != "P-256" || k["use"] != "sig" || k["alg"] != "ES256" {
					t.Errorf("unexpected key shape %v", k)
				}
				thumb := sha256.Sum256([]byte(`{"crv":"` + k["crv"] + `","kty":"` + k["kty"] + `","x":"` + k["x"] + `","y":"` + k["y"] + `"}`))
				if k["kid"] != base64.RawURLEncoding.EncodeToString(thumb[:]) {
					t.Errorf("kid %q is not the RFC 7638 thumbprint", k["kid"])
				}
			}
			e.srv.load(t, name)
			svc := e.mk(pdpPersonIssuer, time.Unix(1792497600, 0))
			v, err := svc.Create(context.Background(), e.admin, Input{Name: pdpPtr("Pi Durable Platform"), Issuer: pdpPtr(pdpIssuer), Audience: pdpPtr(pdpPortalAud)})
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Delete(context.Background(), e.admin, v.Platform.ID) //nolint:errcheck
			res, err := svc.Test(context.Background(), e.admin, v.Platform.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK || len(res.KeyIDs) != len(doc.Keys) {
				t.Fatalf("test result %+v for %d published keys", res, len(doc.Keys))
			}
			if res.CacheFor != 5*time.Minute {
				t.Errorf("cache lifetime %s, PDP publishes max-age=300", res.CacheFor)
			}
		})
	}
	if n < 3 {
		t.Fatalf("only %d jwks fixtures found", n)
	}
}

// A rotation seen from the portal (pdp rotate-mcp-identity-key): the cache
// holds the old key set, a token signed by the new key arrives, the portal
// fetches the set again once and accepts it. The two JWKS documents and the
// token are PDP's own (jwks-single before, jwks-overlap after the rotation).
func TestPDPContractRotationRefetch(t *testing.T) {
	e := newPDPEnv(t)
	raw, err := pdpFixtures.ReadFile("testdata/pdp/tokens/rot_new_key.jwt")
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(string(raw))
	var c struct{ Iat int64 }
	pdpSegment(t, tok, 1, &c)
	svc := e.mk(pdpPersonIssuer, time.Unix(c.Iat, 0))
	v, err := svc.Create(context.Background(), e.admin, Input{Name: pdpPtr("Pi Durable Platform"), Issuer: pdpPtr(pdpIssuer), Audience: pdpPtr(pdpPortalAud)})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.load(t, "jwks-single") // what the portal cached before the rotation
	if res, err := svc.Test(context.Background(), e.admin, v.Platform.ID); err != nil || !res.OK || len(res.KeyIDs) != 1 {
		t.Fatalf("warm-up: %+v %v", res, err)
	}
	e.srv.load(t, "jwks-overlap") // PDP now publishes both keys
	e.srv.mu.Lock()
	before := len(e.srv.hits)
	e.srv.mu.Unlock()
	if _, err := svc.Verify(context.Background(), tok); err != nil {
		t.Fatalf("the new key's token after a rotation: %v", err)
	}
	e.srv.mu.Lock()
	fetches := len(e.srv.hits) - before
	e.srv.mu.Unlock()
	if fetches != 1 {
		t.Fatalf("%d JWKS fetches for an unknown kid, want 1", fetches)
	}
}
