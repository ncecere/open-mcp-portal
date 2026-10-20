package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// hardenedEnv is a service over a real database with the v0.2.2 limits.
func hardenedEnv(t *testing.T, cfg Config) (*Service, *pgxpool.Pool) {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	cfg.Issuer, cfg.Pepper = "https://portal.example.com", make([]byte, 32)
	s := New(pool, nil, cfg)
	s.Log = testutil.Logger()
	return s, pool
}

func registerFrom(s *Service, addr string) (Registered, error) {
	return s.Register(context.Background(), ClientMetadata{ClientName: "App", RedirectURIs: []string{"https://app.example.com/cb"}}, "req", addr)
}

// A registration nobody used is gone after 24 hours (it no longer resolves,
// and the next registration deletes it); one that received tokens lives its 30
// days from its last use. The clock is the service's.
func TestUnusedRegistrationAgesOutAfter24Hours(t *testing.T) {
	s, pool := hardenedEnv(t, Config{})
	ctx := context.Background()
	unused, err := registerFrom(s, "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	used, err := registerFrom(s, "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE oauth_clients SET authorized_at = now() WHERE client_id = $1`, used.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	at := func(d time.Duration) { s.now = func() time.Time { return now.Add(d) } }

	for _, c := range []struct {
		after            time.Duration
		unusedOK, usedOK bool
	}{
		{23 * time.Hour, true, true},
		{25 * time.Hour, false, true},
		{29 * 24 * time.Hour, false, true},
		{31 * 24 * time.Hour, false, false},
	} {
		at(c.after)
		if _, err := s.ResolveClient(ctx, unused.ID); (err == nil) != c.unusedOK {
			t.Errorf("after %s: unused registration resolves = %v, want %v", c.after, err == nil, c.unusedOK)
		}
		if _, err := s.ResolveClient(ctx, used.ID); (err == nil) != c.usedOK {
			t.Errorf("after %s: used registration resolves = %v, want %v", c.after, err == nil, c.usedOK)
		}
	}
	// The next registration deletes what expired.
	at(25 * time.Hour)
	if _, err := registerFrom(s, "203.0.113.2"); err != nil {
		t.Fatal(err)
	}
	if n := liveClients(t, pool); n != 2 {
		t.Errorf("%d registrations stored after the unused one expired, want 2 (the used one and the new one)", n)
	}
}

// One address can hold only so many registrations that received no tokens;
// others are unaffected; a used or expired registration frees a place; an
// unknown address (no one to count) is never refused for it.
func TestUnusedRegistrationsPerAddress(t *testing.T) {
	s, pool := hardenedEnv(t, Config{MaxUnusedClientsPerAddress: 3})
	ctx := context.Background()
	var first string
	for i := range 3 {
		reg, err := registerFrom(s, "203.0.113.1")
		if err != nil {
			t.Fatalf("registration %d: %v", i+1, err)
		}
		if i == 0 {
			first = reg.ID
		}
	}
	_, err := registerFrom(s, "203.0.113.1")
	var oe *Error
	if !errors.As(err, &oe) || oe.Code != "slow_down" || oe.Status != http.StatusTooManyRequests || oe.ShowPage() ||
		!strings.Contains(oe.Description, "none of them has been used") {
		t.Fatalf("over the address's share: %v", err)
	}
	if n := liveClients(t, pool); n != 3 {
		t.Fatalf("%d registrations stored after a refusal", n)
	}
	if _, err := registerFrom(s, "203.0.113.2"); err != nil {
		t.Fatalf("another address: %v", err)
	}
	for range 5 {
		if _, err := registerFrom(s, ""); err != nil {
			t.Fatalf("without an address: %v", err)
		}
	}
	// One signs in (receives tokens): it stops counting.
	if _, err := pool.Exec(ctx, `UPDATE oauth_clients SET authorized_at = now() WHERE client_id = $1`, first); err != nil {
		t.Fatal(err)
	}
	if _, err := registerFrom(s, "203.0.113.1"); err != nil {
		t.Fatalf("after one was used: %v", err)
	}
	if _, err := registerFrom(s, "203.0.113.1"); err == nil {
		t.Fatal("the address is full again and was not refused")
	}
	// After 24 hours the rest have expired.
	s.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if _, err := registerFrom(s, "203.0.113.1"); err != nil {
		t.Fatalf("after 25 hours: %v", err)
	}
	// The per-address cap off.
	s.maxUnused = 0
	for range 5 {
		if _, err := registerFrom(s, "203.0.113.1"); err != nil {
			t.Fatalf("without a per-address cap: %v", err)
		}
	}
}

// The per-address cap holds under concurrent registrations (replicas).
func TestUnusedRegistrationsPerAddressHoldsUnderConcurrency(t *testing.T) {
	s, pool := hardenedEnv(t, Config{MaxUnusedClientsPerAddress: 4})
	results := make(chan error, 20)
	for range 20 {
		go func() { _, err := registerFrom(s, "203.0.113.1"); results <- err }()
	}
	ok := 0
	for range 20 {
		if err := <-results; err == nil {
			ok++
		}
	}
	if ok != 4 || liveClients(t, pool) != 4 {
		t.Fatalf("registered %d, stored %d, want 4", ok, liveClients(t, pool))
	}
}

// The switch: off, registration is refused with 403 access_denied, before the
// metadata is looked at; clients registered before still resolve.
func TestRegistrationSwitchOff(t *testing.T) {
	s, pool := hardenedEnv(t, Config{})
	ctx := context.Background()
	before, err := registerFrom(s, "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if open, err := s.OpenRegistration(ctx); err != nil || !open {
		t.Fatalf("default = %v %v", open, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE oauth_settings SET open_registration = false`); err != nil {
		t.Fatal(err)
	}
	for _, m := range []ClientMetadata{{ClientName: "App", RedirectURIs: []string{"https://app.example.com/cb"}}, {}} {
		_, err := s.Register(ctx, m, "req", "203.0.113.1")
		var oe *Error
		if !errors.As(err, &oe) || oe.Code != "access_denied" || oe.Status != http.StatusForbidden {
			t.Fatalf("registration while closed: %v", err)
		}
	}
	if n := liveClients(t, pool); n != 1 {
		t.Errorf("%d registrations stored", n)
	}
	if _, err := s.ResolveClient(ctx, before.ID); err != nil {
		t.Errorf("a client registered before no longer resolves: %v", err)
	}
	live, open, err := RegistrationStatus(ctx, dbgen.New(pool), time.Now())
	if err != nil || open || live != 1 {
		t.Errorf("status = %d %v %v", live, open, err)
	}
}

// Metadata fetches are counted per source address, only when the document
// isn't cached, and only when the request names an address.
func TestMetadataFetchesAreLimitedPerAddress(t *testing.T) {
	s, _ := hardenedEnv(t, Config{Rates: ratelimit.New()})
	s.Log = testutil.Logger()
	ctx := WithSource(context.Background(), "203.0.113.1")
	ok, refused := 0, 0
	for range MetadataFetchesPerMinute + 10 {
		if err := s.allowFetch(ctx); err == nil {
			ok++
		} else if oe := (*Error)(nil); errors.As(err, &oe) && oe.Code == "slow_down" && oe.Status == http.StatusTooManyRequests && oe.ShowPage() {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if ok != MetadataFetchesPerMinute || refused != 10 {
		t.Fatalf("allowed %d, refused %d", ok, refused)
	}
	if err := s.allowFetch(WithSource(context.Background(), "203.0.113.2")); err != nil {
		t.Errorf("another address: %v", err)
	}
	if err := s.allowFetch(context.Background()); err != nil {
		t.Errorf("no address: %v", err)
	}
}

// The successors of a refresh token are the same every time, differ between
// tokens, and look like tokens; they are not derivable without the pepper.
func TestRefreshSuccessorIsDeterministic(t *testing.T) {
	s, _ := hardenedEnv(t, Config{})
	a1, r1 := s.successor("omprt_one")
	a2, r2 := s.successor("omprt_one")
	a3, r3 := s.successor("omprt_two")
	if a1 != a2 || r1 != r2 || a1 == a3 || r1 == r3 || a1 == r1 || !IsAccessToken(a1) || !validTokenShape(r1, RefreshPrefix) {
		t.Fatalf("successors: %s %s / %s %s / %s %s", a1, r1, a2, r2, a3, r3)
	}
	other := New(nil, nil, Config{Issuer: "https://portal.example.com", Pepper: []byte("another pepper, another pepper!!")})
	if a, r := other.successor("omprt_one"); a == a1 || r == r1 {
		t.Fatal("successors don't depend on the pepper")
	}
}

// GrantExpiry counts from the last sign-in (or the creation, for a grant the
// previous release made) and is nil without a limit.
func TestGrantExpiry(t *testing.T) {
	s := New(nil, nil, Config{Issuer: "https://portal.example.com", Pepper: make([]byte, 32), RefreshAbsoluteTTL: 180 * 24 * time.Hour})
	created, signedIn := time.Now().Add(-300*24*time.Hour), time.Now().Add(-10*24*time.Hour)
	g := dbgen.OauthGrant{CreatedAt: created}
	if got := s.GrantExpiry(g); got == nil || !got.Equal(created.Add(180*24*time.Hour)) || !s.expired(g) {
		t.Errorf("without authorized_at: %v", got)
	}
	g.AuthorizedAt = &signedIn
	if got := s.GrantExpiry(g); got == nil || !got.Equal(signedIn.Add(180*24*time.Hour)) || s.expired(g) {
		t.Errorf("with authorized_at: %v", got)
	}
	s.refreshTTL = 0
	if s.GrantExpiry(g) != nil || s.expired(g) {
		t.Error("a limit of 0 still expires")
	}
}
