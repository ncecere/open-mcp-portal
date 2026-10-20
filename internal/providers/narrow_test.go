package providers

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The in-memory cache of narrowed tokens (decision 69): a token lives until
// it expires, is keyed by connection, consent and scope set (in any order),
// and the cache is bounded.
func TestNarrowCache(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var c narrowCache
	conn := dbgen.ProviderConnection{ID: uuid.New(), ConnectedAt: now}
	key := narrowKeyOf(conn, []string{"repo", "read:user"})
	if _, ok := c.get(key, now); ok {
		t.Fatal("an empty cache returned a token")
	}
	c.put(key, "tok", now.Add(time.Minute), now)
	if got, ok := c.get(narrowKeyOf(conn, []string{"read:user", "repo"}), now.Add(59*time.Second)); !ok || got != "tok" {
		t.Fatalf("scope order changed the key: %q %v", got, ok)
	}
	if _, ok := c.get(narrowKeyOf(conn, []string{"repo"}), now); ok {
		t.Fatal("another scope set shared a token")
	}
	// A reconnect (the same row, a new consent) never finds the old consent's token.
	again := conn
	again.ConnectedAt = now.Add(time.Second)
	if _, ok := c.get(narrowKeyOf(again, []string{"repo", "read:user"}), now); ok {
		t.Fatal("a reconnect found the old token")
	}
	other := dbgen.ProviderConnection{ID: uuid.New(), ConnectedAt: now}
	if _, ok := c.get(narrowKeyOf(other, []string{"repo", "read:user"}), now); ok {
		t.Fatal("another connection shared a token")
	}
	if _, ok := c.get(key, now.Add(time.Minute)); ok {
		t.Fatal("an expired token was returned")
	}
	if c.len() != 0 {
		t.Fatalf("expired token kept: %d", c.len())
	}

	// Bounded: it never grows past narrowCacheMax, and keeps the newest entry.
	for i := 0; i < narrowCacheMax+50; i++ {
		k := narrowKeyOf(dbgen.ProviderConnection{ID: uuid.New(), ConnectedAt: now}, []string{"s"})
		c.put(k, "t", now.Add(time.Hour), now)
		if c.len() > narrowCacheMax {
			t.Fatalf("cache grew to %d", c.len())
		}
		if _, ok := c.get(k, now); !ok {
			t.Fatal("the entry just stored is gone")
		}
	}
}

// narrows: only platform providers with the switch on, a refresh token held
// and scopes to narrow to.
func TestNarrows(t *testing.T) {
	refreshable := dbgen.ProviderConnection{RefreshTokenCipher: []byte("x")}
	on := dbgen.AuthProvider{Kind: KindOAuth2, NarrowOnRefresh: true}
	cases := []struct {
		name   string
		p      dbgen.AuthProvider
		c      dbgen.ProviderConnection
		scopes []string
		want   bool
	}{
		{"on", on, refreshable, []string{"repo"}, true},
		{"switch off", dbgen.AuthProvider{Kind: KindOAuth2}, refreshable, []string{"repo"}, false},
		{"no refresh token", on, dbgen.ProviderConnection{}, []string{"repo"}, false},
		{"no scopes asked", on, refreshable, nil, false},
		{"an oauth server's own sign-in", dbgen.AuthProvider{Kind: KindMCPServer, NarrowOnRefresh: true}, refreshable, []string{"repo"}, false},
	}
	for _, tc := range cases {
		if got := narrows(tc.p, tc.c, tc.scopes); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Only a preset whose provider documents a refresh request's scope narrowing
// the new token pre-fills the switch (docs/phase5-delegated-credentials.md);
// adding another needs the documentation to be checked, not a guess.
func TestOnlyDocumentedPresetsNarrow(t *testing.T) {
	for _, p := range Presets {
		if want := p.Preset == "microsoft"; p.NarrowOnRefresh != want {
			t.Errorf("preset %s: NarrowOnRefresh = %v, want %v", p.Preset, p.NarrowOnRefresh, want)
		}
		if !p.NarrowOnRefresh && !strings.Contains(p.Notes, "narrowing") {
			t.Errorf("preset %s says nothing about narrowing", p.Preset)
		}
	}
}
