package agentidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Only public P-256 signing keys with a kid, once each, are trusted.
func TestParseJWKSKeepsOnlyUsableKeys(t *testing.T) {
	good, other, dupA, dupB := p256(t), p256(t), p256(t), p256(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := []jose.JSONWebKey{
		{Key: &good.PublicKey, KeyID: "good", Algorithm: "ES256", Use: "sig"},
		{Key: &other.PublicKey, KeyID: "no-alg-no-use"},
		{Key: good, KeyID: "private"}, // a private key: never trusted
		{Key: &p384.PublicKey, KeyID: "p384"},
		{Key: &rsaKey.PublicKey, KeyID: "rsa"},
		{Key: &other.PublicKey, KeyID: ""},                                         // no kid
		{Key: &other.PublicKey, KeyID: "encryption", Use: "enc"},                   // not for signing
		{Key: &other.PublicKey, KeyID: "rs256", Algorithm: "RS256"},                // another algorithm
		{Key: &dupA.PublicKey, KeyID: "dup"}, {Key: &dupB.PublicKey, KeyID: "dup"}, // ambiguous
	}
	raws := make([]json.RawMessage, len(keys))
	for i, k := range keys {
		b, err := k.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		raws[i] = b
	}
	body, _ := json.Marshal(map[string]any{"keys": append(raws, json.RawMessage(`{"kty":"EC","crv":"P-256","x":"!!","y":"!!","kid":"junk"}`), json.RawMessage(`"not a key"`))})
	got, kids, err := parseJWKS(body)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"good", "no-alg-no-use"}; !slices.Equal(kids, want) || len(got) != 2 {
		t.Fatalf("kids = %v, want %v", kids, want)
	}
	for _, bad := range []string{`{}`, `{"keys":null}`, `[]`, `not json`} {
		if _, _, err := parseJWKS([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestCacheTTL(t *testing.T) {
	for cc, want := range map[string]time.Duration{
		"":                       defaultCacheTTL,
		"public, max-age=300":    5 * time.Minute,
		"max-age=3600":           5 * time.Minute,
		"max-age=30":             30 * time.Second,
		"max-age=0":              minCacheTTL,
		"MAX-AGE=45, public":     45 * time.Second,
		"no-store":               minCacheTTL,
		"no-cache":               minCacheTTL,
		"max-age=99999999999999": defaultCacheTTL, // not a number we parse: the default
		"s-maxage=10":            defaultCacheTTL,
		"max-age=abc":            defaultCacheTTL,
	} {
		if got := cacheTTL(cc); got != want {
			t.Errorf("Cache-Control %q: %s, want %s", cc, got, want)
		}
	}
}
