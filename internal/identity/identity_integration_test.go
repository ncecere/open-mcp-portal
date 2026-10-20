package identity_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func newService(t *testing.T) (*identity.Service, func(sql string)) {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	key, _ := secrets.ParseKey("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	return identity.New(pool, box, "https://mcp.example.com", testutil.Logger()), exec
}

// verify checks a token against a key set: signature, issuer, audience and
// expiry.
func verify(set jose.JSONWebKeySet, token string) (jwt.Claims, error) {
	var c jwt.Claims
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return c, err
	}
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) == 0 {
		return c, jose.ErrUnsupportedKeyType
	}
	if err := tok.Claims(keys[0].Key, &c); err != nil {
		return c, err
	}
	return c, c.Validate(jwt.Expected{Issuer: "https://mcp.example.com", AnyAudience: jwt.Audience{"https://srv.example.com/mcp"}, Time: time.Now()})
}

func kidOf(t *testing.T, token string) string {
	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Headers[0].KeyID
}

func kids(set jose.JSONWebKeySet) []string {
	out := []string{}
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	slices.Sort(out)
	return out
}

func sorted(ids ...string) []string {
	slices.Sort(ids)
	return ids
}

func TestSigningAndRotation(t *testing.T) {
	s, exec := newService(t)
	ctx := context.Background()
	claims := identity.Claims{Audience: "https://srv.example.com/mcp", Subject: "u1", Gateway: "g", Tool: "s__t"}
	if s.Prepublish != identity.DefaultPrepublish {
		t.Fatalf("prepublish = %s", s.Prepublish)
	}

	// The first key, on an empty table, is created on first use and signs at once.
	old, err := s.Sign(ctx, claims)
	if err != nil {
		t.Fatal(err)
	}
	set, err := s.JWKS(ctx)
	if err != nil || len(set.Keys) != 1 || set.Keys[0].Algorithm != "ES256" || !set.Keys[0].IsPublic() {
		t.Fatalf("jwks = %+v %v", set, err)
	}
	c, err := verify(set, old)
	if err != nil || c.Expiry.Time().Sub(c.IssuedAt.Time()) != identity.TokenTTL {
		t.Fatalf("verify = %+v %v", c, err)
	}
	oldKid := kidOf(t, old)
	// Nothing to rotate yet.
	if r, err := s.Rotate(ctx); err != nil || r.Created != "" || r.Promoted != "" || r.Retired != 0 {
		t.Fatalf("early rotation = %+v %v", r, err)
	}

	// A day (and the check interval) before the active key's rotation time,
	// the next key is created and published, but doesn't sign.
	exec(`UPDATE signing_keys SET activated_at = now() - interval '29 days 1 minute' WHERE state = 'active'`)
	r, err := s.Rotate(ctx)
	if err != nil || r.Created == "" || r.Created == oldKid || r.Promoted != "" {
		t.Fatalf("prepare = %+v %v", r, err)
	}
	nextKid := r.Created
	set, _ = s.JWKS(ctx)
	if got := kids(set); !slices.Equal(got, sorted(oldKid, nextKid)) {
		t.Fatalf("published while next = %v", got)
	}
	if tok, err := s.Sign(ctx, claims); err != nil || kidOf(t, tok) != oldKid {
		t.Fatalf("signed with the next key before its time (%v)", err)
	}
	if r, err := s.Rotate(ctx); err != nil || r.Created != "" || r.Promoted != "" {
		t.Fatalf("second pass = %+v %v", r, err)
	}

	// At the rotation time, a next key that hasn't been published for the
	// pre-publication period yet holds the rotation back.
	exec(`UPDATE signing_keys SET activated_at = now() - interval '31 days' WHERE state = 'active'`)
	if r, err := s.Rotate(ctx); err != nil || r.Promoted != "" || r.Created != "" {
		t.Fatalf("early promotion = %+v %v", r, err)
	}

	// Once published long enough it is promoted; the old key stays
	// published, so tokens it signed still verify.
	exec(`UPDATE signing_keys SET created_at = now() - interval '25 hours' WHERE state = 'next'`)
	r, err = s.Rotate(ctx)
	if err != nil || r.Promoted != nextKid || r.Created != "" {
		t.Fatalf("promotion = %+v %v", r, err)
	}
	fresh, err := s.Sign(ctx, claims)
	if err != nil || kidOf(t, fresh) != nextKid {
		t.Fatalf("signed with %s, want %s (%v)", kidOf(t, fresh), nextKid, err)
	}
	set, _ = s.JWKS(ctx)
	if got := kids(set); !slices.Equal(got, sorted(oldKid, nextKid)) {
		t.Fatalf("published after promotion = %v", got)
	}
	for _, tok := range []string{old, fresh} {
		if _, err := verify(set, tok); err != nil {
			t.Fatalf("token of %s: %v", kidOf(t, tok), err)
		}
	}
	// The promoted key's rotation time counts from its promotion.
	if r, err := s.Rotate(ctx); err != nil || r.Created != "" || r.Promoted != "" {
		t.Fatalf("after promotion = %+v %v", r, err)
	}

	// A day later the old key is retired and no longer published.
	exec(`UPDATE signing_keys SET retire_after = now() - interval '1 minute' WHERE state = 'retiring'`)
	if r, err := s.Rotate(ctx); err != nil || r.Retired != 1 || r.Created != "" || r.Promoted != "" {
		t.Fatalf("retire = %+v %v", r, err)
	}
	set, _ = s.JWKS(ctx)
	if len(set.Keys) != 1 || set.Keys[0].KeyID != nextKid {
		t.Fatalf("after retirement = %+v", set)
	}
	if _, err := verify(set, old); err == nil {
		t.Fatal("a retired key's token still verifies")
	}
	exec(`DO $$ BEGIN IF EXISTS (SELECT 1 FROM signing_keys WHERE state = 'retired' AND private_key_cipher IS NOT NULL) THEN RAISE 'kept'; END IF; END $$`)
}

// Without an active key, a published next key is promoted rather than a
// new, unpublished key created.
func TestNextKeyPromotedWhenNoneActive(t *testing.T) {
	s, exec := newService(t)
	ctx := context.Background()
	// The first pass on an empty table creates a key that signs at once.
	if r, err := s.Rotate(ctx); err != nil || r.Created == "" || r.Promoted != r.Created {
		t.Fatalf("first key = %+v %v", r, err)
	}
	exec(`UPDATE signing_keys SET activated_at = now() - interval '29 days 1 minute'`)
	r, err := s.Rotate(ctx)
	if err != nil || r.Created == "" {
		t.Fatalf("prepare = %+v %v", r, err)
	}
	exec(`UPDATE signing_keys SET state = 'retiring', retire_after = now() + interval '1 hour', rotated_at = now() WHERE state = 'active'`)
	tok, err := s.Sign(ctx, identity.Claims{Audience: "https://srv.example.com/mcp", Subject: "u1"})
	if err != nil || kidOf(t, tok) != r.Created {
		t.Fatalf("signed with %v, want the next key %s", err, r.Created)
	}
}

// With no pre-publication, a due key is replaced in one pass.
func TestRotationWithoutPrepublish(t *testing.T) {
	s, exec := newService(t)
	s.Prepublish = 0
	ctx := context.Background()
	if _, err := s.JWKS(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE signing_keys SET activated_at = now() - interval '31 days'`)
	r, err := s.Rotate(ctx)
	if err != nil || r.Created == "" || r.Promoted != r.Created {
		t.Fatalf("rotation = %+v %v", r, err)
	}
}

func TestPlanRotation(t *testing.T) {
	for _, c := range []struct {
		hasNext, prepareDue, rotateDue, nextReady bool
		want                                      identity.Plan
	}{
		{false, false, false, false, identity.Plan{}},
		{false, true, false, false, identity.Plan{CreateNext: true}},
		{false, true, true, false, identity.Plan{CreateNext: true}},
		{true, true, false, true, identity.Plan{}},
		{true, true, true, false, identity.Plan{}},
		{true, true, true, true, identity.Plan{Promote: true}},
	} {
		if got := identity.PlanRotation(c.hasNext, c.prepareDue, c.rotateDue, c.nextReady); got != c.want {
			t.Errorf("%+v: %+v", c, got)
		}
	}
}

func TestHeaderChoice(t *testing.T) {
	for static, want := range map[string]string{"": "Authorization", "X-API-Key": "Authorization", "authorization": "MCP-Gateway-Identity"} {
		name, value := identity.Header(static, "tok")
		if name != want || (name == "Authorization") != (value == "Bearer tok") {
			t.Errorf("static %q: %s %s", static, name, value)
		}
	}
}

// The act claim (decision 66, RFC 8693 style) names the agent behind a call
// an agent platform relayed for a person; it is in a token exactly when the
// claims carry an Actor.
func TestActClaim(t *testing.T) {
	s, _ := newService(t)
	claimsOf := func(c identity.Claims) map[string]any {
		t.Helper()
		token, err := s.Sign(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := tok.UnsafeClaimsWithoutVerification(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	base := identity.Claims{Audience: "https://srv.example.com/mcp", PrincipalType: identity.PrincipalUser, Subject: "u-1", Email: "ada@example.com",
		Name: "Ada", Teams: []string{"tools"}, Gateway: "support", Client: "pdp-relay"}
	plain := claimsOf(base)
	if _, ok := plain["act"]; ok {
		t.Fatalf("a call without an actor has act: %v", plain["act"])
	}
	base.Act = &identity.Actor{Subject: "agent-1", Name: "Mail assistant", Issuer: "https://agents.example.com", PrincipalType: identity.PrincipalAgent, PersonPresent: false}
	got := claimsOf(base)
	act, _ := got["act"].(map[string]any)
	if len(act) != 5 || act["sub"] != "agent-1" || act["name"] != "Mail assistant" || act["iss"] != "https://agents.example.com" || act["principal_type"] != "agent" || act["person_present"] != false {
		t.Fatalf("act = %v", act)
	}
	// The person's own claims are untouched by it.
	if got["principal_type"] != "user" || got["sub"] != "u-1" || got["email"] != "ada@example.com" || got["client"] != "pdp-relay" {
		t.Fatalf("claims = %v", got)
	}
	// An actor without a name leaves the member out.
	base.Act = &identity.Actor{Subject: "agent-2", Issuer: "https://agents.example.com", PrincipalType: identity.PrincipalAgent, PersonPresent: true}
	if act, _ := claimsOf(base)["act"].(map[string]any); len(act) != 4 || act["name"] != nil || act["person_present"] != true {
		t.Fatalf("nameless act = %v", act)
	}
}
