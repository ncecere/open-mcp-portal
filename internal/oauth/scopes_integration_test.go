package oauth

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// A silent flow can pass its initial ConsentState check before a human
// narrows another flow. Approve must enforce expansion again under the
// serialization lock, not trust that earlier (now stale) decision.
func TestScopeSilentApprovalCannotRestoreHumanCeiling(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	q := dbgen.New(pool)
	var uid, gid uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES ('test','person','person@example.com') RETURNING id`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO gateways(slug,name,owner_kind) VALUES ('scoped','Scoped','platform') RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	g, err := q.GetGateway(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	s := New(pool, nil, Config{Issuer: "https://portal.example", Pepper: []byte(strings.Repeat("p", 32))})
	c := Client{ID: "https://claude.ai/oauth/mcp-oauth-client-metadata", Name: "Trusted", Kind: KindMetadata}
	a := authz.Actor{UserID: uid}
	r := AuthorizeRequest{ClientID: c.ID, RedirectURI: "https://client.example/cb", Resource: s.Resource(g.Slug), CodeChallenge: strings.Repeat("x", 43)}
	if _, err := s.Approve(ctx, a, c, g, r, ConsentTrusted); err != nil {
		t.Fatal(err)
	}
	state, err := s.ConsentState(ctx, uid, c, gid, r.RedirectURI, nil)
	if err != nil || !state.Silent() {
		t.Fatalf("initial state=%+v %v", state, err)
	}
	// Another flow records the human's narrower choice before this silent
	// approval reaches its transaction. The old silent decision is stale.
	read := &toolscope.Scope{Classes: []string{"read"}}
	if _, err := s.Approve(ctx, a, c, g, r, ConsentAllowed, read); err != nil {
		t.Fatal(err)
	}
	gr, err := q.GetActiveOAuthGrant(ctx, dbgen.GetActiveOAuthGrantParams{UserID: uid, ClientID: c.ID, GatewayID: gid})
	if err != nil {
		t.Fatal(err)
	}
	var before int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM oauth_codes`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, a, c, g, r, ConsentTrusted); err == nil {
		t.Fatal("stale silent approval restored unrestricted access")
	} else if e, ok := apperr.As(err); !ok || e.Code != "consent_required" {
		t.Fatalf("wrong failure: %v", err)
	}
	current, err := q.GetActiveOAuthGrant(ctx, dbgen.GetActiveOAuthGrantParams{UserID: uid, ClientID: c.ID, GatewayID: gid})
	if err != nil || current.ID != gr.ID || !toolscope.Equal(toolscope.Stored(current.ToolScope), read) {
		t.Fatalf("grant mutated: %+v %v", current, err)
	}
	var after int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM oauth_codes`).Scan(&after); err != nil || before != after {
		t.Fatalf("silent expansion issued a code: %d -> %d (%v)", before, after, err)
	}
}
