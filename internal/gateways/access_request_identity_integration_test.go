package gateways_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestAccessRequestGrantBindsRequesterIDWithDuplicateEmail(t *testing.T) {
	f := newAccessFixture(t)
	ctx := context.Background()
	q := dbgen.New(f.pool)
	requester, err := q.GetUser(ctx, f.requester.UserID)
	if err != nil {
		t.Fatal(err)
	}
	other := uuid.New()
	// A distinct issuer/subject may legitimately share an email. Place the
	// other identity first in the old email lookup order: it must get no grant.
	if _, err := f.pool.Exec(ctx, `INSERT INTO users(id,oidc_issuer,oidc_subject,email,created_at)
		VALUES($1,'different-issuer',$2,$3,clock_timestamp()-interval '1 day')`, other, other.String(), requester.Email); err != nil {
		t.Fatal(err)
	}
	gateway := f.gateway(t)
	r, err := f.svc.CreateAccessRequest(ctx, f.requester, gateway, nil, "exact requesting identity")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := f.svc.DecideAccessRequest(ctx, f.admin, r.ID, gateways.AccessDecision{Decision: "approve"})
	if err != nil || approved.GrantID == nil {
		t.Fatalf("approve: %+v %v", approved, err)
	}
	var granted uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT user_id FROM gateway_grants WHERE id=$1`, *approved.GrantID).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if granted != f.requester.UserID {
		t.Fatalf("grant resolved by ambiguous email: %s, want %s", granted, f.requester.UserID)
	}
	g, err := q.GetGateway(ctx, gateway)
	if err != nil {
		t.Fatal(err)
	}
	u, err := q.GetUser(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := f.svc.CallerOf(ctx, g, u)
	if err != nil || caller.Allowed() {
		t.Fatalf("other identity gained access: %+v %v", caller, err)
	}
}
