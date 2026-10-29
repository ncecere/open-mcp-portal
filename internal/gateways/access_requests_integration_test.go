package gateways_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type accessFixture struct {
	pool             *pgxpool.Pool
	svc              *gateways.Service
	requester, admin authz.Actor
}

func newAccessFixture(t *testing.T) accessFixture {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	f := accessFixture{pool: pool, svc: gateways.New(pool, "http://localhost", testutil.Logger()),
		requester: authz.Actor{UserID: uuid.New()}, admin: authz.Actor{UserID: uuid.New(), PlatformRole: authz.PlatformAdmin}}
	for _, a := range []authz.Actor{f.requester, f.admin} {
		role := a.PlatformRole
		if role == "" {
			role = "none"
		}
		if _, err := pool.Exec(context.Background(), `INSERT INTO users(id,oidc_issuer,oidc_subject,email,platform_role) VALUES($1,'access',$2,$3,$4)`, a.UserID, a.UserID.String(), a.UserID.String()+"@example.invalid", role); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f accessFixture) gateway(t *testing.T) uuid.UUID {
	t.Helper()
	g, err := f.svc.AdminCreate(context.Background(), f.admin, gateways.CreateInput{Slug: "g-" + uuid.NewString(), Name: "Requestable", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetAccessSettings(context.Background(), f.admin, g.Gateway.ID, g.Gateway.Revision, true, nil); err != nil {
		t.Fatal(err)
	}
	return g.Gateway.ID
}

func TestAccessRequestConcurrentPendingLimitAndDuplicates(t *testing.T) {
	f := newAccessFixture(t)
	ctx := context.Background()
	gateways := make([]uuid.UUID, 12)
	for i := range gateways {
		gateways[i] = f.gateway(t)
	}
	start := make(chan struct{})
	results := make(chan error, len(gateways))
	for _, id := range gateways {
		go func(id uuid.UUID) {
			<-start
			_, err := f.svc.CreateAccessRequest(ctx, f.requester, id, nil, "concurrent request")
			results <- err
		}(id)
	}
	close(start)
	success, limited := 0, 0
	for range gateways {
		err := <-results
		if err == nil {
			success++
			continue
		}
		if e, ok := apperr.As(err); ok && e.Code == "too_many_requests" {
			limited++
		} else {
			t.Errorf("unexpected create error: %v", err)
		}
	}
	if success != 10 || limited != 2 {
		t.Fatalf("pending limit: successes=%d limited=%d", success, limited)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM access_requests WHERE status='pending'`).Scan(&n); err != nil || n != 10 {
		t.Fatalf("pending=%d %v", n, err)
	}

	other := authz.Actor{UserID: uuid.New()}
	if _, err := f.pool.Exec(ctx, `INSERT INTO users(id,oidc_issuer,oidc_subject,email) VALUES($1,'access',$2,$3)`, other.UserID, other.UserID.String(), other.UserID.String()+"@example.invalid"); err != nil {
		t.Fatal(err)
	}
	results = make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.CreateAccessRequest(ctx, other, gateways[0], nil, "duplicate race")
			results <- err
		}()
	}
	wg.Wait()
	success, duplicate := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if e, ok := apperr.As(err); ok && e.Code == "request_pending" {
			duplicate++
		} else {
			t.Errorf("duplicate error: %v", err)
		}
	}
	if success != 1 || duplicate != 1 {
		t.Fatalf("duplicate race successes=%d duplicates=%d", success, duplicate)
	}
}

func TestAccessRequestConcurrentDecisionsAndAtomicRollback(t *testing.T) {
	f := newAccessFixture(t)
	ctx := context.Background()
	g := f.gateway(t)
	r, err := f.svc.CreateAccessRequest(ctx, f.requester, g, nil, "decision race")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			_, err := f.svc.DecideAccessRequest(ctx, f.admin, r.ID, gateways.AccessDecision{Decision: "approve"})
			results <- err
		}()
	}
	close(start)
	success, conflict := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if e, ok := apperr.As(err); ok && e.Code == "request_decided" {
			conflict++
		} else {
			t.Errorf("decision error: %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("decision race successes=%d conflicts=%d", success, conflict)
	}
	var grants, audits int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM gateway_grants WHERE gateway_id=$1), (SELECT count(*) FROM audit_log WHERE action='access_request.approve')`, g).Scan(&grants, &audits); err != nil || grants != 1 || audits != 1 {
		t.Fatalf("grants=%d decisions=%d err=%v", grants, audits, err)
	}

	g2 := f.gateway(t)
	r2, err := f.svc.CreateAccessRequest(ctx, f.requester, g2, nil, "rollback sentinel")
	if err != nil {
		t.Fatal(err)
	}
	owner := testutil.OwnerPool(t, f.pool)
	// Privileged failure instrumentation stays in this disposable test DB.
	if _, err := owner.Exec(ctx, fmt.Sprintf(`ALTER TABLE access_requests ADD CONSTRAINT reject_this_decision CHECK(id<>'%s' OR status<>'approved')`, r2.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DecideAccessRequest(ctx, f.admin, r2.ID, gateways.AccessDecision{Decision: "approve"}); err == nil {
		t.Fatal("instrumented decision unexpectedly committed")
	}
	var status string
	if err := f.pool.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM gateway_grants WHERE gateway_id=$2) FROM access_requests WHERE id=$1`, r2.ID, g2).Scan(&status, &grants); err != nil || status != "pending" || grants != 0 {
		t.Fatalf("partial commit status=%s grants=%d err=%v", status, grants, err)
	}
}
