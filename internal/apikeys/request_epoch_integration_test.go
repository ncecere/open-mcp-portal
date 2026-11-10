package apikeys

// The before-fix future-contract experiment is preserved privately. This
// retained regression now requires decision90's first application epoch fence;
// it does not claim complete directory or lifecycle enforcement.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/platform"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestCreateRejectsPreCycleRequestAfterReactivation(t *testing.T) {
	pool, dsn := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	userID, adminID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject,platform_role)
 VALUES ($1,'epoch-subject@example.test','Epoch subject','test','epoch-subject','none'),
 ($2,'epoch-admin@example.test','Epoch admin','test','epoch-admin','platform_admin')`, userID, adminID); err != nil {
		t.Fatal("fixture user creation failed")
	}
	q := dbgen.New(pool)
	user, err := q.GetUser(ctx, userID)
	if err != nil {
		t.Fatal("fixture subject lookup failed")
	}
	admin, err := q.GetUser(ctx, adminID)
	if err != nil {
		t.Fatal("fixture administrator lookup failed")
	}
	oldActor := (auth.Identity{User: user}).Actor("future-epoch-queued-request", "")
	adminActor := (auth.Identity{User: admin}).Actor("future-epoch-standing-change", "")
	base := New(pool, []byte("owned-future-epoch-fixture-pepper"), nil)
	existing, err := base.Create(ctx, oldActor, CreateInput{Name: "preserved-existing"})
	if err != nil {
		t.Fatal("existing-key control failed")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("private runtime pool config failed")
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0
	var armed atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	//lint:ignore SA1019 this hook only has to block or refuse an acquire; PrepareConn's error return adds nothing here
	cfg.BeforeAcquire = func(c context.Context, _ *pgx.Conn) bool {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			select {
			case <-release:
				return true
			case <-c.Done():
				return false
			}
		}
		return true
	}
	requestPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("request runtime pool creation failed")
	}
	defer func() { unblock(); requestPool.Close() }()
	var originalRole, requestRole string
	var authenticated bool
	var super bool
	if err := pool.QueryRow(ctx, `SELECT current_user,current_user=session_user,rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&originalRole, &authenticated, &super); err != nil || !authenticated {
		t.Fatal("original runtime authentication proof failed")
	}
	if os.Getenv("OMP_TEST_SPLIT_ROLES") == "1" && super {
		t.Fatal("split runtime must not be superuser")
	}
	if err := requestPool.QueryRow(ctx, `SELECT current_user`).Scan(&requestRole); err != nil || requestRole != originalRole {
		t.Fatal("request pool must independently authenticate as the same runtime")
	}
	svc := New(requestPool, []byte("owned-future-epoch-fixture-pepper"), nil)
	type result struct {
		created Created
		err     error
	}
	finished := make(chan result, 1)
	armed.Store(true)
	go func() {
		c, e := svc.Create(ctx, oldActor, CreateInput{Name: "old-request-must-not-mint"})
		finished <- result{c, e}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("request never reached explicit BeforeAcquire barrier")
	}

	// These are the actual administrative service transactions on a separate
	// independently authenticated runtime pool, not direct status SQL or sleeps.
	administration := platform.NewService(pool)
	suspended := "suspended"
	afterSuspend, err := administration.UpdateUser(ctx, adminActor, userID, platform.UserUpdate{Status: &suspended}, user.Revision)
	if err != nil {
		t.Fatal("actual administrative suspension failed")
	}
	if _, err := base.Authenticate(ctx, existing.Secret); !errors.Is(err, ErrInvalid) {
		t.Fatal("suspended existing-key denial control failed")
	}
	active := "active"
	afterReactivate, err := administration.UpdateUser(ctx, adminActor, userID, platform.UserUpdate{Status: &active}, afterSuspend.Revision)
	if err != nil || afterReactivate.Status != "active" || afterSuspend.RequestEpoch != user.RequestEpoch+1 || afterReactivate.RequestEpoch != afterSuspend.RequestEpoch+1 {
		t.Fatal("actual administrative reactivation failed")
	}
	if _, err := base.Authenticate(ctx, existing.Secret); err != nil {
		t.Fatal("reversible existing-key preservation control failed")
	}

	unblock()
	var got result
	select {
	case got = <-finished:
	case <-ctx.Done():
		t.Fatal("queued writer failed to finish after explicit barrier release")
	}
	freshActor := (auth.Identity{User: afterReactivate}).Actor("fresh-request-after-reactivation", "")
	if _, err := base.Create(ctx, freshActor, CreateInput{Name: "fresh-request-allowed"}); err != nil {
		t.Fatal("fresh request after reactivation must remain allowed")
	}
	var cycles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE target_type='user' AND target_id=$1 AND action IN ('platform.user_suspend','platform.user_reactivate')`, userID.String()).Scan(&cycles); err != nil || cycles != 2 {
		t.Fatal("actual committed suspend/reactivate audit proof failed")
	}
	problem, ok := apperr.As(got.err)
	if got.created.Secret != "" || !ok || problem.Status != http.StatusConflict || problem.Code != "request_authority_changed" {
		t.Fatal("pre-cycle request did not refuse exact stale authority without returning a secret")
	}
	var keys, creates int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys WHERE user_id=$1),
(SELECT count(*) FROM audit_log WHERE action='api_key.create' AND actor_user_id=$1)`, userID).Scan(&keys, &creates); err != nil || keys != 2 || creates != 2 {
		t.Fatal("stale admission minted a key or successful create audit")
	}
}

func TestCreateRequiresExactNonzeroAdmittedRequestEpoch(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'epoch-required@example.test','Epoch required','test','epoch-required')`, userID); err != nil {
		t.Fatal(err)
	}
	user, err := dbgen.New(pool).GetUser(ctx, userID)
	if err != nil || user.RequestEpoch < 1 {
		t.Fatal("fixture did not establish a positive request epoch")
	}
	svc := New(pool, []byte("owned-epoch-required-fixture-pepper"), nil)
	for _, epoch := range []int64{0, -1, user.RequestEpoch + 1} {
		created, err := svc.Create(ctx, authz.Actor{UserID: userID, RequestEpoch: epoch}, CreateInput{Name: "must-not-stamp-fresh"})
		problem, ok := apperr.As(err)
		if !ok || problem.Status != http.StatusConflict || problem.Code != "request_authority_changed" || created.Secret != "" {
			t.Fatal("incomplete/incorrect admission was silently refreshed or minted authority")
		}
	}
	actor := (auth.Identity{User: user}).Actor("genuinely-admitted-key-request", "")
	if _, err := svc.Create(ctx, actor, CreateInput{Name: "proper-admission"}); err != nil {
		t.Fatal("fresh correctly admitted request refused:", err)
	}
	var keys, creates int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys WHERE user_id=$1),
(SELECT count(*) FROM audit_log WHERE action='api_key.create' AND actor_user_id=$1)`, userID).Scan(&keys, &creates); err != nil || keys != 1 || creates != 1 {
		t.Fatal("refused admission changed key/audit inventory")
	}
}
