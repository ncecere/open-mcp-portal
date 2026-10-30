package teams

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Multiple invite teams and a manual membership writer must coexist. The
// authority journal appends independent events; it does NOT hold a shared hot
// row for each membership write. This observed positive case must not be
// misreported as a second reproduced deadlock.
func TestAcceptInvitesWithConcurrentManualMember(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	q := dbgen.New(pool)
	seedUser := func(email string) dbgen.User {
		t.Helper()
		u, err := q.UpsertLoginUser(ctx, dbgen.UpsertLoginUserParams{OIDCIssuer: "https://invite.test", OIDCSubject: uuid.NewString(), Email: email, Claims: json.RawMessage(`{}`), Groups: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	u, other := seedUser("several@example.test"), seedUser("other@example.test")
	ids := []uuid.UUID{uuid.MustParse("10000000-0000-4000-8000-000000000001"), uuid.MustParse("f0000000-0000-4000-8000-000000000001")}
	for i, id := range ids {
		if _, err := pool.Exec(ctx, `INSERT INTO teams(id,slug,name) VALUES($1,$2,'Team')`, id, []string{"first", "second"}[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := q.UpsertInvite(ctx, dbgen.UpsertInviteParams{TeamID: id, Email: u.Email, Role: "member", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	manual, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer manual.Rollback(context.Background()) //nolint:errcheck
	mq := dbgen.New(manual)
	if _, err := mq.LockTeam(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	accept, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer accept.Rollback(context.Background()) //nolint:errcheck
	holder, waiter := manual.Conn().PgConn().PID(), accept.Conn().PgConn().PID()
	finished := make(chan error, 1)
	go func() {
		err := AcceptInvites(ctx, dbgen.New(accept), u, "invite-journal-order", "127.0.0.1")
		if err == nil {
			err = accept.Commit(ctx)
		} else {
			_ = accept.Rollback(ctx)
		}
		finished <- err
	}()
	waitInviteBlocked(t, ctx, pool, holder, waiter)
	_, manualErr := mq.InsertMember(ctx, dbgen.InsertMemberParams{TeamID: ids[1], UserID: other.ID, Role: "member"})
	if manualErr == nil {
		manualErr = manual.Commit(ctx)
	} else {
		_ = manual.Rollback(ctx)
	}
	if manualErr != nil {
		t.Errorf("manual membership: %v", manualErr)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("acceptance: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("acceptance did not finish", ctx.Err())
	}
	if t.Failed() {
		return
	}
	for _, id := range ids {
		m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: id, UserID: u.ID})
		if err != nil || m.Role != "member" {
			t.Fatalf("invited team %s: role=%s err=%v", id, m.Role, err)
		}
	}
	if _, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: ids[1], UserID: other.ID}); err != nil {
		t.Fatal(err)
	}
}
