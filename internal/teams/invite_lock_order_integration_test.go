package teams

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Revocation holds the team before it locks the invite. Acceptance must wait
// for that team WITHOUT holding the invite; otherwise its membership INSERT's
// team foreign-key check and the revoker's invite lock form a real deadlock.
func TestAcceptInvitesAndRevocationUseTeamFirstLockOrder(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	q := dbgen.New(pool)
	user, err := q.UpsertLoginUser(ctx, dbgen.UpsertLoginUserParams{
		OIDCIssuer: "https://invite.test", OIDCSubject: uuid.NewString(),
		Email: "invitee@example.test", DisplayName: "Invitee",
		Claims: json.RawMessage(`{}`), Groups: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	team, err := q.InsertTeam(ctx, dbgen.InsertTeamParams{Slug: "invite-lock", Name: "Invite lock"})
	if err != nil {
		t.Fatal(err)
	}
	invite, err := q.UpsertInvite(ctx, dbgen.UpsertInviteParams{TeamID: team.ID, Email: user.Email, Role: "member", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	// These are the real RevokeInvite transaction's lock/query/write sequence.
	revoke, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke.Rollback(context.Background()) //nolint:errcheck
	rq := dbgen.New(revoke)
	if _, err := rq.LockTeam(ctx, team.ID); err != nil {
		t.Fatal(err)
	}
	accept, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer accept.Rollback(context.Background()) //nolint:errcheck
	acceptPID, revokePID := accept.Conn().PgConn().PID(), revoke.Conn().PgConn().PID()
	accepted := make(chan error, 1)
	go func() {
		err := AcceptInvites(ctx, dbgen.New(accept), user, "invite-lock-test", "127.0.0.1")
		if err == nil {
			err = accept.Commit(ctx)
		} else {
			_ = accept.Rollback(ctx)
		}
		accepted <- err
	}()

	// pg_blocking_pids is an observed lock barrier, not a timing assumption:
	// both the broken and corrected accept paths must wait for our team lock.
	waitInviteBlocked(t, ctx, pool, revokePID, acceptPID)
	_, revokeErr := rq.GetOpenInvite(ctx, dbgen.GetOpenInviteParams{ID: invite.ID, TeamID: team.ID})
	if revokeErr == nil {
		revokeErr = rq.RevokeInvite(ctx, invite.ID)
	}
	if revokeErr == nil {
		revokeErr = revoke.Commit(ctx)
	} else {
		_ = revoke.Rollback(ctx)
	}
	if revokeErr != nil {
		t.Errorf("revocation: %v", revokeErr)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Errorf("acceptance: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("acceptance did not finish", ctx.Err())
	}
	if t.Failed() {
		return
	}
	if _, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: team.ID, UserID: user.ID}); err != pgx.ErrNoRows {
		t.Fatalf("revoked invite granted membership: %v", err)
	}
	var acceptedAt, revokedAt bool
	if err := pool.QueryRow(ctx, `SELECT accepted_at IS NOT NULL, revoked_at IS NOT NULL FROM team_invites WHERE id=$1`, invite.ID).Scan(&acceptedAt, &revokedAt); err != nil {
		t.Fatal(err)
	}
	if acceptedAt || !revokedAt {
		t.Fatalf("invite accepted=%t revoked=%t", acceptedAt, revokedAt)
	}
}
