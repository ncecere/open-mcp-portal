package teams

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type inviteOrderTrace struct {
	locks, writes int
	earlyWrite    bool
}

type inviteOrderTraceKey struct{}

func (tr *inviteOrderTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "-- name: InsertMemberIfAbsent :execrows") {
		tr.writes++
		tr.earlyWrite = tr.earlyWrite || tr.locks != 2
	}
	return context.WithValue(ctx, inviteOrderTraceKey{}, strings.Contains(d.SQL, "-- name: LockTeam :one"))
}

func (tr *inviteOrderTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err == nil && ctx.Value(inviteOrderTraceKey{}) == true {
		tr.locks++
	}
}

func waitInviteBlocked(t *testing.T, ctx context.Context, pool *pgxpool.Pool, holder, waiter uint32) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $1::integer = ANY(pg_blocking_pids($2::integer))`, holder, waiter).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("invite acceptance never reached the observed lock barrier", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestAcceptInvitesRechecksAfterTeamWait(t *testing.T) {
	for _, change := range []string{"expiry", "role"} {
		t.Run(change, func(t *testing.T) {
			pool, _ := testutil.NewDB(t)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			q := dbgen.New(pool)
			u, err := q.UpsertLoginUser(ctx, dbgen.UpsertLoginUserParams{OIDCIssuer: "https://invite.test", OIDCSubject: uuid.NewString(), Email: "current@example.test", Claims: json.RawMessage(`{}`), Groups: []string{}})
			if err != nil {
				t.Fatal(err)
			}
			team, err := q.InsertTeam(ctx, dbgen.InsertTeamParams{Slug: "current-invite", Name: "Current invite"})
			if err != nil {
				t.Fatal(err)
			}
			inv, err := q.UpsertInvite(ctx, dbgen.UpsertInviteParams{TeamID: team.ID, Email: u.Email, Role: "member", ExpiresAt: time.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			writer, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background()) //nolint:errcheck
			if _, err := dbgen.New(writer).LockTeam(ctx, team.ID); err != nil {
				t.Fatal(err)
			}
			accept, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer accept.Rollback(context.Background()) //nolint:errcheck
			finished := make(chan error, 1)
			go func() {
				err := AcceptInvites(ctx, dbgen.New(accept), u, "invite-recheck", "127.0.0.1")
				if err == nil {
					err = accept.Commit(ctx)
				} else {
					_ = accept.Rollback(ctx)
				}
				finished <- err
			}()
			waitInviteBlocked(t, ctx, pool, writer.Conn().PgConn().PID(), accept.Conn().PgConn().PID())
			if change == "expiry" {
				_, err = writer.Exec(ctx, `UPDATE team_invites SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, inv.ID)
			} else {
				_, err = dbgen.New(writer).UpsertInvite(ctx, dbgen.UpsertInviteParams{TeamID: team.ID, Email: u.Email, Role: "editor", ExpiresAt: time.Now().Add(time.Hour)})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("acceptance did not finish", ctx.Err())
			}
			m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: team.ID, UserID: u.ID})
			if change == "expiry" {
				if err != pgx.ErrNoRows {
					t.Fatalf("expired invite granted membership: %v", err)
				}
				var consumed bool
				if err := pool.QueryRow(ctx, `SELECT accepted_at IS NOT NULL FROM team_invites WHERE id=$1`, inv.ID).Scan(&consumed); err != nil {
					t.Fatal(err)
				}
				if consumed {
					t.Fatal("expired invite was consumed")
				}
			} else if err != nil || m.Role != "editor" {
				t.Fatalf("fresh role not honoured: role=%s err=%v", m.Role, err)
			}
		})
	}
}

func TestAcceptInvitesSortsTeamsAndPreservesExistingMembership(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	q := dbgen.New(pool)
	u, err := q.UpsertLoginUser(ctx, dbgen.UpsertLoginUserParams{OIDCIssuer: "https://invite.test", OIDCSubject: uuid.NewString(), Email: "several@example.test", Claims: json.RawMessage(`{}`), Groups: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	ids := []uuid.UUID{uuid.MustParse("f0000000-0000-4000-8000-000000000001"), uuid.MustParse("10000000-0000-4000-8000-000000000001")}
	for i, id := range ids {
		if _, err := pool.Exec(ctx, `INSERT INTO teams(id,slug,name) VALUES($1,$2,'Team')`, id, []string{"high", "low"}[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := q.UpsertInvite(ctx, dbgen.UpsertInviteParams{TeamID: id, Email: u.Email, Role: "owner", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.InsertMember(ctx, dbgen.InsertMemberParams{TeamID: ids[0], UserID: u.ID, Role: "editor"}); err != nil {
		t.Fatal(err)
	}
	ordered, err := q.ListInviteTeamsForEmail(ctx, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 2 || ordered[0] != ids[1] || ordered[1] != ids[0] {
		t.Fatalf("candidate order: %v", ordered)
	}
	trace := &inviteOrderTrace{}
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = trace
	traced, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer traced.Close()
	tx, err := traced.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if err := AcceptInvites(ctx, dbgen.New(tx), u, "invite-order", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if trace.locks != 2 || trace.writes != 2 || trace.earlyWrite {
		t.Fatalf("all sorted teams must be locked before membership writes: %+v", trace)
	}
	for i, id := range ids {
		m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: id, UserID: u.ID})
		want := []string{"editor", "owner"}[i]
		if err != nil || m.Role != want {
			t.Fatalf("team %s: role=%s want=%s err=%v", id, m.Role, want, err)
		}
	}
	remaining, err := q.ListInviteTeamsForEmail(ctx, u.Email)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("unconsumed candidates: %v %v", remaining, err)
	}
}
