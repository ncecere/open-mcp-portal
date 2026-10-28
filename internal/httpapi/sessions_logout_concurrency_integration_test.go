package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestLogoutConcurrentWithSessionRevocation(t *testing.T) {
	e := newProvEnv(t)
	id := browserSessionID(t, e.member)
	code, ec, start := e.start(e.member, map[string]any{"providerId": e.provider.Id})
	mustCode(t, "start", code, ec, 200, "")
	providerAuthorize(t, e.member, start.AuthorizeUrl)
	var pending int
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM provider_auth_states WHERE session_digest=$1`, auth.Digest(id)).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending provider states = %d, err = %v", pending, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gate, err := e.app.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = gate.Rollback(cleanup)
	}()
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(719203, 1)`); err != nil {
		t.Fatal(err)
	}

	// This trigger exists only in this test's scratch database. AFTER DELETE
	// means revocation already owns the session row lock when it reaches the
	// advisory gate, but has not yet tried to delete the pending provider state.
	if _, err := testutil.OwnerPool(t, e.app.Pool).Exec(ctx, fmt.Sprintf(`
CREATE FUNCTION pause_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(719203, 1);
  RETURN OLD;
END $$;
CREATE TRIGGER pause_session_delete AFTER DELETE ON sessions
FOR EACH ROW WHEN (OLD.id = '%s'::uuid) EXECUTE FUNCTION pause_session_delete();`, id)); err != nil {
		t.Fatal(err)
	}
	// Keep authentication read-only throughout this bounded schedule: an
	// activity touch must not wait on the session before logout's transaction.
	if _, err := e.app.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}

	type result struct {
		code int
		body []byte
		err  error
	}
	launch := func(s *session, method, path string) <-chan result {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, e.app.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", e.app.URL)
		req.Header.Set("X-CSRF-Token", s.csrf)
		done := make(chan result, 1)
		go func() {
			res, err := s.client.Do(req)
			if err != nil {
				done <- result{err: err}
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			done <- result{code: res.StatusCode, body: body, err: err}
		}()
		return done
	}
	waitBlocked := func(label string, blocker int32, event string) int32 {
		t.Helper()
		wait, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			var pid int32
			err := e.app.Pool.QueryRow(wait, `
SELECT coalesce((SELECT pid FROM pg_locks
 WHERE NOT granted
   AND $1::int = ANY(pg_blocking_pids(pid))
   AND ($2::text = '' OR locktype=$2)
 LIMIT 1), 0)`, blocker, event).Scan(&pid)
			if err != nil {
				t.Fatalf("wait for %s: %v", label, err)
			}
			if pid != 0 {
				return pid
			}
			select {
			case <-tick.C:
			case <-wait.Done():
				t.Fatalf("timed out waiting for %s to block on backend %d", label, blocker)
			}
		}
	}

	revoke := launch(e.admin, http.MethodDelete, "/v1/admin/users/"+e.member.me.User.Id.String()+"/sessions")
	revokePID := waitBlocked("revocation at advisory gate", int32(gate.Conn().PgConn().PID()), "advisory")
	logout := launch(e.member, http.MethodPost, "/auth/logout")
	logoutPID := waitBlocked("logout on revocation's session row", revokePID, "")
	t.Logf("revocation backend %d holds session; logout backend %d is blocked", revokePID, logoutPID)

	// Old logout order owns the provider-state row at this point, so releasing
	// the gate creates S -> P -> S and PostgreSQL aborts one request. With the
	// fixed session-first order logout owns neither row: revocation commits,
	// then logout completes (and audits) even though the session is already gone.
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, op := range []struct {
		name string
		done <-chan result
	}{{"revocation", revoke}, {"logout", logout}} {
		select {
		case got := <-op.done:
			if got.err != nil || got.code != http.StatusOK {
				t.Errorf("%s = %d %s, err = %v", op.name, got.code, got.body, got.err)
			}
		case <-ctx.Done():
			t.Fatalf("%s did not finish: %v", op.name, ctx.Err())
		}
	}
	if t.Failed() {
		return
	}

	var sessions, states, logouts, revocations int
	userID := e.member.me.User.Id.String()
	if err := e.app.Pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM sessions WHERE user_id=$1::uuid),
 (SELECT count(*) FROM provider_auth_states WHERE session_digest=$2),
 (SELECT count(*) FROM audit_log WHERE action='auth.logout' AND actor_user_id=$1::uuid AND target_type='user' AND target_id=$1::text),
 (SELECT count(*) FROM audit_log WHERE action='session.admin_revoke' AND actor_user_id=$3::uuid AND target_type='user' AND target_id=$1::text AND metadata='{"count":1}'::jsonb)`,
		userID, auth.Digest(id), e.admin.me.User.Id.String()).Scan(&sessions, &states, &logouts, &revocations); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || states != 0 || logouts != 1 || revocations != 1 {
		t.Fatalf("sessions=%d states=%d logout audits=%d revocation audits=%d; want 0, 0, 1, 1", sessions, states, logouts, revocations)
	}
	if e.member.get("/v1/me", nil) != http.StatusUnauthorized {
		t.Fatal("revoked browser session is still accepted")
	}
	if e.admin.get("/v1/me", nil) != http.StatusOK {
		t.Fatal("unrelated administrator session was revoked")
	}
	if e.oauth.TokenRequests() != 0 {
		t.Fatal("pending provider flow exchanged a code")
	}
}
