package httpapi_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionConsentMutationsLockUserBeforeSession(t *testing.T) {
	for _, action := range []string{"start", "reconnect"} {
		t.Run(action, func(t *testing.T) {
			e := newProvEnv(t)
			c := sharedByNameAfterStart(t, e)
			path := "/v1/admin/users/" + e.owner.me.User.Id.String()
			var detail apitypes.UserDetail
			if code := e.admin.get(path, &detail); code != 200 {
				t.Fatalf("user detail = %d", code)
			}
			g := pauseServiceMutation(t, e, `SELECT 1 FROM sessions WHERE user_id=$1 FOR UPDATE`, e.owner.me.User.Id)
			suspension := g.launchAs(e.admin, "PATCH", path, map[string]any{"status": "suspended"}, detail.User.Revision)
			adminPID := g.blockedBy(g.pid, "-- name: DeleteUserSessions")
			method, mutationPath, body := "POST", sharedBase, any(map[string]any{"providerId": e.provider.Id, "name": "suspended-start"})
			if action == "reconnect" {
				mutationPath, body = sharedBase+"/"+c.Id.String()+"/reconnect", nil
			}
			mutation := g.launch(method, mutationPath, body, c.Revision)
			g.blockedBy(adminPID, "-- name: LockServiceConsentUser")
			if err := g.tx.Commit(g.ctx); err != nil {
				t.Fatal(err)
			}
			g.finish(suspension, 200, "")
			g.finish(mutation, 403, "forbidden")
			if n := e.scalar(`SELECT count(*)::text FROM service_connections`); n != "1" {
				t.Fatal("suspended consent mutation created a connection")
			}
			if got := sharedByName(t, e.editor, "queued-target"); got.Revision != c.Revision {
				t.Fatal("suspended consent mutation advanced the connection")
			}
			if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action IN ('service_connection.create','service_connection.reconnect')`); n != "1" {
				t.Fatal("refused consent mutation wrote an audit")
			}
		})
	}
}

// Exercise the actual administrative HTTP suspension, not a direct users UPDATE:
// it locks USER FOR UPDATE and then deletes SESSION. Observe each scheduling
// edge in pg_blocking_pids; no elapsed-time ordering or sleeps are used.
func TestServiceConnectionCallbackAdministrativeSuspensionLockOrder(t *testing.T) {
	for _, winner := range []string{"callback", "suspension"} {
		t.Run(winner, func(t *testing.T) {
			e := newProvEnv(t)
			st := startShared(t, e.owner, e.provider.Id, "suspension-race")
			c := sharedByName(t, e.owner, "suspension-race")
			path := "/v1/admin/users/" + e.owner.me.User.Id.String()
			var detail apitypes.UserDetail
			if code := e.admin.get(path, &detail); code != 200 {
				t.Fatalf("user detail = %d", code)
			}
			location := providerAuthorize(t, e.owner, st.AuthorizeUrl)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			e.oauth.Set(func(f *testutil.FakeOAuth) {
				f.BeforeCodeExchange = func() { close(entered); <-release }
			})
			result := make(chan string, 1)
			go func() { result <- callback(t, e.owner, location) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("callback did not reach exchange")
			}
			var g *serviceMutationWait
			var suspension <-chan oauthConcurrentResponse
			if winner == "callback" {
				// Pause token commit after it has acquired USER and SESSION.
				g = pauseServiceMutation(t, e, `SELECT 1 FROM service_connections WHERE id=$1 FOR UPDATE`, c.Id)
				unblock()
				callbackPID := g.blockedBy(g.pid, "-- name: LockServiceConnection")
				suspension = g.launchAs(e.admin, "PATCH", path, map[string]any{"status": "suspended"}, detail.User.Revision)
				// With the old SESSION-first order suspension acquired USER here,
				// forming a cycle when callback later wrote connected_by/audit FK.
				g.blockedBy(callbackPID, "-- name: GetUserForUpdate")
			} else {
				// Pause actual suspension after USER is locked, before deleting
				// SESSION. Callback must wait at USER, never hold SESSION first.
				g = pauseServiceMutation(t, e, `SELECT 1 FROM sessions WHERE user_id=$1 FOR UPDATE`, e.owner.me.User.Id)
				suspension = g.launchAs(e.admin, "PATCH", path, map[string]any{"status": "suspended"}, detail.User.Revision)
				adminPID := g.blockedBy(g.pid, "-- name: DeleteUserSessions")
				unblock()
				g.blockedBy(adminPID, "-- name: LockServiceConsentUser")
			}
			if err := g.tx.Commit(g.ctx); err != nil {
				t.Fatal(err)
			}
			g.finish(suspension, 200, "")
			select {
			case to := <-result:
				connected := strings.Contains(to, "result=connected")
				if connected != (winner == "callback") {
					t.Fatalf("%s won but callback returned %s", winner, to)
				}
			case <-g.ctx.Done():
				t.Fatal("callback did not finish (possible deadlock)")
			}
			if n := e.scalar(`SELECT count(*)::text FROM users WHERE id=$1 AND status='suspended'`, e.owner.me.User.Id); n != "1" {
				t.Fatal("administrative suspension did not commit")
			}
			if n := e.scalar(`SELECT count(*)::text FROM sessions WHERE user_id=$1`, e.owner.me.User.Id); n != "0" {
				t.Fatal("suspension did not end browser access")
			}
			if code, _ := e.owner.call("GET", "/v1/me", nil, nil, nil); code != 401 {
				t.Fatalf("suspended browser access = %d, want 401", code)
			}
			if got := sharedByName(t, e.editor, "suspension-race"); got.Status != "lapsed" {
				t.Fatalf("suspended connector's shared access = %s, want lapsed", got.Status)
			}
			want := "1"
			if winner == "suspension" {
				want = "0"
			}
			if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='service_connection.connect' AND target_id=$1`, c.Id.String()); n != want {
				t.Fatalf("connect audits = %s, want %s", n, want)
			}
			if winner == "suspension" {
				if n := e.scalar(`SELECT count(*)::text FROM service_connections WHERE id=$1 AND (access_token_cipher IS NOT NULL OR refresh_token_cipher IS NOT NULL)`, c.Id); n != "0" {
					t.Fatal("suspension-winning callback stored credentials")
				}
			}
		})
	}
}
