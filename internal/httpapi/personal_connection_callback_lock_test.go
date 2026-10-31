package httpapi_test

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestPersonalConnectionCallbackContendedAuthorityDoesNotWait(t *testing.T) {
	for _, target := range []string{"user", "session"} {
		t.Run(target, func(t *testing.T) {
			e := newProvEnv(t)
			code, ec, started := e.start(e.member, map[string]any{"providerId": e.provider.Id})
			mustCode(t, "start personal callback", code, ec, 200, "")
			location := providerAuthorize(t, e.member, started.AuthorizeUrl)
			query := `SELECT 1 FROM users WHERE id=$1 FOR UPDATE`
			if target == "session" {
				query = `SELECT 1 FROM sessions WHERE user_id=$1 FOR UPDATE`
			}
			g := pauseServiceMutation(t, e, query, e.member.me.User.Id)
			var exchanges atomic.Int32
			e.oauth.Set(func(f *testutil.FakeOAuth) { f.BeforeCodeExchange = func() { exchanges.Add(1) } })
			result := make(chan string, 1)
			go func() { result <- callback(t, e.member, location) }()
			// The row lock remains held until AFTER the callback has refused.
			// A blocking authority check cannot satisfy this schedule.
			select {
			case to := <-result:
				u, err := url.Parse(to)
				if err != nil || u.Query().Get("result") != "expired" {
					t.Fatal("contended original browser authority did not refuse consent")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("personal callback waited on a contended authority row")
			}
			if err := g.tx.Commit(g.ctx); err != nil {
				t.Fatal(err)
			}
			if n := e.scalar(`SELECT count(*)::text FROM provider_connections`); n != "0" {
				t.Fatal("contended callback stored personal credentials")
			}
			if n := e.scalar(`SELECT count(*)::text FROM provider_auth_states`); n != "0" {
				t.Fatal("contended callback restored consumed state")
			}
			if to := callback(t, e.member, location); !strings.Contains(to, "result=expired") || exchanges.Load() != 1 {
				t.Fatal("contended callback retried a consumed code or state")
			}
		})
	}
}

// Refresh may hold CONNECTION during bounded provider I/O. Waiting for that
// row must not retain USER/SESSION locks that prevent administrative suspension.
func TestPersonalConnectionCallbackConnectionWaitDoesNotBlockSuspension(t *testing.T) {
	e := newProvEnv(t)
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id}); !strings.Contains(to, "result=connected") {
		t.Fatal("initial personal connection failed")
	}
	userID := e.member.me.User.Id
	connectionID := e.scalar(`SELECT id::text FROM provider_connections WHERE user_id=$1`, userID)
	snapshot := func() string {
		return e.scalar(`SELECT to_jsonb(c)::text FROM provider_connections c WHERE id=$1`, connectionID)
	}
	before := snapshot() // Includes sealed state; do not print it.
	code, ec, started := e.start(e.member, map[string]any{"providerId": e.provider.Id})
	mustCode(t, "start personal reconnect", code, ec, 200, "")
	location := providerAuthorize(t, e.member, started.AuthorizeUrl)
	g := pauseServiceMutation(t, e, `SELECT 1 FROM provider_connections WHERE id=$1 FOR UPDATE`, connectionID)
	result := make(chan string, 1)
	go func() { result <- callback(t, e.member, location) }()
	g.blocked("-- name: LockProviderConnection")
	path := "/v1/admin/users/" + userID.String()
	var detail apitypes.UserDetail
	if code := e.admin.get(path, &detail); code != 200 {
		t.Fatalf("user detail = %d", code)
	}
	suspension := g.launchAs(e.admin, "PATCH", path, map[string]any{"status": "suspended"}, detail.User.Revision)
	select {
	case response := <-suspension:
		if response.err != nil || response.status != 200 {
			t.Fatal("administrative suspension did not commit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback retained authority locks while waiting for its connection")
	}
	if err := g.tx.Commit(g.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case to := <-result:
		u, err := url.Parse(to)
		if err != nil || u.Query().Get("result") != "expired" {
			t.Fatal("connection-waiting callback ignored completed suspension")
		}
	case <-g.ctx.Done():
		t.Fatal("connection-waiting callback did not finish")
	}
	if snapshot() != before {
		t.Fatal("late callback replaced preserved existing credentials")
	}
	var sessions int
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions WHERE user_id=$1`, userID).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("suspension did not retain its session revocation")
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='provider_connection.create'`); n != "1" {
		t.Fatal("refused reconnect recorded a successful connection audit")
	}
}
