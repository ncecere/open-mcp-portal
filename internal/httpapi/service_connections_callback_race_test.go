package httpapi_test

import (
	"context"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The token endpoint is blocked after state consumption. Mutations here must
// win before commit, never resurrecting revoked or superseded shared consent.
func TestServiceConnectionCallbackCommitRechecks(t *testing.T) {
	for _, kind := range []string{"revoke", "revision", "logout", "demotion", "provider", "session_generation"} {
		t.Run(kind, func(t *testing.T) {
			e := newProvEnv(t)
			st := startShared(t, e.owner, e.provider.Id, "pending")
			c := sharedByName(t, e.owner, "pending")
			location := providerAuthorize(t, e.owner, st.AuthorizeUrl)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var exchanges atomic.Int32
			e.oauth.Set(func(f *testutil.FakeOAuth) {
				f.BeforeCodeExchange = func() {
					if exchanges.Add(1) == 1 {
						close(entered)
					}
					<-release
				}
			})
			result := make(chan string, 1)
			go func() { result <- callback(t, e.owner, location) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				unblock()
				t.Fatal("callback never exchanged code")
			}
			switch kind {
			case "revoke":
				code, ec := e.owner.call("DELETE", sharedBase+"/"+c.Id.String(), nil, nil, nil)
				mustCode(t, "revoke during exchange", code, ec, 200, "")
			case "revision":
				code, ec, _ := assignShared(t, e.owner, c, nil, nil)
				mustCode(t, "update during exchange", code, ec, 200, "")
			case "logout":
				code, ec := e.owner.call("POST", "/auth/logout", nil, nil, nil)
				mustCode(t, "logout during exchange", code, ec, 200, "")
			case "demotion":
				e.scalar(`UPDATE team_members SET role='editor' WHERE user_id=(SELECT connected_by FROM service_connections WHERE id=$1) RETURNING 'ok'`, c.Id)
			case "provider":
				e.scalar(`UPDATE auth_providers SET enabled=false,revision=revision+1 WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
			case "session_generation":
				fenceCtx, fenceCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, err := e.app.Pool.Exec(fenceCtx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, e.owner.me.User.Id)
				fenceCancel()
				if err != nil {
					t.Fatal("shared generation fence during provider exchange:", err)
				}
				if n := e.scalar(`SELECT count(*)::text FROM sessions WHERE user_id=$1`, e.owner.me.User.Id); n == "0" {
					t.Fatal("shared generation refusal cannot rely on deleting the browser session")
				}
				t.Log("SHARED_CALLBACK_GENERATION_FENCE_COMMITTED_DURING_BLOCKED_EXCHANGE")
			}
			unblock()
			select {
			case to := <-result:
				if strings.Contains(to, "result=connected") {
					t.Fatalf("%s lost to callback commit", kind)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("callback did not finish")
			}
			if n := e.scalar(`SELECT count(*)::text FROM service_connections WHERE access_token_cipher IS NOT NULL OR refresh_token_cipher IS NOT NULL`); n != "0" {
				t.Fatal("callback resurrected tokens")
			}
			if n := e.scalar(`SELECT count(*)::text FROM provider_connections`); n != "0" {
				t.Fatal("service callback escaped into personal owner")
			}
			if kind == "session_generation" {
				if n := e.scalar(`SELECT count(*)::text FROM service_connection_auth_states`); n != "0" {
					t.Fatal("generation refusal restored consumed shared consent")
				}
				to := callback(t, e.owner, location)
				if strings.Contains(to, "result=connected") || exchanges.Load() != 1 {
					t.Fatal("ended shared session replayed consumed consent or exchanged code twice")
				}
			}
		})
	}
}
