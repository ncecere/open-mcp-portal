package httpapi_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// A callback is bound to its original browser session, not just the user UUID
// the handler authenticated before a potentially slow provider exchange.
func TestPersonalConnectionCallbackRechecksSessionAfterExchange(t *testing.T) {
	for _, reconnect := range []bool{false, true} {
		name := "new"
		if reconnect {
			name = "reconnect"
		}
		t.Run(name, func(t *testing.T) {
			for _, mutation := range []string{"logout", "session_expiry", "session_idle", "suspend", "suspend_reactivate"} {
				t.Run(mutation, func(t *testing.T) {
					e := newProvEnvHook(t, func(d *httpapi.Deps) {
						if mutation == "session_idle" {
							d.Providers.SessionIdleTimeout = 5 * time.Minute
						}
					})
					if reconnect {
						if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id}); !strings.Contains(to, "result=connected") {
							t.Fatal("initial connection failed")
						}
					}
					userID := e.member.me.User.Id
					connections := func() string {
						return e.scalar(`SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.id),'[]'::jsonb)::text
							FROM provider_connections c WHERE user_id=$1`, userID)
					}
					before := connections() // Includes ciphertext; never print it.
					audits := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='provider_connection.create'`)
					code, ec, started := e.start(e.member, map[string]any{"providerId": e.provider.Id})
					mustCode(t, "start personal callback", code, ec, 200, "")
					location := providerAuthorize(t, e.member, started.AuthorizeUrl)
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
					go func() { result <- callback(t, e.member, location) }()
					select {
					case <-entered:
					case <-time.After(5 * time.Second):
						t.Fatal("personal callback did not enter code exchange")
					}
					setStatus := func(status string) {
						path := "/v1/admin/users/" + userID.String()
						var detail apitypes.UserDetail
						if code := e.admin.get(path, &detail); code != 200 {
							t.Fatalf("user detail = %d", code)
						}
						code, ec := e.admin.call("PATCH", path, map[string]any{"status": status}, nil, ifMatch(detail.User.Revision))
						mustCode(t, "manual status during exchange", code, ec, 200, "")
					}
					switch mutation {
					case "logout":
						code, ec := e.member.call("POST", "/auth/logout", nil, nil, nil)
						mustCode(t, "logout during personal exchange", code, ec, 200, "")
					case "session_expiry":
						if _, err := e.app.Pool.Exec(context.Background(), `UPDATE sessions SET expires_at=now()-interval '1 minute' WHERE user_id=$1`, userID); err != nil {
							t.Fatal(err)
						}
					case "session_idle":
						if _, err := e.app.Pool.Exec(context.Background(), `UPDATE sessions SET last_seen_at=now()-interval '10 minutes' WHERE user_id=$1`, userID); err != nil {
							t.Fatal(err)
						}
					case "suspend", "suspend_reactivate":
						setStatus("suspended")
						if mutation == "suspend_reactivate" {
							setStatus("active")
						}
					}
					unblock()
					select {
					case to := <-result:
						u, err := url.Parse(to)
						if err != nil || u.Query().Get("result") != "expired" {
							t.Fatal("personal callback committed after its browser authority ended")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("personal callback did not finish")
					}
					if connections() != before {
						t.Fatal("refused callback created or replaced stored personal credentials")
					}
					if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='provider_connection.create'`); n != audits {
						t.Fatal("refused callback recorded a successful connection audit")
					}
					if n := e.scalar(`SELECT count(*)::text FROM provider_auth_states`); n != "0" {
						t.Fatal("refused callback restored consumed authorization state")
					}
					to := callback(t, e.member, location)
					if !strings.Contains(to, "result=expired") || exchanges.Load() != 1 {
						t.Fatal("consumed callback state was replayed or code exchanged twice")
					}
				})
			}
		})
	}
}
