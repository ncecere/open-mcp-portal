package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestCurationRecheckedAfterCredentialWait(t *testing.T) {
	for _, identity := range []bool{true, false} {
		for _, change := range []string{"policy", "disabled", "minimum-role", "fingerprint"} {
			t.Run(fmt.Sprintf("%s/identity=%t", change, identity), func(t *testing.T) {
				e := newEraEnv(t)
				entered, release := make(chan struct{}), make(chan struct{})
				token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(entered)
					<-release
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"access_token":"machine-token","token_type":"Bearer","expires_in":3600}`))
				}))
				defer token.Close()
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				e.patchServer(e.owner, e.server, map[string]any{"sendIdentity": identity, "authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": token.URL, "clientId": "client", "clientSecret": "secret-value-long-enough"}})
				setCuration(t, e.gwEnv, e.owner, e.path, "echo", map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": "original"}}})
				after := curationLastCall(t, e.gwEnv)
				done := make(chan map[string]any, 1)
				go func() { _, _, out := e.legacy("tools/call", map[string]any{"name": "status__echo"}); done <- out }()
				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					t.Fatal("call never requested machine credential")
				}
				switch change {
				case "policy":
					setCuration(t, e.gwEnv, e.owner, e.path, "echo", map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": "replacement"}}})
				case "disabled":
					g := e.gateway(e.owner, e.path)
					code, ec := e.owner.call("PATCH", e.path, map[string]any{"enabled": false}, nil, ifMatch(g.Revision))
					mustCode(t, "disable while waiting", code, ec, 200, "")
				case "minimum-role":
					echo := selectedTool(t, e.owner, e.path, "echo")
					e.mustSetCaps(e.owner, e.path, sel(echo.CapabilityId.String()+":owner"))
				case "fingerprint":
					// Discovery would need the same pending credential. Mutate the scratch
					// database directly to simulate a completed concurrent discovery.
					_, err := e.app.Pool.Exec(t.Context(), `UPDATE mcp_capabilities SET fingerprint=repeat('f',64) WHERE server_id=$1 AND name='echo'`, e.server.Id)
					if err != nil {
						t.Fatal(err)
					}
				}
				unblock()
				select {
				case out := <-done:
					if out["error"] == nil {
						t.Fatalf("stale call forwarded: %v", out)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("call did not finish")
				}
				assertCurationRefusalRecord(t, e.gwEnv, after, nil, change)
				if len(e.fake.ToolCalls()) != 0 {
					t.Fatal("stale policy/access snapshot reached upstream")
				}
			})
		}
	}
}
