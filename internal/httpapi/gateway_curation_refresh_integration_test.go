package httpapi_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func blockCurationRefresh(t *testing.T, as *testutil.FakeOAuth, grant string) (<-chan struct{}, func()) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var arrived, released sync.Once
	unblock := func() { released.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	as.Set(func(f *testutil.FakeOAuth) {
		f.BeforeToken = func(g string) {
			if g == grant {
				arrived.Do(func() { close(entered) })
				<-release
			}
		}
	})
	return entered, unblock
}

func mutateCurationDuringRefresh(t *testing.T, e *gwEnv, path, change string) {
	t.Helper()
	if change == "policy" {
		setCuration(t, e, e.owner, path, "echo", map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": "replacement"}}})
	} else {
		g := e.gateway(e.owner, path)
		code, ec := e.owner.call("PATCH", path, map[string]any{"enabled": false}, nil, ifMatch(g.Revision))
		mustCode(t, "disable while refreshing", code, ec, 200, "")
	}
}

func waitCurationRefresh(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("post-401 credential refresh was not reached")
	}
}
func refusedCurationRefresh(t *testing.T, done <-chan map[string]any) {
	t.Helper()
	select {
	case out := <-done:
		if out["error"] == nil {
			t.Fatalf("stale post-refresh call succeeded: %v", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("post-refresh call did not finish")
	}
}

func TestCurationRecheckedAfterMachine401Refresh(t *testing.T) {
	for _, change := range []string{"policy", "disabled"} {
		t.Run(change, func(t *testing.T) {
			e := newMachineEnv(t)
			e.mustPatch(e.editor, e.machine(nil))
			e.approve()
			e.mustSetCaps(e.owner, e.supportTeamPath, sel(e.capID(e.owner, e.server, "tool", "echo")))
			setCuration(t, e.gwEnv, e.owner, e.supportTeamPath, "echo", map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": "original"}}})
			if _, out := e.callTool(e.key.Secret, "status__echo", nil); out["error"] != nil {
				t.Fatal(out)
			}
			before := len(e.fake.ToolCalls())
			requests := e.tokenRequests()
			e.as.InvalidateAll(false)
			entered, unblock := blockCurationRefresh(t, e.as, "client_credentials")
			done := make(chan map[string]any, 1)
			go func() { _, out := e.callTool(e.key.Secret, "status__echo", nil); done <- out }()
			waitCurationRefresh(t, entered)
			mutateCurationDuringRefresh(t, e.gwEnv, e.supportTeamPath, change)
			unblock()
			refusedCurationRefresh(t, done)
			if len(e.fake.ToolCalls()) != before || e.tokenRequests() != requests+1 {
				t.Fatalf("stale args forwarded or no post-401 renewal: calls=%d->%d tokens=%d->%d", before, len(e.fake.ToolCalls()), requests, e.tokenRequests())
			}
		})
	}
}

func TestCurationRecheckedAfterPersonal401Refresh(t *testing.T) {
	for _, change := range []string{"policy", "disabled"} {
		t.Run(change, func(t *testing.T) {
			e := newUpEnv(t, true)
			code, raw := e.createOAuth(e.owner, "gh", e.pm.URL(), map[string]any{"registration": "auto", "scopes": []string{"repo"}}, nil)
			if code != 201 {
				t.Fatalf("create: %d %s", code, raw)
			}
			var created struct{ Data apitypes.McpServerCreated }
			if err := json.Unmarshal(raw, &created); err != nil {
				t.Fatal(err)
			}
			sv := created.Data.Server
			if _, to := e.setup(e.owner, sv.Id.String()); !strings.Contains(to, "setup=connected") {
				t.Fatal(to)
			}
			gw := e.createGateway(e.owner, toolsTeam+"/gateways", "curated")
			path := toolsTeam + "/gateways/" + gw.Id.String()
			e.mustSetCaps(e.owner, path, sel(e.capID(e.owner, sv, "tool", "echo")))
			setCuration(t, e.gwEnv, e.owner, path, "echo", map[string]any{"constraints": map[string]any{"text": map[string]any{"fixed": "original"}}})
			key := newKey(t, e.owner, "laptop").Secret
			call := func() map[string]any {
				_, _, out := rawMCP(t, e.app, "POST", "curated", key, rpc(1, "tools/call", map[string]any{"name": "gh__echo"}), nil)
				return out
			}
			if out := call(); out["error"] != nil {
				t.Fatal(out)
			}
			before, refreshes := len(e.pm.ToolCalls()), e.as.RefreshRequests()
			e.as.InvalidateAll(false)
			entered, unblock := blockCurationRefresh(t, e.as, "refresh_token")
			done := make(chan map[string]any, 1)
			go func() { done <- call() }()
			waitCurationRefresh(t, entered)
			mutateCurationDuringRefresh(t, e.gwEnv, path, change)
			unblock()
			refusedCurationRefresh(t, done)
			if len(e.pm.ToolCalls()) != before || e.as.RefreshRequests() != refreshes+1 {
				t.Fatalf("stale args forwarded or no post-401 refresh: calls=%d->%d refreshes=%d->%d", before, len(e.pm.ToolCalls()), refreshes, e.as.RefreshRequests())
			}
		})
	}
}
