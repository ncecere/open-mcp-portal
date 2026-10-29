package httpapi_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/mcpgw"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/retention"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The Tasks extension relay, end to end over real HTTP, PostgreSQL and a raw
// modern upstream (testutil.FakeTasks) that speaks the released extension.

const (
	tasksExtension = "io.modelcontextprotocol/tasks"
	// The static credential the portal sends the upstream (a sentinel).
	tasksStaticKey = "static-credential-sentinel-4417"
)

// tasksEnv is the "tools" team with a published server "tasks" on the fake,
// a team gateway "support" and a platform gateway "shared" (granted to blair),
// both selecting its tools, with blair's API key.
type tasksEnv struct {
	*gwEnv
	up                      *testutil.FakeTasks
	docs                    *docServer
	logs                    *syncBuffer
	mcp                     *mcpgw.Handler
	ret                     *retention.Service
	owned                   *pgxpool.Pool // the fixture owner: direct SQL the runtime role may not run
	srv                     apitypes.McpServer
	support, shared         apitypes.Gateway
	supportPath, sharedPath string
	grantID                 string
	key                     apitypes.ApiKeyCreated
}

type tasksOptions struct {
	maxOpen int  // 0: the default
	capture bool // capture payloads on both gateways
}

func newTasksEnv(t *testing.T, opts tasksOptions) *tasksEnv {
	t.Helper()
	e := &tasksEnv{logs: &syncBuffer{}, docs: newDocServer(t)}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.gwEnv = newGwEnvHook(t, log, func(d *httpapi.Deps) {
		trustDocs(e.docs)(d)
		e.mcp = d.MCP.(*mcpgw.Handler)
		e.ret = d.Retention
		if opts.maxOpen > 0 {
			store, err := mcptasks.NewStore(e.mcp.Pool, e.mcp.Secrets, mcptasks.DefaultMaxTTL, opts.maxOpen)
			if err != nil {
				t.Fatal(err)
			}
			e.mcp.Tasks = store
		}
	})
	e.owned = testutil.OwnerPool(t, e.app.Pool)
	e.up = testutil.NewFakeTasks(t)
	e.up.AddTool(testutil.FakeTasksTool{Name: "slowread", Class: "read", Mode: testutil.TasksModeTask})
	e.up.AddTool(testutil.FakeTasksTool{Name: "strict", Mode: testutil.TasksModeStrict})
	e.up.AddTool(testutil.FakeTasksTool{Name: "sync", Mode: testutil.TasksModeSync})
	e.up.AddTool(testutil.FakeTasksTool{Name: "ask", Mode: testutil.TasksModeInput})
	e.srv = e.createServer(e.owner, "tools", "tasks", e.up.URL(), map[string]any{"credentials": []any{
		map[string]any{"kind": "header", "name": "X-Api-Key", "value": tasksStaticKey}}})
	e.publish(e.owner, e.srv)
	var ids []string
	for _, name := range []string{"slow", "slowread", "strict", "sync", "ask"} {
		ids = append(ids, e.capID(e.owner, e.srv, "tool", name))
	}
	e.support = e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.supportPath = toolsTeam + "/gateways/" + e.support.Id.String()
	e.mustSetCaps(e.owner, e.supportPath, sel(ids...))
	e.shared = e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	e.sharedPath = "/v1/admin/gateways/" + e.shared.Id.String()
	e.mustSetCaps(e.admin, e.sharedPath, sel(ids...))
	for _, email := range []string{"blair@localhost", "casey@localhost"} {
		var g apitypes.GatewayGrant
		code, ec := e.admin.call("POST", e.sharedPath+"/grants", map[string]any{"subjectKind": "user", "userEmail": email}, &g, nil)
		mustCode(t, "grant "+email, code, ec, 201, "")
		if email == "blair@localhost" {
			e.grantID = g.Id.String()
		}
	}
	if opts.capture {
		enableCurationCapture(t, e.gwEnv, e.supportPath)
	}
	e.key = newKey(t, e.member, "laptop")
	return e
}

// declared is a modern client's capabilities with the extension (and, when
// elicit is set, form elicitation).
func declared(elicit bool) map[string]any {
	caps := map[string]any{"extensions": map[string]any{tasksExtension: map[string]any{}}}
	if elicit {
		caps["elicitation"] = map[string]any{"form": map[string]any{}}
	}
	return caps
}

// tool calls a modern tools/call (name is the exposed name).
func (e *tasksEnv) tool(gateway, key, name string, caps map[string]any) (int, http.Header, map[string]any) {
	e.t.Helper()
	return rawModern(e.t, e.app, gateway, key, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"text": "hello"}}, caps, nil)
}

// op sends a task method with Mcp-Name set to handle.
func (e *tasksEnv) op(gateway, key, method, handle string, extra, caps map[string]any) (int, http.Header, map[string]any) {
	e.t.Helper()
	params := map[string]any{"taskId": handle}
	for k, v := range extra {
		params[k] = v
	}
	return rawModern(e.t, e.app, gateway, key, method, params, caps, map[string]string{"Mcp-Name": handle})
}

// create starts a task on gateway as key and returns its portal handle.
func (e *tasksEnv) create(gateway, key string) string {
	e.t.Helper()
	code, _, out := e.tool(gateway, key, "tasks__slow", declared(true))
	if code != 200 || out["error"] != nil {
		e.t.Fatalf("create = %d %v", code, out)
	}
	r := resultOf(e.t, out)
	handle, _ := r["taskId"].(string)
	if r["resultType"] != "task" || !strings.HasPrefix(handle, mcptasks.HandlePrefix) {
		e.t.Fatalf("create result = %v", r)
	}
	return handle
}

// allowPoll lifts the stored poll pacing so the next get reaches the upstream.
func (e *tasksEnv) allowPoll() {
	e.t.Helper()
	if _, err := e.owned.Exec(context.Background(), `UPDATE mcp_tasks SET next_poll_at = clock_timestamp() - interval '1 second'`); err != nil {
		e.t.Fatal(err)
	}
}

// get is a poll that is allowed to reach the upstream.
func (e *tasksEnv) get(gateway, key, handle string) (int, map[string]any) {
	e.t.Helper()
	e.allowPoll()
	code, _, out := e.op(gateway, key, "tasks/get", handle, nil, declared(true))
	return code, out
}

func (e *tasksEnv) rows(sql string, args ...any) string {
	e.t.Helper()
	var out string
	if err := e.owned.QueryRow(context.Background(), sql, args...).Scan(&out); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// recorded waits for the n-th call record and returns the newest one as
// "method|exposed_name|outcome|error_class".
func (e *tasksEnv) recorded(n int) string {
	e.t.Helper()
	waitCalls(e.t, e.owned, n)
	return e.rows(`SELECT method || '|' || coalesce(exposed_name,'') || '|' || outcome || '|' || coalesce(error_class,'') FROM mcp_calls ORDER BY id DESC LIMIT 1`)
}

// expire makes every task row past its lifetime without waiting for it.
func (e *tasksEnv) expire() {
	e.t.Helper()
	if _, err := e.owned.Exec(context.Background(), `UPDATE mcp_tasks SET created_at = clock_timestamp() - interval '3 hours',
		ceiling_at = clock_timestamp() - interval '1 minute', expires_at = clock_timestamp() - interval '1 minute'`); err != nil {
		e.t.Fatal(err)
	}
}

func isNotFound(out map[string]any) bool {
	e, _ := out["error"].(map[string]any)
	return e != nil && e["code"] == float64(-32602) && e["message"] == "Task not found" && e["data"] == nil
}

// waitUntil polls cond for up to two seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
