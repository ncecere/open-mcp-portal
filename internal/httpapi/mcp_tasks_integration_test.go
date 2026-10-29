package httpapi_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func objectOf(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("not an object: %v", v)
	}
	return m
}

// create, get, input, update, cancel and completion of a task through the
// gateway, with the wire the upstream saw proving the handle never left the
// portal and the actual ID never reached the client.
func TestTasksLifecycleEndToEnd(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	if len(e.up.Tasks()) != 0 {
		t.Fatal("setup created a task")
	}
	code, hdr, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	if code != 200 || out["error"] != nil {
		t.Fatalf("create = %d %v", code, out)
	}
	r := resultOf(t, out)
	handle, _ := r["taskId"].(string)
	if hdr.Get("Cache-Control") != "no-store" || r["resultType"] != "task" || r["status"] != "working" || !strings.HasPrefix(handle, mcptasks.HandlePrefix) || len(handle) != len(mcptasks.HandlePrefix)+43 {
		t.Fatalf("creation = %v", r)
	}
	ids := e.up.Tasks()
	if len(ids) != 1 {
		t.Fatalf("upstream tasks = %v", ids)
	}
	actual := ids[0]
	// The flat released shape: portal timeline, whole-ms bounded lifetime, a
	// bounded poll hint, and nothing else of the upstream's.
	created, err1 := time.Parse(time.RFC3339Nano, r["createdAt"].(string))
	updated, err2 := time.Parse(time.RFC3339Nano, r["lastUpdatedAt"].(string))
	ttl, poll := r["ttlMs"].(float64), r["pollIntervalMs"].(float64)
	if err1 != nil || err2 != nil || updated.Before(created) || ttl <= 0 || ttl > float64(24*time.Hour/time.Millisecond) || ttl != float64(int64(ttl)) ||
		poll < 1000 || poll > 60000 || r["task"] != nil {
		t.Fatalf("creation timeline = %v", r)
	}
	if strings.Contains(e.mustJSON(out), actual) {
		t.Fatal("the upstream task ID reached the client")
	}
	// Creation: one tools/call, the extension declared on it, the original
	// arguments and the portal's static credential, once.
	var create testutil.TasksRequest
	for _, rq := range e.up.Requests() {
		if rq.Method == "tools/call" {
			create = rq
		}
	}
	if e.up.Count("tools/call") != 1 || !create.Declared || create.McpName != "slow" || create.Header.Get("X-Api-Key") != tasksStaticKey ||
		!strings.Contains(string(create.Body), `"text":"hello"`) || strings.Contains(string(create.Body), e.key.Secret) || create.Header.Get("MCP-Gateway-Identity") == "" && create.Header.Get("Authorization") == "" {
		t.Fatalf("creation request = %s", create.Body)
	}
	if got := e.recorded(1); got != "tools/call|tasks__slow|ok|task_created" {
		t.Fatalf("creation record = %q", got)
	}

	// tasks/get: the upstream sees the ACTUAL ID in params, Mcp-Name, with the
	// exact Mcp-Method and the extension declared; the client sees the handle.
	code, out = e.get("support", e.key.Secret, handle)
	if code != 200 || out["error"] != nil {
		t.Fatalf("get = %d %v", code, out)
	}
	g := resultOf(t, out)
	if g["resultType"] != "complete" || g["status"] != "working" || g["taskId"] != handle || g["result"] != nil || g["inputRequests"] != nil || g["error"] != nil {
		t.Fatalf("get result = %v", g)
	}
	var seenGet testutil.TasksRequest
	for _, rq := range e.up.Requests() {
		if rq.Method == "tasks/get" {
			seenGet = rq
		}
	}
	if seenGet.McpMethod != "tasks/get" || seenGet.McpName != actual || seenGet.TaskID != actual || !seenGet.Declared || seenGet.Header.Get("X-Api-Key") != tasksStaticKey {
		t.Fatalf("upstream get = %s %v", seenGet.Body, seenGet.Header)
	}
	if strings.Contains(string(seenGet.Body), handle) || strings.Contains(seenGet.McpName, handle) {
		t.Fatal("the portal handle reached the upstream")
	}
	// A poll before the stored interval is answered from the snapshot, with no
	// upstream request.
	before := e.up.Count("tasks/get")
	code, _, out = e.op("support", e.key.Secret, "tasks/get", handle, nil, declared(true))
	if code != 200 || resultOf(t, out)["status"] != "working" || e.up.Count("tasks/get") != before {
		t.Fatalf("paced get = %d %v (upstream gets %d -> %d)", code, out, before, e.up.Count("tasks/get"))
	}

	// input_required: the request is rebuilt and keyed by a portal key, never
	// the server's key.
	e.up.Update(actual, func(k *testutil.FakeTask) {
		k.Status = "input_required"
		k.InputRequests = map[string]any{"server-key-1": map[string]any{"method": "elicitation/create", "params": map[string]any{
			"mode": "form", "message": "Which region?", "requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"region": map[string]any{"type": "string"}}}}}}
	})
	code, out = e.get("support", e.key.Secret, handle)
	g = resultOf(t, out)
	reqs, _ := g["inputRequests"].(map[string]any)
	if code != 200 || g["status"] != "input_required" || len(reqs) != 1 {
		t.Fatalf("input_required get = %d %v", code, out)
	}
	var portalKey string
	for k := range reqs {
		portalKey = k
	}
	if !strings.HasPrefix(portalKey, mcptasks.InputKeyPrefix) || strings.Contains(e.mustJSON(out), "server-key-1") || strings.Contains(e.mustJSON(out), actual) {
		t.Fatalf("input keys leaked or not mapped: %v", reqs)
	}
	if p := objectOf(t, objectOf(t, reqs[portalKey])["params"]); p["mode"] != "form" || p["message"] != "Which region?" {
		t.Fatalf("rebuilt request = %v", reqs[portalKey])
	}
	// The same poll repeats the outstanding request under the SAME key.
	code, out = e.get("support", e.key.Secret, handle)
	if _, same := objectOf(t, resultOf(t, out)["inputRequests"])[portalKey]; code != 200 || !same {
		t.Fatalf("repeat poll changed the key: %v", out)
	}
	// A client that cannot show the form is told so, and nothing is consumed.
	e.allowPoll()
	if code, _, out = e.op("support", e.key.Secret, "tasks/get", handle, nil, declared(false)); code != 200 || objectOf(t, out["error"])["data"].(map[string]any)["reason"] != "task_input_unsupported" {
		t.Fatalf("get without elicitation = %d %v", code, out)
	}

	// update: the answer reaches the server under ITS key, the response is an
	// ack and nothing else.
	answer := map[string]any{portalKey: map[string]any{"action": "accept", "content": map[string]any{"region": "eu"}}, "ompin_unknown": map[string]any{"action": "cancel"}}
	code, _, out = e.op("support", e.key.Secret, "tasks/update", handle, map[string]any{"inputResponses": answer}, declared(true))
	if code != 200 || out["error"] != nil {
		t.Fatalf("update = %d %v", code, out)
	}
	if ack := resultOf(t, out); ack["resultType"] != "complete" || len(ack) != 2 || ack["_meta"] == nil {
		t.Fatalf("update result is not an acknowledgement: %v", ack)
	}
	k, _ := e.up.Task(actual)
	if len(k.UpdateBodies) != 1 || !strings.Contains(string(k.UpdateBodies[0]), `"server-key-1"`) || strings.Contains(string(k.UpdateBodies[0]), portalKey) ||
		strings.Contains(string(k.UpdateBodies[0]), "ompin_unknown") || !strings.Contains(string(k.UpdateBodies[0]), `"region":"eu"`) {
		t.Fatalf("server got %s", k.UpdateBodies)
	}
	var seenUpdate testutil.TasksRequest
	for _, rq := range e.up.Requests() {
		if rq.Method == "tasks/update" {
			seenUpdate = rq
		}
	}
	if seenUpdate.McpMethod != "tasks/update" || seenUpdate.McpName != actual || seenUpdate.TaskID != actual || !seenUpdate.Declared {
		t.Fatalf("upstream update = %s", seenUpdate.Body)
	}
	// Single use: the same answer again is ignored (acknowledged, not sent).
	code, _, out = e.op("support", e.key.Secret, "tasks/update", handle, map[string]any{"inputResponses": answer}, declared(true))
	if k, _ = e.up.Task(actual); code != 200 || out["error"] != nil || len(k.UpdateBodies) != 1 || e.up.Count("tasks/update") != 1 {
		t.Fatalf("replayed update = %d %v (server updates %d)", code, out, e.up.Count("tasks/update"))
	}

	// Completed: the original tool result, and a tool's own isError is still a
	// completed task.
	e.up.Update(actual, func(k *testutil.FakeTask) {
		k.Status = "completed"
		k.Result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "the tool said no"}}, "isError": true,
			"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "upstream-internal"}}}
	})
	code, out = e.get("support", e.key.Secret, handle)
	g = resultOf(t, out)
	res := objectOf(t, g["result"])
	if code != 200 || g["status"] != "completed" || res["isError"] != true || g["error"] != nil || g["taskId"] != handle ||
		objectOf(t, res["content"].([]any)[0])["text"] != "the tool said no" || strings.Contains(e.mustJSON(res), "upstream-internal") {
		t.Fatalf("completed get = %d %v", code, out)
	}
	if got := e.recorded(1); !strings.HasPrefix(got, "tasks/get|tasks__slow|tool_error|task_completed") {
		t.Fatalf("completed record = %q", got)
	}
	// Terminal results stay retrievable while the handle lives.
	if code, out = e.get("support", e.key.Secret, handle); code != 200 || resultOf(t, out)["status"] != "completed" {
		t.Fatalf("second terminal get = %d %v", code, out)
	}
	e.up.Update(actual, func(k *testutil.FakeTask) { k.Status = "working"; k.Result = nil })
	if code, out = e.get("support", e.key.Secret, handle); code == 200 && out["error"] == nil {
		t.Fatalf("a terminal task moved back to %v", resultOf(t, out)["status"])
	}

	// cancel: one send with the actual ID, an acknowledgement only.
	code, _, out = e.op("support", e.key.Secret, "tasks/cancel", handle, nil, declared(false))
	if ack := resultOf(t, out); code != 200 || ack["resultType"] != "complete" || len(ack) != 2 {
		t.Fatalf("cancel = %d %v", code, out)
	}
	var seenCancel testutil.TasksRequest
	for _, rq := range e.up.Requests() {
		if rq.Method == "tasks/cancel" {
			seenCancel = rq
		}
	}
	if k, _ = e.up.Task(actual); !k.CancelRequested || e.up.Count("tasks/cancel") != 1 || seenCancel.McpName != actual || seenCancel.McpMethod != "tasks/cancel" {
		t.Fatalf("upstream cancel = %s", seenCancel.Body)
	}

	// Records: the lifecycle methods with the ORIGINAL exposed tool, no audit
	// event per poll, and neither ID anywhere stored or logged.
	waitCalls(t, e.owned, 9)
	if n := e.rows(`SELECT count(*)::text FROM mcp_calls WHERE method IN ('tasks/get','tasks/update','tasks/cancel') AND exposed_name <> 'tasks__slow'`); n != "0" {
		t.Fatalf("%s task calls lost the exposed tool", n)
	}
	if n := e.rows(`SELECT count(*)::text FROM mcp_calls WHERE method='tasks/get'`); n == "0" {
		t.Fatal("no tasks/get was recorded")
	}
	if n := e.rows(`SELECT count(*)::text FROM audit_log WHERE action LIKE '%task%'`); n != "0" {
		t.Fatalf("%s audit events for task operations", n)
	}
	dump := e.rows(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`) + e.rows(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`) + e.logs.String()
	for _, secret := range []string{handle, actual, portalKey, "server-key-1", e.key.Secret, tasksStaticKey} {
		if strings.Contains(dump, secret) {
			t.Fatalf("%q leaked into records or logs", secret)
		}
	}
	if strings.Contains(e.logs.String(), "omptask_") {
		t.Fatal("a handle was logged")
	}
}

func (e *tasksEnv) mustJSON(v any) string {
	e.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}
