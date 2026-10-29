package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func (e *tasksEnv) serverView(s *session, sv apitypes.McpServer) apitypes.McpServer {
	e.t.Helper()
	var out apitypes.McpServer
	if code := s.get("/v1/teams/"+sv.TeamSlug+"/mcp-servers/"+sv.Id.String(), &out); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	return out
}

// lastToolCall is the newest tools/call the upstream saw.
func (e *tasksEnv) lastToolCall() (testutil.TasksRequest, bool) {
	var last testutil.TasksRequest
	found := false
	for _, r := range e.up.Requests() {
		if r.Method == "tools/call" {
			last, found = r, true
		}
	}
	return last, found
}

func (e *tasksEnv) taskRowCount() string { return e.rows(`SELECT count(*)::text FROM mcp_tasks`) }

func TestTasksServerSupportIsRecordedAndAdvertisedOnlyWhenEnabled(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	if sv := e.serverView(e.owner, e.srv); sv.SupportsTasks == nil || !*sv.SupportsTasks {
		t.Fatalf("a modern server that advertises the extension: supportsTasks = %v", sv.SupportsTasks)
	}
	// A legacy server never supports tasks.
	if sv := e.serverView(e.outsider, e.other); sv.SupportsTasks == nil || *sv.SupportsTasks {
		t.Fatalf("a legacy server: supportsTasks = %v", sv.SupportsTasks)
	}
	// The server stops advertising: the next successful read records false.
	e.up.Advertise(false)
	e.refresh(e.owner, e.srv)
	if sv := e.serverView(e.owner, e.srv); sv.SupportsTasks == nil || *sv.SupportsTasks {
		t.Fatalf("after the extension disappeared: supportsTasks = %v", sv.SupportsTasks)
	}
	e.up.Advertise(true)
	e.refresh(e.owner, e.srv)
	if sv := e.serverView(e.owner, e.srv); sv.SupportsTasks == nil || !*sv.SupportsTasks {
		t.Fatal("support was not recorded again")
	}
	// A new URL clears what was learned from the old endpoint.
	other := testutil.NewFakeTasks(t) // advertises the extension, but cannot be read
	other.OnRequest(func(_ *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return true
	})
	e.patchServer(e.owner, e.srv, map[string]any{"url": other.URL(), "credentials": []any{
		map[string]any{"kind": "header", "name": "X-Api-Key", "value": tasksStaticKey}}})
	if sv := e.serverView(e.owner, e.srv); sv.SupportsTasks == nil || *sv.SupportsTasks {
		t.Fatal("a changed URL kept the old endpoint's task support")
	}

	// Modern discovery advertises the extension (empty object); the legacy
	// initialize result never does.
	_, _, out := rawModern(t, e.app, "support", e.key.Secret, "server/discover", nil, nil, nil)
	caps := objectOf(t, resultOf(t, out)["capabilities"])
	if ext := objectOf(t, caps["extensions"]); len(ext) != 1 || e.mustJSON(ext[tasksExtension]) != "{}" {
		t.Fatalf("discover extensions = %v", caps["extensions"])
	}
	_, _, init := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "initialize", map[string]any{"protocolVersion": legacyVersion,
		"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "raw", "version": "1"}}), nil)
	if objectOf(t, resultOf(t, init)["capabilities"])["extensions"] != nil {
		t.Fatalf("initialize advertised tasks: %v", init)
	}
}

func TestTasksDisabledStoreIsNotAdvertisedNegotiatedOrServed(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	e.mcp.Tasks = nil
	_, _, out := rawModern(t, e.app, "support", e.key.Secret, "server/discover", nil, nil, nil)
	if caps := objectOf(t, resultOf(t, out)["capabilities"]); caps["extensions"] != nil {
		t.Fatalf("a portal without tasks advertised them: %v", caps)
	}
	// Even a declared call to a server that supports tasks never negotiates.
	code, _, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	if call, ok := e.lastToolCall(); code != 200 || !ok || call.Declared || resultOf(t, out)["resultType"] == "task" {
		t.Fatalf("declared call with tasks off = %d %v (upstream declared=%v)", code, out, call.Declared)
	}
	for _, m := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		code, _, out := e.op("support", e.key.Secret, m, "omptask_unknown", map[string]any{"inputResponses": map[string]any{}}, declared(false))
		if code != 404 || rpcErrorCode(out) != -32601 {
			t.Errorf("%s with tasks off = %d %v", m, code, out)
		}
	}
	// An approval-less composition cannot run the read-only no-rule check either.
	e2 := newTasksEnv(t, tasksOptions{})
	e2.mcp.Approvals = nil
	if _, _, out := rawModern(t, e2.app, "support", e2.key.Secret, "server/discover", nil, nil, nil); objectOf(t, resultOf(t, out)["capabilities"])["extensions"] != nil {
		t.Fatal("advertised tasks without the approval runtime")
	}
}

func TestTasksEveryRequestMustDeclareTheExtensionAndNameTheTask(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	handle := e.create("support", e.key.Secret)
	for _, method := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		extra := map[string]any{}
		if method == "tasks/update" {
			extra["inputResponses"] = map[string]any{}
		}
		for name, caps := range map[string]map[string]any{
			"no declaration":  nil,
			"other extension": {"extensions": map[string]any{"io.example/other": map[string]any{}}},
			"not an object":   {"extensions": map[string]any{tasksExtension: true}},
			"null":            {"extensions": map[string]any{tasksExtension: nil}},
			"extensions list": {"extensions": []any{tasksExtension}},
		} {
			before := e.up.Count(method)
			code, _, out := e.op("support", e.key.Secret, method, handle, extra, caps)
			errObj, _ := out["error"].(map[string]any)
			data, _ := errObj["data"].(map[string]any)
			req, _ := data["requiredCapabilities"].(map[string]any)
			ext, _ := req["extensions"].(map[string]any)
			if code != 400 || rpcErrorCode(out) != -32021 || e.mustJSON(ext) != `{"`+tasksExtension+`":{}}` || e.up.Count(method) != before {
				t.Errorf("%s with %s = %d %v", method, name, code, out)
			}
		}
		// A declaration made on an earlier request is not remembered: the next
		// declared request works, the undeclared one right after it does not.
		if code, _, out := e.op("support", e.key.Secret, method, handle, extra, declared(true)); code != 200 && method != "tasks/get" {
			t.Errorf("%s declared = %d %v", method, code, out)
		}
		if code, _, _ := e.op("support", e.key.Secret, method, handle, extra, nil); code != 400 {
			t.Errorf("%s right after a declared request = %d", method, code)
		}
	}
	// Header rules: Mcp-Name is required and must equal params.taskId.
	for name, headers := range map[string]map[string]string{"missing": {"Mcp-Name": ""}, "other": {"Mcp-Name": "omptask_other"}, "tool name": {"Mcp-Name": "tasks__slow"}, "method": {"Mcp-Method": "tasks/cancel"}} {
		code, _, out := rawModern(t, e.app, "support", e.key.Secret, "tasks/get", map[string]any{"taskId": handle}, declared(true), headers)
		if code != 400 || rpcErrorCode(out) != -32020 || strings.Contains(e.mustJSON(out), handle) || strings.Contains(e.mustJSON(out), "omptask_other") {
			t.Errorf("header %s = %d %v", name, code, out)
		}
	}
	// Invalid shapes are invalid params, before any lookup.
	for _, params := range []map[string]any{{}, {"taskId": 7}, {"taskId": ""}} {
		code, _, out := rawModern(t, e.app, "support", e.key.Secret, "tasks/get", params, declared(true), map[string]string{"Mcp-Name": "x"})
		if rpcErrorCode(out) == 0 || (code != 200 && code != 400) {
			t.Errorf("params %v = %d %v", params, code, out)
		}
	}
	if code, _, out := e.op("support", e.key.Secret, "tasks/update", handle, map[string]any{"inputResponses": "no"}, declared(true)); rpcErrorCode(out) != -32602 || isNotFound(out) {
		t.Errorf("update with bad responses = %d %v", code, out)
	}
	// Legacy clients never see tasks, even with the extension in the body.
	code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tasks/get", map[string]any{"taskId": handle}), nil)
	if code != 200 || rpcErrorCode(out) != -32601 {
		t.Errorf("legacy tasks/get = %d %v", code, out)
	}
}

// Every way a call does NOT qualify for tasks reaches the server with no
// declaration at all, and no reservation or task row is made.
func TestTasksAreNeverNegotiatedWhenAnyConditionFails(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	undeclared := func(what string, code int, out map[string]any) {
		t.Helper()
		call, ok := e.lastToolCall()
		if !ok || call.Declared || strings.Contains(string(call.Body), "extensions") || code != 200 || out["error"] != nil || resultOf(t, out)["resultType"] == "task" {
			t.Fatalf("%s: code=%d out=%v upstream declared=%v", what, code, out, call.Declared)
		}
		if e.taskRowCount() != "0" {
			t.Fatalf("%s: a task row was made", what)
		}
	}
	// A legacy-era client.
	code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/call", map[string]any{"name": "tasks__slow"}), nil)
	undeclared("legacy client", code, out)
	// A modern client that did not declare it, or declared something else.
	code, _, out = e.tool("support", e.key.Secret, "tasks__slow", nil)
	undeclared("modern without the extension", code, out)
	code, _, out = e.tool("support", e.key.Secret, "tasks__slow", map[string]any{"extensions": map[string]any{tasksExtension: "yes"}})
	undeclared("a non-object declaration", code, out)
	// A server whose primary no longer advertises support.
	e.up.Advertise(false)
	e.refresh(e.owner, e.srv)
	code, _, out = e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	undeclared("a server without support", code, out)
	e.up.Advertise(true)
	e.refresh(e.owner, e.srv)
	// A streamed request (progress token over SSE) is out of the first scope.
	params := modernParams(map[string]any{"name": "tasks__slow", "arguments": map[string]any{}}, declared(true))
	params["_meta"].(map[string]any)["progressToken"] = "p1"
	if c, _, _ := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/call", params),
		modernHeaders("tools/call", map[string]any{"name": "tasks__slow"}, nil)); c != 200 {
		t.Fatalf("streamed call = %d", c)
	}
	if call, _ := e.lastToolCall(); call.Declared || e.taskRowCount() != "0" {
		t.Fatal("a streamed request negotiated a task")
	}
	// A call that supplies upstream continuation state is not an initial call.
	if call, _ := e.lastToolCall(); strings.Contains(string(call.Body), "requestState") {
		t.Fatal("unexpected continuation")
	}
	// A server that cannot answer synchronously says so itself: the error is
	// the upstream's, with no task or reservation behind it.
	code, _, out = e.tool("support", e.key.Secret, "tasks__strict", nil)
	if code == 200 && out["error"] == nil || e.taskRowCount() != "0" {
		t.Fatalf("strict undeclared = %d %v", code, out)
	}
	// Declared, supported, ungoverned and not streamed: a task, exactly once.
	handle := e.create("support", e.key.Secret)
	if !strings.HasPrefix(handle, "omptask_") || e.taskRowCount() != "1" {
		t.Fatalf("task rows = %s", e.taskRowCount())
	}
	// A server that returns a task to a request that did not declare the
	// extension is a bad response: nothing is tracked and no ID is revealed.
	e.up.AddTool(testutil.FakeTasksTool{Name: "rogue", Mode: testutil.TasksModeAlwaysTask})
	e.refresh(e.owner, e.srv)
	e.mustSetCaps(e.owner, e.supportPath, sel(e.capID(e.owner, e.srv, "tool", "rogue")))
	code, _, out = e.tool("support", e.key.Secret, "tasks__rogue", nil)
	if code == 200 && out["error"] == nil || strings.Contains(e.mustJSON(out), "upstream-task-") {
		t.Fatalf("rogue task to an undeclared client = %d %v", code, out)
	}
}

// A call an approval rule governs is dispatched once with the approval and
// without any task declaration; a rule that appears AFTER a task was created
// refuses its lifecycle without creating a receipt.
func TestTasksGovernedCallsAndNewRulesNeverNegotiateOrSpend(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	handle := e.create("support", e.key.Secret)
	before := e.up.Count("tasks/get")
	code, _ := e.get("support", e.key.Secret, handle)
	if code != 200 {
		t.Fatalf("ungoverned get = %d", code)
	}
	// A rule now governs the server's tools.
	var rule approvals.Rule
	c, ec := e.owner.call("POST", toolsTeam+"/approval-rules", approvals.RuleInput{Name: "Review everything", TargetKind: "server", TargetID: e.srv.Id,
		Classes: []string{"read", "write", "destructive"}, Enabled: true, PendingMinutes: 5, ValidMinutes: 1}, &rule, nil)
	mustCode(t, "create rule", c, ec, 201, "")
	receipts := e.rows(`SELECT (SELECT count(*) FROM approval_requests)::text`)
	for _, op := range []struct {
		method string
		extra  map[string]any
	}{{"tasks/get", nil}, {"tasks/update", map[string]any{"inputResponses": map[string]any{"ompin_x": map[string]any{"action": "cancel"}}}}, {"tasks/cancel", nil}} {
		e.allowPoll()
		n := e.up.Count(op.method)
		code, _, out := e.op("support", e.key.Secret, op.method, handle, op.extra, declared(true))
		if code != 200 || !isNotFound(out) || e.up.Count(op.method) != n {
			t.Errorf("%s under a new rule = %d %v", op.method, code, out)
		}
	}
	if e.up.Count("tasks/get") != before+1 {
		t.Error("a refused poll reached the upstream")
	}
	if got := e.rows(`SELECT (SELECT count(*) FROM approval_requests)::text`); got != receipts {
		t.Fatalf("a lifecycle operation created approval rows: %s -> %s", receipts, got)
	}
	// A declared call of a governed tool needs approval first, creates no task
	// and, once approved, is dispatched with NO declaration.
	tasksBefore := e.taskRowCount()
	calls := e.up.Count("tools/call")
	code, _, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	if code != 200 || !strings.Contains(e.mustJSON(out), "needs human approval") || e.up.Count("tools/call") != calls || e.taskRowCount() != tasksBefore {
		t.Fatalf("governed call = %d %v", code, out)
	}
	r := soleApproval(t, e.member)
	approvalDecide(t, e.owner, approvalDetail(t, e.owner, r.ID), "approve")
	code, _, out = e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	call, _ := e.lastToolCall()
	if code != 200 || out["error"] != nil || e.up.Count("tools/call") != calls+1 || call.Declared || strings.Contains(string(call.Body), "extensions") ||
		resultOf(t, out)["resultType"] == "task" || e.taskRowCount() != tasksBefore {
		t.Fatalf("approved governed call = %d %v (upstream declared=%v)", code, out, call.Declared)
	}
}
