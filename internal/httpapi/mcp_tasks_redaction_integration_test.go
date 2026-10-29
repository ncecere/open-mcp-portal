package httpapi_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// A server that echoes the actual task ID and every credential it was sent into
// every field it controls — a creation's statusMessage, a poll's statusMessage,
// an input request, a completed result and a failure — must get none of it to
// the client, the call records, the audit log, the logs or a captured payload.
// The credentials include one the upstream saw ONLY on the creation (the
// portal's first signed identity), which later polls must still scrub.
func TestTaskEchoedIDAndCredentialsNeverLeave(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{capture: true})
	var mu sync.Mutex
	// The credential each task was CREATED with is echoed by every later answer
	// about that task, long after the portal signed a different one.
	firstOf := map[string]string{}
	e.up.SetLeak(func(id string, h http.Header) string {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := firstOf[id]; !ok {
			firstOf[id] = h.Get("Authorization")
		}
		return "id=" + id + " key=" + h.Get("X-Api-Key") + " auth=" + h.Get("Authorization") + " first=" + firstOf[id]
	})
	var bodies []string
	keep := func(out map[string]any) map[string]any { bodies = append(bodies, e.mustJSON(out)); return out }

	code, _, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	keep(out)
	handle, _ := resultOf(t, out)["taskId"].(string)
	if code != 200 || handle == "" {
		t.Fatalf("create = %d %v", code, out)
	}
	actual := e.up.Tasks()[0]
	first := firstOf[actual]
	firstToken := strings.TrimPrefix(first, "Bearer ")
	if len(firstToken) < 20 || !strings.Contains(e.mustJSON(resultOf(t, out)), "statusMessage") {
		t.Fatalf("the echo was not exercised: %q %v", firstToken, out)
	}
	form := map[string]any{"method": "elicitation/create", "params": map[string]any{"mode": "form", "message": "Pick one",
		"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "string"}}}}}
	steps := []struct {
		name   string
		update func(k *testutil.FakeTask)
	}{
		{"working", func(k *testutil.FakeTask) {}},
		{"input_required", func(k *testutil.FakeTask) { k.Status, k.InputRequests = "input_required", map[string]any{"s": form} }},
		{"completed", func(k *testutil.FakeTask) {
			k.Status, k.Result = "completed", map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "ctx"}}}
			k.Result["content"].([]any)[0].(map[string]any)["text"] = "result echo " + first + " " + actual
		}},
	}
	for _, step := range steps {
		e.up.Update(actual, step.update)
		c, out := e.get("support", e.key.Secret, handle)
		keep(out)
		if c != 200 || out["error"] != nil || resultOf(t, out)["status"] != step.name {
			t.Fatalf("%s get = %d %v", step.name, c, out)
		}
		if !strings.Contains(e.mustJSON(resultOf(t, out)), "[REDACTED]") {
			t.Fatalf("%s: nothing was scrubbed, so the echo did not reach the portal: %v", step.name, out)
		}
	}
	// A failed task (terminal states are sticky, so it is a second task).
	code, _, out = e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	keep(out)
	handle2, _ := resultOf(t, out)["taskId"].(string)
	actual2 := e.up.Tasks()[1]
	e.up.Update(actual2, func(k *testutil.FakeTask) { k.Status = "failed" })
	c, out := e.get("support", e.key.Secret, handle2)
	keep(out)
	g := resultOf(t, out)
	if failure, _ := g["error"].(map[string]any); c != 200 || g["status"] != "failed" || failure["code"] != float64(-32603) || !strings.Contains(e.mustJSON(failure), "[REDACTED]") {
		t.Fatalf("failed get = %d %v", c, out)
	}
	// Every credential and ID the upstream ever saw, from the wire record.
	sentinels := []string{actual, actual2, tasksStaticKey, firstToken}
	for _, rq := range e.up.Requests() {
		if tok := strings.TrimPrefix(rq.Header.Get("Authorization"), "Bearer "); len(tok) > 20 {
			sentinels = append(sentinels, tok)
		}
	}
	callID := waitForPayload(t, e.gwEnv, "")
	dump := leakSurfaces(t, e.gwEnv, e.logs, bodies, callID)
	surfaces := map[string]string{"logs": e.logs.String(), "responses": strings.Join(bodies, " "),
		"calls": e.rows(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`),
		"audit": e.rows(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`), "everything": dump}
	for _, s := range sentinels {
		for name, text := range surfaces {
			if strings.Contains(text, s) {
				t.Errorf("%.30q... leaked into %s", s, name)
				if name == "responses" {
					for i, b := range bodies {
						if strings.Contains(b, s) {
							t.Errorf("response %d: %.1500s", i, b)
						}
					}
				}
			}
		}
	}
	// Neither the handle nor an input key is ever logged or recorded.
	for _, s := range []string{handle, "ompin_", e.key.Secret} {
		if strings.Contains(e.logs.String(), s) || strings.Contains(e.rows(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`), s) {
			t.Errorf("%.12q... reached the logs or the call records", s)
		}
	}
	// Only the creating call's own arguments were captured: no lifecycle
	// payload is ever stored.
	if n := e.rows(`SELECT count(*)::text FROM mcp_call_payloads p JOIN mcp_calls c ON c.id = p.call_id WHERE c.method <> 'tools/call'`); n != "0" {
		t.Fatalf("%s task lifecycle payloads were captured", n)
	}
	if n := e.rows(`SELECT count(*)::text FROM mcp_call_payloads p JOIN mcp_calls c ON c.id = p.call_id WHERE c.method = 'tools/call' AND p.result_cipher IS NOT NULL`); n != "0" {
		t.Fatalf("%s task creation results were captured", n)
	}
}

// An upstream 401 on a machine_oauth server renews the portal's token for the
// NEXT request but never re-sends a task creation or lifecycle exchange (an
// ordinary call is still retried once, as before).
func TestTaskExchangesAreNeverResentAfterAnUpstream401(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	as := testutil.NewFakeOAuth(t)
	as.Set(func(f *testutil.FakeOAuth) {
		f.ClientSecret, f.EnforceExpiry, f.MachineScopes = machineSecret, true, []string{"read"}
	})
	e.up.OnRequest(func(_ *testutil.TasksRequest, w http.ResponseWriter, r *http.Request) bool {
		if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); !as.Valid(tok) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return true
		}
		return false
	})
	path := toolsTeam + "/mcp-servers/" + e.srv.Id.String()
	var cur struct{ Revision int64 }
	e.owner.get(path, &cur)
	code, ec := e.owner.call("PATCH", path, map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{
		"tokenUrl": as.URL + "/token", "clientId": as.ClientID, "clientSecret": machineSecret, "scopes": []string{"read"}, "resource": e.up.URL()}}, nil, ifMatch(cur.Revision))
	mustCode(t, "machine mode", code, ec, 200, "")
	code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+e.srv.Id.String()+"/review", approveBody(t, e.admin, e.srv.Id.String()), nil, nil)
	mustCode(t, "approve", code, ec, 200, "")
	e.refresh(e.owner, e.srv)
	if sv := e.serverView(e.owner, e.srv); sv.SupportsTasks == nil || !*sv.SupportsTasks {
		t.Fatal("the machine server lost task support")
	}
	handle := e.create("support", e.key.Secret)
	if code, out := e.get("support", e.key.Secret, handle); code != 200 || out["error"] != nil {
		t.Fatalf("get with a fresh token = %d %v", code, out)
	}

	// A creation refused with 401 is sent once; the token is renewed for later.
	as.InvalidateAll(false)
	calls, tokens, rows := e.up.Count("tools/call"), as.TokenRequests(), e.taskRowCount()
	code, _, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	if out["error"] == nil || e.up.Count("tools/call") != calls+1 || as.TokenRequests() != tokens+1 || e.taskRowCount() != rows {
		t.Fatalf("task creation after a revocation = %d %v (sent %d, token requests %d, rows %s -> %s)", code, out,
			e.up.Count("tools/call")-calls, as.TokenRequests()-tokens, rows, e.taskRowCount())
	}
	if code, _, out = e.tool("support", e.key.Secret, "tasks__slow", declared(true)); code != 200 || out["error"] != nil || resultOf(t, out)["resultType"] != "task" {
		t.Fatalf("the next creation uses the renewed token: %d %v", code, out)
	}
	// An ordinary call IS retried once with the new token.
	as.InvalidateAll(false)
	calls = e.up.Count("tools/call")
	if code, _, out = e.tool("support", e.key.Secret, "tasks__slow", nil); code != 200 || out["error"] != nil || e.up.Count("tools/call") != calls+2 {
		t.Fatalf("ordinary call after a revocation = %d %v (sent %d)", code, out, e.up.Count("tools/call")-calls)
	}

	// A lifecycle poll refused with 401 is sent once, releases its claim, and
	// the next poll works with the renewed token.
	as.InvalidateAll(false)
	gets := e.up.Count("tasks/get")
	if code, out := e.get("support", e.key.Secret, handle); out["error"] == nil || e.up.Count("tasks/get") != gets+1 {
		t.Fatalf("get after a revocation = %d %v (sent %d)", code, out, e.up.Count("tasks/get")-gets)
	}
	if code, out := e.get("support", e.key.Secret, handle); code != 200 || out["error"] != nil || e.up.Count("tasks/get") != gets+2 {
		t.Fatalf("the next get = %d %v", code, out)
	}
}
