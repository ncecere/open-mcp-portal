package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// post sends a modern tools/call without failing the test from a goroutine.
func (e *tasksEnv) post(gateway, key, name string, caps map[string]any) (int, map[string]any, error) {
	params := modernParams(map[string]any{"name": name, "arguments": map[string]any{"text": "hello"}}, caps)
	body, _ := json.Marshal(rpc(1, "tools/call", params))
	req, _ := http.NewRequest("POST", e.app.URL+"/mcp/"+gateway, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range modernHeaders("tools/call", map[string]any{"name": name}, nil) {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out, nil
}

func TestTasksCapacityIsPerPrincipalAcrossCredentialsAndFreesOnCompletion(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{maxOpen: 2})
	second := newKey(t, e.member, "second")
	e.create("support", e.key.Secret)
	h2 := e.create("shared", second.Secret) // another key and gateway: the same person's budget
	calls := e.up.Count("tools/call")
	code, _, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true))
	errObj, _ := out["error"].(map[string]any)
	data, _ := errObj["data"].(map[string]any)
	if code != 200 || rpcErrorCode(out) != -32010 || data["reason"] != "task_capacity" || e.up.Count("tools/call") != calls || e.taskRowCount() != "2" {
		t.Fatalf("over capacity = %d %v (upstream calls %d -> %d, rows %s)", code, out, calls, e.up.Count("tools/call"), e.taskRowCount())
	}
	if got := e.recorded(1); got != "tools/call|tasks__slow|denied|task_capacity" {
		t.Fatalf("capacity record = %q", got)
	}
	// Another person has their own budget.
	caseyKey := newKey(t, e.outsider, "casey")
	e.create("shared", caseyKey.Secret)
	// The reservation precedes dispatch for every call that may become a task,
	// so at the cap even a tool that would have answered synchronously is
	// refused (a call that does not declare the extension is not).
	if code, _, out := e.tool("support", e.key.Secret, "tasks__sync", declared(true)); code != 200 || rpcErrorCode(out) != -32010 {
		t.Fatalf("declared call at the cap = %d %v", code, out)
	}
	if code, _, out := e.tool("support", e.key.Secret, "tasks__sync", nil); code != 200 || out["error"] != nil {
		t.Fatalf("undeclared call at the cap = %d %v", code, out)
	}
	// A finished task frees its slot.
	actual := e.up.Tasks()[1]
	e.up.Update(actual, func(k *testutil.FakeTask) { k.Status = "completed" })
	if code, out := e.get("shared", second.Secret, h2); code != 200 || resultOf(t, out)["status"] != "completed" {
		t.Fatalf("completing get = %d %v", code, out)
	}
	e.create("support", e.key.Secret)
	// A send that fails abandons its reservation and never leaks a slot.
	e.up.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		if r.Method == "tools/call" {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	before := e.rows(`SELECT count(*)::text FROM mcp_tasks WHERE status IN ('reserved','working','input_required')`)
	for range 5 {
		if code, _, out := e.tool("support", e.key.Secret, "tasks__slow", declared(true)); out["error"] == nil {
			t.Fatalf("failed creation = %d %v", code, out)
		}
	}
	if got := e.rows(`SELECT count(*)::text FROM mcp_tasks WHERE status IN ('reserved','working','input_required')`); got != before || e.rows(`SELECT count(*)::text FROM mcp_tasks WHERE status='reserved'`) != "0" {
		t.Fatalf("open rows %s -> %s after failed creations", before, got)
	}
}

func TestTasksConcurrentCreationsCannotExceedTheCap(t *testing.T) {
	const cap, workers = 3, 12
	e := newTasksEnv(t, tasksOptions{maxOpen: cap})
	keys := []string{e.key.Secret, newKey(t, e.member, "b").Secret, newKey(t, e.member, "c").Secret}
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, refused := 0, 0
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gateway := []string{"support", "shared"}[i%2]
			_, out, err := e.post(gateway, keys[i%len(keys)], "tasks__slow", declared(true))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				t.Errorf("request: %v", err)
			case out["error"] == nil && resultOf(t, out)["resultType"] == "task":
				created++
			case rpcErrorCode(out) == -32010:
				refused++
			default:
				t.Errorf("unexpected answer %v", out)
			}
		}()
	}
	wg.Wait()
	if created != cap || refused != workers-cap || e.up.Count("tools/call") != cap || e.taskRowCount() != "3" {
		t.Fatalf("created %d refused %d (upstream tools/call %d, rows %s), want %d/%d", created, refused, e.up.Count("tools/call"), e.taskRowCount(), cap, workers-cap)
	}
}

func TestTasksExpireWithoutCleanupAndTheirLifetimeOnlyShrinks(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	handle := e.create("support", e.key.Secret)
	actual := e.up.Tasks()[0]
	// A shorter upstream lifetime shortens the local deadline; a longer or
	// unlimited one afterwards never extends it.
	short := int64(90_000)
	e.up.Update(actual, func(k *testutil.FakeTask) { k.TTLMs = &short })
	_, out := e.get("support", e.key.Secret, handle)
	if ttl := resultOf(t, out)["ttlMs"].(float64); ttl <= 0 || ttl > 90_000 {
		t.Fatalf("ttlMs after a short upstream lifetime = %v", ttl)
	}
	long := int64(10 * 24 * 3600 * 1000)
	for _, ttl := range []*int64{&long, nil} {
		e.up.Update(actual, func(k *testutil.FakeTask) { k.TTLMs = ttl })
		_, out = e.get("support", e.key.Secret, handle)
		if got := resultOf(t, out)["ttlMs"].(float64); got <= 0 || got > 90_000 {
			t.Fatalf("ttlMs after the upstream lifetime grew = %v", got)
		}
	}
	// An out-of-range value is a bad response, not a lifetime.
	huge := int64(1) << 60
	e.up.Update(actual, func(k *testutil.FakeTask) { k.TTLMs = &huge })
	if code, out := e.get("support", e.key.Secret, handle); code == 200 && out["error"] == nil {
		t.Fatalf("an out-of-range lifetime was accepted: %v", out)
	}
	e.up.Update(actual, func(k *testutil.FakeTask) { k.TTLMs = nil })

	// Expiry denies every operation by itself, without waiting for cleanup.
	e.expire()
	if e.taskRowCount() != "1" {
		t.Fatal("setup: the row is gone")
	}
	n := e.up.Count("tasks/get")
	for _, m := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		code, _, out := e.op("support", e.key.Secret, m, handle, map[string]any{"inputResponses": map[string]any{"k": map[string]any{"action": "cancel"}}}, declared(true))
		if code != 200 || !isNotFound(out) {
			t.Errorf("%s on an expired task = %d %v", m, code, out)
		}
	}
	if e.up.Count("tasks/get") != n || e.up.Count("tasks/update") != 0 || e.up.Count("tasks/cancel") != 0 {
		t.Fatal("an expired task reached the upstream")
	}
	// The retention loop reclaims it, a bounded batch at a time.
	if _, ran, err := e.ret.Pass(context.Background()); err != nil || !ran {
		t.Fatalf("retention pass = %v %v", ran, err)
	}
	waitUntil(t, "retention to prune the expired task", func() bool { return e.taskRowCount() == "0" })
}

func TestTasksSendOnceAndFailuresNeverRestoreInput(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	if _, err := e.owned.Exec(context.Background(), `UPDATE mcp_capabilities SET tool_class='read' WHERE kind='tool' AND name='slowread'`); err != nil {
		t.Fatal(err)
	}

	// A read tool is retried when it is an ordinary call; as a task it is sent
	// exactly once.
	down := func(method string) func(*testutil.TasksRequest, http.ResponseWriter, *http.Request) bool {
		return func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
			if r.Method == method {
				w.Header().Set("Retry-After", "0")
				http.Error(w, "down", http.StatusServiceUnavailable)
				return true
			}
			return false
		}
	}
	e.up.OnRequest(down("tools/call"))
	if _, out := e.postOut("support", e.key.Secret, "tasks__slowread", nil); out["error"] == nil {
		t.Fatalf("ordinary read call = %v", out)
	}
	ordinary := e.up.Count("tools/call")
	if ordinary < 2 {
		t.Fatalf("an ordinary read call was sent %d time(s); the comparison needs retries", ordinary)
	}
	if _, out := e.postOut("support", e.key.Secret, "tasks__slowread", declared(true)); out["error"] == nil {
		t.Fatalf("task read call = %v", out)
	}
	if got := e.up.Count("tools/call") - ordinary; got != 1 {
		t.Fatalf("a task creation was sent %d times", got)
	}
	if e.taskRowCount() != "0" {
		t.Fatal("a failed creation left a row")
	}
	// A connection lost after the request was written: the upstream may hold a
	// task, the portal tracks nothing and claims nothing.
	e.up.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		if r.Method == "tools/call" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return true
		}
		return false
	})
	calls := e.up.Count("tools/call")
	if _, out := e.postOut("support", e.key.Secret, "tasks__slow", declared(true)); out["error"] == nil || e.up.Count("tools/call") != calls+1 || e.taskRowCount() != "0" {
		t.Fatalf("lost creation answer = %v (sent %d, rows %s)", out, e.up.Count("tools/call")-calls, e.taskRowCount())
	}
	e.up.OnRequest(nil)

	handle := e.create("support", e.key.Secret)
	actual := e.up.Tasks()[len(e.up.Tasks())-1]
	// A failed poll is not retried and releases its claim.
	e.up.OnRequest(down("tasks/get"))
	gets := e.up.Count("tasks/get")
	if code, out := e.get("support", e.key.Secret, handle); code == 200 && out["error"] == nil || e.up.Count("tasks/get") != gets+1 {
		t.Fatalf("failed get = %d %v (sent %d)", code, out, e.up.Count("tasks/get")-gets)
	}
	e.up.OnRequest(nil)
	if code, out := e.get("support", e.key.Secret, handle); code != 200 || out["error"] != nil {
		t.Fatalf("get after a failed one = %d %v (the claim was not released)", code, out)
	}
	// A lost update acknowledgement never restores the consumed input.
	e.up.Update(actual, func(k *testutil.FakeTask) {
		k.Status = "input_required"
		k.InputRequests = map[string]any{"s1": map[string]any{"method": "elicitation/create", "params": map[string]any{"mode": "form", "message": "m",
			"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "string"}}}}}}
	})
	_, out := e.get("support", e.key.Secret, handle)
	var key string
	for k := range objectOf(t, resultOf(t, out)["inputRequests"]) {
		key = k
	}
	e.up.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		if r.Method == "tasks/update" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return true
		}
		return false
	})
	answer := map[string]any{key: map[string]any{"action": "accept", "content": map[string]any{"a": "b"}}}
	if code, _, out := e.op("support", e.key.Secret, "tasks/update", handle, map[string]any{"inputResponses": answer}, declared(true)); code == 200 && out["error"] == nil {
		t.Fatalf("update with a lost answer = %d %v", code, out)
	}
	e.up.OnRequest(nil)
	updates := e.up.Count("tasks/update")
	for range 2 {
		if code, _, out := e.op("support", e.key.Secret, "tasks/update", handle, map[string]any{"inputResponses": answer}, declared(true)); code != 200 || out["error"] != nil {
			t.Fatalf("replayed update = %d %v", code, out)
		}
	}
	if e.up.Count("tasks/update") != updates {
		t.Fatal("a consumed input was sent again after a lost acknowledgement")
	}
	// The consumed key is not offered again by the next poll.
	e.up.Update(actual, func(k *testutil.FakeTask) { k.Status = "input_required" })
	if _, out = e.get("support", e.key.Secret, handle); len(objectOf(t, resultOf(t, out)["inputRequests"])) != 0 {
		t.Fatalf("an answered request was offered again: %v", out)
	}
}

// postOut posts a modern tools/call and returns its status and body.
func (e *tasksEnv) postOut(gateway, key, name string, caps map[string]any) (int, map[string]any) {
	e.t.Helper()
	code, out, err := e.post(gateway, key, name, caps)
	if err != nil {
		e.t.Fatal(err)
	}
	return code, out
}

// While one poll holds the task, another is answered from the stored status
// without contacting the upstream (and an update is a retryable busy error).
func TestTasksBusyPollsAreAnsweredFromTheSnapshot(t *testing.T) {
	e := newTasksEnv(t, tasksOptions{})
	handle := e.create("support", e.key.Secret)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.up.OnRequest(func(r *testutil.TasksRequest, _ http.ResponseWriter, _ *http.Request) bool {
		if r.Method == "tasks/get" {
			once.Do(func() { close(entered) })
			<-release
		}
		return false
	})
	done := make(chan map[string]any, 1)
	e.allowPoll()
	go func() {
		_, out := e.getRaw("support", e.key.Secret, handle)
		done <- out
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first poll never reached the upstream")
	}
	before := e.up.Count("tasks/get")
	code, _, out := e.op("support", e.key.Secret, "tasks/get", handle, nil, declared(true))
	if g := resultOf(t, out); code != 200 || g["status"] != "working" || g["taskId"] != handle || e.up.Count("tasks/get") != before {
		t.Fatalf("busy get = %d %v", code, out)
	}
	code, _, out = e.op("support", e.key.Secret, "tasks/cancel", handle, nil, declared(true))
	errObj, _ := out["error"].(map[string]any)
	data, _ := errObj["data"].(map[string]any)
	if code != 200 || data["reason"] != "task_busy" || e.up.Count("tasks/cancel") != 0 {
		t.Fatalf("busy cancel = %d %v", code, out)
	}
	close(release)
	if first := <-done; first["error"] != nil {
		t.Fatalf("the first poll failed: %v", first)
	}
}

// getRaw is get without t.Fatal, for goroutines.
func (e *tasksEnv) getRaw(gateway, key, handle string) (int, map[string]any) {
	params := modernParams(map[string]any{"taskId": handle}, declared(true))
	body, _ := json.Marshal(rpc(1, "tasks/get", params))
	req, _ := http.NewRequest("POST", e.app.URL+"/mcp/"+gateway, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range modernHeaders("tasks/get", params, map[string]string{"Mcp-Name": handle}) {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out
}
