package testutil

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// FakeTasks is a MODERN-only (2026-07-28) MCP server written directly over
// raw JSON-RPC that speaks the released Tasks extension
// (io.modelcontextprotocol/tasks): server/discover advertising it, tools/list,
// tools/call that answers with a flat CreateTaskResult to a request declaring
// the extension, and tasks/get, tasks/update and tasks/cancel keyed by the
// task ID in params.taskId and the Mcp-Name header. It records every request
// (headers, params, whether the extension was declared) so tests can prove
// what the portal sent, and offers fault injection for lost responses.
//
// It is deliberately independent of the Go SDK so the wire it produces and
// checks is exactly what the specification says, not what a library does.
type FakeTasks struct {
	*httptest.Server

	mu       sync.Mutex
	advert   bool
	tools    map[string]*FakeTasksTool
	order    []string
	tasks    map[string]*FakeTask
	requests []TasksRequest
	leak     func(taskID string, h http.Header) string
	// OnRequest, when set, sees every request after it is recorded and may
	// answer it itself (returning true). It runs without the fake's lock.
	onRequest func(*TasksRequest, http.ResponseWriter, *http.Request) bool
}

// TasksMode is how a tool answers tools/call.
type TasksMode string

const (
	// TasksModeTask answers a request that declared the extension with a task
	// and any other request with an ordinary complete result.
	TasksModeTask TasksMode = "task"
	// TasksModeStrict answers a request that declared the extension with a
	// task and any other with -32021 (it cannot answer synchronously).
	TasksModeStrict TasksMode = "strict"
	// TasksModeSync always answers with an ordinary complete result.
	TasksModeSync TasksMode = "sync"
	// TasksModeInput answers input_required (a multi round-trip request).
	TasksModeInput TasksMode = "input"
	// TasksModeAlwaysTask answers with a task even to a request that did NOT
	// declare the extension (a misbehaving server).
	TasksModeAlwaysTask TasksMode = "always"
)

// FakeTasksTool is one listed tool.
type FakeTasksTool struct {
	Name, Description string
	// Class is "read", "write" or "destructive" annotations ("": none).
	Class string
	Mode  TasksMode
}

// FakeTask is one task the fake holds. Fields are read under the fake's lock;
// use FakeTasks.Task and FakeTasks.Update from tests.
type FakeTask struct {
	ID, Tool, Status, Message string
	Args                      json.RawMessage
	Created, Updated          time.Time
	// TTLMs nil is null (unlimited); PollMs nil omits the hint.
	TTLMs, PollMs *int64
	// InputRequests are the outstanding requests (status input_required).
	InputRequests map[string]any
	// Result is the CompletedTask result (nil: a default text result).
	Result map[string]any
	// Error is the FailedTask JSON-RPC error object.
	Error map[string]any
	// Answered are the input responses received, by key, in arrival order.
	Answered        map[string]json.RawMessage
	UpdateBodies    []json.RawMessage
	CancelRequested bool
}

// TasksRequest is one HTTP request as the fake received it.
type TasksRequest struct {
	Method    string // JSON-RPC method of the body
	McpMethod string // Mcp-Method header
	McpName   string // Mcp-Name header
	Version   string // MCP-Protocol-Version header
	Header    http.Header
	Params    map[string]json.RawMessage
	Body      []byte
	// Declared: params._meta clientCapabilities.extensions has the extension.
	Declared bool
	// Elicitation is the declared elicitation capability (raw; empty: none).
	Elicitation json.RawMessage
	// TaskID is params.taskId (task methods) and ToolName params.name.
	TaskID, ToolName string
	// Status is the HTTP status answered (0 until answered).
	Status int
}

const tasksExt = "io.modelcontextprotocol/tasks"

// NewFakeTasks starts the fake with one tool, "slow" (TasksModeTask), and
// advertising the extension.
func NewFakeTasks(t testing.TB) *FakeTasks {
	t.Helper()
	f := &FakeTasks{advert: true, tools: map[string]*FakeTasksTool{}, tasks: map[string]*FakeTask{}}
	f.AddTool(FakeTasksTool{Name: "slow", Description: "A long-running tool.", Mode: TasksModeTask})
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

// URL is the MCP endpoint.
func (f *FakeTasks) URL() string { return f.Server.URL }

// Advertise sets whether server/discover lists the Tasks extension.
func (f *FakeTasks) Advertise(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advert = on
}

// AddTool adds or replaces a tool.
func (f *FakeTasks) AddTool(tool FakeTasksTool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if tool.Mode == "" {
		tool.Mode = TasksModeTask
	}
	if _, ok := f.tools[tool.Name]; !ok {
		f.order = append(f.order, tool.Name)
	}
	f.tools[tool.Name] = &tool
}

// SetLeak makes every status message, result text, input request message and
// error message carry fn's text, which tests build from the task ID and the
// request's credential headers to prove nothing of it reaches a client.
func (f *FakeTasks) SetLeak(fn func(taskID string, h http.Header) string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leak = fn
}

// OnRequest installs a hook that may answer (true) or let the fake answer.
func (f *FakeTasks) OnRequest(fn func(*TasksRequest, http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onRequest = fn
}

// Requests are copies of every request received, oldest first.
func (f *FakeTasks) Requests() []TasksRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]TasksRequest(nil), f.requests...)
}

// Count is how many requests of a JSON-RPC method arrived.
func (f *FakeTasks) Count(method string) (n int) {
	for _, r := range f.Requests() {
		if r.Method == method {
			n++
		}
	}
	return n
}

// Tasks lists the IDs of the tasks created, oldest first.
func (f *FakeTasks) Tasks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id := range f.tasks {
		ids = append(ids, id)
	}
	// Creation order, by timestamp then ID.
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			a, b := f.tasks[ids[i]], f.tasks[ids[j]]
			if b.Created.Before(a.Created) || (b.Created.Equal(a.Created) && ids[j] < ids[i]) {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	return ids
}

// Task is a copy of one task (ok false when unknown).
func (f *FakeTasks) Task(id string) (FakeTask, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tasks[id]
	if !ok {
		return FakeTask{}, false
	}
	c := *t
	c.Answered = map[string]json.RawMessage{}
	for k, v := range t.Answered {
		c.Answered[k] = v
	}
	return c, true
}

// Update changes a task and advances its last-updated time.
func (f *FakeTasks) Update(id string, fn func(*FakeTask)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tasks[id]
	if !ok {
		return
	}
	fn(t)
	t.Updated = time.Now().UTC()
}

func newFakeTaskID() string {
	var b [18]byte
	_, _ = rand.Read(b[:])
	return "upstream-task-" + hex.EncodeToString(b[:])
}

type fakeRPC struct {
	ID     json.RawMessage            `json:"id"`
	Method string                     `json:"method"`
	Params map[string]json.RawMessage `json:"params"`
}

func (f *FakeTasks) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var msg fakeRPC
	if json.Unmarshal(body, &msg) != nil || msg.Method == "" {
		http.Error(w, "not json-rpc", http.StatusBadRequest)
		return
	}
	rec := TasksRequest{Method: msg.Method, McpMethod: r.Header.Get("Mcp-Method"), McpName: r.Header.Get("Mcp-Name"),
		Version: r.Header.Get("MCP-Protocol-Version"), Header: r.Header.Clone(), Params: msg.Params, Body: body}
	if raw, ok := msg.Params["taskId"]; ok {
		_ = json.Unmarshal(raw, &rec.TaskID)
	}
	if raw, ok := msg.Params["name"]; ok {
		_ = json.Unmarshal(raw, &rec.ToolName)
	}
	var wrap struct {
		Params struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &wrap)
	var caps struct {
		Extensions  map[string]json.RawMessage `json:"extensions"`
		Elicitation json.RawMessage            `json:"elicitation"`
	}
	_ = json.Unmarshal(wrap.Params.Meta["io.modelcontextprotocol/clientCapabilities"], &caps)
	if v, ok := caps.Extensions[tasksExt]; ok && strings.TrimSpace(string(v)) == "{}" {
		rec.Declared = true
	}
	rec.Elicitation = caps.Elicitation
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	idx := len(f.requests) - 1
	hook := f.onRequest
	f.mu.Unlock()
	answer := func(status int, result any, rpcErr map[string]any) {
		f.mu.Lock()
		f.requests[idx].Status = status
		f.mu.Unlock()
		out := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID)}
		if rpcErr != nil {
			out["error"] = rpcErr
		} else {
			out["result"] = result
		}
		b, _ := json.Marshal(out)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(b)
	}
	if hook != nil && hook(&rec, w, r) {
		f.mu.Lock()
		f.requests[idx].Status = -1
		f.mu.Unlock()
		return
	}
	mismatch := func(what string) {
		answer(http.StatusBadRequest, nil, map[string]any{"code": -32020, "message": "Header mismatch: " + what})
	}
	if rec.Version != "2026-07-28" {
		answer(http.StatusBadRequest, nil, map[string]any{"code": -32022, "message": "Unsupported protocol version",
			"data": map[string]any{"supported": []string{"2026-07-28"}}})
		return
	}
	if rec.McpMethod != msg.Method {
		mismatch("Mcp-Method")
		return
	}
	switch msg.Method {
	case "server/discover":
		f.mu.Lock()
		caps := map[string]any{"tools": map[string]any{}}
		if f.advert {
			caps["extensions"] = map[string]any{tasksExt: map[string]any{}}
		}
		f.mu.Unlock()
		answer(200, map[string]any{"resultType": "complete", "supportedVersions": []string{"2026-07-28"}, "capabilities": caps,
			"serverInfo": map[string]any{"name": "fake-tasks", "version": "1"}}, nil)
	case "tools/list":
		answer(200, f.list(), nil)
	case "tools/call":
		if rec.McpName != rec.ToolName {
			mismatch("Mcp-Name")
			return
		}
		f.call(answer, rec)
	case "tasks/get", "tasks/update", "tasks/cancel":
		if rec.McpName != rec.TaskID || rec.TaskID == "" {
			mismatch("Mcp-Name")
			return
		}
		if !rec.Declared {
			answer(http.StatusBadRequest, nil, map[string]any{"code": -32021, "message": "Missing required client capability",
				"data": map[string]any{"requiredCapabilities": map[string]any{"extensions": map[string]any{tasksExt: map[string]any{}}}}})
			return
		}
		f.lifecycle(answer, rec, msg)
	default:
		answer(http.StatusNotFound, nil, map[string]any{"code": -32601, "message": "Method not found"})
	}
}

func (f *FakeTasks) list() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	tools := []any{}
	for _, name := range f.order {
		t := f.tools[name]
		def := map[string]any{"name": t.Name, "description": t.Description,
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}}}
		switch t.Class {
		case "read":
			def["annotations"] = map[string]any{"readOnlyHint": true, "destructiveHint": false}
		case "write":
			def["annotations"] = map[string]any{"readOnlyHint": false, "destructiveHint": false}
		case "destructive":
			def["annotations"] = map[string]any{"readOnlyHint": false, "destructiveHint": true}
		}
		tools = append(tools, def)
	}
	return map[string]any{"resultType": "complete", "tools": tools}
}

func (f *FakeTasks) leakText(id string, h http.Header) string {
	if f.leak == nil {
		return ""
	}
	return f.leak(id, h)
}

func (f *FakeTasks) call(answer func(int, any, map[string]any), rec TasksRequest) {
	f.mu.Lock()
	tool := f.tools[rec.ToolName]
	if tool == nil {
		f.mu.Unlock()
		answer(http.StatusOK, nil, map[string]any{"code": -32602, "message": "Unknown tool"})
		return
	}
	mode := tool.Mode
	switch {
	case mode == TasksModeAlwaysTask || (rec.Declared && (mode == TasksModeTask || mode == TasksModeStrict)):
		now := time.Now().UTC().Truncate(time.Millisecond)
		id := newFakeTaskID()
		var args json.RawMessage
		if a, ok := rec.Params["arguments"]; ok {
			args = a
		}
		poll := int64(1000)
		task := &FakeTask{ID: id, Tool: rec.ToolName, Status: "working", Args: args, Created: now, Updated: now, PollMs: &poll,
			Answered: map[string]json.RawMessage{}}
		f.tasks[id] = task
		msgText := ""
		if l := f.leakText(id, rec.Header); l != "" {
			msgText = "started " + l
			task.Message = msgText
		}
		out := taskJSON(task, "task")
		f.mu.Unlock()
		answer(http.StatusOK, out, nil)
	case mode == TasksModeStrict:
		f.mu.Unlock()
		answer(http.StatusBadRequest, nil, map[string]any{"code": -32021, "message": "Missing required client capability",
			"data": map[string]any{"requiredCapabilities": map[string]any{"extensions": map[string]any{tasksExt: map[string]any{}}}}})
	case mode == TasksModeInput:
		f.mu.Unlock()
		answer(http.StatusOK, map[string]any{"resultType": "input_required", "requestState": "fake-state",
			"inputRequests": map[string]any{"q": map[string]any{"method": "elicitation/create",
				"params": map[string]any{"mode": "form", "message": "Which?", "requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "string"}}}}}}}, nil)
	default:
		f.mu.Unlock()
		answer(http.StatusOK, map[string]any{"resultType": "complete", "content": []any{map[string]any{"type": "text", "text": "sync result"}}}, nil)
	}
}

func taskJSON(t *FakeTask, resultType string) map[string]any {
	out := map[string]any{"resultType": resultType, "taskId": t.ID, "status": t.Status,
		"createdAt": t.Created.Format(time.RFC3339Nano), "lastUpdatedAt": t.Updated.Format(time.RFC3339Nano)}
	if t.TTLMs == nil {
		out["ttlMs"] = nil
	} else {
		out["ttlMs"] = *t.TTLMs
	}
	if t.PollMs != nil {
		out["pollIntervalMs"] = *t.PollMs
	}
	if t.Message != "" {
		out["statusMessage"] = t.Message
	}
	return out
}

func (f *FakeTasks) lifecycle(answer func(int, any, map[string]any), rec TasksRequest, msg fakeRPC) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tasks[rec.TaskID]
	unknown := func() {
		f.mu.Unlock()
		defer f.mu.Lock()
		answer(http.StatusOK, nil, map[string]any{"code": -32602, "message": fmt.Sprintf("Task %q not found", rec.TaskID)})
	}
	if t == nil {
		unknown()
		return
	}
	leak := f.leakText(t.ID, rec.Header)
	switch msg.Method {
	case "tasks/get":
		out := taskJSON(t, "complete")
		if leak != "" {
			out["statusMessage"] = "state " + leak
		}
		switch t.Status {
		case "input_required":
			reqs := map[string]any{}
			for k, v := range t.InputRequests {
				reqs[k] = v
			}
			if leak != "" {
				for k, v := range reqs {
					if m, ok := v.(map[string]any); ok {
						if p, ok := m["params"].(map[string]any); ok {
							if s, ok := p["message"].(string); ok {
								p["message"] = s + " " + leak
							}
						}
					}
					reqs[k] = v
				}
			}
			out["inputRequests"] = reqs
		case "completed":
			res := t.Result
			if res == nil {
				res = map[string]any{"content": []any{map[string]any{"type": "text", "text": "task done " + leak}}}
			}
			out["result"] = res
		case "failed":
			e := t.Error
			if e == nil {
				e = map[string]any{"code": -32603, "message": "task failed " + leak}
			}
			out["error"] = e
		}
		f.mu.Unlock()
		answer(http.StatusOK, out, nil)
		f.mu.Lock()
	case "tasks/update":
		raw := msg.Params["inputResponses"]
		t.UpdateBodies = append(t.UpdateBodies, append(json.RawMessage(nil), raw...))
		var responses map[string]json.RawMessage
		_ = json.Unmarshal(raw, &responses)
		for k, v := range responses {
			if _, ok := t.InputRequests[k]; ok {
				t.Answered[k] = append(json.RawMessage(nil), v...)
				delete(t.InputRequests, k)
			}
		}
		if t.Status == "input_required" && len(t.InputRequests) == 0 {
			t.Status = "working"
		}
		t.Updated = time.Now().UTC()
		f.mu.Unlock()
		answer(http.StatusOK, map[string]any{"resultType": "complete"}, nil)
		f.mu.Lock()
	case "tasks/cancel":
		t.CancelRequested = true
		f.mu.Unlock()
		answer(http.StatusOK, map[string]any{"resultType": "complete"}, nil)
		f.mu.Lock()
	}
}

// DeclaredCalls is a test convenience: the number of tools/call requests
// that carried the extension declaration.
func (f *FakeTasks) DeclaredCalls() (n int) {
	for _, r := range f.Requests() {
		if r.Method == "tools/call" && r.Declared {
			n++
		}
	}
	return n
}

// AnyBodyContains reports whether any request body contains s.
func (f *FakeTasks) AnyBodyContains(s string) bool {
	for _, r := range f.Requests() {
		if bytes.Contains(r.Body, []byte(s)) {
			return true
		}
	}
	return false
}
