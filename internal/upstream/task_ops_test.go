package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func tasksTarget(f *testutil.FakeTasks) Target {
	return Target{URL: f.URL(), ServerID: "tasks-" + f.URL(), Timeout: 5 * time.Second}
}

func createTask(t *testing.T, c *Client, f *testutil.FakeTasks, tgt Target) *TaskState {
	t.Helper()
	res, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "slow", Arguments: []byte(`{"text":"x"}`), Tasks: true})
	if err != nil || res.Task == nil {
		t.Fatalf("create = %+v, %v", res, err)
	}
	return res.Task
}

func TestForwardDeclaresTasksOnlyWhenAskedAndParsesFlatCreation(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	tgt := tasksTarget(f)

	// Not asked: no declaration on the wire and an ordinary result.
	res, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "slow"})
	if err != nil || res.Tool == nil || res.Task != nil {
		t.Fatalf("plain forward = %+v, %v", res, err)
	}
	for _, r := range f.Requests() {
		if r.Declared || strings.Contains(string(r.Body), "extensions") {
			t.Fatalf("an undeclared request carried the extension: %s", r.Body)
		}
	}
	// Asked: declared on this request, flat creation parsed and validated.
	state := createTask(t, c, f, tgt)
	if state.Status != TaskWorking || state.ID == "" || !strings.HasPrefix(state.ID, "upstream-task-") {
		t.Fatalf("state = %+v", state)
	}
	if f.DeclaredCalls() != 1 {
		t.Fatalf("declared calls = %d", f.DeclaredCalls())
	}
	// The declaration is an empty object under clientCapabilities.extensions.
	var last testutil.TasksRequest
	for _, r := range f.Requests() {
		if r.Method == MethodToolsCall && r.Declared {
			last = r
		}
	}
	if !strings.Contains(string(last.Body), `"extensions":{"io.modelcontextprotocol/tasks":{}}`) {
		t.Fatalf("body = %s", last.Body)
	}
}

func TestUndeclaredOrMisplacedTaskResultsStayBadResponses(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	f.AddTool(testutil.FakeTasksTool{Name: "rogue", Mode: testutil.TasksModeAlwaysTask})
	c := eraClient()
	var e *Error
	// A server answering a task to a request that did not declare the extension.
	res, err := c.Forward(context.Background(), tasksTarget(f), ForwardRequest{Method: MethodToolsCall, Name: "rogue"})
	if !errors.As(err, &e) || e.Class != ClassBadResponse || res != nil {
		t.Fatalf("undeclared task = %+v, %v", res, err)
	}
	// Tasks only applies to an initial tools/call, and sends nothing otherwise.
	before := len(f.Requests())
	for _, req := range []ForwardRequest{
		{Method: MethodPromptsGet, Name: "p", Tasks: true},
		{Method: MethodResourcesRead, Name: "r", Tasks: true},
		{Method: MethodToolsCall, Name: "slow", Tasks: true, RequestState: "s"},
		{Method: MethodToolsCall, Name: "slow", Tasks: true, InputResponses: []byte(`{"a":{}}`)},
	} {
		if _, err := c.Forward(context.Background(), tasksTarget(f), req); !errors.As(err, &e) || e.Reason != "task_not_supported" {
			t.Fatalf("%+v: %v", req, err)
		}
	}
	if len(f.Requests()) != before {
		t.Fatal("a refused task request reached the server")
	}
}

func TestTaskCreationIsASingleAttempt(t *testing.T) {
	primary, extra := testutil.NewFakeTasks(t), testutil.NewFakeTasks(t)
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusTooManyRequests} {
		primary.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
			if r.Method != MethodToolsCall {
				return false
			}
			w.Header().Set("Retry-After", "0")
			http.Error(w, "busy", status)
			return true
		})
		before := primary.Count(MethodToolsCall)
		c := eraClient()
		tgt := tasksTarget(primary)
		tgt.Endpoints = []Endpoint{{ID: "e1", URL: extra.URL()}}
		_, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "slow", Tasks: true, Retryable: true,
			Expected: &ExpectedCapability{Kind: KindTool, Name: "slow", Fingerprint: strings.Repeat("a", 64)}})
		if err == nil {
			t.Fatal("expected a failure")
		}
		if n := primary.Count(MethodToolsCall) - before; n != 1 {
			t.Fatalf("status %d: tools/call sent %d times", status, n)
		}
		if len(extra.Requests()) != 0 {
			t.Fatalf("failover reached another endpoint: %d requests", len(extra.Requests()))
		}
	}
}

func TestTaskCreationNeverResendsAfterEraRecovery(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	f.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		if r.Method != MethodToolsCall {
			return false
		}
		// What a server of the other era answers a modern call with.
		http.Error(w, "unsupported", http.StatusBadRequest)
		return true
	})
	c := eraClient()
	tgt := tasksTarget(f)
	c.Eras.put(eraKey(tgt), Protocol{Era: EraModern, Version: ModernVersion}) // a remembered, now stale, era
	if _, err := c.Forward(context.Background(), tgt, ForwardRequest{Method: MethodToolsCall, Name: "slow", Tasks: true}); err == nil {
		t.Fatal("expected a failure")
	}
	if f.Count(MethodToolsCall) != 1 || f.Count("initialize") != 0 || f.Count("server/discover") != 0 {
		t.Fatalf("tools/call=%d initialize=%d discover=%d", f.Count(MethodToolsCall), f.Count("initialize"), f.Count("server/discover"))
	}
}

func TestTaskOperationWireShape(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	tgt := tasksTarget(f)
	tgt.ParamHeaders = map[string]string{"Mcp-Param-Region": "eu"}
	state := createTask(t, c, f, tgt)

	got, err := c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID, Elicitation: json.RawMessage(`{"form":{}}`)})
	if err != nil || got.State == nil || got.State.ID != state.ID || got.State.Status != TaskWorking || got.Protocol.Era != EraModern {
		t.Fatalf("get = %+v, %v", got, err)
	}
	f.Update(state.ID, func(k *testutil.FakeTask) {
		k.Status = "input_required"
		k.InputRequests = map[string]any{"q1": map[string]any{"method": "elicitation/create", "params": map[string]any{"mode": "form", "message": "m",
			"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{}}}}}
	})
	got, err = c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID})
	if err != nil || got.State.Status != TaskInputRequired || !strings.Contains(string(got.State.InputRequests), "q1") {
		t.Fatalf("input_required get = %+v, %v", got, err)
	}
	if got, err = c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksUpdate, TaskID: state.ID, InputResponses: json.RawMessage(`{"q1":{"action":"accept","content":{"a":"b"}}}`)}); err != nil || got.State != nil {
		t.Fatalf("update = %+v, %v", got, err)
	}
	if got, err = c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksCancel, TaskID: state.ID}); err != nil || got.State != nil {
		t.Fatalf("cancel = %+v, %v", got, err)
	}
	k, _ := f.Task(state.ID)
	if !k.CancelRequested || len(k.Answered) != 1 {
		t.Fatalf("server state = %+v", k)
	}
	seen := 0
	for _, r := range f.Requests() {
		if !isTaskMethod(r.Method) {
			continue
		}
		seen++
		// Mcp-Method exact, Mcp-Name and params.taskId are the actual ID, the
		// extension is declared on this very request, and no tools/call-only
		// parameter header leaks onto a lifecycle request.
		if r.McpMethod != r.Method || r.McpName != state.ID || r.TaskID != state.ID || !r.Declared || r.Version != ModernVersion ||
			r.Header.Get("Mcp-Param-Region") != "" || r.Status != 200 {
			t.Errorf("%s request = %+v", r.Method, r)
		}
		if r.Method != MethodTasksUpdate && strings.Contains(string(r.Body), "inputResponses") {
			t.Errorf("%s carried inputResponses", r.Method)
		}
		if r.Method == MethodTasksGet && len(r.Elicitation) > 0 && string(r.Elicitation) != `{"form":{}}` {
			t.Errorf("elicitation = %s", r.Elicitation)
		}
	}
	if seen != 4 {
		t.Fatalf("task requests = %d", seen)
	}
}

func TestTaskOperationValidationSendsNothing(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	tgt := tasksTarget(f)
	for _, req := range []TaskRequest{
		{Method: MethodToolsCall, TaskID: "x"},
		{Method: MethodTasksGet},
		{Method: MethodTasksGet, TaskID: strings.Repeat("x", MaxTaskIDBytes+1)},
		{Method: MethodTasksUpdate, TaskID: "x"},
		{Method: MethodTasksUpdate, TaskID: "x", InputResponses: json.RawMessage(`[1]`)},
		{Method: MethodTasksGet, TaskID: "x", InputResponses: json.RawMessage(`{"a":1}`)},
	} {
		var e *Error
		if _, err := c.Task(context.Background(), tgt, req); !errors.As(err, &e) || e.Reason != "task_not_supported" {
			t.Errorf("%+v: %v", req, err)
		}
	}
	if len(f.Requests()) != 0 {
		t.Fatalf("an invalid operation reached the server: %d", len(f.Requests()))
	}
}

func TestTaskOperationsAreSingleAttemptWithoutFailoverOrResend(t *testing.T) {
	for _, method := range []string{MethodTasksGet, MethodTasksUpdate, MethodTasksCancel} {
		for _, fault := range []string{"503", "429", "400", "drop"} {
			t.Run(method+"/"+fault, func(t *testing.T) {
				f, extra := testutil.NewFakeTasks(t), testutil.NewFakeTasks(t)
				c := eraClient()
				tgt := tasksTarget(f)
				state := createTask(t, c, f, tgt)
				f.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
					if r.Method != method {
						return false
					}
					switch fault {
					case "drop":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							_ = conn.Close()
						}
					case "503":
						http.Error(w, "down", http.StatusServiceUnavailable)
					case "429":
						w.Header().Set("Retry-After", "0")
						http.Error(w, "slow", http.StatusTooManyRequests)
					default:
						http.Error(w, "other era", http.StatusBadRequest)
					}
					return true
				})
				tgt.Endpoints = []Endpoint{{ID: "e", URL: extra.URL()}}
				req := TaskRequest{Method: method, TaskID: state.ID}
				if method == MethodTasksUpdate {
					req.InputResponses = json.RawMessage(`{"k":{"action":"accept"}}`)
				}
				if _, err := c.Task(context.Background(), tgt, req); err == nil {
					t.Fatal("expected a failure")
				}
				if n := f.Count(method); n != 1 {
					t.Fatalf("%s sent %d times", method, n)
				}
				if len(extra.Requests()) != 0 || f.Count("initialize") != 0 {
					t.Fatalf("failover/era resend: extra=%d initialize=%d", len(extra.Requests()), f.Count("initialize"))
				}
			})
		}
	}
}

func TestTaskOperationRefusesALegacyServerWithoutSending(t *testing.T) {
	fake := testutil.NewFakeMCP(t)
	fake.SetProtocol(testutil.ProtocolLegacy)
	fake.EnableGatewayTools()
	var e *Error
	_, err := eraClient().Task(context.Background(), Target{URL: fake.URL(), ServerID: "legacy", Timeout: 5 * time.Second},
		TaskRequest{Method: MethodTasksGet, TaskID: "secret-upstream-id"})
	if !errors.As(err, &e) || e.Reason != "task_protocol_unavailable" || strings.Contains(e.Message, "secret-upstream-id") {
		t.Fatalf("err = %v", err)
	}
	for _, m := range []string{MethodTasksGet, "initialize", MethodToolsCall} {
		if countMethod(fake, m) != 0 {
			t.Fatalf("%s reached a legacy server", m)
		}
	}
}

func TestTaskOperationErrorsNeverEchoIDsOrCredentials(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	tgt := tasksTarget(f)
	state := createTask(t, c, f, tgt)
	tgt.Credentials = []Credential{{Kind: CredHeader, Name: "X-Api-Key", Value: "static-key-sentinel-91"}}
	tgt.IdentityHeader, tgt.IdentityValue = "MCP-Gateway-Identity", "identity-sentinel-77"
	// The server echoes the actual ID and the portal's credentials in its error.
	f.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		if r.Method != MethodTasksGet {
			return false
		}
		msg := "no task " + r.TaskID + " key=" + r.Header.Get("X-Api-Key") + " who=" + r.Header.Get("MCP-Gateway-Identity") + " old=prior-secret-55"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32602, "message": msg}})
		_, _ = w.Write(b)
		return true
	})
	_, err := c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID, Redact: []string{"prior-secret-55"}})
	var e *Error
	if !errors.As(err, &e) || e.RPCCode != -32602 {
		t.Fatalf("err = %v", err)
	}
	for _, leak := range []string{state.ID, "static-key-sentinel-91", "identity-sentinel-77", "prior-secret-55"} {
		if strings.Contains(err.Error(), leak) || strings.Contains(e.Message, leak) {
			t.Fatalf("error leaks %q: %s", leak, e.Message)
		}
	}
}

func TestTaskGetRejectsAnotherTaskIDWithoutEcho(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	tgt := tasksTarget(f)
	state := createTask(t, c, f, tgt)
	f.OnRequest(func(r *testutil.TasksRequest, w http.ResponseWriter, _ *http.Request) bool {
		if r.Method != MethodTasksGet {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","taskId":"someone-elses-task","status":"working","createdAt":"2026-10-29T12:00:00Z","lastUpdatedAt":"2026-10-29T12:00:01Z","ttlMs":null}}`))
		return true
	})
	_, err := c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID})
	var e *Error
	if !errors.As(err, &e) || e.Reason != "invalid_task_state" || strings.Contains(err.Error(), "someone-elses-task") || strings.Contains(err.Error(), state.ID) {
		t.Fatalf("err = %v", err)
	}
}

func TestTaskOperationHooksSeeOneDispatchAttempt(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	base := tasksTarget(f)
	state := createTask(t, c, f, base)
	var attempts, dispatches, other atomic.Int32
	tgt := base
	tgt.BeforeAttempt = func(_ context.Context, attempt int) error {
		if attempt != 0 {
			t.Errorf("attempt = %d", attempt)
		}
		attempts.Add(1)
		return nil
	}
	tgt.BeforeTransport = func(_ context.Context, dispatch bool) error {
		if dispatch {
			dispatches.Add(1)
		} else {
			other.Add(1)
		}
		return nil
	}
	if _, err := c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID}); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 1 || dispatches.Load() != 1 {
		t.Fatalf("attempts=%d dispatches=%d", attempts.Load(), dispatches.Load())
	}
	// A refusal before the attempt or the transport sends nothing and never
	// echoes the hook's cause.
	before := f.Count(MethodTasksGet)
	tgt.BeforeAttempt = func(context.Context, int) error { return errors.New("quota secret=hook-cause") }
	if _, err := c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID}); err == nil || strings.Contains(err.Error(), "hook-cause") {
		t.Fatalf("attempt refusal = %v", err)
	}
	tgt.BeforeAttempt = nil
	tgt.BeforeTransport = func(_ context.Context, dispatch bool) error {
		if dispatch {
			return errors.New("grant expired secret=hook-cause")
		}
		return nil
	}
	if _, err := c.Task(context.Background(), tgt, TaskRequest{Method: MethodTasksGet, TaskID: state.ID}); err == nil || strings.Contains(err.Error(), "hook-cause") {
		t.Fatalf("transport refusal = %v", err)
	}
	if f.Count(MethodTasksGet) != before {
		t.Fatal("a refused operation was sent")
	}
}

func TestDiscoverRecordsTaskSupportOnlyForModernAdvertisement(t *testing.T) {
	f := testutil.NewFakeTasks(t)
	c := eraClient()
	d, err := c.Discover(context.Background(), tasksTarget(f))
	if err != nil || !d.SupportsTasks || d.Protocol.Era != EraModern {
		t.Fatalf("advertised = %+v, %v", d, err)
	}
	f.Advertise(false)
	if d, err = eraClient().Discover(context.Background(), tasksTarget(f)); err != nil || d.SupportsTasks {
		t.Fatalf("not advertised = %+v, %v", d, err)
	}
	fake := testutil.NewFakeMCP(t)
	fake.SetProtocol(testutil.ProtocolLegacy)
	if d, err = eraClient().Discover(context.Background(), Target{URL: fake.URL(), ServerID: "l", Timeout: 5 * time.Second}); err != nil || d.SupportsTasks {
		t.Fatalf("legacy = %+v, %v", d, err)
	}
	for _, v := range []map[string]any{nil, {TasksExtension: true}, {TasksExtension: nil}, {"other": map[string]any{}}} {
		if hasTasksExtension(v) {
			t.Fatalf("accepted %v", v)
		}
	}
	if !hasTasksExtension(map[string]any{TasksExtension: map[string]any{}}) {
		t.Fatal("rejected the released declaration shape")
	}
}
