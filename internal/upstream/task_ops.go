package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"
)

// Task lifecycle operations (tasks/get, tasks/update, tasks/cancel) of the
// released Tasks extension, spoken to a MODERN server only.
//
// Each operation is exactly one guarded exchange: the same address rule, body
// bound, timeout, quota/admission hook, transport hook and server lease/breaker
// as Forward, but never a retry, never a failover endpoint, never an era
// re-negotiation resend and never a legacy fallback. A lost response may hide a
// state change (an update's consumed input, a cancellation), so nothing is ever
// sent twice. The ID sent is the ACTUAL upstream task ID the caller recovered
// from its own sealed storage; nothing a downstream client supplied.

// isTaskMethod reports whether method is a task lifecycle method.
func isTaskMethod(method string) bool {
	switch method {
	case MethodTasksGet, MethodTasksUpdate, MethodTasksCancel:
		return true
	}
	return false
}

// TaskRequest is one lifecycle operation.
type TaskRequest struct {
	// Method is MethodTasksGet, MethodTasksUpdate or MethodTasksCancel.
	Method string
	// TaskID is the actual upstream task ID (Mcp-Name and params.taskId).
	TaskID string
	// InputResponses is a tasks/update's responses keyed by the SERVER's own
	// input keys (required for update, forbidden otherwise).
	InputResponses json.RawMessage
	// Elicitation is the elicitation capability the downstream client declared
	// on this very request (nil: none), declared again to the server.
	Elicitation json.RawMessage
	Trace       Trace
	// Redact are further values (the initial redaction-only secrets of the
	// task) to scrub from any error message, besides the target's own secrets
	// and the task ID, which are always scrubbed.
	Redact []string
}

// TaskResult is a validated operation outcome: State for tasks/get (with the
// exact expected ID, still secret-bearing), nothing for an acknowledgement.
type TaskResult struct {
	State    *TaskState
	Protocol Protocol
	Latency  time.Duration
}

func taskFailure(reason, message string) error {
	return &Error{Class: ClassBadRequest, Reason: reason, BeforeDispatch: true, Message: message}
}

func validTaskRequest(r TaskRequest) error {
	if !isTaskMethod(r.Method) || r.TaskID == "" || len(r.TaskID) > MaxTaskIDBytes || !utf8.ValidString(r.TaskID) {
		return taskFailure("task_not_supported", "The task operation is not valid.")
	}
	responses := bytes.TrimSpace(r.InputResponses)
	switch {
	case r.Method == MethodTasksUpdate:
		if len(responses) == 0 || responses[0] != '{' || len(responses) > 64<<10 || !json.Valid(responses) {
			return taskFailure("task_not_supported", "The task update has no valid input responses.")
		}
	case len(responses) != 0:
		return taskFailure("task_not_supported", "Only a task update carries input responses.")
	}
	return nil
}

// Task performs one task lifecycle operation: a single attempt on the target's
// canonical primary, in the modern era only. Failures are *Error, whose message
// never carries the task ID, the target's credentials or Redact.
func (c *Client) Task(ctx context.Context, t Target, req TaskRequest) (out *TaskResult, err error) {
	start, caller := time.Now(), ctx
	if err := validTaskRequest(req); err != nil {
		return nil, err
	}
	redact := append([]string{req.TaskID}, req.Redact...)
	t.redactionSecrets = append(slices.Clone(t.redactionSecrets), redact...)
	defer func() {
		// Defence in depth: classification already redacts through the target,
		// but nothing here may ever leave with the ID or a credential in it.
		var classified *Error
		if errors.As(err, &classified) {
			copy := *classified
			copy.Message = SafeMessage(copy.Message, append(t.Secrets(), redact...)...)
			err = &copy
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	// Never any failover endpoint, and always the one-attempt transport guard.
	t.Endpoints, t.NoReplay, t.forwarding = nil, true, true
	guard := &forwardTransportGuard{before: t.BeforeTransport}
	t.BeforeTransport = guard.check

	p := c.protector()
	lease, denied := p.acquire(t.ServerID, t.MaxConcurrent)
	if t.ServerID != "" && c.OnCircuitState != nil {
		c.OnCircuitState(t, p.CircuitState(t.ServerID))
	}
	if denied != nil {
		return nil, denied
	}
	defer func() {
		lease.finish(protectionResult(caller, err))
		if t.ServerID != "" && c.OnCircuitState != nil {
			c.OnCircuitState(t, p.CircuitState(t.ServerID))
		}
	}()
	if err = forwardCancellation(ctx); err != nil {
		return nil, err
	}
	if t.BeforeAttempt != nil {
		if err = t.BeforeAttempt(ctx, 0); err != nil {
			return nil, forwardAdmissionError(err)
		}
	}
	if err = forwardCancellation(ctx); err != nil {
		return nil, err
	}
	proto, _, err := c.negotiate(ctx, t)
	if err != nil {
		return nil, err
	}
	if proto.Era != EraModern {
		// Tasks exist only in the modern era: never downgraded to anything else.
		return nil, &Error{Class: ClassConfig, Reason: "task_protocol_unavailable", BeforeDispatch: true,
			Message: "The server no longer speaks the protocol that created this task."}
	}
	version := proto.Version
	if version == "" {
		version = ModernVersion
	}
	params := map[string]any{"taskId": req.TaskID}
	if len(bytes.TrimSpace(req.InputResponses)) > 0 {
		params["inputResponses"] = json.RawMessage(bytes.TrimSpace(req.InputResponses))
	}
	params["_meta"] = modernMetaExt(version, req.Elicitation, req.Trace, nil, true)

	ex := &exchange{}
	hc, done := c.httpClient(t, ex)
	defer done()
	// Exactly one roundTrip: a stale-era, 4xx or lost-response outcome is
	// reported, never resent.
	r, rerr := c.roundTrip(ctx, hc, t, rpcRequest{Method: req.Method, Version: version, Name: req.TaskID, Params: params}, nil)
	if rerr != nil {
		return nil, c.classify(ctx, t, ex, rerr)
	}
	res, err := c.taskOutcome(ctx, t, ex, req, r)
	if err != nil {
		return nil, err
	}
	res.Protocol, res.Latency = proto, time.Since(start)
	return res, nil
}

// taskOutcome validates a lifecycle answer. Unlike modernResult it never marks
// an answer stale: nothing is ever resent in another era.
func (c *Client) taskOutcome(ctx context.Context, t Target, ex *exchange, req TaskRequest, r reply) (*TaskResult, error) {
	switch {
	case r.status == http.StatusUnauthorized || r.status == http.StatusForbidden || r.status == http.StatusTooManyRequests || r.status >= 500:
		return nil, c.classify(ctx, t, ex, errStatus)
	case r.status >= 400:
		if r.msg != nil && r.msg.Error != nil {
			return nil, rpcFailure(t, r.status, r.msg.Error)
		}
		return nil, c.classify(ctx, t, ex, errStatus)
	case r.msg == nil:
		return nil, &Error{Class: ClassBadResponse, Message: "The server's answer was not a JSON-RPC response."}
	case r.msg.Error != nil:
		return nil, rpcFailure(t, 0, r.msg.Error)
	}
	out := &TaskResult{}
	if req.Method == MethodTasksGet {
		state, err := ParseGetTaskResult(r.msg.Result, req.TaskID)
		if err != nil {
			return nil, err
		}
		out.State = state
		return out, nil
	}
	if err := ParseTaskAcknowledgement(r.msg.Result); err != nil {
		return nil, err
	}
	return out, nil
}

// hasTasksExtension reports whether a server's advertised extensions include
// the Tasks extension as an object (the released capability shape).
func hasTasksExtension(extensions map[string]any) bool {
	v, ok := extensions[TasksExtension]
	if !ok {
		return false
	}
	_, object := v.(map[string]any)
	return object
}
