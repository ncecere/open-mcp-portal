package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Task lifecycle: tasks/get, tasks/update and tasks/cancel (docs/mcp-tasks.md
// "Handle and authority binding"). Every operation:
//
//  1. authenticates like any request (done before dispatch) and declares the
//     extension itself (-32021 otherwise: nothing is remembered);
//  2. finds the task by its handle AND the authenticated principal's starting
//     credential root: unknown, malformed, foreign, expired or later
//     unauthorized handles all get the one -32602 "Task not found";
//  3. re-resolves the caller's CURRENT access to the exact offer the task was
//     created from (selected, served, allowed, same revision, URL, definition
//     and curation) and the read-only no-rule approval check (never creating or
//     spending a receipt);
//  4. acquires FRESH credentials and identity for the actual URL and requires
//     the same dependency identity (nothing retained is ever sent);
//  5. claims the task for ONE fenced exchange, sends once (no retry, failover,
//     era re-negotiation or 401 resend) and builds the public result from
//     validated fields only, scrubbed of the upstream task ID and every
//     credential of the original and this exchange.
//
// An update's responses are consumed BEFORE their single send and never
// restored, so an ambiguous send cannot replay input. Cancellation is
// cooperative and eventually consistent: an acknowledgement is only intent.

// task serves one lifecycle method of a modern request that declared the
// extension and a Tasks-enabled gateway.
func (rc *request) task() {
	if eerr := validateTaskName(rc.r.Header, rc.msg.Params); eerr != nil {
		n := writeRPC(rc.w, eerr.status, rc.msg.ID, nil, &rpcError{Code: eerr.code, Message: eerr.message})
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "header_mismatch"}, n)
		return
	}
	if !rc.tasksDeclared() {
		rc.taskMissingCapability()
		return
	}
	rc.taskOp = true
	method := rc.msg.Method
	invalid := func(msg string) {
		n := rc.fail(codeInvalidParams, "Invalid parameters: "+msg)
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_params"}, n)
	}
	var p struct {
		TaskID         json.RawMessage `json:"taskId"`
		InputResponses json.RawMessage `json:"inputResponses"`
	}
	if len(rc.msg.Params) == 0 || json.Unmarshal(rc.msg.Params, &p) != nil {
		invalid("params must be an object")
		return
	}
	var handle string
	if json.Unmarshal(p.TaskID, &handle) != nil || handle == "" {
		invalid("taskId is required")
		return
	}
	if responses := bytes.TrimSpace(p.InputResponses); method == methodTasksUpdate && (len(responses) == 0 || responses[0] != '{') {
		invalid("inputResponses must be an object")
		return
	}
	ctx := rc.r.Context()
	snap, err := rc.h.Tasks.Lookup(ctx, handle, rc.taskRoot())
	switch {
	case err == nil:
	case errors.Is(err, mcptasks.ErrNotFound):
		rc.taskNotFound(calls.Call{}, "task_not_found")
		return
	default:
		rc.internal(err)
		return
	}
	b, payload := snap.Binding(), snap.Payload()
	rec := calls.Call{ExposedName: b.ExposedName, CapabilityID: b.CapabilityID}
	o, ok := rc.taskOffer(b, &rec)
	if !ok {
		return
	}
	rec = calls.Call{ExposedName: o.ExposedName, Server: &o.Server, CapabilityID: o.Capability.ID, ToolClass: o.Capability.ToolClass}
	if !rc.taskUngoverned(o, &rec) {
		return
	}
	target, cred, token, ok := rc.taskTarget(o, b, &rec)
	if !ok {
		return
	}
	red := newTaskRedactor(payload.UpstreamID, payload.RedactionOnly, rc.taskCredentialValues(target, token))

	// An update with nothing this task can still accept consumes nothing and
	// sends nothing.
	var responses json.RawMessage
	if method == methodTasksUpdate {
		var keys []string
		for _, in := range payload.Inputs {
			if !in.Attempted {
				keys = append(keys, in.Key)
			}
		}
		if responses, err = relayResponses(rc.msg.Params, keys); err != nil {
			invalid(err.Error())
			return
		}
		if responses == nil {
			rc.taskAck(rec, "task_input_ignored")
			return
		}
	}

	timeout := min(max(target.Timeout+10*time.Second, mcptasks.MinOperationTimeout), mcptasks.MaxOperationTimeout)
	op, err := rc.h.Tasks.Begin(ctx, snap, method == methodTasksGet, timeout)
	switch {
	case err == nil:
	case errors.Is(err, mcptasks.ErrBusy):
		rc.taskBusy(snap, handle, red, rec)
		return
	default:
		rc.internal(err)
		return
	}
	claimed := true
	defer func() {
		if claimed {
			_ = rc.h.Tasks.Release(ctx, op) // consumed input is never restored
		}
	}()

	req := upstream.TaskRequest{Method: method, TaskID: payload.UpstreamID, Elicitation: rc.clientElicitation().declared(),
		Trace: upstream.TraceFromMeta(rc.paramsMeta()), Redact: append(append([]string(nil), payload.RedactionOnly...), rc.taskCredentialValues(target, token)...)}
	if method == methodTasksUpdate {
		var body json.RawMessage
		var n int
		if op, body, n, err = rc.h.Tasks.CommitInput(ctx, op, responses); err != nil {
			if errors.Is(err, mcptasks.ErrBusy) {
				rc.taskBusy(snap, handle, red, rec)
				return
			}
			rc.internal(err)
			return
		}
		if n == 0 {
			rc.taskAck(rec, "task_input_ignored")
			return
		}
		req.InputResponses = body
	}
	rc.guardTaskTransport(o, &target)
	rc.forwarded = true
	res, ok := rc.taskExchange(o, &rec, cred, target, req)
	if !ok {
		return
	}
	switch method {
	case methodTasksGet:
		rc.taskObserved(ctx, rec, snap, op, handle, res.State, red, &claimed)
	case methodTasksUpdate:
		rc.taskAck(rec, "task_input_sent")
	default:
		rc.taskAck(rec, "cancel_requested") // intent only: never proof the work stopped
	}
}

// taskOffer re-resolves the offer a task was created from and requires it to
// be identical and currently allowed. Anything else is the uniform not-found.
func (rc *request) taskOffer(b mcptasks.Binding, rec *calls.Call) (gateways.Offer, bool) {
	offers, err := rc.offers(upstream.KindTool)
	if err != nil {
		rc.internal(err)
		return gateways.Offer{}, false
	}
	for _, o := range offers {
		if o.Capability.ID == b.CapabilityID && o.ExposedName == b.ExposedName {
			if sameOffer(o, b) && rc.gateway.ID == b.GatewayID {
				return o, true
			}
			break
		}
	}
	rc.taskNotFound(*rec, "task_binding_changed")
	return gateways.Offer{}, false
}

// taskUngoverned is the read-only, non-spending approval check: a rule that now
// applies to this call refuses the lifecycle (as not found), and nothing is
// created or spent. One re-read of the policy epoch separates a rule from a
// concurrent unrelated policy change.
func (rc *request) taskUngoverned(o gateways.Offer, rec *calls.Call) bool {
	ctx := rc.r.Context()
	for attempt := 0; ; attempt++ {
		in := rc.approvalInput(o, nil, nil)
		err := rc.h.Approvals.CheckUngoverned(ctx, in.Binding, in.CredentialExpiresAt)
		switch {
		case err == nil:
			return true
		case errors.Is(err, approvals.ErrContextChanged) && attempt == 0:
			epoch, eerr := rc.h.Approvals.Epoch(ctx)
			if eerr != nil {
				rc.taskUnavailable(*rec, "authority_unavailable")
				return false
			}
			rc.approvalEpoch = epoch
		case errors.Is(err, approvals.ErrContextChanged):
			rc.taskNotFound(*rec, "task_approval_required")
			return false
		default:
			rc.taskUnavailable(*rec, "authority_unavailable")
			return false
		}
	}
}

// taskTarget acquires FRESH credentials for the task's server and builds the
// target for one exchange to its canonical primary only: nothing from the
// original exchange is reused, and the dependency identity must be unchanged.
func (rc *request) taskTarget(o gateways.Offer, b mcptasks.Binding, rec *calls.Call) (upstream.Target, *providers.Credential, string, bool) {
	ctx := rc.r.Context()
	changed := func() (upstream.Target, *providers.Credential, string, bool) {
		rc.taskNotFound(*rec, "task_dependency_changed")
		return upstream.Target{}, nil, "", false
	}
	var cred *providers.Credential
	if o.Requires != nil {
		rec.ProviderSlug = o.Requires.Provider.Slug
		if rc.h.Providers == nil {
			return changed()
		}
		var c providers.Credential
		var err error
		if rc.principal.account != nil {
			c, err = rc.h.Providers.ServiceCredential(ctx, o.Requires, rc.serviceCallContext(o))
		} else {
			c, err = rc.h.Providers.Credential(ctx, o.Requires, rc.callContext(o))
		}
		var down *providers.UnavailableError
		var consent *providers.ConsentNeeded
		var serviceErr *providers.ServiceCredentialError
		switch {
		case err == nil:
			cred = &c
		case errors.As(err, &down):
			rc.taskUnavailable(*rec, ProviderUnavailable)
			return upstream.Target{}, nil, "", false
		case errors.Is(err, providers.ErrProviderDisabled), errors.Is(err, providers.ErrProviderNotAllowed),
			errors.As(err, &consent), errors.As(err, &serviceErr):
			return changed() // interactive consent is never started by a lifecycle poll
		default:
			rc.internal(err)
			return upstream.Target{}, nil, "", false
		}
	}
	var secret *personsecrets.Secret
	if _, ok := registry.PersonSecretConfig(o.Server); ok {
		if rc.principal.account != nil || rc.h.PersonSecrets == nil {
			return changed()
		}
		sec, err := rc.h.PersonSecrets.Resolve(ctx, rc.secretContext(o))
		var need *personsecrets.NeedsSecret
		switch {
		case err == nil:
			secret = &sec
			rc.personSecretUsed = &sec
		case errors.As(err, &need), errors.Is(err, personsecrets.ErrInactive):
			return changed()
		default:
			rc.internal(err)
			return upstream.Target{}, nil, "", false
		}
	}
	target, err := rc.h.Registry.Target(ctx, o.Server)
	if err != nil {
		rc.targetFailed(*rec, err)
		return upstream.Target{}, nil, "", false
	}
	target.Endpoints = nil // never a fallback: the task lives at its recorded primary
	if target.URL != b.ServerURL || !rc.withPersonSecret(&target, secret) {
		return changed()
	}
	if serverBound(cred) && cred.Resource != o.Server.URL {
		return changed()
	}
	token, ok := rc.prepareTarget(&target, identityFor{tool: o.ExposedName}, o, cred, rec)
	if !ok {
		return upstream.Target{}, nil, "", false
	}
	dependency, err := rc.dependencyDigest(o, cred, secret, target)
	if err != nil {
		rc.internal(err)
		return upstream.Target{}, nil, "", false
	}
	if dependency != b.DependencyDigest {
		return changed()
	}
	return target, cred, token, true
}

// guardTaskTransport installs the per-exchange admission and live checks: the
// server quota counts this operation, the approval policy epoch and the
// credential's deadline are checked again right before transport, and so is
// the gateway grant's deadline.
func (rc *request) guardTaskTransport(o gateways.Offer, target *upstream.Target) {
	rc.guardServerAttempt(o, target)
	deadline := rc.approvalInput(o, nil, nil).CredentialExpiresAt
	epoch := rc.approvalEpoch
	prior := target.BeforeTransport
	target.BeforeTransport = func(ctx context.Context, dispatch bool) error {
		if prior != nil {
			if err := prior(ctx, dispatch); err != nil {
				return err
			}
		}
		if err := rc.h.Approvals.CheckContext(ctx, epoch, deadline); err != nil {
			return fmt.Errorf("%w: %w", errServerAttemptAuthority, err)
		}
		return nil
	}
	rc.guardGrantExpiry(target)
	rc.noResend = true
}

// taskExchange sends the one lifecycle request through the shared exchange
// handling (local refusals, rate limits, circuit breaker, upstream errors).
func (rc *request) taskExchange(o gateways.Offer, rec *calls.Call, cred *providers.Credential, target upstream.Target, req upstream.TaskRequest) (*upstream.TaskResult, bool) {
	ctx := rc.r.Context()
	client := rc.h.Registry.Client()
	out, _, ok := rc.exchange(o, rec, cred, target, func(t upstream.Target) (any, bool, error) {
		sp := rc.span("mcp.upstream.task", trace.SpanKindClient, observability.AttrServer.String(o.Server.Slug),
			observability.AttrCapability.String(o.Capability.Kind))
		f := req
		f.Trace = req.Trace.WithParent(observability.Outgoing(sp))
		res, err := client.Task(ctx, t, f)
		if res != nil {
			upstreamAttrs(sp, &upstream.ForwardResult{Protocol: res.Protocol}, nil)
		} else {
			upstreamAttrs(sp, nil, err)
		}
		sp.End()
		if err != nil {
			return nil, false, err
		}
		return res, false, nil
	})
	if !ok {
		return nil, false
	}
	return out.(*upstream.TaskResult), true
}

// taskAck answers a successful update or cancel: an empty acknowledgement,
// never task state, and never a claim that anything stopped or changed.
func (rc *request) taskAck(rec calls.Call, class string) {
	n := rc.reply(map[string]any{})
	rec.Outcome, rec.ErrorClass = calls.OutcomeOK, class
	rc.record(rec, n)
}

// taskUnavailable answers a transient inability to check a dependency.
func (rc *request) taskUnavailable(rec calls.Call, class string) {
	rec.IdentitySent = nil
	n := rc.failData(codeDenied, "A dependency of this task is temporarily unavailable; try again shortly", map[string]any{"reason": class})
	rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, class
	rc.record(rec, n)
}

// taskBusy answers an operation that could not claim the task (another
// exchange holds it, a poll came before the stored interval, or the snapshot
// went stale) without contacting the upstream. A get of an unfinished task
// still answers from the last stored status; anything else is a retryable
// busy error.
func (rc *request) taskBusy(snap mcptasks.Snapshot, handle string, red *taskRedactor, rec calls.Call) {
	rec.IdentitySent = nil
	if rc.msg.Method == methodTasksGet && snap.Status() == upstream.TaskWorking {
		// Only "working" can be reproduced exactly: nothing else keeps its
		// payload (input requests, results) outside the sealed exchange.
		if result, ok := publicTask(handle, snap, snap.Status(), "", red, time.Now()); ok {
			result["resultType"] = resultComplete
			n := rc.reply(result)
			rec.Outcome, rec.ErrorClass = calls.OutcomeOK, "task_snapshot"
			rc.record(rec, n)
			return
		}
		rc.taskNotFound(rec, "task_expired")
		return
	}
	retry := max(1, int((snap.PollMillis()+999)/1000))
	n := rc.failData(codeDenied, "The task is busy; try again shortly", map[string]any{"reason": "task_busy", "retryAfterSeconds": retry})
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "task_busy"
	rc.record(rec, n)
}

// taskObserved records a validated tasks/get observation and answers with the
// public DetailedTask. It clears claimed once Finish consumed the claim, so the
// caller never releases it twice.
func (rc *request) taskObserved(ctx context.Context, rec calls.Call, snap mcptasks.Snapshot, op mcptasks.Operation,
	handle string, st *upstream.TaskState, red *taskRedactor, claimed *bool) {
	modes := rc.clientElicitation()
	if st.Status == upstream.TaskInputRequired {
		// The client's CURRENT capability decides whether a request can be shown.
		if !modes.any() {
			rc.taskInputUnsupported(rec)
			return
		}
		if _, _, err := relayedRequests(st.InputRequests, modes, rc.h.Registry.Client().AllowPrivate); err != nil {
			rc.taskInputUnsupported(rec)
			return
		}
	}
	var inputRaw json.RawMessage
	if st.Status == upstream.TaskInputRequired {
		inputRaw = st.InputRequests
	}
	obs := mcptasks.Observation{ID: st.ID, Status: st.Status, CreatedAt: st.CreatedAt, UpdatedAt: st.LastUpdatedAt,
		TTLMillis: st.TTLMillis, PollMillis: st.PollMillis}
	next, portalInputs, err := rc.h.Tasks.Finish(ctx, op, obs, inputRaw)
	switch {
	case err == nil:
		*claimed = false
	case errors.Is(err, mcptasks.ErrBusy):
		rc.taskBusy(snap, handle, red, rec)
		return
	case errors.Is(err, mcptasks.ErrNotFound):
		rc.taskNotFound(rec, "task_expired")
		return
	case errors.Is(err, mcptasks.ErrUnavailable):
		n := rc.fail(codeInternal, "The server's task state could not be relayed")
		rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, "task_state_invalid"
		rc.record(rec, n)
		return
	default:
		rc.internal(err)
		return
	}
	result, ok := publicTask(handle, next, st.Status, st.Message, red, time.Now())
	if !ok {
		rc.taskNotFound(rec, "task_expired")
		return
	}
	result["resultType"] = resultComplete
	switch st.Status {
	case upstream.TaskInputRequired:
		requests, _, err := relayedRequests(portalInputs, modes, rc.h.Registry.Client().AllowPrivate)
		if err != nil {
			rc.taskInputUnsupported(rec)
			return
		}
		scrubbed, err := red.json(mustJSON(requests))
		if err != nil {
			rc.taskUnsafe(rec)
			return
		}
		result["inputRequests"] = scrubbed
	case upstream.TaskCompleted:
		tool, ok := taskToolResult(st.Result, red)
		if !ok {
			rc.taskUnsafe(rec)
			return
		}
		result["result"] = tool
	case upstream.TaskFailed:
		failure := map[string]any{"code": st.Error.Code, "message": red.text(st.Error.Message)}
		if data := bytes.TrimSpace(st.Error.Data); len(data) > 0 && !bytes.Equal(data, []byte("null")) && len(data) <= mcptasks.MaxInputRequestsBytes {
			if d, err := red.json(data); err == nil {
				failure["data"] = d
			}
		}
		result["error"] = failure
	}
	encoded, err := json.Marshal(result)
	if err != nil || !red.clean(encoded) {
		rc.taskUnsafe(rec)
		return
	}
	if len(encoded) > MaxResponseBytes {
		n := rc.fail(codeInternal, "The server's response is too large")
		rec.Outcome, rec.ErrorClass = calls.OutcomeTooLarge, upstream.ClassTooLarge
		rc.record(rec, n)
		return
	}
	n := rc.reply(result)
	rec.Outcome, rec.ErrorClass = calls.OutcomeOK, "task_"+st.Status
	if st.Status == upstream.TaskCompleted && taskIsError(st.Result) {
		rec.Outcome = calls.OutcomeToolError
	}
	rc.record(rec, n)
	return
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// taskInputUnsupported: the task wants input the client can't give now.
func (rc *request) taskInputUnsupported(rec calls.Call) {
	n := rc.failData(codeDenied, "This task needs input that your client can't give: it didn't declare support for the kind of request the server asked for",
		map[string]any{"reason": "task_input_unsupported"})
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "task_input_unsupported"
	rc.record(rec, n)
}

// taskToolResult relays a completed task's original tool result the way a
// synchronous result is relayed: decoded as a tool result (so no upstream
// continuation or unknown member survives), the upstream's own serverInfo
// removed, then scrubbed. A tool's own isError stays inside the result: that
// is still a completed task.
func taskToolResult(raw json.RawMessage, red *taskRedactor) (json.RawMessage, bool) {
	var tool mcp.CallToolResult
	if json.Unmarshal(raw, &tool) != nil || tool.NeedsInput() || len(tool.InputRequests) > 0 || tool.RequestState != "" {
		return nil, false
	}
	if tool.Content == nil {
		tool.Content = []mcp.Content{}
	}
	encoded, err := json.Marshal(&tool)
	if err == nil {
		encoded, err = scrubMetaFor(encoded, true)
	}
	if err != nil {
		return nil, false
	}
	out, err := red.json(encoded)
	return out, err == nil
}

func taskIsError(raw json.RawMessage) bool {
	var v struct {
		IsError bool `json:"isError"`
	}
	return json.Unmarshal(raw, &v) == nil && v.IsError
}
