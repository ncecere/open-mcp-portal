package mcpgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Task creation (docs/mcp-tasks.md "Conservative first scope").
//
// A tools/call may ask its modern server for a task ONLY when all of these
// hold, decided after the approval plan is known: the downstream client
// declared the Tasks extension on this very request, the store is enabled, the
// server's canonical primary advertised the extension, the capability is a
// tool, the call is UNGOVERNED (no approval rule applies: an approved call
// authorizes exactly one dispatch, never an open-ended task), the request is
// not a streamed one (progress token over SSE: out of this first scope) and it
// is not the retry of an upstream input request. Otherwise the call is exactly
// what it always was, and an undeclared upstream is never told about tasks.
//
// The task is reserved (capacity and sealed state) BEFORE anything is sent,
// then sent exactly once: no retry, no failover, no 401 renew-and-resend. A task
// result activates the reservation (the mapping is durable) before the portal
// handle is revealed; any other result or any failure abandons the reservation
// without ever claiming that upstream work was cancelled.

// taskInit is a reservation made for the call in flight.
type taskInit struct {
	res       mcptasks.Reservation
	redaction []string // credential values sent with the creation: scrub only
	activated bool
}

// negotiateTask reserves a task and switches the exchange to single-attempt
// task negotiation when every condition holds. nil, true: not negotiated (the
// call proceeds unchanged). ok false: it answered the request itself.
func (rc *request) negotiateTask(o gateways.Offer, args json.RawMessage, again retry, target *upstream.Target, fwd *upstream.ForwardRequest,
	cred *providers.Credential, secret *personsecrets.Secret, token string, streaming bool, rec *calls.Call) (*taskInit, bool) {
	if !rc.tasksEnabled() || !rc.tasksDeclared() || !o.Server.SupportsTasks || o.Capability.Kind != upstream.KindTool ||
		streaming || again.relay != nil || len(bytes.TrimSpace(fwd.InputResponses)) != 0 || fwd.RequestState != "" {
		return nil, true
	}
	if rc.approval == nil || rc.approval.plan.Required || target.NoReplay {
		return nil, true // governed: never negotiated, whatever the upstream offers
	}
	ctx := rc.r.Context()
	normalized := bytes.TrimSpace(args)
	if len(normalized) == 0 || bytes.Equal(normalized, []byte("null")) {
		normalized = []byte("{}")
	}
	argumentsDigest, err := mcptasks.DigestArguments(normalized)
	if err != nil {
		return nil, true
	}
	values, ok := validRedactionValues(rc.taskCredentialValues(*target, token))
	if !ok {
		return nil, true
	}
	dependency, err := rc.dependencyDigest(o, cred, secret, *target)
	if err != nil {
		rc.h.log().WarnContext(ctx, "mcp task dependency identity unavailable; calling without a task", "server", o.Server.Slug)
		return nil, true
	}
	binding := rc.taskBinding(o, argumentsDigest, dependency)
	if _, err := mcptasks.DigestBinding(binding); err != nil {
		return nil, true // a shape the task store cannot bind (e.g. an unusual name): an ordinary call
	}
	reservation, err := rc.h.Tasks.Reserve(ctx, binding, mcptasks.Payload{Arguments: bytes.Clone(normalized), RedactionOnly: values})
	switch {
	case err == nil:
	case errors.Is(err, mcptasks.ErrCapacity):
		rec.IdentitySent = nil // nothing was sent
		n := rc.failData(codeDenied, "Too many unfinished tasks for this account; wait for one to finish, then try again",
			map[string]any{"reason": "task_capacity"})
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "task_capacity"
		rc.record(*rec, n)
		return nil, false
	default:
		// The store (not the call) is unavailable: an ordinary synchronous call.
		rc.h.log().WarnContext(ctx, "mcp task reservation unavailable; calling without a task", "server", o.Server.Slug)
		return nil, true
	}
	// From here exactly one attempt on the canonical primary: no retry, no
	// failover endpoint, no automatic renew-and-resend of a 401. The transport
	// guard enforces the same inside the upstream client.
	fwd.Tasks = true
	target.NoReplay, target.Endpoints = true, nil
	rc.noResend = true
	return &taskInit{res: reservation, redaction: values}, true
}

// abandonTask releases a reservation that never became a task. It cancels
// nothing upstream: a failed or ambiguous send may have left untracked work.
func (rc *request) abandonTask() {
	ti := rc.creating
	if ti == nil || ti.activated {
		return
	}
	ctx := context.WithoutCancel(rc.r.Context())
	if err := rc.h.Tasks.AbandonReservation(ctx, ti.res); err != nil && !errors.Is(err, mcptasks.ErrNotFound) {
		rc.h.log().WarnContext(ctx, "mcp task reservation could not be released", "err", err)
	}
}

// relayTaskCreated answers a tools/call the server turned into a task: it
// persists the mapping, rechecks live authority and only then reveals the
// portal handle, in a public CreateTaskResult built from validated fields.
func (rc *request) relayTaskCreated(o gateways.Offer, rec calls.Call, st *upstream.TaskState) {
	ti := rc.creating
	if ti == nil {
		// Unreachable: a task is only requested with a reservation.
		rc.internal(errors.New("a task came back without a reservation"))
		return
	}
	ctx := rc.r.Context()
	red := newTaskRedactor(st.ID, ti.redaction, rc.scrub)
	// The call may have run for long: re-verify access and the offer BEFORE a
	// mapping is committed, so a revoked caller leaves no orphan row behind.
	if !rc.liveTool(o, &rec) {
		return
	}
	obs := mcptasks.Observation{ID: st.ID, Status: st.Status, CreatedAt: st.CreatedAt, UpdatedAt: st.LastUpdatedAt,
		TTLMillis: st.TTLMillis, PollMillis: st.PollMillis}
	handle, snap, err := rc.h.Tasks.Activate(ctx, ti.res, obs)
	if err != nil {
		rc.h.log().WarnContext(ctx, "mcp task could not be recorded", "err", err)
		n := rc.fail(codeInternal, "The server started a task that the portal could not track; it may still be running")
		rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, "task_unrecorded"
		rc.record(rec, n)
		return
	}
	ti.activated = true
	result, ok := publicTask(handle, snap, snap.Status(), st.Message, red, time.Now())
	if !ok {
		rc.taskUnsafe(rec)
		return
	}
	result["resultType"] = "task"
	if encoded, err := json.Marshal(result); err != nil || len(encoded) > MaxResponseBytes || !red.clean(encoded) {
		rc.taskUnsafe(rec)
		return
	}
	n := rc.reply(result)
	rec.Outcome, rec.ErrorClass = calls.OutcomeOK, "task_created"
	rc.record(rec, n)
}

// taskUnsafe answers a task result that could not be made safe to relay.
func (rc *request) taskUnsafe(rec calls.Call) {
	n := rc.fail(codeInternal, "The task response could not be relayed safely")
	rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, "task_response_unsafe"
	rc.record(rec, n)
}
