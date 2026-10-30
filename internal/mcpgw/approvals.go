package mcpgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// ApprovalRuntime separates network-free policy transactions from transport.
// A successful Consume authorizes one attempt, not a confirmed upstream effect.
type ApprovalRuntime interface {
	Epoch(context.Context) (int64, error)
	Begin(context.Context, approvals.BeginInput) (approvals.Plan, error)
	CheckContext(context.Context, int64, time.Time) error
	// CheckUngoverned is the read-only, non-spending policy check of task
	// lifecycle operations: a rule that now governs the call refuses with
	// approvals.ErrContextChanged and never creates a receipt or request.
	CheckUngoverned(context.Context, approvals.Binding, time.Time) error
	Consume(context.Context, approvals.Plan) error
	CancelBound(context.Context, approvals.BeginInput, uuid.UUID, int64) error
	URL(uuid.UUID) string
}

type approvalAttempt struct {
	plan  approvals.Plan
	spent atomic.Bool
}

func (rc *request) approvalInput(o gateways.Offer, args json.RawMessage, secrets []string) approvals.BeginInput {
	b := approvals.Binding{Epoch: rc.approvalEpoch, RequesterKind: "user", RequesterID: rc.principal.user.ID,
		GatewayID: rc.gateway.ID, ServerID: o.Server.ID, CapabilityID: o.Capability.ID, ExposedName: o.ExposedName,
		ToolClass: o.Capability.ToolClass, CapabilityFingerprint: o.Capability.Fingerprint, ServerOrigin: registry.OriginOf(o.Server.URL)}
	if p := rc.principal.account; p != nil {
		b.RequesterKind, b.RequesterID, b.RequesterTeamID = "service_account", p.Account.ID, &p.Team.ID
	}
	in := approvals.BeginInput{Binding: b, Arguments: args, Secrets: secrets}
	if rc.principal.expiresAt != nil {
		in.CredentialExpiresAt = *rc.principal.expiresAt
	}
	if expires := rc.caller.ExpiresAt; expires != nil && (in.CredentialExpiresAt.IsZero() || expires.Before(in.CredentialExpiresAt)) {
		in.CredentialExpiresAt = *expires
	}
	// A serving permit cannot outlive the server's frozen sunset, even when
	// time passes without an authority-journal write. Never extend this
	// request's permit by rereading a later deadline.
	if sunset := o.Server.SunsetAt; sunset != nil && (in.CredentialExpiresAt.IsZero() || sunset.Before(in.CredentialExpiresAt)) {
		in.CredentialExpiresAt = *sunset
	}
	return in
}

// prepareApproval runs after fallible target/request preparation, before any
// network transport. The hook rechecks context and spends only at tools/call.
func (rc *request) prepareApproval(o gateways.Offer, args json.RawMessage, again retry, target *upstream.Target, fwd *upstream.ForwardRequest, rec calls.Call) bool {
	if rc.h.Approvals == nil {
		return true
	}
	in := rc.approvalInput(o, args, target.Secrets())
	if again.approvalID != uuid.Nil && again.declined {
		err := rc.h.Approvals.CancelBound(rc.r.Context(), in, again.approvalID, again.approvalRevision)
		if err != nil {
			rc.approvalFailed(rec, err)
			return false
		}
		rc.declined(o)
		return false
	}
	plan, err := rc.h.Approvals.Begin(rc.r.Context(), in)
	if err != nil {
		rc.approvalFailed(rec, err)
		return false
	}
	if plan.Required {
		if again.relay != nil {
			n := rc.fail(codeInvalidParams, "Governed tools do not accept an upstream continuation; start a new call and approval")
			rec.Outcome, rec.ErrorClass, rec.IdentitySent = calls.OutcomeDenied, "approval_continuation", nil
			rc.record(rec, n)
			return false
		}
		if plan.Receipt.Status != approvals.Approved {
			rc.approvalRequired(o, plan.Receipt, rec)
			return false
		}
		// Approval covers exactly this dispatch, never arbitrary subsequent
		// server input. An unexpected input_required is a spent attempt.
		fwd.Elicitation, fwd.InputResponses, fwd.RequestState = nil, nil, ""
		target.NoReplay = true
	}
	a := &approvalAttempt{plan: plan}
	rc.approval = a
	prior := target.BeforeTransport
	target.BeforeTransport = func(ctx context.Context, tool bool) error {
		if prior != nil {
			if err := prior(ctx, tool); err != nil {
				return err
			}
		}
		if !tool || !plan.Required {
			return rc.h.Approvals.CheckContext(ctx, plan.Binding.Epoch, plan.CredentialExpiresAt)
		}
		if err := rc.h.Approvals.Consume(ctx, plan); err != nil {
			if errors.Is(err, approvals.ErrSpent) {
				a.spent.Store(true)
			}
			return err
		}
		a.spent.Store(true)
		return nil
	}
	return true
}

func (rc *request) approvalFailed(rec calls.Call, err error) {
	message := "Approval policy or authority changed; retry the original call for a fresh review"
	if e, ok := apperr.As(err); ok && e.Code == "approval_unavailable" {
		message = "Approval is temporarily unavailable; retry the original call or ask the server's team"
	}
	if rc.r.Context().Err() != nil {
		message = "The approval check was cancelled; retry the original call"
	}
	n := rc.failData(codeDenied, message, map[string]any{"reason": "approval_unavailable"})
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "approval_unavailable"
	if !hasPriorForward(err) {
		rec.IdentitySent = nil
	}
	rc.record(rec, n)
}

func (rc *request) approvalRequired(o gateways.Offer, receipt approvals.Receipt, rec calls.Call) {
	url := rc.h.Approvals.URL(receipt.ID)
	message := fmt.Sprintf("%s needs human approval. Open %s to review this exact call, then retry.", o.ExposedName, url)
	rec.IdentitySent = nil
	if receipt.Status == approvals.Denied {
		message = fmt.Sprintf("Approval was denied. Open %s; only an explicit renewal can request another review.", url)
		n := rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": message}}, "isError": true})
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "approval_denied"
		rc.record(rec, n)
		return
	}
	if rc.urlElicitation() {
		if box := rc.h.states(); box != nil {
			claims := rc.stateFor(purposeApproval)
			claims.ApprovalID, claims.ApprovalRevision = receipt.ID.String(), receipt.ReviewRevision
			ttl := receipt.ExpiresAt.Sub(box.now())
			if ttl > 24*time.Hour {
				ttl = 24 * time.Hour
			}
			if ttl > 0 {
				if token, err := box.sealTTL(claims, ttl); err == nil {
					n := rc.reply(map[string]any{"resultType": resultInputRequired, "inputRequests": map[string]any{
						"approval_" + receipt.ID.String(): map[string]any{"method": methodElicit, "params": map[string]any{"mode": "url", "url": url, "message": message}}}, "requestState": token})
					rec.Outcome, rec.ErrorClass = calls.OutcomeNeedsApproval, "approval_required"
					rc.record(rec, n)
					return
				}
			}
		}
	}
	var n int64
	if rc.modern {
		n = rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": message}}, "isError": true})
	} else {
		n = rc.failData(codeURLElicitationRequired, message, map[string]any{"elicitations": []map[string]any{{"mode": "url", "elicitationId": receipt.ID.String(), "url": url, "message": message}}})
	}
	rec.Outcome, rec.ErrorClass = calls.OutcomeNeedsApproval, "approval_required"
	rc.record(rec, n)
}

// approvalTransportFailed handles local refusals before an attempt separately
// from failures after authorization was spent. Never expose a hook's cause.
func (rc *request) approvalTransportFailed(rec calls.Call, err error) bool {
	if rc.approval == nil {
		return false
	}
	var local *upstream.BeforeTransportError
	if !rc.approval.spent.Load() {
		if errors.Is(err, errServerAttemptAuthority) {
			return false
		} // Preserve prior retry dispatch facts in the admission handler.
		if errors.As(err, &local) {
			rc.approvalFailed(rec, err)
			return true
		}
		return false
	}
	rc.approvalUnknown(rec)
	return true
}

func (rc *request) approvalUnknown(rec calls.Call) {
	url := rc.h.Approvals.URL(rc.approval.plan.Receipt.ID)
	message := "Approval was spent, but the upstream result is not confirmed. Repeating this call may duplicate effects. Review " + url
	n := rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": message}}, "isError": true})
	rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, "approval_outcome_unknown"
	rc.record(rec, n)
}
