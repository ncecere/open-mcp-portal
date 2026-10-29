package mcpgw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

var errServerAttemptAuthority = errors.New("server attempt authority is unavailable")

func hasPriorForward(err error) bool {
	var e *upstream.Error
	return errors.As(err, &e) && e.PriorAttempts > 0
}

// guardServerAttempt is network-free admission, before any tools/call hook can
// spend approval. Unlike inbound quotas, a forwarded retry is charged again.
func (rc *request) guardServerAttempt(o gateways.Offer, target *upstream.Target) {
	prior := target.BeforeAttempt
	deadline := rc.approvalInput(o, nil, nil).CredentialExpiresAt
	target.BeforeAttempt = func(ctx context.Context, attempt int) error {
		if prior != nil {
			if err := prior(ctx, attempt); err != nil {
				return err
			}
		}
		if rc.h.Approvals != nil {
			if err := rc.h.Approvals.CheckContext(ctx, rc.approvalEpoch, deadline); err != nil {
				return fmt.Errorf("%w: %w", errServerAttemptAuthority, err)
			}
		} else if attempt > 0 {
			return errServerAttemptAuthority // No fresh authority source: no automatic retry.
		}
		if rc.h.Limits == nil || rc.h.RateStore == nil {
			return nil
		}
		team, err := dbgen.New(rc.h.Pool).GetTeamByID(ctx, o.Server.TeamID)
		if err != nil {
			return fmt.Errorf("%w: %w", errServerAttemptAuthority, err)
		}
		d, err := rc.h.Limits.CheckServer(ctx, rc.h.RateStore, o.Server, team)
		if err != nil {
			return fmt.Errorf("%w: %w", errServerAttemptAuthority, err)
		}
		if d.Exceeded != "" {
			return &upstream.Error{Class: upstream.ClassRateLimited, HTTPStatus: http.StatusTooManyRequests,
				Reason: limits.ServerPerMinute, RetryAfter: d.Reset, LimitPerMinute: d.LimitPerMinute,
				Message: "The upstream server's forwarded-operation quota is exceeded; try again shortly."}
		}
		return nil
	}
}

// Called after spent-approval handling, never instead of it. Local admission
// must not masquerade as remote OAuth rejection or destroy a stored consent.
func (rc *request) serverProtectionFailed(rec calls.Call, err error) bool {
	var e *upstream.Error
	errors.As(err, &e)
	if e == nil || e.PriorAttempts == 0 {
		rec.IdentitySent = nil
	}
	if errors.Is(err, errServerAttemptAuthority) {
		n := rc.failData(codeDenied, "Authority changed or could not be checked; retry the original request", map[string]any{"reason": "authority_changed"})
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "authority_changed"
		rc.record(rec, n)
		return true
	}
	if e == nil {
		return false
	}
	switch e.Reason {
	case limits.ServerPerMinute, "server_busy":
		retry := ratelimit.RetryAfter(e.RetryAfter)
		rc.w.Header().Set("Retry-After", strconv.Itoa(retry))
		code := int64(codeRateLimited)
		if rc.modern {
			code = codeRateLimitedModern
		}
		data := map[string]any{"reason": "rate_limited", "limit": e.Reason, "retryAfterSeconds": retry}
		if e.LimitPerMinute > 0 {
			data["limitPerMinute"] = e.LimitPerMinute
		}
		n := writeRPC(rc.w, http.StatusTooManyRequests, rc.msg.ID, nil, &rpcError{Code: code, Message: e.Message, Data: data})
		rec.Outcome, rec.ErrorClass = calls.OutcomeRateLimited, e.Reason
		observability.MCPRateLimited.WithLabelValues(e.Reason).Inc()
		rc.record(rec, n)
		return true
	case "circuit_open":
		n := rc.failData(codeDenied, e.Message, map[string]any{"reason": "circuit_open", "retryAfterSeconds": ratelimit.RetryAfter(e.RetryAfter)})
		rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, "circuit_open"
		rc.record(rec, n)
		return true
	}
	return false
}
