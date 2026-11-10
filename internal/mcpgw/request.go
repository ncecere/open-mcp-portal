package mcpgw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// request is one exchange.
type request struct {
	approvalEpoch int64
	approval      *approvalAttempt
	h             *Handler
	w             http.ResponseWriter
	r             *http.Request
	start         time.Time
	msg           message
	principal     principal
	requestBytes  int64
	gateway       dbgen.Gateway
	caller        gateways.Caller
	// outcome is the recorded outcome (metrics; "" for requests that are
	// not recorded).
	outcome string
	// forwarded: the call reached its server (call latency metric).
	forwarded bool
	// capture is the payload to store with the call record (nil: none).
	capture *capture.Input
	// scrub are a person's tokens for an oauth server, removed from the
	// server's answer should it echo them (the client and the model never
	// see them).
	scrub []string
	// personSecretUsed is the person's own secret the call carries (nil:
	// none), kept to mark it rejected when the server refuses it.
	personSecretUsed *personsecrets.Secret
	// modern: the request is of the 2026-07-28 era (era.go); clientCaps are
	// the capabilities it declared.
	modern     bool
	clientCaps map[string]json.RawMessage
	// stream is the SSE response of a streamed call (stream.go; nil: the
	// answer is one JSON object). Once set, w is the stream.
	stream *stream
	// creating is the reserved-but-not-yet-exposed creation of a task for this
	// tools/call (tasks_create.go); taskOp marks a task lifecycle request
	// (tasks_ops.go), whose refusals never distinguish one cause from another;
	// noResend forbids the automatic renew-and-resend of an upstream 401, because
	// a task creation or lifecycle exchange is sent exactly once.
	creating *taskInit
	taskOp   bool
	noResend bool
}

// observe records the request's metrics.
func (rc *request) observe() {
	method, outcome := rc.msg.Method, rc.outcome
	if method == "" || len(rc.msg.ID) == 0 {
		method = "notification"
	}
	if outcome == "" {
		outcome = calls.OutcomeOK
	}
	observability.ObserveMCP(method, outcome, time.Since(rc.start))
}

// rateLimit counts the request toward every limit that applies and, over
// one, answers 429 (recorded as rate_limited for lists and calls). The
// caller's own tightest limit is shown in RateLimit-* headers.
func (rc *request) rateLimit() bool {
	h := rc.h
	if h.Limits == nil || h.RateStore == nil {
		return true
	}
	ctx := rc.r.Context()
	p := rc.principal
	sub := limits.Subject{Gateway: rc.gateway}
	switch {
	case p.account != nil:
		t := p.account.Team
		sub.ServiceAccountID, sub.ServiceAccountTeam = p.account.Account.ID, &t
	case p.grant != nil:
		sub.UserID, sub.CredentialID = p.user.ID, p.grant.ID
	default:
		sub.UserID, sub.CredentialID = p.user.ID, p.keyID
	}
	if rc.gateway.TeamID.Valid {
		t, err := dbgen.New(h.Pool).GetTeamByID(ctx, rc.gateway.TeamID.UUID)
		if err != nil {
			rc.internal(err)
			return false
		}
		sub.GatewayTeam = &t
	}
	sp := rc.span("mcp.rate_limit", trace.SpanKindInternal)
	d, err := h.Limits.Check(ctx, h.RateStore, sub)
	if err != nil {
		observability.Fail(sp, "error")
	} else if d.Exceeded != "" {
		observability.Annotate(sp, observability.AttrRateLimit.String(d.Exceeded))
	}
	sp.End()
	if err != nil {
		rc.internal(err)
		return false
	}
	retry := ratelimit.RetryAfter(d.Reset)
	if d.Own != nil {
		hd := rc.w.Header()
		hd.Set("RateLimit-Limit", strconv.FormatInt(d.Own.Limit, 10))
		hd.Set("RateLimit-Remaining", strconv.FormatInt(d.Own.Remaining, 10))
		hd.Set("RateLimit-Reset", strconv.Itoa(retry))
	}
	if d.Exceeded == "" {
		return true
	}
	observability.MCPRateLimited.WithLabelValues(d.Exceeded).Inc()
	rc.w.Header().Set("Retry-After", strconv.Itoa(retry))
	name := strings.TrimSuffix(d.Exceeded, "_per_minute")
	limitedCode := int64(codeRateLimited)
	if rc.modern {
		limitedCode = codeRateLimitedModern
	}
	n := writeRPC(rc.w, http.StatusTooManyRequests, rc.msg.ID, nil, &rpcError{Code: limitedCode,
		Message: fmt.Sprintf("Rate limit exceeded (%s); try again in %d s", strings.ReplaceAll(name, "_", " "), retry),
		Data:    map[string]any{"reason": "rate_limited", "limit": d.Exceeded, "limitPerMinute": d.LimitPerMinute, "retryAfterSeconds": retry}})
	rc.outcome = calls.OutcomeRateLimited
	if recorded(rc.msg.Method) && len(rc.msg.ID) > 0 {
		rc.record(calls.Call{Outcome: calls.OutcomeRateLimited, ErrorClass: d.Exceeded, ExposedName: rc.requestedName()}, n)
	}
	return false
}

func recorded(method string) bool {
	switch method {
	case methodToolsList, methodToolsCall, methodPromptsList, methodPromptsGet, methodResources, methodTemplates, methodRead,
		methodTasksGet, methodTasksUpdate, methodTasksCancel:
		return true
	}
	return false
}

// resolveGateway finds the gateway and checks the key and the person may
// use it. An unknown or disabled gateway, a team gateway of an archived
// team, one the key is not limited to, or one they may not use, is 404
// (recorded as denied for lists and calls of an existing gateway).
func (rc *request) resolveGateway(slug string) bool {
	return rc.resolveGatewayAttempt(slug, nil)
}

// prior is the explicit live-check record. Before transport its IdentitySent
// is nil; only a completed forwarding attempt supplies attempted-call metadata.
func (rc *request) resolveGatewayAttempt(slug string, prior *calls.Call) bool {
	ctx := rc.r.Context()
	g, err := rc.h.Gateways.Resolve(ctx, slug)
	if err != nil {
		if !isNotFound(err) {
			rc.liveInternal(err, prior)
			return false
		}
		refuse(rc.w, http.StatusNotFound, "Gateway not found")
		if prior != nil {
			rec := *prior
			rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "gateway_not_found"
			rc.record(rec, 0)
		}
		return false
	}
	rc.gateway = g
	denied := ""
	if !rc.principal.inScope(g.ID) {
		denied = DeniedKeyScope
	} else if denied, err = rc.h.Gateways.Unserved(ctx, g); err != nil {
		rc.liveInternal(err, prior)
		return false
	}
	if denied == "" {
		var c gateways.Caller
		if sa := rc.principal.account; sa != nil {
			c, err = rc.h.Gateways.ServiceAccountCaller(ctx, g, sa.Team.ID, sa.Account.Role)
		} else {
			c, err = rc.h.Gateways.CallerOf(ctx, g, rc.principal.user)
		}
		if err != nil {
			rc.liveInternal(err, prior)
			return false
		}
		rc.caller = c
		if !c.Allowed() {
			denied = "no_access"
		}
	}
	if denied == "" {
		return true
	}
	n := int64(0)
	if rc.msg.Method != "" {
		n = writeRPC(rc.w, http.StatusNotFound, rc.msg.ID, nil, &rpcError{Code: codeRefused, Message: "Gateway not found"})
	} else {
		refuse(rc.w, http.StatusNotFound, "Gateway not found")
	}
	if recorded(rc.msg.Method) && len(rc.msg.ID) > 0 {
		rec := calls.Call{ExposedName: rc.requestedName()}
		if prior != nil {
			rec = *prior
		}
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, denied
		rc.record(rec, n)
	}
	return false
}

func isNotFound(err error) bool {
	e, ok := apperr.As(err)
	return ok && e.Status == http.StatusNotFound
}

func (rc *request) internal(err error) {
	rc.outcome = "error"
	if errors.Is(err, context.Canceled) && rc.r.Context().Err() != nil {
		// The client went away (a probe that gave up, a closed session): not
		// the gateway's failure.
		rc.h.log().InfoContext(rc.r.Context(), "mcp request cancelled by the client", "request_id", httpx.RequestID(rc.r.Context()))
	} else {
		rc.h.log().ErrorContext(rc.r.Context(), "mcp request failed", "err", err, "request_id", httpx.RequestID(rc.r.Context()))
	}
	writeRPC(rc.w, http.StatusInternalServerError, rc.msg.ID, nil, &rpcError{Code: codeInternal, Message: "Something went wrong"})
}

// clientName is clientInfo.name when this request carries it (initialize,
// or the _meta of 2026-07-28 requests).
func (rc *request) clientName() string {
	var p struct {
		ClientInfo *struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(rc.msg.Params) == 0 || json.Unmarshal(rc.msg.Params, &p) != nil {
		return ""
	}
	if p.ClientInfo != nil {
		return p.ClientInfo.Name
	}
	var info struct {
		Name string `json:"name"`
	}
	if raw, ok := p.Meta[metaClientInfo]; ok && json.Unmarshal(raw, &info) == nil {
		return info.Name
	}
	return ""
}

// requestedName is params.name of a call, or params.uri of a read, for
// records (bounded by calls.Record).
func (rc *request) requestedName() string {
	var p struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	switch rc.msg.Method {
	case methodToolsCall, methodPromptsGet:
		_ = json.Unmarshal(rc.msg.Params, &p)
		return p.Name
	case methodRead:
		_ = json.Unmarshal(rc.msg.Params, &p)
		return p.URI
	}
	return ""
}

// record stores the exchange's metadata, and its captured payload when the
// call was forwarded and the gateway or server captures payloads.
func (rc *request) record(c calls.Call, responseBytes int64) {
	rc.outcome = c.Outcome
	c.RequestID, c.Method, c.Gateway = httpx.RequestID(rc.r.Context()), rc.msg.Method, rc.gateway
	p := rc.principal
	c.PrincipalKind, c.APIKeyID, c.KeyName = p.kind, p.keyID, p.keyName
	switch {
	case p.account != nil:
		c.ServiceAccountID, c.ServiceAccountName, c.ServiceAccountTeamID = p.account.Account.ID, p.account.Account.Name, p.account.Team.ID
	case p.grant != nil:
		c.UserID, c.OAuthGrantID, c.OAuthClientName, c.OAuthClientKind = p.user.ID, p.grant.ID, p.grant.ClientName, p.grant.ClientKind
	default:
		c.UserID = p.user.ID
	}
	c.ClientName = rc.clientName()
	c.TraceID = observability.SampledTraceID(rc.r.Context())
	if rc.stream != nil {
		responseBytes = rc.stream.bytes() // progress events and the response
	}
	c.Latency, c.RequestBytes, c.ResponseBytes = time.Since(rc.start), rc.requestBytes, responseBytes
	ctx, cancel := context.WithTimeout(context.WithoutCancel(rc.r.Context()), 5*time.Second)
	defer cancel()
	if rc.forwarded && c.Server != nil {
		observability.ObserveCall(rc.gateway.Slug, c.Server.Slug, c.Latency)
	}
	var after calls.After
	var prepared *capture.Prepared
	if rc.capture != nil && rc.h.Capture != nil {
		var err error
		if prepared, err = rc.h.Capture.Prepare(ctx, *rc.capture); err != nil {
			rc.h.Capture.Failed(ctx, err)
		} else {
			after = rc.h.Capture.Hook(prepared)
		}
		rc.capture = nil
	}
	captureErr, err := calls.Record(ctx, rc.h.Pool, c, after)
	if err != nil {
		rc.h.log().WarnContext(ctx, "could not record an MCP call", "err", err, "request_id", c.RequestID)
	} else if prepared != nil {
		rc.h.Capture.Recorded(ctx, prepared, captureErr)
	}
	rc.h.log().DebugContext(ctx, "mcp call", "gateway", rc.gateway.Slug, "method", c.Method, "name", c.ExposedName,
		"outcome", c.Outcome, "error_class", c.ErrorClass, "latency_ms", c.Latency.Milliseconds(), "request_id", c.RequestID)
}

func (rc *request) reply(result any) int64 {
	return writeRPC(rc.w, http.StatusOK, rc.msg.ID, rc.shape(result), nil)
}

func (rc *request) fail(code int64, msg string) int64 {
	return writeRPC(rc.w, http.StatusOK, rc.msg.ID, nil, &rpcError{Code: code, Message: msg})
}

func (rc *request) failData(code int64, msg string, data any) int64 {
	return writeRPC(rc.w, http.StatusOK, rc.msg.ID, nil, &rpcError{Code: code, Message: msg, Data: data})
}
