package mcpgw

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Tracing of /mcp/{slug} (decision 71, docs/deploy.md "Tracing").
//
// One server span per request, "MCP <method>", with children for
// authentication, gateway resolution and authorization, the rate limit, the
// provider credential (a refresh happens inside it) and the call to the
// server. Its parent is the request's traceparent header, else the
// traceparent in params._meta (when it is well-formed: upstream.TraceFromMeta),
// else the span starts a new trace. The _meta parent is known only once the
// body is read, after authentication, so the span is created then, with the
// time the request started, and authentication is recorded as a child of it
// afterwards. A request that ends before its body is read gets its span from
// the header alone.
//
// Attributes come only from observability's allow-list: the MCP method, the
// gateway and server slugs, the outcome, the principal kind and fixed
// classes. Never a person, a key, a tool name, an argument or a result.

// reqTrace is the trace of one request; nil when tracing is off, so a
// request without tracing allocates nothing and wraps nothing.
type reqTrace struct {
	start time.Time
	route string
	sw    *statusWriter
	span  trace.Span
	auth  authPhase
	rc    *request
}

type authPhase struct {
	start, end time.Time
	principal  string
	ok         bool
	done       bool
}

// newReqTrace starts tracing a request (nil: tracing is off) and returns the
// ResponseWriter to use, which also records the status.
func newReqTrace(w http.ResponseWriter, r *http.Request, start time.Time) (*reqTrace, http.ResponseWriter) {
	if !observability.Tracing() {
		return nil, w
	}
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	return &reqTrace{start: start, route: r.Pattern, sw: sw}, sw
}

// authenticated records the authentication phase (kind: the principal's kind
// when it succeeded).
func (t *reqTrace) authenticated(start time.Time, kind string, ok bool) {
	if t != nil {
		t.auth = authPhase{start: start, end: time.Now(), principal: kind, ok: ok, done: true}
	}
}

// begin creates the server span once, as a child of the traceparent header
// or else of the _meta's, and returns the request carrying it.
func (t *reqTrace) begin(r *http.Request, msg *message) *http.Request {
	if t == nil || t.span != nil {
		return r
	}
	ctx := observability.ExtractHeader(r.Context(), r.Header)
	name := "MCP request"
	attrs := []attribute.KeyValue{observability.AttrHTTPMethod.String(observability.HTTPMethod(r.Method))}
	if msg != nil {
		method := observability.MCPMethod(msg.Method)
		if msg.Method == "" || len(msg.ID) == 0 {
			method = "notification"
		}
		name = "MCP " + method
		attrs = append(attrs, observability.AttrMCPMethod.String(method))
		if !observability.HasRemoteParent(ctx) {
			// The client's _meta, validated as it is for the server.
			_, meta := paramsOf(msg.Params)
			tc := upstream.TraceFromMeta(meta)
			ctx = observability.Extract(ctx, tc.Traceparent, tc.Tracestate)
		}
	}
	if t.auth.principal != "" {
		attrs = append(attrs, observability.AttrPrincipal.String(t.auth.principal))
	}
	ctx, t.span = observability.StartAt(ctx, name, trace.SpanKindServer, t.start, attrs...)
	if t.auth.done {
		_, a := observability.StartAt(ctx, "mcp.authenticate", trace.SpanKindInternal, t.auth.start)
		if !t.auth.ok {
			observability.Fail(a, "refused")
		}
		a.End(trace.WithTimestamp(t.auth.end))
	}
	observability.RecordInSlot(ctx) // the access log of this request names its trace
	return r.WithContext(ctx)
}

// finish ends the server span with the request's outcome and status.
func (t *reqTrace) finish(r *http.Request) {
	if t == nil {
		return
	}
	if t.span == nil {
		t.begin(r, nil)
	}
	attrs := []attribute.KeyValue{observability.AttrHTTPRoute.String(t.route), observability.AttrHTTPStatus.Int(t.sw.status)}
	if rc := t.rc; rc != nil {
		if g := rc.gateway.Slug; g != "" {
			attrs = append(attrs, observability.AttrGateway.String(g))
		}
		outcome := rc.outcome
		if outcome == "" {
			outcome = calls.OutcomeOK
		}
		attrs = append(attrs, observability.AttrOutcome.String(outcome))
		era := "legacy"
		if rc.modern {
			era = "modern"
		}
		attrs = append(attrs, observability.AttrEra.String(era))
		if outcome == "error" {
			observability.Fail(t.span, "internal")
		}
	}
	if t.sw.status >= 500 {
		observability.Fail(t.span, "http_5xx")
	}
	observability.Annotate(t.span, attrs...)
	t.span.End()
}

// span starts a child of the request's span (a no-op when tracing is off).
func (rc *request) span(name string, kind trace.SpanKind, attrs ...attribute.KeyValue) trace.Span {
	_, s := observability.Start(rc.r.Context(), name, kind, attrs...)
	return s
}

// statusWriter records the status a response was written with. It keeps
// streaming (Flush, and Unwrap for http.ResponseController).
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// statusClass is "2xx", "4xx" and so on.
func statusClass(status int) string { return strconv.Itoa(status/100) + "xx" }

// upstreamAttrs annotates the span of a call to a server with how it ended:
// the server's protocol era, or the error's class and HTTP status class.
func upstreamAttrs(span trace.Span, res *upstream.ForwardResult, err error) {
	switch {
	case err != nil:
		class := "error"
		var ue *upstream.Error
		if errors.As(err, &ue) {
			class = ue.Class
			if ue.HTTPStatus > 0 {
				observability.Annotate(span, observability.AttrStatusClass.String(statusClass(ue.HTTPStatus)))
			}
		}
		observability.Annotate(span, observability.AttrErrorClass.String(class))
		observability.Fail(span, class)
	case res != nil:
		observability.Annotate(span, observability.AttrEra.String(string(res.Protocol.Era)), observability.AttrStatusClass.String("2xx"))
	}
}
