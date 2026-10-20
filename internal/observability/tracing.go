package observability

// OpenTelemetry tracing (docs/deploy.md "Tracing", decision 71).
//
// Tracing is off unless an OTLP endpoint is configured. Off, no provider is
// installed, no span is created, no header is read and nothing is sent:
// Start returns the caller's context and a span that records nothing.
//
// Spans carry a fixed set of attributes (allowedAttributes): the MCP method,
// gateway, server and provider slugs, outcomes, classes and status codes, the
// same low-cardinality facts the metrics use. Start and Annotate drop any
// other key, so a new call site cannot export a person, a credential, a tool
// name, an argument or a result by accident (tracing_test.go enumerates what
// a call exports). Errors are recorded as a class, never as the error's
// text, which can hold addresses and server messages.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// The attributes a span may carry.
const (
	AttrMCPMethod   = attribute.Key("mcp.method.name")     // MCPMethod's fixed list, else other
	AttrGateway     = attribute.Key("omp.gateway.slug")    // an existing gateway
	AttrServer      = attribute.Key("omp.server.slug")     // an existing server
	AttrProvider    = attribute.Key("omp.provider.slug")   // an existing auth provider
	AttrOutcome     = attribute.Key("omp.outcome")         // a call outcome (calls.Outcome*)
	AttrPrincipal   = attribute.Key("omp.principal.kind")  // api_key, oauth or service_account
	AttrEra         = attribute.Key("omp.protocol.era")    // legacy or modern (the client's, or the server's upstream)
	AttrErrorClass  = attribute.Key("omp.error.class")     // an upstream error class or a refusal reason
	AttrRateLimit   = attribute.Key("omp.rate_limit")      // the limit that was exceeded
	AttrResult      = attribute.Key("omp.result")          // ok, refused, error or the like
	AttrTrigger     = attribute.Key("omp.trigger")         // scheduled or manual
	AttrCapability  = attribute.Key("omp.capability.kind") // tool, prompt, resource
	AttrHTTPMethod  = attribute.Key("http.request.method")
	AttrHTTPRoute   = attribute.Key("http.route") // the route pattern, never the path
	AttrHTTPStatus  = attribute.Key("http.response.status_code")
	AttrStatusClass = attribute.Key("omp.http.status_class") // 2xx, 4xx, 5xx of the server's answer
)

// allowedAttributes is every key Start and Annotate keep.
var allowedAttributes = map[attribute.Key]bool{
	AttrMCPMethod: true, AttrGateway: true, AttrServer: true, AttrProvider: true, AttrOutcome: true, AttrPrincipal: true,
	AttrEra: true, AttrErrorClass: true, AttrRateLimit: true, AttrResult: true, AttrTrigger: true, AttrCapability: true,
	AttrHTTPMethod: true, AttrHTTPRoute: true, AttrHTTPStatus: true, AttrStatusClass: true,
}

// AllowedAttributeKeys lists the keys a span may carry (tests).
func AllowedAttributeKeys() []string {
	out := make([]string, 0, len(allowedAttributes))
	for k := range allowedAttributes {
		out = append(out, string(k))
	}
	return out
}

// maxAttrValue bounds a string attribute.
const maxAttrValue = 128

// tracerName is the instrumentation scope of the portal's spans.
const tracerName = "github.com/ncecere/open-mcp-portal"

// active is the tracer while tracing is on (nil: off).
var active atomic.Pointer[trace.Tracer]

// Tracing reports whether spans are being created.
func Tracing() bool { return active.Load() != nil }

// UseTracerProvider turns tracing on with tp (tests; InitTracing does it for
// the process) and returns a function that turns it off again.
func UseTracerProvider(tp trace.TracerProvider) (restore func()) {
	tr := tp.Tracer(tracerName)
	prev := active.Swap(&tr)
	return func() { active.Store(prev) }
}

func keep(attrs []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		if !allowedAttributes[a.Key] {
			continue
		}
		if a.Value.Type() == attribute.STRING && len(a.Value.AsString()) > maxAttrValue {
			a = attribute.String(string(a.Key), a.Value.AsString()[:maxAttrValue])
		}
		out = append(out, a)
	}
	return out
}

// noSpan is what Start returns while tracing is off: it records nothing and
// ending it ends nothing.
var noSpan = trace.SpanFromContext(context.Background())

// Start begins a span (a no-op when tracing is off). kind is the span's
// role; attrs outside the allow-list are dropped.
func Start(ctx context.Context, name string, kind trace.SpanKind, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tr := active.Load()
	if tr == nil {
		return ctx, noSpan
	}
	return (*tr).Start(ctx, name, trace.WithSpanKind(kind), trace.WithAttributes(keep(attrs)...))
}

// StartAt is Start for a span whose work began at start (a phase measured
// before its trace could be told: see mcpgw's trace.go).
func StartAt(ctx context.Context, name string, kind trace.SpanKind, start time.Time, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tr := active.Load()
	if tr == nil {
		return ctx, noSpan
	}
	return (*tr).Start(ctx, name, trace.WithSpanKind(kind), trace.WithTimestamp(start), trace.WithAttributes(keep(attrs)...))
}

// Annotate sets allowed attributes on a span.
func Annotate(span trace.Span, attrs ...attribute.KeyValue) {
	if span == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(keep(attrs)...)
}

// Fail marks a span as failed with a class (never the error's text).
func Fail(span trace.Span, class string) {
	if span == nil || !span.IsRecording() {
		return
	}
	if len(class) > maxAttrValue {
		class = class[:maxAttrValue]
	}
	span.SetStatus(codes.Error, class)
}

// Extract reads a W3C traceparent (and tracestate) into ctx as a remote
// parent; it is what HTTP headers and _meta carry. Malformed values leave
// ctx unchanged. Baggage is never read: the portal adds none and passes the
// client's on as sent.
func Extract(ctx context.Context, traceparent, tracestate string) context.Context {
	if traceparent == "" || !Tracing() {
		return ctx
	}
	c := propagation.MapCarrier{"traceparent": traceparent}
	if tracestate != "" {
		c["tracestate"] = tracestate
	}
	return propagation.TraceContext{}.Extract(ctx, c)
}

// ExtractHeader is Extract for a request's HTTP headers.
func ExtractHeader(ctx context.Context, h http.Header) context.Context {
	if !Tracing() {
		return ctx
	}
	return Extract(ctx, h.Get("traceparent"), h.Get("tracestate"))
}

// HasRemoteParent reports whether ctx holds a parent that arrived from
// outside (Extract found one).
func HasRemoteParent(ctx context.Context) bool {
	sc := trace.SpanContextFromContext(ctx)
	return sc.IsValid() && sc.IsRemote()
}

// SampledTraceID is the trace ID of the span in ctx when it is sampled (the
// trace is exported), else "": the value call records and links carry.
func SampledTraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.IsSampled() {
		return ""
	}
	return sc.TraceID().String()
}

// Outgoing is the traceparent and tracestate that name span as the parent
// of the next hop, or "" when span is not sampled (the caller then passes
// on whatever the client sent, as it does with tracing off).
func Outgoing(span trace.Span) (traceparent, tracestate string) {
	sc := span.SpanContext()
	if !sc.IsValid() || !sc.IsSampled() {
		return "", ""
	}
	return fmt.Sprintf("00-%s-%s-01", sc.TraceID(), sc.SpanID()), sc.TraceState().String()
}

// httpMethods are the methods with their own attribute value.
var httpMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}

// HTTPMethod is a method's attribute value (_OTHER for anything unusual).
func HTTPMethod(m string) string {
	if httpMethods[m] {
		return m
	}
	return "_OTHER"
}

// untraced paths are probes: sampled, they would be most of the traffic.
func untraced(path string) bool { return path == "/healthz" || path == "/readyz" }

// TraceSlot lets the access log of a request that is traced deeper (an /mcp/
// request, whose span the gateway creates) carry its trace ID.
type TraceSlot struct {
	ctx atomic.Pointer[context.Context]
}

type slotKey struct{}

// WithTraceSlot returns ctx with an empty slot (nil, and ctx unchanged, when
// tracing is off).
func WithTraceSlot(ctx context.Context) (context.Context, *TraceSlot) {
	if !Tracing() {
		return ctx, nil
	}
	s := &TraceSlot{}
	return context.WithValue(ctx, slotKey{}, s), s
}

// RecordInSlot stores the context of a started span in ctx's slot.
func RecordInSlot(ctx context.Context) {
	if s, ok := ctx.Value(slotKey{}).(*TraceSlot); ok {
		c := context.WithoutCancel(ctx)
		s.ctx.Store(&c)
	}
}

// LogContext is the context to log a request with: the one with the span the
// gateway recorded, else ctx itself.
func (s *TraceSlot) LogContext(ctx context.Context) context.Context {
	if s != nil {
		if c := s.ctx.Load(); c != nil {
			return *c
		}
	}
	return ctx
}

// ServerSpan is the span of one HTTP request (nil-safe: a request that is
// not traced has none).
type ServerSpan struct{ span trace.Span }

// StartHTTP starts the server span of a request, as a child of its
// traceparent header when it has a valid one. /mcp/ requests are traced by
// the gateway (mcpgw), which also reads _meta; probes are not traced.
// Tracing off: the context is returned unchanged and the span is nil.
func StartHTTP(r *http.Request) (context.Context, *ServerSpan) {
	ctx := r.Context()
	if !Tracing() || untraced(r.URL.Path) || strings.HasPrefix(r.URL.Path, "/mcp/") {
		return ctx, nil
	}
	ctx = ExtractHeader(ctx, r.Header)
	ctx, span := Start(ctx, "HTTP "+HTTPMethod(r.Method), trace.SpanKindServer, AttrHTTPMethod.String(HTTPMethod(r.Method)))
	return ctx, &ServerSpan{span}
}

// End names the span after the matched route pattern (never the raw path,
// which holds IDs), records the status and ends it.
func (s *ServerSpan) End(pattern string, status int) {
	if s == nil {
		return
	}
	if pattern == "" {
		pattern = "unmatched"
	}
	s.span.SetName(pattern)
	attrs := []attribute.KeyValue{AttrHTTPRoute.String(pattern), AttrHTTPStatus.Int(status)}
	Annotate(s.span, attrs...)
	if status >= 500 {
		Fail(s.span, "http_"+fmt.Sprint(status/100)+"xx")
	}
	s.span.End()
}

// TracingOptions configures InitTracing.
type TracingOptions struct {
	// Endpoint is the full OTLP/HTTP traces URL (".../v1/traces"); empty:
	// tracing stays off.
	Endpoint string
	// Headers are sent with every export (a collector's credentials; never
	// logged).
	Headers map[string]string
	// ServiceName and Version name the resource.
	ServiceName, Version string
	// Sampler is an OTEL_TRACES_SAMPLER name; Arg its ratio.
	Sampler string
	Arg     float64
}

// Samplers are the OTEL_TRACES_SAMPLER values the portal accepts.
var Samplers = []string{"always_on", "always_off", "traceidratio", "parentbased_always_on", "parentbased_always_off", "parentbased_traceidratio"}

// NewSampler returns the sampler named by an OTEL_TRACES_SAMPLER value.
func NewSampler(name string, arg float64) (sdktrace.Sampler, error) {
	switch name {
	case "always_on":
		return sdktrace.AlwaysSample(), nil
	case "always_off":
		return sdktrace.NeverSample(), nil
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(arg), nil
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample()), nil
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample()), nil
	case "parentbased_traceidratio", "":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(arg)), nil
	}
	return nil, fmt.Errorf("unknown sampler %q", name)
}

// InitTracing turns tracing on when an endpoint is configured and returns the
// function that flushes and stops it (bounded by the context it is given).
// Without an endpoint it does nothing.
func InitTracing(ctx context.Context, o TracingOptions) (shutdown func(context.Context) error, err error) {
	if o.Endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	u, err := url.Parse(o.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("the tracing endpoint must be an http(s) URL")
	}
	sampler, err := NewSampler(o.Sampler, o.Arg)
	if err != nil {
		return nil, err
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(o.Endpoint)}
	if len(o.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(o.Headers))
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("tracing exporter: %w", err)
	}
	res := resource.NewSchemaless(attribute.String("service.name", o.ServiceName), attribute.String("service.version", o.Version))
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithSampler(sampler), sdktrace.WithResource(res))
	UseTracerProvider(tp)
	return func(ctx context.Context) error {
		active.Store(nil)
		return tp.Shutdown(ctx)
	}, nil
}
