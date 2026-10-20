package observability

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// recorder turns tracing on with an in-memory recorder for one test.
func recorder(t *testing.T, sampler sdktrace.Sampler) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr), sdktrace.WithSampler(sampler))
	restore := UseTracerProvider(tp)
	t.Cleanup(func() { restore(); _ = tp.Shutdown(context.Background()) })
	return sr
}

// With tracing off nothing is created, read or sent: the context comes back
// as it was, spans record nothing, and a request's headers are ignored.
func TestTracingOffDoesNothing(t *testing.T) {
	if Tracing() {
		t.Fatal("tracing is on without a provider")
	}
	ctx := context.Background()
	ctx2, span := Start(ctx, "x", trace.SpanKindServer, AttrGateway.String("g"))
	if ctx2 != ctx || span.IsRecording() || span.SpanContext().IsValid() {
		t.Error("Start created something")
	}
	span.End() // the shared no-op span: ending it ends nothing
	r := httptest.NewRequest("GET", "/v1/teams", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01")
	ctx3, ss := StartHTTP(r)
	if ss != nil || ctx3 != r.Context() || HasRemoteParent(ExtractHeader(ctx, r.Header)) {
		t.Error("a request was traced or its traceparent read")
	}
	ss.End("GET /v1/teams", 200) // nil-safe
	if tp, ts := Outgoing(span); tp != "" || ts != "" {
		t.Errorf("Outgoing = %q %q", tp, ts)
	}
	if id := SampledTraceID(ctx); id != "" {
		t.Error(id)
	}
	if c, slot := WithTraceSlot(ctx); c != ctx || slot != nil || slot.LogContext(ctx) != ctx {
		t.Error("slot")
	}
	if in, _ := InitTracingForTest(); in {
		t.Error("tracing turned on without an endpoint")
	}
}

// InitTracingForTest: InitTracing without an endpoint leaves tracing off.
func InitTracingForTest() (bool, error) {
	stop, err := InitTracing(context.Background(), TracingOptions{})
	if err == nil {
		err = stop(context.Background())
	}
	return Tracing(), err
}

// Only allow-listed attributes reach a span, whatever a call site passes
// (Start, StartAt and Annotate), and long values are cut. Errors are a class,
// never text.
func TestSpanAttributesAreAllowListed(t *testing.T) {
	sr := recorder(t, sdktrace.AlwaysSample())
	ctx, span := Start(context.Background(), "s", trace.SpanKindInternal,
		AttrGateway.String("support"), attribute.String("user.email", "alice@example.com"), attribute.String("tool.arguments", "sentinel"),
		AttrServer.String(strings.Repeat("x", 500)))
	Annotate(span, attribute.String("authorization", "Bearer sentinel"), AttrOutcome.String("ok"))
	_, child := StartAt(ctx, "c", trace.SpanKindClient, time.Now(), attribute.String("http.url", "https://x/?token=sentinel"), AttrEra.String("modern"))
	Fail(child, "upstream_timeout")
	child.End()
	span.End()
	ended := sr.Ended()
	if len(ended) != 2 {
		t.Fatalf("%d spans", len(ended))
	}
	allowed := map[string]bool{}
	for _, k := range AllowedAttributeKeys() {
		allowed[k] = true
	}
	for _, s := range ended {
		for _, a := range s.Attributes() {
			if !allowed[string(a.Key)] || strings.Contains(a.Value.Emit(), "sentinel") || strings.Contains(a.Value.Emit(), "@") {
				t.Errorf("%s carries %s=%s", s.Name(), a.Key, a.Value.Emit())
			}
			if len(a.Value.Emit()) > maxAttrValue {
				t.Errorf("%s: %s is %d long", s.Name(), a.Key, len(a.Value.Emit()))
			}
		}
		if len(s.Events()) != 0 {
			t.Errorf("%s has events", s.Name())
		}
	}
	if st := ended[0].Status(); st.Code != codes.Error || st.Description != "upstream_timeout" {
		t.Errorf("status %+v", st)
	}
	// Adding an attribute is a decision about what telemetry may carry
	// (docs/threat-model.md "Telemetry"): it has to be added here as well.
	want := []string{"http.request.method", "http.response.status_code", "http.route", "mcp.method.name", "omp.capability.kind", "omp.error.class",
		"omp.gateway.slug", "omp.http.status_class", "omp.outcome", "omp.principal.kind", "omp.protocol.era", "omp.provider.slug", "omp.rate_limit",
		"omp.result", "omp.server.slug", "omp.trigger"}
	got := AllowedAttributeKeys()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("allowed attributes changed:\n got %v\nwant %v", got, want)
	}
}

// A request's server span is a child of its traceparent header, is named
// after the route pattern (never the path, which holds IDs), and the
// sentinel in the path, query and headers is nowhere in it.
func TestServerSpan(t *testing.T) {
	sr := recorder(t, sdktrace.ParentBased(sdktrace.NeverSample()))
	const tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
	r := httptest.NewRequest("GET", "/v1/teams/sentinel-team-slug?token=sentinel", nil)
	r.Header.Set("traceparent", tp)
	r.Header.Set("tracestate", "vendor=1")
	r.Header.Set("Authorization", "Bearer sentinel")
	ctx, ss := StartHTTP(r)
	if SampledTraceID(ctx) != "0af7651916cd43dd8448eb211c80319c" {
		t.Fatalf("trace id %q: the sampled parent's decision was not kept", SampledTraceID(ctx))
	}
	out, state := Outgoing(trace.SpanFromContext(ctx))
	if !strings.HasPrefix(out, "00-0af7651916cd43dd8448eb211c80319c-") || strings.HasSuffix(out, "-00f067aa0ba902b7-01") || state != "vendor=1" {
		t.Errorf("outgoing %q %q", out, state)
	}
	ss.End("GET /v1/teams/{team}", 502)
	got := sr.Ended()
	if len(got) != 1 || got[0].Name() != "GET /v1/teams/{team}" || got[0].Parent().SpanID().String() != "00f067aa0ba902b7" || got[0].SpanKind() != trace.SpanKindServer {
		t.Fatalf("%+v", got)
	}
	if got[0].Status().Code != codes.Error {
		t.Error("a 5xx is not an error")
	}
	for _, a := range got[0].Attributes() {
		if strings.Contains(a.Value.Emit(), "sentinel") {
			t.Errorf("%s=%s", a.Key, a.Value.Emit())
		}
	}
	// Probes and /mcp/ requests get no span here; an unsampled parent stays unsampled.
	for _, path := range []string{"/healthz", "/readyz", "/mcp/support"} {
		if _, s := StartHTTP(httptest.NewRequest("GET", path, nil)); s != nil {
			t.Errorf("%s traced by the HTTP middleware", path)
		}
	}
	r = httptest.NewRequest("GET", "/v1/teams", nil)
	r.Header.Set("traceparent", "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-00")
	ctx, _ = StartHTTP(r)
	if SampledTraceID(ctx) != "" {
		t.Error("an unsampled parent was sampled")
	}
	// A malformed traceparent starts a new trace.
	r = httptest.NewRequest("GET", "/v1/teams", nil)
	r.Header.Set("traceparent", "00-00000000000000000000000000000000-00f067aa0ba902b7-01")
	if ctx, _ := StartHTTP(r); HasRemoteParent(ctx) {
		t.Error("an all-zero trace ID was accepted")
	}
}

func TestSamplers(t *testing.T) {
	for _, name := range append([]string{""}, Samplers...) {
		if _, err := NewSampler(name, 0.5); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, err := NewSampler("jaeger_remote", 1); err == nil {
		t.Error("an unknown sampler")
	}
	if _, err := InitTracing(context.Background(), TracingOptions{Endpoint: "ftp://x", Sampler: "always_on"}); err == nil {
		t.Error("a non-http endpoint")
	}
	if Tracing() {
		t.Error("a failed start left tracing on")
	}
}

// Logs of a sampled span carry trace_id and span_id; others do not.
func TestTraceLogHandler(t *testing.T) {
	recorder(t, sdktrace.AlwaysSample())
	var buf bytes.Buffer
	log := slog.New(NewTraceLogHandler(slog.NewJSONHandler(&buf, nil))).With("mode", "serve").WithGroup("g")
	ctx, span := Start(context.Background(), "s", trace.SpanKindServer)
	log.InfoContext(ctx, "traced")
	log.InfoContext(context.Background(), "plain")
	span.End()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"trace_id":"`+span.SpanContext().TraceID().String()+`"`) || !strings.Contains(lines[0], span.SpanContext().SpanID().String()) ||
		!strings.Contains(lines[0], `"mode":"serve"`) || strings.Contains(lines[1], "trace_id") {
		t.Errorf("%s", buf.String())
	}
}

// The slot gives the access log of an /mcp/ request the context of the span
// the gateway made.
func TestTraceSlot(t *testing.T) {
	recorder(t, sdktrace.AlwaysSample())
	ctx, slot := WithTraceSlot(context.Background())
	if slot.LogContext(ctx) != ctx {
		t.Error("an empty slot changed the context")
	}
	inner, span := Start(ctx, "s", trace.SpanKindServer)
	RecordInSlot(inner)
	if SampledTraceID(slot.LogContext(ctx)) != span.SpanContext().TraceID().String() {
		t.Error("the slot lost the span")
	}
}

// InitTracing exports finished spans over OTLP/HTTP to the configured URL,
// with the configured headers, and flushes them at shutdown. The collector
// here is an httptest server; what it receives is protobuf.
func TestInitTracingExportsOTLP(t *testing.T) {
	type got struct {
		path, auth, ctype string
		body              []byte
	}
	received := make(chan got, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- got{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b}
	}))
	defer srv.Close()
	stop, err := InitTracing(context.Background(), TracingOptions{Endpoint: srv.URL + "/v1/traces", Headers: map[string]string{"Authorization": "Bearer collector-token"},
		ServiceName: "omp-test", Version: "v9", Sampler: "always_on"})
	if err != nil {
		t.Fatal(err)
	}
	if !Tracing() {
		t.Fatal("tracing is off after InitTracing")
	}
	_, span := Start(context.Background(), "MCP tools/call", trace.SpanKindServer, AttrGateway.String("support"), attribute.String("user.email", "alice@example.com"))
	span.End()
	if err := stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if Tracing() {
		t.Error("tracing is still on after shutdown")
	}
	select {
	case g := <-received:
		if g.path != "/v1/traces" || g.auth != "Bearer collector-token" || g.ctype != "application/x-protobuf" {
			t.Errorf("%s %q %q", g.path, g.auth, g.ctype)
		}
		for _, want := range []string{"MCP tools/call", "omp.gateway.slug", "support", "omp-test"} {
			if !bytes.Contains(g.body, []byte(want)) {
				t.Errorf("the export lacks %q", want)
			}
		}
		if bytes.Contains(g.body, []byte("alice@example.com")) || bytes.Contains(g.body, []byte("collector-token")) {
			t.Error("the export carries a dropped attribute or the export header")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was exported")
	}
}
