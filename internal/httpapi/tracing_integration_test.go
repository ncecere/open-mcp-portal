package httpapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
)

// Tracing of the gateway call path and the management API (decision 71):
// one trace with the spans of the call, the server receiving the portal's
// span as its parent, trace IDs in logs and call records, the client's
// context passed through unchanged when tracing is off or the trace is not
// sampled, and nothing personal or secret in anything exported.

const (
	traceTP   = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
	traceTS   = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"
	traceBG   = "userId=alice,serverNode=DF%2028"
	traceID   = "0af7651916cd43dd8448eb211c80319c"
	traceHdrP = "00-4bf92f3577b34da6a3ce929d0e0e4736-b9c7c989f97918e1-01"
	traceHdrT = "4bf92f3577b34da6a3ce929d0e0e4736"
)

// tracingOn turns tracing on for one test, sampling like the default (a
// sampled parent is followed; without a parent, everything is sampled here).
func tracingOn(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())))
	restore := observability.UseTracerProvider(tp)
	t.Cleanup(func() { restore(); _ = tp.Shutdown(context.Background()) })
	return sr
}

// newTracedEnv is newRelayEnv with a log the test can read and a trace link
// template.
func newTracedEnv(t *testing.T, logs *syncBuffer) *relayEnv {
	t.Helper()
	log := slog.New(observability.NewTraceLogHandler(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	e := &relayEnv{gwEnv: newGwEnvHook(t, log, func(d *httpapi.Deps) {
		d.Config.Tracing.LinkTemplate = "https://traces.example.com/trace/{trace_id}"
	})}
	e.fake.SetJWKS(e.app.URL+"/.well-known/jwks.json", e.fake.URL())
	e.refresh(e.owner, e.server)
	e.gw = e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.path = toolsTeam + "/gateways/" + e.gw.Id.String()
	e.mustSetCaps(e.owner, e.path, sel(e.capID(e.owner, e.server, "tool", "echo"), e.capID(e.owner, e.server, "tool", "whoami")))
	e.key = newKey(t, e.member, "laptop").Secret
	return e
}

// echoCall makes a tools/call of echo with a sentinel argument, in an era,
// with the given _meta entries and HTTP headers.
func (e *relayEnv) echoCall(modern bool, text string, meta map[string]any, headers map[string]string) {
	e.t.Helper()
	body, h := toolRequest(modern, "status__echo", map[string]any{"text": text}, meta)
	for k, v := range headers {
		h = mergeHeader(h, k, v)
	}
	code, _, out := rawMCP(e.t, e.app, "POST", "support", e.key, body, h)
	if code != 200 || out["error"] != nil {
		e.t.Fatalf("call: %d %v", code, out)
	}
}

func mergeHeader(h map[string]string, k, v string) map[string]string {
	if h == nil {
		h = map[string]string{}
	}
	h[k] = v
	return h
}

// lastEchoMeta is the _meta the server received with its latest echo call.
func (e *relayEnv) lastEchoMeta() map[string]any {
	e.t.Helper()
	calls := e.fake.ToolCalls()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Tool == "echo" {
			return calls[i].Meta
		}
	}
	e.t.Fatal("no echo call")
	return nil
}

func spansOf(sr *tracetest.SpanRecorder, traceID string) map[string]sdktrace.ReadOnlySpan {
	out := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range sr.Ended() {
		if s.SpanContext().TraceID().String() == traceID {
			out[s.Name()] = s
		}
	}
	return out
}

func TestTracingCallTrace(t *testing.T) {
	logs := &syncBuffer{}
	sr := tracingOn(t)
	e := newTracedEnv(t, logs)
	const sentinel = "SENTINEL-ARGUMENT-7f3a91"

	for _, modern := range []bool{true, false} {
		// The client's trace context in _meta: the portal is a hop of that trace.
		e.echoCall(modern, sentinel, map[string]any{"traceparent": traceTP, "tracestate": traceTS, "baggage": traceBG}, nil)
		e.lastRecord("ok ")
		spans := spansOf(sr, traceID)
		server := spans["MCP tools/call"]
		if server == nil {
			t.Fatalf("modern=%v: no server span; have %v", modern, spans)
		}
		if server.SpanKind() != trace.SpanKindServer || server.Parent().SpanID().String() != "00f067aa0ba902b7" || !server.Parent().IsRemote() {
			t.Errorf("modern=%v: server span %v parent %v", modern, server.SpanKind(), server.Parent())
		}
		for _, name := range []string{"mcp.authenticate", "mcp.resolve_gateway", "mcp.rate_limit", "mcp.authorize", "mcp.upstream.forward"} {
			child := spans[name]
			if child == nil {
				t.Errorf("modern=%v: no %s span", modern, name)
				continue
			}
			if child.Parent().SpanID() != server.SpanContext().SpanID() {
				t.Errorf("modern=%v: %s is not a child of the server span", modern, name)
			}
		}
		up := spans["mcp.upstream.forward"]
		if up != nil && up.SpanKind() != trace.SpanKindClient {
			t.Errorf("upstream span kind %v", up.SpanKind())
		}
		// The server's parent is the portal's span; tracestate and baggage are the client's, as sent.
		meta := e.lastEchoMeta()
		if up != nil {
			want := "00-" + traceID + "-" + up.SpanContext().SpanID().String() + "-01"
			if meta["traceparent"] != want || meta["tracestate"] != traceTS || meta["baggage"] != traceBG {
				t.Errorf("modern=%v: the server received %v, want traceparent %s", modern, meta, want)
			}
		}
		// The call record and the logs carry the trace ID.
		if got := e.scalar(`SELECT coalesce((SELECT trace_id FROM mcp_calls ORDER BY id DESC LIMIT 1), '')`); got != traceID {
			t.Errorf("modern=%v: recorded trace_id = %q", modern, got)
		}
	}

	// An HTTP traceparent header wins over _meta.
	e.echoCall(true, sentinel, map[string]any{"traceparent": traceTP}, map[string]string{"traceparent": traceHdrP})
	if s := spansOf(sr, traceHdrT)["MCP tools/call"]; s == nil || s.Parent().SpanID().String() != "b9c7c989f97918e1" {
		t.Errorf("the header's trace parent was not used: %v", s)
	}
	if meta := e.lastEchoMeta(); !strings.HasPrefix(meta["traceparent"].(string), "00-"+traceHdrT+"-") {
		t.Errorf("the server received %v", meta["traceparent"])
	}

	// No trace context: the portal starts a trace, and the server is told about it.
	e.echoCall(true, sentinel, nil, nil)
	meta := e.lastEchoMeta()
	tp, _ := meta["traceparent"].(string)
	if len(tp) != 55 || !strings.HasSuffix(tp, "-01") || meta["tracestate"] != nil || meta["baggage"] != nil {
		t.Fatalf("a portal-started trace: %v", meta)
	}
	own := tp[3:35]
	if s := spansOf(sr, own)["MCP tools/call"]; s == nil || s.Parent().IsValid() {
		t.Errorf("a new trace's server span: %v", s)
	}
	e.lastRecord("ok ")
	if got := e.scalar(`SELECT trace_id FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != own {
		t.Errorf("recorded %q, want %q", got, own)
	}

	// An unsampled client trace stays unsampled: nothing is recorded or
	// exported and the client's own context passes through exactly.
	const unsampled = "00-11111111111111111111111111111111-2222222222222222-00"
	e.echoCall(true, sentinel, map[string]any{"traceparent": unsampled, "baggage": traceBG}, nil)
	if meta := e.lastEchoMeta(); meta["traceparent"] != unsampled || meta["baggage"] != traceBG {
		t.Errorf("an unsampled trace: the server received %v", meta)
	}
	if len(spansOf(sr, "11111111111111111111111111111111")) != 0 {
		t.Error("spans of an unsampled trace were exported")
	}
	e.lastRecord("ok ")
	if got := e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE trace_id IS NULL AND method = 'tools/call'`); got != "1" {
		t.Errorf("%s calls without a trace ID, want the unsampled one only", got)
	}

	// A failing request is a span with its status; the bad credential is nowhere.
	const badKey = "omp_SENTINEL-BAD-KEY-0000"
	if code, _, _ := rawMCP(t, e.app, "POST", "support", badKey, rpc(1, "tools/list", nil), map[string]string{"traceparent": traceHdrP}); code != 401 {
		t.Fatalf("bad key: %d", code)
	}
	var refused sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		if s.SpanContext().TraceID().String() == traceHdrT && s.Name() == "MCP request" {
			refused = s
		}
	}
	if refused == nil {
		t.Fatal("no span for a refused request")
	}
	if !hasAttr(refused, "http.response.status_code", "401") {
		t.Errorf("status not recorded: %v", refused.Attributes())
	}

	// The access log and the call's debug log name the trace; the record's link too.
	var access, call bool
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["trace_id"] != traceID {
			continue
		}
		access = access || (rec["msg"] == "http request" && rec["route"] == "POST /mcp/{slug}" && rec["span_id"] != nil && rec["request_id"] != nil)
		call = call || (rec["msg"] == "mcp call" && rec["request_id"] != nil)
	}
	if !access || !call {
		t.Errorf("trace_id in the access log: %v, in the call log: %v", access, call)
	}
	var c apitypes.McpCall
	var id string
	id = e.scalar(`SELECT id::text FROM mcp_calls WHERE trace_id = $1 ORDER BY id DESC LIMIT 1`, traceID)
	if code := e.admin.get("/v1/admin/calls/"+id, &c); code != 200 {
		t.Fatalf("call detail = %d", code)
	}
	if c.TraceId == nil || *c.TraceId != traceID || c.TraceUrl == nil || *c.TraceUrl != "https://traces.example.com/trace/"+traceID {
		t.Errorf("call detail: traceId %v traceUrl %v", c.TraceId, c.TraceUrl)
	}
	var plain apitypes.McpCall
	if code := e.admin.get("/v1/admin/calls/"+e.scalar(`SELECT id::text FROM mcp_calls WHERE trace_id IS NULL ORDER BY id DESC LIMIT 1`), &plain); code != 200 || plain.TraceId != nil || plain.TraceUrl != nil {
		t.Errorf("call without a trace: %d %v %v", code, plain.TraceId, plain.TraceUrl)
	}

	// Registry probes (the server was refreshed while tracing was on) and API
	// requests are spans, named by route pattern.
	var probe, api bool
	for _, s := range sr.Ended() {
		probe = probe || (s.Name() == "registry.probe" && hasAttr(s, "omp.server.slug", "status") && hasAttr(s, "omp.trigger", "manual") && hasAttr(s, "omp.result", "healthy"))
		api = api || (s.Name() == "POST /v1/teams/{team}/mcp-servers/{serverId}/refresh" && s.SpanKind() == trace.SpanKindServer && hasAttr(s, "http.response.status_code", "200"))
	}
	if !probe || !api {
		t.Errorf("registry probe span: %v, refresh request span: %v", probe, api)
	}

	assertNothingSensitive(t, sr, e, sentinel, badKey)
}

// Nothing a span carries (its name, attributes, status, events, links or
// resource) holds a person, a credential, an argument or a result.
func assertNothingSensitive(t *testing.T, sr *tracetest.SpanRecorder, e *relayEnv, sentinels ...string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, k := range observability.AllowedAttributeKeys() {
		allowed[k] = true
	}
	forbidden := append(sentinels, e.key, "blair@localhost", "user@localhost", "alex@localhost", "casey@localhost", "admin@localhost", "laptop",
		"status__echo", traceBG, "Bearer", "Authorization", "127.0.0.1", "localhost")
	spans := sr.Ended()
	if len(spans) < 10 {
		t.Fatalf("only %d spans to check", len(spans))
	}
	for _, s := range spans {
		texts := []string{s.Name(), s.Status().Description}
		for _, a := range s.Attributes() {
			if !allowed[string(a.Key)] {
				t.Errorf("%s carries the attribute %s", s.Name(), a.Key)
			}
			texts = append(texts, a.Value.Emit())
		}
		if len(s.Events()) != 0 || len(s.Links()) != 0 {
			t.Errorf("%s has events or links", s.Name())
		}
		for _, a := range s.Resource().Attributes() {
			texts = append(texts, a.Value.Emit())
		}
		for _, text := range texts {
			for _, bad := range forbidden {
				if strings.Contains(text, bad) {
					t.Errorf("span %q: %q contains %q", s.Name(), text, bad)
				}
			}
		}
		if s.Status().Code == codes.Error && strings.ContainsAny(s.Status().Description, " :/") {
			t.Errorf("span %q: status description %q is not a class", s.Name(), s.Status().Description)
		}
	}
}

func hasAttr(s sdktrace.ReadOnlySpan, key, value string) bool {
	for _, a := range s.Attributes() {
		if string(a.Key) == key && a.Value.Emit() == value {
			return true
		}
	}
	return false
}

// With tracing off (the default) nothing is created and the client's trace
// context passes through exactly as it always did: no portal span, no trace
// ID in the record, none in the logs.
func TestTracingOffPassthrough(t *testing.T) {
	if observability.Tracing() {
		t.Fatal("tracing is on")
	}
	logs := &syncBuffer{}
	e := newTracedEnv(t, logs)
	e.echoCall(true, "x", map[string]any{"traceparent": traceTP, "tracestate": traceTS, "baggage": traceBG}, map[string]string{"traceparent": traceHdrP})
	meta := e.lastEchoMeta()
	if meta["traceparent"] != traceTP || meta["tracestate"] != traceTS || meta["baggage"] != traceBG {
		t.Errorf("passthrough changed: %v", meta)
	}
	e.echoCall(false, "x", nil, nil)
	if meta := e.lastEchoMeta(); meta["traceparent"] != nil {
		t.Errorf("a trace context was made up: %v", meta)
	}
	e.lastRecord("ok ")
	if got := e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE trace_id IS NOT NULL`); got != "0" {
		t.Errorf("%s call records have a trace ID", got)
	}
	if strings.Contains(logs.String(), "trace_id") || strings.Contains(logs.String(), "span_id") {
		t.Error("logs carry trace IDs with tracing off")
	}
	var c apitypes.McpCall
	if code := e.admin.get("/v1/admin/calls/"+e.scalar(`SELECT id::text FROM mcp_calls ORDER BY id DESC LIMIT 1`), &c); code != 200 || c.TraceId != nil || c.TraceUrl != nil {
		t.Errorf("%d %v %v", code, c.TraceId, c.TraceUrl)
	}
}

// A slow or failing server is a failed span with its class, not its message.
func TestTracingUpstreamFailure(t *testing.T) {
	sr := tracingOn(t)
	logs := &syncBuffer{}
	e := newTracedEnv(t, logs)
	e.fake.Close()
	body, h := toolRequest(true, "status__echo", map[string]any{"text": "x"}, map[string]any{"traceparent": traceTP})
	code, _, _ := rawMCP(t, e.app, "POST", "support", e.key, body, h)
	if code == 0 {
		t.Fatal("no answer")
	}
	deadline := time.Now().Add(5 * time.Second)
	var up sdktrace.ReadOnlySpan
	for up == nil && time.Now().Before(deadline) {
		up = spansOf(sr, traceID)["mcp.upstream.forward"]
		time.Sleep(10 * time.Millisecond)
	}
	if up == nil {
		t.Fatal("no upstream span")
	}
	if up.Status().Code != codes.Error || strings.ContainsAny(up.Status().Description, " /:") || !hasAttr(up, "omp.server.slug", "status") {
		t.Errorf("status %+v attributes %v", up.Status(), up.Attributes())
	}
	var class bool
	for _, a := range up.Attributes() {
		class = class || a.Key == "omp.error.class"
	}
	if !class {
		t.Error("no error class")
	}
	assertNothingSensitive(t, sr, e, "x-never")
}

// A streamed answer (SSE with progress events) still streams with the
// response writer wrapped for tracing, and its span ends with the stream.
func TestTracingStreamedCall(t *testing.T) {
	sr := tracingOn(t)
	e := newRelayEnv(t, nil)
	body, headers := toolRequest(true, "status__progress", map[string]any{"count": 3, "delay_ms": 0}, map[string]any{"progressToken": "p1", "traceparent": traceTP})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %q", ct)
	}
	events := readSSE(res.Body)
	if len(events) != 4 || !strings.Contains(events[len(events)-1].data, `"result"`) {
		t.Fatalf("%d events", len(events))
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && spansOf(sr, traceID)["MCP tools/call"] == nil {
		time.Sleep(10 * time.Millisecond)
	}
	s := spansOf(sr, traceID)["MCP tools/call"]
	if s == nil || !hasAttr(s, "http.response.status_code", "200") || !hasAttr(s, "omp.outcome", "ok") || spansOf(sr, traceID)["mcp.upstream.forward"] == nil {
		t.Errorf("the streamed call's spans: %v", spansOf(sr, traceID))
	}
}
