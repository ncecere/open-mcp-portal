package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type sseEvent struct {
	comment bool
	event   string
	data    string
	at      time.Time
}

// readSSE reads events until the stream ends.
func readSSE(r io.Reader) []sseEvent {
	var out []sseEvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	cur := sseEvent{}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.data != "" || cur.event != "" {
				cur.at = time.Now()
				out = append(out, cur)
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, ":"):
			out = append(out, sseEvent{comment: true, data: line, at: time.Now()})
		case strings.HasPrefix(line, "event: "):
			cur.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data += strings.TrimPrefix(line, "data: ")
		}
	}
	return out
}

func (e *relayEnv) post(ctx context.Context, body any, headers map[string]string) *http.Response {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", e.app.URL+"/mcp/support", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+e.key)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// toolRequest is a tools/call as a modern or legacy client sends it, with a
// progress token.
func toolRequest(modern bool, name string, args map[string]any, meta map[string]any) (body map[string]any, headers map[string]string) {
	p := argsCall(name, args, nil)
	if modern {
		p = modernMeta(p, nil, meta)
		return rpc(1, "tools/call", p), modernHeaders("tools/call", p, nil)
	}
	p["_meta"] = meta
	return rpc(1, "tools/call", p), nil
}

func TestStreamProgress(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, upstreamEra := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		f := testutil.NewFakeMCP(t)
		f.SetProtocol(upstreamEra)
		f.EnableStreamTools()
		sv := e.createServer(e.owner, "tools", "s-"+string(upstreamEra), f.URL(), nil)
		g := e.createGateway(e.owner, toolsTeam+"/gateways", "s-"+string(upstreamEra))
		e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+g.Id.String(), sel(e.capID(e.owner, sv, "tool", "progress")))
		for _, downstreamModern := range []bool{true, false} {
			t.Run(fmt.Sprintf("upstream %s, downstream modern=%v", upstreamEra, downstreamModern), func(t *testing.T) {
				for _, token := range []any{"tok-1", 42} {
					body, headers := toolRequest(downstreamModern, "s-"+string(upstreamEra)+"__progress", map[string]any{"count": 3, "delay_ms": 20},
						map[string]any{"progressToken": token})
					b, _ := json.Marshal(body)
					req, _ := http.NewRequest("POST", e.app.URL+"/mcp/s-"+string(upstreamEra), bytes.NewReader(b))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept", "application/json, text/event-stream")
					req.Header.Set("Authorization", "Bearer "+e.key)
					for k, v := range headers {
						req.Header.Set(k, v)
					}
					res, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" || res.Header.Get("X-Accel-Buffering") != "no" {
						t.Fatalf("response = %d %v", res.StatusCode, res.Header)
					}
					events := readSSE(res.Body)
					res.Body.Close()
					if len(events) != 4 {
						t.Fatalf("%d events: %+v", len(events), events)
					}
					for i, ev := range events[:3] {
						var n struct {
							Method string
							Params struct {
								ProgressToken   any
								Progress, Total float64
								Message         string
							}
						}
						if err := json.Unmarshal([]byte(ev.data), &n); err != nil || ev.event != "message" || n.Method != "notifications/progress" ||
							fmt.Sprint(n.Params.ProgressToken) != fmt.Sprint(token) || n.Params.Progress != float64(i+1) || n.Params.Total != 3 ||
							n.Params.Message != fmt.Sprintf("step %d", i+1) {
							t.Fatalf("event %d = %+v (%v)", i, ev, err)
						}
					}
					var final map[string]any
					if err := json.Unmarshal([]byte(events[3].data), &final); err != nil || final["id"] != float64(1) || textOf(t, final) != "progress: 3 steps" {
						t.Fatalf("final = %s (%v)", events[3].data, err)
					}
					// Events arrive while the call runs, not all at the end.
					if events[2].at.Sub(events[0].at) < 20*time.Millisecond {
						t.Errorf("progress events %v apart: they were buffered", events[2].at.Sub(events[0].at))
					}
				}
			})
		}
	}
	// One record per call: the sizes include the stream.
	var n, minBytes int
	if _, err := fmt.Sscan(e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE exposed_name LIKE '%progress'`), &n); err != nil || n != 8 {
		t.Errorf("%d records for 8 streamed calls (%v)", n, err)
	}
	// Three progress events and the response: well over the response alone.
	if _, err := fmt.Sscan(e.scalar(`SELECT coalesce(min(response_bytes), 0)::text FROM mcp_calls WHERE exposed_name LIKE '%progress'`), &minBytes); err != nil || minBytes < 500 {
		t.Errorf("response_bytes = %d: the stream should count (%v)", minBytes, err)
	}
}

func TestStreamOnlyWhenAskedFor(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, tc := range []struct {
		name    string
		modern  bool
		accept  string
		meta    map[string]any
		wantSSE bool
	}{
		{"modern with token and SSE", true, "application/json, text/event-stream", map[string]any{"progressToken": "p"}, true},
		{"legacy with token and SSE", false, "application/json, text/event-stream", map[string]any{"progressToken": "p"}, true},
		{"no token", true, "application/json, text/event-stream", nil, false},
		{"JSON only", true, "application/json", map[string]any{"progressToken": "p"}, false},
		{"token of a bad type", true, "application/json, text/event-stream", map[string]any{"progressToken": true}, false},
		{"empty token", true, "application/json, text/event-stream", map[string]any{"progressToken": ""}, false},
		{"float token", true, "application/json, text/event-stream", map[string]any{"progressToken": 1.5}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, headers := toolRequest(tc.modern, "status__echo", map[string]any{"text": "plain"}, tc.meta)
			headers2 := map[string]string{"Accept": tc.accept}
			for k, v := range headers {
				headers2[k] = v
			}
			res := e.post(context.Background(), body, headers2)
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			sse := strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream")
			if sse != tc.wantSSE {
				t.Fatalf("content type %q for %s", res.Header.Get("Content-Type"), tc.name)
			}
			if res.StatusCode != 200 {
				t.Fatalf("status %d: %s", res.StatusCode, raw)
			}
			if !sse {
				var out map[string]any
				if err := json.Unmarshal(raw, &out); err != nil || textOf(t, out) != "plain" {
					t.Fatalf("answer = %s", raw)
				}
				return
			}
			events := readSSE(bytes.NewReader(raw))
			if len(events) != 1 {
				t.Fatalf("events = %+v", events)
			}
		})
	}
	// Refusals before the call reaches the server are the JSON answers they
	// always were, even with a token.
	body, headers := toolRequest(true, "status__nope", nil, map[string]any{"progressToken": "p"})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(raw), "Unknown tool") {
		t.Fatalf("an unknown tool = %s %s", res.Header.Get("Content-Type"), raw)
	}
}

func TestStreamKeepAlive(t *testing.T) {
	e := newRelayEnv(t, func(d *httpapi.Deps) {
		d.MCP.(interface{ SetStreamKeepAlive(time.Duration) }).SetStreamKeepAlive(40 * time.Millisecond)
	})
	body, headers := toolRequest(true, "status__progress", map[string]any{"count": 1, "delay_ms": 400}, map[string]any{"progressToken": "k"})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	events := readSSE(res.Body)
	comments := 0
	for _, ev := range events {
		if ev.comment {
			comments++
		}
	}
	if comments < 3 || events[len(events)-1].comment || len(events) != comments+2 {
		t.Fatalf("%d comments in %+v", comments, events)
	}
}

// Closing the downstream connection cancels the call to the server.
func TestStreamCancelsUpstream(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, p := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		t.Run(string(p), func(t *testing.T) {
			f := testutil.NewFakeMCP(t)
			f.SetProtocol(p)
			f.EnableStreamTools()
			slug := "c-" + string(p)
			sv := e.createServer(e.owner, "tools", slug, f.URL(), nil)
			g := e.createGateway(e.owner, toolsTeam+"/gateways", slug)
			e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+g.Id.String(), sel(e.capID(e.owner, sv, "tool", "block")))

			ctx, cancel := context.WithCancel(context.Background())
			body, headers := toolRequest(true, slug+"__block", nil, map[string]any{"progressToken": "b"})
			b, _ := json.Marshal(body)
			req, _ := http.NewRequestWithContext(ctx, "POST", e.app.URL+"/mcp/"+slug, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Authorization", "Bearer "+e.key)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.Header.Get("Content-Type") != "text/event-stream" {
				t.Fatalf("content type = %q", res.Header.Get("Content-Type"))
			}
			f.WaitBlocked(t)
			if f.Cancellations() != 0 {
				t.Fatal("cancelled before the client left")
			}
			cancel()
			res.Body.Close()
			deadline := time.Now().Add(10 * time.Second)
			for f.Cancellations() == 0 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if f.Cancellations() != 1 {
				t.Fatalf("the server saw %d cancellations after the client closed the stream", f.Cancellations())
			}
			// Recorded once, as a call that ended because the client left.
			e.lastRecord("upstream_error client_cancelled", slug+"__block")
			if n := e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE exposed_name = $1`, slug+"__block"); n != "1" {
				t.Errorf("%s records", n)
			}
		})
	}
}

// At most 64 progress events are relayed per call; the call still completes.
func TestStreamProgressCap(t *testing.T) {
	e := newRelayEnv(t, nil)
	body, headers := toolRequest(true, "status__progress", map[string]any{"count": 100, "delay_ms": 0}, map[string]any{"progressToken": "many"})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	events := readSSE(res.Body)
	progress := 0
	for _, ev := range events {
		if strings.Contains(ev.data, "notifications/progress") {
			progress++
		}
	}
	if progress != 64 || len(events) != 65 || !strings.Contains(events[len(events)-1].data, `"result"`) {
		t.Fatalf("%d progress events, %d in all", progress, len(events))
	}
}

func TestTraceContextPassthrough(t *testing.T) {
	e := newRelayEnv(t, nil)
	const tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
	const ts = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"
	const bg = "userId=alice,serverNode=DF%2028,isProduction=false"
	lastEcho := func() testutil.ToolCall {
		calls := e.fake.ToolCalls()
		for i := len(calls) - 1; i >= 0; i-- {
			if calls[i].Tool == "echo" {
				return calls[i]
			}
		}
		t.Fatal("no echo call")
		return testutil.ToolCall{}
	}
	trace := func(c testutil.ToolCall) [3]any {
		return [3]any{c.Meta["traceparent"], c.Meta["tracestate"], c.Meta["baggage"]}
	}
	for _, upstreamEra := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		e.fake.SetProtocol(upstreamEra)
		e.refresh(e.owner, e.server)
		for _, modern := range []bool{true, false} {
			name := fmt.Sprintf("upstream %s downstream modern=%v", upstreamEra, modern)
			send := func(meta map[string]any) testutil.ToolCall {
				t.Helper()
				body, headers := toolRequest(modern, "status__echo", map[string]any{"text": "x"}, meta)
				code, _, out := rawMCP(t, e.app, "POST", "support", e.key, body, headers)
				if code != 200 || out["error"] != nil {
					t.Fatalf("%s: %d %v", name, code, out)
				}
				return lastEcho()
			}
			// Valid values reach the server's _meta as they were.
			if got := trace(send(map[string]any{"traceparent": tp, "tracestate": ts, "baggage": bg})); got != [3]any{tp, ts, bg} {
				t.Errorf("%s: trace context = %v", name, got)
			}
			// None sent: none passed on.
			if got := trace(send(nil)); got != [3]any{nil, nil, nil} {
				t.Errorf("%s: trace context without any = %v", name, got)
			}
			// Malformed or oversized values are dropped, the valid ones stay.
			for what, meta := range map[string]map[string]any{
				"bad traceparent":        {"traceparent": "nonsense", "tracestate": ts, "baggage": bg},
				"all-zero trace id":      {"traceparent": "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
				"uppercase traceparent":  {"traceparent": strings.ToUpper(tp)},
				"traceparent not string": {"traceparent": 7},
			} {
				got := trace(send(meta))
				if got[0] != nil || got[1] != nil {
					t.Errorf("%s: %s: traceparent/tracestate = %v", name, what, got)
				}
			}
			if got := trace(send(map[string]any{"traceparent": tp, "tracestate": "BAD KEY=x", "baggage": strings.Repeat("a=b,", 600)})); got != [3]any{tp, nil, nil} {
				t.Errorf("%s: invalid tracestate and oversized baggage = %v", name, got)
			}
		}
	}
	// A client's other _meta (and its credentials) are not passed on.
	body, headers := toolRequest(true, "status__echo", map[string]any{"text": "x"}, map[string]any{"x-secret": "nope", "traceparent": tp})
	if code, _, _ := rawMCP(t, e.app, "POST", "support", e.key, body, headers); code != 200 {
		t.Fatal(code)
	}
	if _, ok := lastEcho().Meta["x-secret"]; ok {
		t.Error("an unknown _meta entry was passed on")
	}
}
