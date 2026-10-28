package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Forwarding a gateway's calls (docs/phase3-gateways.md "Runtime",
// docs/mcp-protocol.md "The portal as a client"): one exchange per call,
// through the same guard, timeout and response bound as discovery, in the
// era the server speaks (era.go).
//
//   - Modern servers get one stateless POST (modern.go). The caller says which
//     elicitation modes the downstream client declared; the portal declares
//     exactly those (per request, nothing remembered) and no other
//     capability. A server's input_required result comes back untouched for
//     the caller to relay.
//   - Legacy servers get an SDK session (initialize) declaring no capability,
//     so they can't ask anything.
//
// Both carry the downstream request's trace context and progress token, and
// report the server's progress notifications while the call runs. Cancelling
// ctx cancels the call (the connection closes on a modern server, the SDK sends
// notifications/cancelled to a legacy one).

// The methods that can be forwarded.
const (
	MethodToolsCall     = "tools/call"
	MethodPromptsGet    = "prompts/get"
	MethodResourcesRead = "resources/read"
)

// Progress is one notifications/progress from a server for the request's
// token.
type Progress struct {
	Progress float64
	// Total is nil when unknown.
	Total   *float64
	Message string
}

// ForwardRequest is one call to forward.
type ForwardRequest struct {
	// Method is one of the Method constants; Name is the tool or prompt name,
	// or the resource URI, on the server.
	Method, Name string
	// Arguments is a tool's arguments object, or a prompt's (strings).
	Arguments json.RawMessage
	// Elicitation is the elicitation capability to declare to a modern
	// server, as the downstream client declared it (nil: declare none).
	Elicitation json.RawMessage
	// InputResponses and RequestState are the retry of an input_required
	// result: the client's responses (a JSON object) and the server's own
	// state. Modern servers only.
	InputResponses json.RawMessage
	RequestState   string
	// ProgressToken (a JSON string or number) asks the server for progress,
	// delivered to OnProgress (which may be called from another goroutine,
	// and not after Forward returns).
	ProgressToken json.RawMessage
	OnProgress    func(Progress)
	Trace         Trace
}

// InputRequired is a modern server's input_required result: its input
// requests (the raw JSON object, empty when none) and requestState, as the
// server sent them. The caller validates them (internal/mcpgw relay.go).
type InputRequired struct {
	Requests     json.RawMessage
	RequestState string
}

// ForwardResult is a server's answer: one of Tool, Prompt and Read for a
// complete result, or Input.
type ForwardResult struct {
	Tool     *mcp.CallToolResult
	Prompt   *mcp.GetPromptResult
	Read     *mcp.ReadResourceResult
	Input    *InputRequired
	Protocol Protocol
	Latency  time.Duration
}

// ErrReplayPrevented means a NoReplay Forward refused a second tools/call
// transport attempt. It is recoverable through errors.Is.
var ErrReplayPrevented = errors.New("upstream: tool call replay prevented")

// forwardTransportGuard is shared by every HTTP client/session of a NoReplay
// Forward, including any SDK reconnect or protocol recovery.
type forwardTransportGuard struct {
	attempted atomic.Bool
	before    func(context.Context, bool) error
}

func (g *forwardTransportGuard) check(ctx context.Context, toolCall bool) error {
	// Consume the attempt before the caller's guard: a refusal must not
	// cause a retry to re-authorize or send the call either.
	if toolCall && !g.attempted.CompareAndSwap(false, true) {
		return ErrReplayPrevented
	}
	if g.before != nil {
		return g.before(ctx, toolCall)
	}
	return nil
}

// Forward makes the call. Failures to get a result are *Error; a tool's own
// failure is a Tool result with IsError set.
func (c *Client) Forward(ctx context.Context, t Target, req ForwardRequest) (*ForwardResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	guard := &forwardTransportGuard{before: t.BeforeTransport}
	if t.NoReplay {
		t.BeforeTransport = guard.check
	}
	proto, cached, err := c.negotiate(ctx, t)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		var res *ForwardResult
		var stale bool
		if proto.Era == EraModern {
			res, stale, err = c.forwardModern(ctx, t, proto, req)
		} else {
			res, stale, err = c.forwardLegacy(ctx, t, proto, req)
		}
		if err != nil && cached && stale && attempt == 0 && !guard.attempted.Load() {
			// The remembered era no longer fits the server: learn it again.
			c.ForgetEra(t)
			if proto, _, err = c.negotiate(ctx, t); err != nil {
				return nil, err
			}
			cached = false
			continue
		}
		if err != nil {
			return nil, err
		}
		res.Protocol, res.Latency = proto, time.Since(start)
		return res, nil
	}
}

func (r ForwardRequest) promptArguments() (map[string]string, error) {
	var args map[string]string
	if a := bytes.TrimSpace(r.Arguments); len(a) > 0 && !bytes.Equal(a, []byte("null")) {
		if err := json.Unmarshal(a, &args); err != nil {
			return nil, &Error{Class: ClassBadRequest, Message: "Prompt arguments must be strings."}
		}
	}
	return args, nil
}

// toolArguments is the arguments object (an empty one when none).
func (r ForwardRequest) toolArguments() json.RawMessage {
	if a := bytes.TrimSpace(r.Arguments); len(a) > 0 && !bytes.Equal(a, []byte("null")) {
		return a
	}
	return json.RawMessage("{}")
}

func (r ForwardRequest) progressMeta(meta map[string]any) {
	if len(r.ProgressToken) > 0 {
		meta["progressToken"] = r.ProgressToken
	}
}

// forwardLegacy calls a legacy server over an SDK session (initialize). It
// declares no capability. stale: the session could not be opened because the
// server is not legacy any more.
func (c *Client) forwardLegacy(ctx context.Context, t Target, proto Protocol, req ForwardRequest) (*ForwardResult, bool, error) {
	if len(bytes.TrimSpace(req.InputResponses)) > 0 || req.RequestState != "" {
		// The retry of a modern server's input request, which this server
		// no longer is: nothing it could continue.
		return nil, false, &Error{Class: ClassBadRequest, Message: "The server no longer speaks the protocol that asked for input; retry the original request."}
	}
	var onProgress func(context.Context, *mcp.ProgressNotificationClientRequest)
	if req.OnProgress != nil && len(req.ProgressToken) > 0 {
		onProgress = func(_ context.Context, n *mcp.ProgressNotificationClientRequest) {
			if n == nil || n.Params == nil || !sameJSONValue(n.Params.ProgressToken, req.ProgressToken) {
				return
			}
			p := Progress{Progress: n.Params.Progress, Message: n.Params.Message}
			if n.Params.Total > 0 {
				total := n.Params.Total
				p.Total = &total
			}
			req.OnProgress(p)
		}
	}
	sess, stale, err := c.connect(ctx, t, proto, onProgress)
	if err != nil {
		return nil, stale, err
	}
	defer sess.close()
	meta := mcp.Meta{}
	if len(req.ProgressToken) > 0 {
		var tok any
		_ = json.Unmarshal(req.ProgressToken, &tok)
		meta["progressToken"] = tok
	}
	traceMeta := map[string]any{}
	req.Trace.addTo(traceMeta)
	for k, v := range traceMeta {
		meta[k] = v
	}
	if len(meta) == 0 {
		meta = nil
	}
	out := &ForwardResult{}
	switch req.Method {
	case MethodToolsCall:
		var arguments any = req.toolArguments()
		res, err := sess.cs.CallTool(ctx, &mcp.CallToolParams{Meta: meta, Name: req.Name, Arguments: arguments})
		if err != nil {
			return nil, false, c.classify(ctx, t, sess.ex, err)
		}
		if res.Content == nil {
			res.Content = []mcp.Content{}
		}
		out.Tool = res
	case MethodPromptsGet:
		args, err := req.promptArguments()
		if err != nil {
			return nil, false, err
		}
		res, err := sess.cs.GetPrompt(ctx, &mcp.GetPromptParams{Meta: meta, Name: req.Name, Arguments: args})
		if err != nil {
			return nil, false, c.classify(ctx, t, sess.ex, err)
		}
		if res.Messages == nil {
			res.Messages = []*mcp.PromptMessage{}
		}
		out.Prompt = res
	case MethodResourcesRead:
		res, err := sess.cs.ReadResource(ctx, &mcp.ReadResourceParams{Meta: meta, URI: req.Name})
		if err != nil {
			return nil, false, c.classify(ctx, t, sess.ex, err)
		}
		if res.Contents == nil {
			res.Contents = []*mcp.ResourceContents{}
		}
		out.Read = res
	default:
		return nil, false, &Error{Class: ClassBadRequest, Message: "Unsupported method."}
	}
	return out, false, nil
}

// forwardModern calls a modern server with one POST.
func (c *Client) forwardModern(ctx context.Context, t Target, proto Protocol, req ForwardRequest) (*ForwardResult, bool, error) {
	version := proto.Version
	if version == "" {
		version = ModernVersion
	}
	params := map[string]any{}
	switch req.Method {
	case MethodToolsCall:
		params["name"], params["arguments"] = req.Name, req.toolArguments()
	case MethodPromptsGet:
		if _, err := req.promptArguments(); err != nil {
			return nil, false, err
		}
		params["name"], params["arguments"] = req.Name, req.toolArguments()
	case MethodResourcesRead:
		params["uri"] = req.Name
	default:
		return nil, false, &Error{Class: ClassBadRequest, Message: "Unsupported method."}
	}
	if len(bytes.TrimSpace(req.InputResponses)) > 0 {
		params["inputResponses"] = req.InputResponses
	}
	if req.RequestState != "" {
		params["requestState"] = req.RequestState
	}
	params["_meta"] = modernMeta(version, req.Elicitation, req.Trace, req.ProgressToken)

	ex := &exchange{}
	hc, done := c.httpClient(t, ex)
	defer done()
	var onNote func(rpcMessage)
	if req.OnProgress != nil && len(req.ProgressToken) > 0 {
		onNote = func(m rpcMessage) {
			if m.Method != "notifications/progress" {
				return
			}
			var p struct {
				Token    json.RawMessage `json:"progressToken"`
				Progress *float64        `json:"progress"`
				Total    *float64        `json:"total"`
				Message  string          `json:"message"`
			}
			if json.Unmarshal(m.Params, &p) != nil || p.Progress == nil || !sameJSONValue(p.Token, req.ProgressToken) {
				return
			}
			req.OnProgress(Progress{Progress: *p.Progress, Total: p.Total, Message: p.Message})
		}
	}
	r, err := c.roundTrip(ctx, hc, t, rpcRequest{Method: req.Method, Version: version, Name: req.Name, Params: params}, onNote)
	if err != nil {
		return nil, false, c.classify(ctx, t, ex, err)
	}
	return c.modernResult(ctx, t, ex, req, r)
}

// modernResult turns a modern server's answer into a result or an error.
// stale: the answer isn't one a modern server gives.
func (c *Client) modernResult(ctx context.Context, t Target, ex *exchange, req ForwardRequest, r reply) (*ForwardResult, bool, error) {
	switch {
	case r.status == http.StatusUnauthorized || r.status == http.StatusForbidden || r.status == http.StatusTooManyRequests || r.status >= 500:
		return nil, false, c.classify(ctx, t, ex, errStatus)
	case r.status >= 400:
		if r.msg != nil && r.msg.Error != nil {
			return nil, r.msg.Error.Code == codeUnsupportedVersion, rpcFailure(t, r.status, r.msg.Error)
		}
		// Not an answer a modern server gives to a call it ran: the server may
		// be of the other era now (the call was refused before it started).
		stale := r.status == http.StatusBadRequest || r.status == http.StatusNotFound || r.status == http.StatusMethodNotAllowed ||
			r.status == http.StatusNotAcceptable || r.status == http.StatusUnsupportedMediaType
		return nil, stale, c.classify(ctx, t, ex, errStatus)
	case r.msg == nil:
		// Nothing says the call didn't run: never repeated for it.
		return nil, false, &Error{Class: ClassBadResponse, Message: "The server's answer was not a JSON-RPC response."}
	case r.msg.Error != nil:
		return nil, false, rpcFailure(t, 0, r.msg.Error)
	}
	var head struct {
		ResultType    string          `json:"resultType"`
		InputRequests json.RawMessage `json:"inputRequests"`
		RequestState  string          `json:"requestState"`
	}
	if err := json.Unmarshal(r.msg.Result, &head); err != nil {
		return nil, false, &Error{Class: ClassBadResponse, Message: "The server's result was not a JSON object."}
	}
	out := &ForwardResult{}
	switch head.ResultType {
	case "input_required":
		requests := bytes.TrimSpace(head.InputRequests)
		if string(requests) == "null" || string(requests) == "{}" {
			requests = nil
		}
		if len(requests) == 0 && head.RequestState == "" {
			return nil, false, &Error{Class: ClassBadResponse, Message: "The server asked for input without saying what."}
		}
		out.Input = &InputRequired{Requests: requests, RequestState: head.RequestState}
		return out, false, nil
	case "", "complete":
	default:
		return nil, false, &Error{Class: ClassBadResponse, Message: "The server's result has an unsupported resultType."}
	}
	var err error
	switch req.Method {
	case MethodToolsCall:
		out.Tool = &mcp.CallToolResult{}
		err = json.Unmarshal(r.msg.Result, out.Tool)
		if err == nil && out.Tool.Content == nil {
			out.Tool.Content = []mcp.Content{}
		}
	case MethodPromptsGet:
		out.Prompt = &mcp.GetPromptResult{}
		err = json.Unmarshal(r.msg.Result, out.Prompt)
		if err == nil && out.Prompt.Messages == nil {
			out.Prompt.Messages = []*mcp.PromptMessage{}
		}
	default:
		out.Read = &mcp.ReadResourceResult{}
		err = json.Unmarshal(r.msg.Result, out.Read)
		if err == nil && out.Read.Contents == nil {
			out.Read.Contents = []*mcp.ResourceContents{}
		}
	}
	if err != nil {
		return nil, false, &Error{Class: ClassBadResponse, Message: "The server's result couldn't be read: " + t.safe(err.Error())}
	}
	return out, false, nil
}

// sameJSONValue compares a decoded progress token with the one sent.
func sameJSONValue(got any, want json.RawMessage) bool {
	var g []byte
	switch v := got.(type) {
	case json.RawMessage:
		g = v
	default:
		var err error
		if g, err = json.Marshal(v); err != nil {
			return false
		}
	}
	norm := func(b []byte) string {
		var v any
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if dec.Decode(&v) != nil {
			return string(b)
		}
		if n, ok := v.(json.Number); ok {
			// 1 and 1.0 are the same token.
			if f, err := n.Float64(); err == nil {
				return strconv.FormatFloat(f, 'g', -1, 64)
			}
		}
		out, _ := json.Marshal(v)
		return string(out)
	}
	return norm(g) == norm(want)
}
