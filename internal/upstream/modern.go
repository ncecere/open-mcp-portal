package upstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
)

// The modern era's wire, spoken directly (MCP 2026-07-28, streamable HTTP):
// one POST per request with the protocol headers and per-request _meta, the
// answer a JSON object or an SSE stream scoped to the request. The Go SDK
// session speaks it for discovery, but forwarded calls need what it can't
// express: an input_required result relayed untouched, the downstream
// client's own declared capabilities, progress relayed while the call runs, and
// no handshake per call. Everything still goes through the guarded
// http.Client of httpClient (address rule, no redirects, body bound).

const (
	metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo      = "io.modelcontextprotocol/clientInfo"
	metaClientCaps      = "io.modelcontextprotocol/clientCapabilities"
)

// rpcMessage is one JSON-RPC message from a server.
type rpcMessage struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// rpcRequest is a modern request to send.
type rpcRequest struct {
	Method  string
	Version string
	// Name is params.name or params.uri (the Mcp-Name header; "" for none).
	Name   string
	Params map[string]any
}

// reply is what a server answered.
type reply struct {
	status int
	// msg is the JSON-RPC response (nil when the body was not one).
	msg *rpcMessage
}

// modernMeta is a request's _meta: the protocol fields, the declared
// capabilities (only elicitation, as wide as the caller says), trace context
// and the progress token.
func modernMeta(version string, elicitation json.RawMessage, trace Trace, progressToken json.RawMessage) map[string]any {
	return modernMetaExt(version, elicitation, trace, progressToken, false)
}

// modernMetaExt is modernMeta that can also declare the Tasks extension (an
// empty object under clientCapabilities.extensions) for this request only.
func modernMetaExt(version string, elicitation json.RawMessage, trace Trace, progressToken json.RawMessage, tasks bool) map[string]any {
	caps := map[string]any{}
	if len(elicitation) > 0 {
		caps["elicitation"] = elicitation
	}
	if tasks {
		caps["extensions"] = map[string]any{TasksExtension: map[string]any{}}
	}
	m := map[string]any{
		metaProtocolVersion: version,
		metaClientInfo:      map[string]any{"name": "open-mcp-portal", "title": "Open MCP Portal", "version": buildinfo.Version},
		metaClientCaps:      caps,
	}
	trace.addTo(m)
	if len(progressToken) > 0 {
		m["progressToken"] = progressToken
	}
	return m
}

// mcpNameHeader encodes params.name or params.uri as the Mcp-Name header
// value (base64 sentinel when it can't be plain ASCII).
func mcpNameHeader(name string) string {
	if needsBase64(name) {
		return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(name)) + "?="
	}
	return name
}

// roundTrip sends one modern request and reads the answer. Notifications
// that arrive on an SSE stream go to onNote. An error is a transport failure
// (classify it); a non-2xx answer is a reply with its status.
func (c *Client) roundTrip(ctx context.Context, hc *http.Client, t Target, r rpcRequest, onNote func(rpcMessage)) (reply, error) {
	// Every request has its own id, so a retry of an input_required call is a
	// different request (MRTR: "the JSON-RPC id MUST be different").
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.nextID.Add(1), "method": r.Method, "params": r.Params})
	if err != nil {
		return reply{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", r.Version)
	req.Header.Set("Mcp-Method", r.Method)
	if r.Name != "" {
		req.Header.Set("Mcp-Name", mcpNameHeader(r.Name))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	out := reply{status: resp.StatusCode}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// An error answer: its JSON-RPC error when it has one (the start of
		// the body is enough).
		head, _ := io.ReadAll(io.LimitReader(resp.Body, errorPeek*4))
		out.msg = parseRPC(head)
		return out, nil
	}
	if resp.StatusCode == http.StatusAccepted {
		return out, nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "text/event-stream":
		msg, err := readStream(resp.Body, onNote)
		out.msg = msg
		return out, err
	default:
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return out, err
		}
		out.msg = parseRPC(raw)
	}
	return out, nil
}

// parseRPC reads one JSON-RPC response (a result or an error); nil when raw
// is anything else.
func parseRPC(raw []byte) *rpcMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil
	}
	var m rpcMessage
	if json.Unmarshal(raw, &m) != nil || (m.Error == nil && len(m.Result) == 0) {
		return nil
	}
	return &m
}

// readStream reads an SSE response stream: notifications go to onNote, the
// first JSON-RPC response ends it. A stream that ends without one is cut off
// (io.ErrUnexpectedEOF). Server-sent requests on the stream (not allowed in
// this era) and other events are ignored.
func readStream(r io.Reader, onNote func(rpcMessage)) (*rpcMessage, error) {
	br := bufio.NewReaderSize(r, 32<<10)
	var data bytes.Buffer
	flush := func() (*rpcMessage, bool) {
		defer data.Reset()
		raw := bytes.TrimSpace(data.Bytes())
		if len(raw) == 0 {
			return nil, false
		}
		var m rpcMessage
		if json.Unmarshal(raw, &m) != nil {
			return nil, false
		}
		switch {
		case m.Method != "":
			if len(m.ID) == 0 && onNote != nil {
				onNote(m)
			}
		case m.Error != nil || len(m.Result) > 0:
			return &m, true
		}
		return nil, false
	}
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if m, done := flush(); done {
				return m, nil
			}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if m, done := flush(); done {
					return m, nil
				}
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

// rpcFailure turns a JSON-RPC error answer into an *Error (the server's
// message is redacted by the caller's safe()).
func rpcFailure(t Target, status int, e *rpcErr) *Error {
	class := ClassBadResponse
	if e.Code == -32602 || e.Code == -32600 {
		class = ClassBadRequest
	}
	st := 0
	if status >= 400 {
		st = status
	}
	return &Error{Class: class, HTTPStatus: st, RPCCode: e.Code, Message: clipMessage("The server returned an error: " + t.safe(e.Message))}
}
