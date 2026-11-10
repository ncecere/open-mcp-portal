package testutil

import (
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SeenRequest is one HTTP request as the fake received it (the MCP ones).
type SeenRequest struct {
	Method string
	// Version is the MCP-Protocol-Version header ("": none); McpMethod the
	// Mcp-Method header; Refused says the era rules of SetProtocol answered
	// it with an error.
	Version, McpMethod string
	Refused            bool
}

// RequestAuth is the identity-bearing headers of one HTTP request, whatever
// it was for (initialize, discovery, a list, a call) and however it was
// answered.
type RequestAuth struct {
	// Authorization and Identity are the Authorization and
	// MCP-Gateway-Identity header values ("": absent).
	Authorization, Identity string
}

// QueryHeader is the header the fake puts on each request it hands to its MCP
// handler, carrying the request's raw query string, so a tool (and ToolCall.Header)
// can see what query the portal sent.
const QueryHeader = "X-Fake-Raw-Query"

// HTTPRequest is one HTTP request as the fake received it, whatever it was for.
type HTTPRequest struct {
	Path, RawQuery string
	Header         http.Header
}

// HTTPRequests are every HTTP request received so far, in order.
func (f *FakeMCP) HTTPRequests() []HTTPRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HTTPRequest(nil), f.httpReqs...)
}

// RequireQuery makes every request need the query parameter name=value. A
// request without it is answered 401 with a body that repeats the request line
// (path and query), as a careless server's error page might.
func (f *FakeMCP) RequireQuery(name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queryName, f.queryValue = name, value
}

// RequestAuths are the credentials of every HTTP request received so far,
// in order (RejectAuthorization'd requests included).
func (f *FakeMCP) RequestAuths() []RequestAuth {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RequestAuth(nil), f.auths...)
}

// RejectAuthorization makes the fake answer every request that carries an
// Authorization header with status (for example 401), at the HTTP level and
// before any MCP handling, like a public server that refuses credentials it
// doesn't use. 0 turns it off.
func (f *FakeMCP) RejectAuthorization(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectAuth = status
}

// SeenRequests are the MCP requests received so far, in order.
func (f *FakeMCP) SeenRequests() []SeenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SeenRequest(nil), f.seen...)
}

// Cancellations is how many block calls ended because their request was
// cancelled.
func (f *FakeMCP) Cancellations() int { return int(f.cancelled.Load()) }

// WaitBlocked waits until a block call has started.
func (f *FakeMCP) WaitBlocked(t testing.TB) {
	t.Helper()
	select {
	case <-f.blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("no block call started")
	}
}

// ToolCalls are the tool calls received so far.
func (f *FakeMCP) ToolCalls() []ToolCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ToolCall(nil), f.toolCalls...)
}

func (f *FakeMCP) sawCall(tool string, h http.Header) {
	c := ToolCall{Tool: tool, Authorization: h.Get("Authorization"), Identity: h.Get("MCP-Gateway-Identity"), Header: h.Clone()}
	f.mu.Lock()
	f.toolCalls = append(f.toolCalls, c)
	hook := f.OnToolCall
	f.mu.Unlock()
	if hook != nil {
		hook(c)
	}
}

// ResourceReads are the resource reads received so far.
func (f *FakeMCP) ResourceReads() []ToolCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ToolCall(nil), f.reads...)
}

func (f *FakeMCP) sawRead(req *mcp.ReadResourceRequest) {
	h := http.Header{}
	if req.Extra != nil && req.Extra.Header != nil {
		h = req.Extra.Header
	}
	c := ToolCall{Tool: "resources/read", URI: req.Params.URI, Authorization: h.Get("Authorization"),
		Identity: h.Get("MCP-Gateway-Identity"), Header: h.Clone()}
	f.mu.Lock()
	f.reads = append(f.reads, c)
	hook := f.OnToolCall
	f.mu.Unlock()
	if hook != nil {
		hook(c)
	}
}

func headerOf(req *mcp.CallToolRequest) http.Header {
	if req.Extra == nil || req.Extra.Header == nil {
		return http.Header{}
	}
	return req.Extra.Header
}

// ProviderTokenRequests counts the HTTP requests, of any kind, that carried
// a provider token (MCP-Gateway-Provider-Token).
func (f *FakeMCP) ProviderTokenRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.providerTokens
}

// Requests counts every HTTP request.
func (f *FakeMCP) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}
