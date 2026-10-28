package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// FakeMCP is a remote MCP server for tests of the registry and for local
// development (cmd/fakemcp), built with the official Go SDK and served
// statelessly over Streamable HTTP at URL() (adapted from Grounded). It
// lists:
//
//   - tools check_outage {service}, search_tickets {query} and
//     create_ticket {title} (annotated destructive);
//   - the resource status://services;
//   - the resource template status://services/{service};
//   - the prompt incident_summary {service}.
//
// RequireHeader makes it answer 401 to requests without a header;
// SetDescription, Hide and AddTool change what tools/list returns (change
// detection); SetPageSize makes every list paginate. EnableGatewayTools adds
// whoami (the identity the portal sent) and echo, and records every tool
// call (ToolCalls) for gateway tests.
//
// SetProtocol makes it speak one era only: ProtocolLegacy behaves like a
// server from before MCP 2026-07-28 (initialize; a request with the new
// headers gets a plain-text 400), ProtocolModern like a stateless server of
// the new revision (server/discover; initialize and requests without the
// protocol headers get a 400 with a JSON-RPC HeaderMismatch error), and
// ProtocolBoth (the default) both. EnableMRTRTools adds tools that answer
// input_required (ask_form, ask_url, ask_sampling), EnableStreamTools adds
// progress (emits progress notifications) and block (waits until its
// request is cancelled, recording it); both switch the fake to SSE responses.
type FakeMCP struct {
	*httptest.Server

	mu           sync.Mutex
	header       string
	value        string
	hidden       map[string]bool
	descriptions map[string]string
	annotations  map[string]*mcp.ToolAnnotations
	extra        []string
	pageSize     int
	requests     int
	// providerTokens counts HTTP requests that carried an
	// MCP-Gateway-Provider-Token header, whatever they were for.
	providerTokens int
	// rejectAuth, when not 0, is the HTTP status every request that carries
	// an Authorization header is answered with (RejectAuthorization);
	// auths records the credentials of every HTTP request (RequestAuths).
	rejectAuth int
	auths      []RequestAuth
	// queryName and queryValue are RequireQuery's; httpReqs is HTTPRequests'.
	queryName, queryValue string
	httpReqs              []HTTPRequest

	gatewayTools bool
	// echoSecrets adds echo_secrets and image (payload capture tests).
	echoSecrets bool
	// schemaTools adds lookup (EnableSchemaTools).
	schemaTools bool
	jwksURL     string
	audience    string
	toolCalls   []ToolCall
	reads       []ToolCall
	// OnToolCall, when set, sees every tool call and resource read
	// (cmd/fakemcp logs them).
	OnToolCall func(ToolCall)
	// protect makes the fake an OAuth resource server (Protect).
	protect *Protection

	protocol    Protocol
	mrtrTools   bool
	streamTools bool
	seen        []SeenRequest
	blocked     chan struct{}
	release     chan struct{}
	cancelled   atomic.Int64
	jsonH, sseH http.Handler
}

// Protocol is which era of MCP the fake speaks.
type Protocol string

// The eras (SetProtocol).
const (
	ProtocolBoth   Protocol = "both"
	ProtocolLegacy Protocol = "legacy"
	ProtocolModern Protocol = "modern"
)

// ParseProtocol reads cmd/fakemcp's -protocol flag.
func ParseProtocol(s string) (Protocol, error) {
	switch p := Protocol(s); p {
	case ProtocolBoth, ProtocolLegacy, ProtocolModern:
		return p, nil
	case "":
		return ProtocolBoth, nil
	}
	return "", fmt.Errorf("protocol %q: want legacy, modern or both", s)
}

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

// SetProtocol sets which era the fake speaks (before the first request).
func (f *FakeMCP) SetProtocol(p Protocol) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protocol = p
}

// SeenRequests are the MCP requests received so far, in order.
func (f *FakeMCP) SeenRequests() []SeenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SeenRequest(nil), f.seen...)
}

// EnableMRTRTools adds ask_form, ask_url {url} and ask_sampling {mixed}:
// tools that answer a modern call with an input_required result (a form
// elicitation, a URL elicitation, a sampling request) and complete when the
// retry carries the responses; also the prompt ask_prompt (a form) and the
// resource status://ask (a URL), which do the same. They record the _meta, requestState and
// inputResponses they received (ToolCalls).
func (f *FakeMCP) EnableMRTRTools() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mrtrTools = true
}

// EnableStreamTools adds progress {count, delay_ms} and block, and makes the
// fake answer with SSE streams. progress sends count notifications/progress
// for the call's progress token, delay_ms apart, then a result; block waits
// until its request is cancelled (Cancellations) and signals WaitBlocked.
func (f *FakeMCP) EnableStreamTools() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streamTools = true
	if f.blocked == nil {
		f.blocked, f.release = make(chan struct{}, 16), make(chan struct{}, 16)
	}
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

// Protection makes the fake an OAuth-protected MCP server (Phase 7): it
// answers 401 with a Bearer challenge naming its protected-resource
// metadata, serves that metadata, and accepts only bearer tokens its
// authorization server says are active and bound to this server's URL.
type Protection struct {
	// Issuer is the authorization server listed in the metadata.
	Issuer string
	// Introspect asks the authorization server about a token.
	Introspect func(ctx context.Context, token string) Introspection
	// ScopesSupported are listed in the metadata; ChallengeScope is the
	// 401 challenge's scope ("": none).
	ScopesSupported []string
	ChallengeScope  string
	// Resource overrides the metadata's resource ("": this server's URL).
	Resource string
	// NoResourceMetadataParam leaves resource_metadata out of the 401 (the
	// metadata is then found at the well-known URI).
	NoResourceMetadataParam bool
	// WriteScope is the scope the write tool needs (403 insufficient_scope
	// without it; default "write").
	WriteScope string
	// IgnoreResource accepts tokens bound to another resource (or none).
	IgnoreResource bool
}

// Protect makes the fake an OAuth resource server, and adds the write tool.
func (f *FakeMCP) Protect(p Protection) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.WriteScope == "" {
		p.WriteScope = "write"
	}
	f.protect = &p
}

// SetProtection changes the protection under the fake's lock.
func (f *FakeMCP) SetProtection(change func(p *Protection)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.protect)
}

func (f *FakeMCP) protection() *Protection {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.protect == nil {
		return nil
	}
	p := *f.protect
	return &p
}

// selfURL is the fake's endpoint as a request reached it.
func selfURL(r *http.Request) string { return "http://" + r.Host + "/mcp" }

func metadataURL(r *http.Request) string {
	return "http://" + r.Host + "/.well-known/oauth-protected-resource/mcp"
}

// guard enforces Protection on an MCP request; false when it answered.
func (f *FakeMCP) guard(w http.ResponseWriter, r *http.Request, p *Protection) bool {
	challenge := func(status int, errCode, scope string) bool {
		parts := []string{}
		if errCode != "" {
			parts = append(parts, `error="`+errCode+`"`)
		}
		if scope != "" {
			parts = append(parts, `scope="`+scope+`"`)
		}
		if !p.NoResourceMetadataParam {
			parts = append(parts, `resource_metadata="`+metadataURL(r)+`"`)
		}
		w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
		http.Error(w, http.StatusText(status), status)
		return false
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return challenge(http.StatusUnauthorized, "", p.ChallengeScope)
	}
	in := p.Introspect(r.Context(), token)
	resource := p.Resource
	if resource == "" {
		resource = selfURL(r)
	}
	if !in.Active || (!p.IgnoreResource && in.Resource != resource) {
		return challenge(http.StatusUnauthorized, "invalid_token", p.ChallengeScope)
	}
	// The write tool needs WriteScope (a step-up).
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &msg)
	if msg.Method == "tools/call" && msg.Params.Name == "write" && !slices.Contains(in.Scopes, p.WriteScope) {
		return challenge(http.StatusForbidden, "insufficient_scope", strings.Join(append(append([]string{}, in.Scopes...), p.WriteScope), " "))
	}
	return true
}

func (f *FakeMCP) serveResourceMetadata(w http.ResponseWriter, r *http.Request, p *Protection) {
	resource := p.Resource
	if resource == "" {
		resource = selfURL(r)
	}
	scopes := p.ScopesSupported
	if scopes == nil {
		scopes = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{p.Issuer},
		"scopes_supported": scopes, "bearer_methods_supported": []string{"header"}, "resource_name": "Fake protected MCP"})
}

// IntrospectAt asks a fake OAuth provider's /introspect over HTTP
// (cmd/fakemcp -protect).
func IntrospectAt(endpoint string) func(ctx context.Context, token string) Introspection {
	return func(ctx context.Context, token string) Introspection {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
		if err != nil {
			return Introspection{}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return Introspection{}
		}
		defer res.Body.Close()
		var out Introspection
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out)
		return out
	}
}

// ToolCall is what the fake received with one tool call (or resource
// read: Tool is then "resources/read" and URI the URI read).
type ToolCall struct {
	Tool string
	URI  string
	// Authorization and Identity are the Authorization and
	// MCP-Gateway-Identity headers as received.
	Authorization, Identity string
	// Header is every request header.
	Header http.Header
	// Meta is params._meta as received, RequestState and InputResponses the
	// retry fields of a multi round-trip call.
	Meta           map[string]any
	RequestState   string
	InputResponses map[string]any
	Arguments      json.RawMessage
}

// FakeMCPTools is how many tools the fake lists by default; with the
// resource, template and prompt it lists FakeMCPCapabilities in all.
const (
	FakeMCPTools        = 3
	FakeMCPCapabilities = 6
)

// NewFakeMCP starts the fake on a loopback address (closed with the test).
func NewFakeMCP(t testing.TB) *FakeMCP {
	f, h := NewFakeMCPHandler()
	f.Server = httptest.NewServer(h)
	t.Cleanup(f.Close)
	return f
}

// NewFakeMCPHandler builds the fake without starting a server (cmd/fakemcp
// serves it; URL() then isn't set).
func NewFakeMCPHandler() (*FakeMCP, http.Handler) {
	f := &FakeMCP{hidden: map[string]bool{}, descriptions: map[string]string{}, protocol: ProtocolBoth}
	getServer := func(*http.Request) *mcp.Server { return f.server() }
	f.jsonH = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	f.sseH = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true})
	return f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		if r.Header.Get("MCP-Gateway-Provider-Token") != "" {
			f.providerTokens++
		}
		name, value := f.header, f.value
		auth, reject := r.Header.Get("Authorization"), f.rejectAuth
		f.auths = append(f.auths, RequestAuth{Authorization: auth, Identity: r.Header.Get("MCP-Gateway-Identity")})
		f.httpReqs = append(f.httpReqs, HTTPRequest{Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header.Clone()})
		qname, qvalue := f.queryName, f.queryValue
		f.mu.Unlock()
		r.Header.Set(QueryHeader, r.URL.RawQuery)
		if qname != "" && r.URL.Query().Get(qname) != qvalue {
			http.Error(w, "unauthorized: GET "+r.URL.RequestURI(), http.StatusUnauthorized)
			return
		}
		if reject != 0 && auth != "" {
			http.Error(w, "credentials are not accepted here", reject)
			return
		}
		if p := f.protection(); p != nil {
			if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
				f.serveResourceMetadata(w, r, p)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/.well-known/") {
				http.NotFound(w, r)
				return
			}
			if !f.guard(w, r, p) {
				return
			}
		}
		if name != "" && r.Header.Get(name) != value {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !f.era(w, r) {
			return
		}
		f.mu.Lock()
		h := f.jsonH
		if f.streamTools {
			h = f.sseH
		}
		f.mu.Unlock()
		if f.watchBlock(r) {
			finished := make(chan struct{})
			defer close(finished)
			go func() {
				select {
				case <-r.Context().Done():
					// The client closed the connection: the block call (which a
					// session of an older protocol version never sees cancelled
					// by the SDK) is told.
					select {
					case f.release <- struct{}{}:
					default:
					}
				case <-finished:
				}
			}()
		}
		h.ServeHTTP(w, r)
	})
}

const modernVersion = "2026-07-28"

// watchBlock reports whether r is a tools/call of the block tool (its body
// has been read and put back by era).
func (f *FakeMCP) watchBlock(r *http.Request) bool {
	f.mu.Lock()
	on := f.streamTools
	f.mu.Unlock()
	if !on || r.Method != http.MethodPost || r.Body == nil {
		return false
	}
	body, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	return json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call" && msg.Params.Name == "block"
}

// era applies SetProtocol to an MCP request and records it; false when it
// answered (the request is of the era the fake doesn't speak).
func (f *FakeMCP) era(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost || r.Body == nil {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		} `json:"params"`
	}
	if err != nil || json.Unmarshal(body, &msg) != nil {
		return true
	}
	version := r.Header.Get("MCP-Protocol-Version")
	_, metaVersion := msg.Params.Meta["io.modelcontextprotocol/protocolVersion"]
	modernRequest := metaVersion || msg.Method == "server/discover" || (version != "" && version >= modernVersion)
	f.mu.Lock()
	protocol := f.protocol
	f.mu.Unlock()
	refused := false
	switch {
	case protocol == ProtocolLegacy && modernRequest:
		// A server from before the revision: the SDK's own answer to a
		// protocol version it doesn't know, plain text.
		http.Error(w, "Bad Request: Unsupported protocol version (supported versions: 2025-11-25,2025-06-18,2025-03-26,2024-11-05)", http.StatusBadRequest)
		refused = true
	case protocol == ProtocolModern && !modernRequest && msg.Method != "":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		id := msg.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32020,
			"message": "MCP-Protocol-Version header is required (this server speaks 2026-07-28)"}})
		_, _ = w.Write(out)
		refused = true
	}
	f.mu.Lock()
	f.seen = append(f.seen, SeenRequest{Method: msg.Method, Version: version, McpMethod: r.Header.Get("Mcp-Method"), Refused: refused})
	f.mu.Unlock()
	return !refused
}

// URL is the Streamable HTTP endpoint.
func (f *FakeMCP) URL() string { return f.Server.URL + "/mcp" }

// RequireHeader makes every request need name: value.
func (f *FakeMCP) RequireHeader(name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.header, f.value = name, value
}

// SetAnnotations changes a built-in tool's untrusted hints on the next discovery.
func (f *FakeMCP) SetAnnotations(tool string, annotations *mcp.ToolAnnotations) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.annotations == nil {
		f.annotations = map[string]*mcp.ToolAnnotations{}
	}
	f.annotations[tool] = annotations
}

// SetDescription changes a tool's description in tools/list.
func (f *FakeMCP) SetDescription(tool, description string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.descriptions[tool] = description
}

// Hide removes a tool, the resource, the template or the prompt (by name
// or URI) from its list.
func (f *FakeMCP) Hide(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hidden[name] = true
}

// Show undoes Hide.
func (f *FakeMCP) Show(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hidden, name)
}

// AddTool lists one more (trivial) tool.
func (f *FakeMCP) AddTool(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extra = append(f.extra, name)
}

// SetPageSize sets the list page size (0: the SDK default).
func (f *FakeMCP) SetPageSize(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pageSize = n
}

// EnableGatewayTools adds the tools whoami, provider_token and echo {text}.
// whoami returns the identity token it received as JSON: which header
// carried it, its claims and, with SetJWKS, whether it verifies.
// provider_token reports the delegated credential it received
// (ProviderTokenReport): never the token, only a digest prefix.
func (f *FakeMCP) EnableGatewayTools() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gatewayTools = true
}

// EnableEchoSecrets adds three tools for payload capture tests: echo_secrets
// returns, as text, every credential it received (the identity token, the
// provider token and the Authorization and X-Api-Key header values), as a
// misbehaving server might; echo_tokens returns only the platform provider
// token (MCP-Gateway-Provider-Token) and the bearer token (Authorization
// without "Bearer "), verbatim, so that no pattern rule such as "Bearer ..."
// can hide a missing exact-value redaction; image returns an image content
// item. Never enabled by cmd/fakemcp.
func (f *FakeMCP) EnableEchoSecrets() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.echoSecrets = true
}

// EnableSchemaTools adds lookup {region, limit, note}, a tool with features of
// the 2026-07-28 revision: its region and limit arguments are marked
// x-mcp-header (Region, Limit), its outputSchema is not an object schema
// (["null","array"]) and its result's structuredContent is an array. It
// records its calls (ToolCalls, with the headers it received).
func (f *FakeMCP) EnableSchemaTools() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schemaTools = true
}

// SetJWKS makes whoami verify the token against the key set at url, for
// audience.
func (f *FakeMCP) SetJWKS(url, audience string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksURL, f.audience = url, audience
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

func fakeText(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func stringArg(name, description string) map[string]any {
	return map[string]any{"type": "object", "required": []string{name},
		"properties": map[string]any{name: map[string]any{"type": "string", "description": description}}}
}

// server builds the MCP server of one request from the current state.
func (f *FakeMCP) server() *mcp.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	opts := &mcp.ServerOptions{PageSize: f.pageSize}
	switch f.protocol {
	case ProtocolLegacy:
		for _, v := range mcp.SupportedProtocolVersions() {
			if v < modernVersion {
				opts.SupportedProtocolVersions = append(opts.SupportedProtocolVersions, v)
			}
		}
	case ProtocolModern:
		opts.SupportedProtocolVersions = []string{modernVersion}
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "fake-status", Version: "1.0.0"}, opts)
	yes := true
	tools := []*mcp.Tool{
		{Name: "check_outage", Title: "Check outage", Description: "Reports whether a company service has an outage right now.",
			InputSchema: stringArg("service", "The service, for example email")},
		{Name: "search_tickets", Title: "Search tickets", Description: "Searches open support tickets.",
			InputSchema: stringArg("query", "Words to look for")},
		{Name: "create_ticket", Title: "Create ticket", Description: "Opens a support ticket.",
			InputSchema: stringArg("title", "The ticket's title"), Annotations: &mcp.ToolAnnotations{DestructiveHint: &yes}},
	}
	for _, name := range f.extra {
		tools = append(tools, &mcp.Tool{Name: name, Description: "An added tool.", InputSchema: map[string]any{"type": "object"}})
	}
	for _, t := range tools {
		if f.hidden[t.Name] {
			continue
		}
		if d, ok := f.descriptions[t.Name]; ok {
			t.Description = d
		}
		if annotations, ok := f.annotations[t.Name]; ok {
			t.Annotations = annotations
		}
		name := t.Name
		s.AddTool(t, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.sawCall(name, headerOf(req))
			return fakeText(fmt.Sprintf("%s: ok", name)), nil
		})
	}
	if f.gatewayTools {
		jwksURL, audience := f.jwksURL, f.audience
		describe := func(name, d string) string {
			if v, ok := f.descriptions[name]; ok {
				return v
			}
			return d
		}
		protected := f.protect != nil
		s.AddTool(&mcp.Tool{Name: "whoami", Title: "Who am I", Description: describe("whoami", "Shows the identity the portal sent with this call."),
			InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("whoami", h)
			if !protected {
				out, _ := json.Marshal(Whoami(ctx, h, jwksURL, audience))
				return fakeText(string(out)), nil
			}
			// Protected: Authorization holds the person's token, never shown;
			// the identity token can only be in MCP-Gateway-Identity.
			bearer := strings.TrimPrefix(h.Get("Authorization"), "Bearer ")
			only := h.Clone()
			only.Del("Authorization")
			who := Whoami(ctx, only, jwksURL, audience)
			if bearer != "" {
				who.BearerSHA256 = TokenDigest(bearer)
			}
			out, _ := json.Marshal(who)
			return fakeText(string(out)), nil
		})
		s.AddTool(&mcp.Tool{Name: "provider_token", Title: "Provider token",
			Description: describe("provider_token", "Reports whether the portal sent a provider token with this call (never the token itself)."),
			InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("provider_token", h)
			out, _ := json.Marshal(ProviderTokenReport(ctx, h, jwksURL, audience))
			return fakeText(string(out)), nil
		})
		s.AddTool(&mcp.Tool{Name: "echo", Title: "Echo", Description: describe("echo", "Returns its text."), InputSchema: stringArg("text", "Any text")},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawFull("echo", req)
				var args struct {
					Text string `json:"text"`
				}
				_ = json.Unmarshal(req.Params.Arguments, &args)
				return fakeText(args.Text), nil
			})
	}
	if f.schemaTools {
		description := "Looks something up (arrays, parameter headers)."
		if d, ok := f.descriptions["lookup"]; ok {
			description = d
		}
		s.AddTool(&mcp.Tool{Name: "lookup", Title: "Lookup", Description: description,
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"region": map[string]any{"type": "string", "x-mcp-header": "Region"},
				"limit":  map[string]any{"type": "integer", "x-mcp-header": "Limit"},
				"note":   map[string]any{"type": "string"},
			}},
			OutputSchema: map[string]any{"type": []string{"null", "array"}}},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawFull("lookup", req)
				var args struct {
					Region string `json:"region"`
					Limit  int    `json:"limit"`
				}
				_ = json.Unmarshal(req.Params.Arguments, &args)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "lookup: ok"}},
					StructuredContent: []any{map[string]any{"region": args.Region, "limit": args.Limit}}}, nil
			})
	}
	if f.mrtrTools {
		f.addMRTRTools(s)
	}
	if f.streamTools {
		f.addStreamTools(s)
	}
	if f.protect != nil {
		s.AddTool(&mcp.Tool{Name: "write", Title: "Write", Description: "Needs the write scope.", InputSchema: map[string]any{"type": "object"}},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawCall("write", headerOf(req))
				return fakeText("written"), nil
			})
	}
	if f.echoSecrets {
		s.AddTool(&mcp.Tool{Name: "echo_secrets", Title: "Echo secrets", Description: "Returns the credentials it received.",
			InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("echo_secrets", h)
			_, id := IdentityToken(h)
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("identity=%s provider=%s authorization=%s apikey=%s query=%s ", id,
					h.Get("MCP-Gateway-Provider-Token"), h.Get("Authorization"), h.Get("X-Api-Key"), h.Get(QueryHeader))},
				&mcp.TextContent{Text: string(req.Params.Arguments)},
			}}, nil
		})
		s.AddTool(&mcp.Tool{Name: "echo_tokens", Title: "Echo tokens", Description: "Returns the provider token and the bearer token it received, verbatim.",
			InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			h := headerOf(req)
			f.sawCall("echo_tokens", h)
			return fakeText(fmt.Sprintf("provider_token=%s oauth_token=%s end", h.Get("MCP-Gateway-Provider-Token"),
				strings.TrimPrefix(h.Get("Authorization"), "Bearer "))), nil
		})
		s.AddTool(&mcp.Tool{Name: "image", Title: "Image", Description: "Returns an image.", InputSchema: map[string]any{"type": "object"}},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				f.sawCall("image", headerOf(req))
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.ImageContent{Data: []byte("0123456789abcdef0123456789abcdef"), MIMEType: "image/png"}}}, nil
			})
	}
	if !f.hidden["status://services"] {
		s.AddResource(&mcp.Resource{URI: "status://services", Name: "services", Title: "Services", Description: "Every monitored service.",
			MIMEType: "text/plain"}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			f.sawRead(req)
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "email\nvpn"}}}, nil
		})
	}
	if !f.hidden["status://services/{service}"] {
		s.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "status://services/{service}", Name: "service", Title: "Service status",
			Description: "The status of one service.", MIMEType: "text/plain"},
			func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				f.sawRead(req)
				return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "operating normally"}}}, nil
			})
	}
	if !f.hidden["incident_summary"] {
		s.AddPrompt(&mcp.Prompt{Name: "incident_summary", Title: "Incident summary", Description: "Summarise an incident for a service.",
			Arguments: []*mcp.PromptArgument{{Name: "service", Description: "The affected service", Required: true}}},
			func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
				return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user",
					Content: &mcp.TextContent{Text: "Summarise the incident for " + req.Params.Arguments["service"]}}}}, nil
			})
	}
	return s
}
