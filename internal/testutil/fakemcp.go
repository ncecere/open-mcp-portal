package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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

// SetProtocol sets which era the fake speaks (before the first request).
func (f *FakeMCP) SetProtocol(p Protocol) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protocol = p
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
