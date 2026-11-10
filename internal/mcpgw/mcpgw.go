// Package mcpgw serves gateways at /mcp/{slug} (SPEC.md §6;
// docs/phase3-gateways.md "Runtime").
//
// It speaks MCP's Streamable HTTP transport statelessly: every request is a
// POST carrying one JSON-RPC message and is answered with one JSON
// response (GET and DELETE are 405: there are no sessions and no server
// stream). It implements initialize, ping, tools/list, tools/call,
// prompts/list, prompts/get, and (when the gateway selects resources or
// resource templates) resources/list, resources/templates/list and
// resources/read; other methods are "method not found", including
// resources/subscribe.
//
// It speaks two protocol eras, chosen per request (era.go, modern.go,
// requeststate.go; docs/mcp-protocol.md). The legacy era (2024-11-05 to
// 2025-11-25) is as described above. A modern request (2026-07-28: per
// request _meta and the MCP-Protocol-Version, Mcp-Method and Mcp-Name
// headers, which must match the body) also gets server/discover, resultType,
// cache hints, era-specific error codes, and "connect your account" as a
// multi round-trip input request.
//
// Every request is authenticated (Authorization: Bearer ...) with a
// personal API key (omp_...), an OAuth access token of a connected client
// (ompat_..., internal/oauth; accepted only by its own gateway) or a service
// account key (omp_sa_..., internal/serviceaccounts), and re-checks
// everything before it lists or calls: the credential and its person (or
// service account, and its team) are active, the key may be used on this
// gateway, the gateway is enabled (and a team gateway's team not archived)
// and the caller may use it, and each capability is still selected, served
// (Availability) and allowed to their role. A refused call looks like an unknown tool,
// prompt or resource, is recorded as denied and never reaches the server. Calls are
// forwarded through internal/upstream (address guard, the server's timeout,
// 1 MiB bounds, the server's static header) with a signed identity
// (internal/identity) and never the client's credential. Lists are served
// from the approved definitions in the database, without contacting
// servers. Every list and call is recorded in mcp_calls, without arguments
// or results; when the gateway or the server captures payloads, a
// forwarded call's arguments and result are stored with it, redacted
// (internal/capture).
//
// Every authenticated request that passes gateway resolution counts toward
// the rate limits (internal/limits, counted in PostgreSQL and shared by
// every replica): over a limit it is answered 429 with Retry-After and
// JSON-RPC -32029, recorded as rate_limited and never forwarded.
package mcpgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Bounds.
const (
	// MaxRequestBytes bounds a client's request body.
	MaxRequestBytes = 1 << 20
	// MaxResponseBytes bounds a response to a call (a server's own response
	// is bounded by internal/upstream as well).
	MaxResponseBytes = 1 << 20
	// listPageBytes bounds the definitions in one list page.
	listPageBytes = 512 << 10
)

// Protocol versions this endpoint negotiates, newest first.
var protocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// statelessVersion is the first protocol version without initialize (the
// modern era, era.go).
const statelessVersion = "2026-07-28"

// metaClientInfo is where 2026-07-28 clients put clientInfo in every
// request's _meta.
const metaClientInfo = "io.modelcontextprotocol/clientInfo"

// JSON-RPC error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	// codeResourceNotFound is MCP's "resource not found".
	codeResourceNotFound = -32002
	// codeRefused is the implementation-defined code of HTTP-level refusals
	// (no credential, unknown gateway).
	codeRefused = -32001
	// codeDenied is the implementation-defined code of a call refused with a
	// reason the caller may know (data.reason): a service account calling a
	// capability that needs a person's account, a turned-off auth provider,
	// or a provider that can't be reached.
	codeDenied = -32010
	// codeURLElicitationRequired is MCP 2025-11-25's
	// URLElicitationRequiredError: the person must open a URL (connect an
	// account) and try again.
	codeURLElicitationRequired = -32042
	// codeRateLimited is the implementation-defined code of a request over
	// a rate limit (HTTP 429).
	codeRateLimited = -32029
	// codeRateLimitedModern is what modern requests get instead: 2026-07-28
	// reserves -32020 to -32099 for the specification, so ours moves out of
	// the JSON-RPC range (the HTTP status).
	codeRateLimitedModern = 429
)

// Methods.
const (
	methodInitialize  = "initialize"
	methodDiscover    = "server/discover"
	methodPing        = "ping"
	methodToolsList   = "tools/list"
	methodToolsCall   = "tools/call"
	methodPromptsList = "prompts/list"
	methodPromptsGet  = "prompts/get"
	methodResources   = "resources/list"
	methodTemplates   = "resources/templates/list"
	methodRead        = "resources/read"
	// The task lifecycle methods of the Tasks extension (modern era only).
	methodTasksGet    = upstream.MethodTasksGet
	methodTasksUpdate = upstream.MethodTasksUpdate
	methodTasksCancel = upstream.MethodTasksCancel
)

// DeniedKeyScope is why a request with a key limited to other gateways is
// refused.
const DeniedKeyScope = "key_scope"

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

// Handler serves /mcp/{slug}.
type Handler struct {
	// Approvals is optional only for legacy test/service compositions. Serving
	// applications wire it so every tool dispatch observes live approval policy.
	Approvals ApprovalRuntime
	Gateways  *gateways.Service
	Keys      *apikeys.Service
	// OAuth checks connected clients' access tokens (nil: none accepted).
	OAuth *oauth.Service
	// ServiceAccounts checks service account keys (nil: none accepted).
	ServiceAccounts *serviceaccounts.Service
	Identity        *identity.Service
	Registry        *registry.Service
	// Providers supplies people's delegated credentials for capabilities
	// that require an auth provider (nil: such calls are refused).
	Providers *providers.Service
	// PersonSecrets supplies people's own secrets for servers in person_secret
	// mode (personsecret.go; nil: such calls are refused).
	PersonSecrets *personsecrets.Service
	// Tasks relays the released Tasks extension's durable task handles
	// (tasks.go; docs/mcp-tasks.md). Nil turns tasks fully off: the extension
	// is not advertised, never negotiated with a server, and the task methods
	// are unknown. Tasks also need Approvals (the read-only no-rule check of
	// every lifecycle operation).
	Tasks *mcptasks.Store
	// Limits and RateStore apply the rate limits (nil: none).
	Limits    *limits.Service
	RateStore ratelimit.Store
	// Capture stores the payloads of calls whose gateway or server captures
	// them (nil: never).
	Capture *capture.Service
	// Secrets derives the key that protects requestState (the consent
	// input request of the modern era; nil: consent is -32042 for legacy clients and a plain error for modern ones).
	Secrets *secrets.Box
	Pool    *pgxpool.Pool
	AppURL  string
	Log     *slog.Logger

	// keepAlive is the interval of SSE keep-alive comments (stream.go; 0:
	// 15 s).
	keepAlive time.Duration

	stateOnce sync.Once
	state     *stateBox
	// now is the clock of requestState expiry (tests set it; nil: time.Now).
	now func() time.Time
}

// SetClock sets the clock that expires requestState tokens (tests). Call it
// before the handler serves its first request.
func (h *Handler) SetClock(now func() time.Time) { h.now = now }

func (h *Handler) log() *slog.Logger {
	if h.Log == nil {
		return slog.Default()
	}
	return h.Log
}

// message is one JSON-RPC message from a client.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type rpcError struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

var nullID = json.RawMessage("null")

// writeRPC writes one JSON-RPC response and returns its size.
func writeRPC(w http.ResponseWriter, status int, id json.RawMessage, result any, rerr *rpcError) int64 {
	if len(id) == 0 {
		id = nullID
	}
	res := response{JSONRPC: "2.0", ID: id, Result: result, Error: rerr}
	if rerr == nil && result == nil {
		res.Result = struct{}{}
	}
	b, err := json.Marshal(res)
	if err != nil {
		b, _ = json.Marshal(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: codeInternal, Message: "The response can't be encoded"}})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
	return int64(len(b))
}

func refuse(w http.ResponseWriter, status int, msg string) {
	writeRPC(w, status, nil, nil, &rpcError{Code: codeRefused, Message: msg})
}

// ServeHTTP handles every method on /mcp/{slug}.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// This header was an external impersonation input. Never silently execute
	// such a request as the credential owner, including non-POST requests.
	for name := range r.Header {
		if strings.EqualFold(name, identity.HeaderIdentity) {
			refuse(w, http.StatusForbidden, "Inbound external identity is retired. Remove the identity header and use an ordinary MCP credential.")
			return
		}
	}
	start := time.Now()
	// Tracing (trace.go): nil, and w unchanged, when it is off. finish gets
	// the request as it is when the handler returns (it carries the span).
	tr, w := newReqTrace(w, r, start)
	defer func() { tr.finish(r) }()
	if r.Method != http.MethodPost {
		// Stateless: no server stream (GET) and no session to end (DELETE).
		w.Header().Set("Allow", "POST")
		refuse(w, http.StatusMethodNotAllowed, "This MCP endpoint accepts POST only")
		return
	}
	slug := r.PathValue("slug")
	if origin := r.Header.Get("Origin"); origin != "" && origin != h.AppURL {
		// DNS rebinding protection (Streamable HTTP §Security): browsers on
		// other origins are refused.
		refuse(w, http.StatusForbidden, "Origin not allowed")
		return
	}
	var approvalEpoch int64
	if h.Approvals != nil {
		var err error
		approvalEpoch, err = h.Approvals.Epoch(r.Context())
		if err != nil {
			refuse(w, http.StatusServiceUnavailable, "Approval policy is unavailable")
			return
		}
	}
	authStart := time.Now()
	principal, ok := h.authenticate(w, r, slug)
	tr.authenticated(authStart, principal.kind, ok)
	if !ok {
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		refuse(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if !acceptsJSON(r.Header.Values("Accept")) {
		refuse(w, http.StatusNotAcceptable, "Accept must include application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			refuse(w, http.StatusRequestEntityTooLarge, "The request is larger than 1 MiB")
			return
		}
		refuse(w, http.StatusBadRequest, "The request body can't be read")
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		writeRPC(w, http.StatusBadRequest, nil, nil, &rpcError{Code: codeInvalidRequest, Message: "JSON-RPC batches are not supported"})
		return
	}
	var msg message
	if err := json.Unmarshal(trimmed, &msg); err != nil {
		writeRPC(w, http.StatusBadRequest, nil, nil, &rpcError{Code: codeParseError, Message: "The request is not valid JSON"})
		return
	}
	if msg.JSONRPC != "2.0" || (msg.Method == "" && msg.Result == nil && msg.Error == nil) || bytes.Equal(msg.ID, nullID) {
		writeRPC(w, http.StatusBadRequest, msg.ID, nil, &rpcError{Code: codeInvalidRequest, Message: "Not a JSON-RPC 2.0 request"})
		return
	}
	// The request's span (a child of the traceparent header or _meta).
	r = tr.begin(r, &msg)
	era, eerr := detectEra(msg, r.Header)
	if eerr != nil {
		writeRPC(w, eerr.status, msg.ID, nil, &rpcError{Code: eerr.code, Message: eerr.message, Data: eerr.data})
		return
	}
	if v := r.Header.Get(headerProtocolVersion); !era.modern && v != "" && !slices.Contains(protocolVersions, v) && v < statelessVersion {
		refuse(w, http.StatusBadRequest, "Unsupported MCP-Protocol-Version (supported: "+strings.Join(protocolVersions, ", ")+")")
		return
	}

	rc := &request{h: h, w: w, r: r, start: start, msg: msg, principal: principal, requestBytes: int64(len(body)),
		modern: era.modern, clientCaps: era.caps, approvalEpoch: approvalEpoch}
	if tr != nil {
		tr.rc = rc
	}
	sp := rc.span("mcp.resolve_gateway", trace.SpanKindInternal)
	resolved := rc.resolveGateway(slug)
	sp.End()
	if !resolved {
		return
	}
	defer rc.observe()
	if !rc.rateLimit() {
		return
	}
	if msg.Method == "" || len(msg.ID) == 0 {
		// A notification (notifications/initialized, cancelled) or a
		// response: accepted, nothing to answer.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	rc.dispatch()
}

func acceptsJSON(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			mt := strings.ToLower(strings.TrimSpace(strings.Split(part, ";")[0]))
			if mt == "application/json" || mt == "application/*" || mt == "*/*" {
				return true
			}
		}
	}
	return false
}
