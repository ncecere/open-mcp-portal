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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
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
)

// DeniedKeyScope is why a request with a key limited to other gateways is
// refused.
const DeniedKeyScope = "key_scope"

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)

// Handler serves /mcp/{slug}.
type Handler struct {
	Gateways *gateways.Service
	Keys     *apikeys.Service
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
		modern: era.modern, clientCaps: era.caps}
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

// principal is who a request authenticates as: a person with an API key
// (calls.PrincipalAPIKey), a person through a connected OAuth client
// (calls.PrincipalOAuth), or a service account with one of its keys
// (calls.PrincipalServiceAccount).
type principal struct {
	toolPolicy toolscope.Policy
	kind       string
	// expiresAt is the exact MCP credential deadline; nil means no fixed
	// expiry. Approval dispatch must not rely on an earlier authentication.
	expiresAt *time.Time
	// user is the person (API keys and OAuth clients).
	user dbgen.User
	// keyID and keyName are the API key or service account key used.
	keyID   uuid.UUID
	keyName string
	// scope limits a key to these gateways (empty: every gateway its owner
	// may use). An OAuth token is bound to its gateway when authenticated.
	scope []uuid.UUID
	// grant is the connected client's grant (OAuth).
	grant *dbgen.OauthGrant
	// account is the service account and its team.
	account *serviceaccounts.Principal
}

func (p principal) inScope(gatewayID uuid.UUID) bool {
	return len(p.scope) == 0 || slices.Contains(p.scope, gatewayID)
}

// authenticate checks the credential: an OAuth access token (only for its
// own gateway), a service account key or an API key. Anything else is 401
// with a WWW-Authenticate challenge pointing at the gateway's protected
// resource metadata, where OAuth clients learn how to sign in.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, slug string) (principal, bool) {
	return h.credential(w, r, slug)
}

// credential authenticates the Authorization header (see authenticate).
func (h *Handler) credential(w http.ResponseWriter, r *http.Request, slug string) (principal, bool) {
	metadata := h.AppURL + "/.well-known/oauth-protected-resource/mcp"
	if slugRE.MatchString(slug) {
		metadata += "/" + slug
	}
	raw := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(raw, " ")
	token = strings.TrimSpace(token)
	if raw == "" || !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+metadata+`"`)
		refuse(w, http.StatusUnauthorized, "Sign in with OAuth, or send a key as Authorization: Bearer omp_...")
		return principal{}, false
	}
	invalid := func(msg string) (principal, bool) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+metadata+`"`)
		refuse(w, http.StatusUnauthorized, msg)
		return principal{}, false
	}
	failed := func(err error) (principal, bool) {
		h.log().ErrorContext(r.Context(), "mcp authentication failed", "err", err, "request_id", httpx.RequestID(r.Context()))
		refuse(w, http.StatusInternalServerError, "Something went wrong")
		return principal{}, false
	}
	ctx := r.Context()
	switch {
	case oauth.IsAccessToken(token):
		if h.OAuth == nil {
			return invalid("The access token is invalid, expired or revoked. Sign in again.")
		}
		p, err := h.OAuth.Authenticate(ctx, token, slug)
		if errors.Is(err, oauth.ErrInvalidToken) {
			return invalid("The access token is invalid, expired, revoked or for another gateway. Sign in again.")
		} else if err != nil {
			return failed(err)
		}
		if err := h.OAuth.Touch(ctx, p.Grant.ID); err != nil {
			h.log().WarnContext(ctx, "could not record a connected app's use", "err", err)
		}
		g := p.Grant
		return principal{kind: calls.PrincipalOAuth, user: p.User, grant: &g, expiresAt: &p.ExpiresAt, toolPolicy: toolscope.Union(toolscope.OAuthStored(g.ToolScope))}, true
	case serviceaccounts.LooksLikeKey(token):
		if h.ServiceAccounts == nil {
			return invalid("The service account key is invalid, expired or revoked")
		}
		p, err := h.ServiceAccounts.Authenticate(ctx, token)
		if errors.Is(err, serviceaccounts.ErrInvalid) {
			return invalid("The service account key is invalid, expired or revoked, or the account is turned off")
		} else if err != nil {
			return failed(err)
		}
		if err := h.ServiceAccounts.Touch(ctx, p); err != nil {
			h.log().WarnContext(ctx, "could not record a service account key's use", "err", err)
		}
		return principal{kind: calls.PrincipalServiceAccount, keyID: p.Key.ID, keyName: p.Key.Name, scope: p.Gateways, account: &p, expiresAt: &p.Key.ExpiresAt, toolPolicy: toolscope.Intersect(toolscope.Union(toolscope.Stored(p.Key.ToolScope)), toolscope.Union(toolscope.Stored(p.Account.ToolScope)))}, true
	}
	p, err := h.Keys.Authenticate(ctx, token)
	if errors.Is(err, apikeys.ErrInvalid) {
		return invalid("The API key is invalid, expired or revoked")
	} else if err != nil {
		return failed(err)
	}
	if err := h.Keys.Touch(ctx, p.Key.ID); err != nil {
		h.log().WarnContext(ctx, "could not record API key use", "err", err)
	}
	return principal{kind: calls.PrincipalAPIKey, user: p.User, keyID: p.Key.ID, keyName: p.Key.Name, scope: p.Gateways, expiresAt: &p.Key.ExpiresAt, toolPolicy: toolscope.Union(toolscope.Stored(p.Key.ToolScope))}, true
}

// request is one exchange.
type request struct {
	h            *Handler
	w            http.ResponseWriter
	r            *http.Request
	start        time.Time
	msg          message
	principal    principal
	requestBytes int64
	gateway      dbgen.Gateway
	caller       gateways.Caller
	// outcome is the recorded outcome (metrics; "" for requests that are
	// not recorded).
	outcome string
	// forwarded: the call reached its server (call latency metric).
	forwarded bool
	// capture is the payload to store with the call record (nil: none).
	capture *capture.Input
	// scrub are a person's tokens for an oauth server, removed from the
	// server's answer should it echo them (the client and the model never
	// see them).
	scrub []string
	// personSecretUsed is the person's own secret the call carries (nil:
	// none), kept to mark it rejected when the server refuses it.
	personSecretUsed *personsecrets.Secret
	// modern: the request is of the 2026-07-28 era (era.go); clientCaps are
	// the capabilities it declared.
	modern     bool
	clientCaps map[string]json.RawMessage
	// stream is the SSE response of a streamed call (stream.go; nil: the
	// answer is one JSON object). Once set, w is the stream.
	stream *stream
}

// observe records the request's metrics.
func (rc *request) observe() {
	method, outcome := rc.msg.Method, rc.outcome
	if method == "" || len(rc.msg.ID) == 0 {
		method = "notification"
	}
	if outcome == "" {
		outcome = calls.OutcomeOK
	}
	observability.ObserveMCP(method, outcome, time.Since(rc.start))
}

// rateLimit counts the request toward every limit that applies and, over
// one, answers 429 (recorded as rate_limited for lists and calls). The
// caller's own tightest limit is shown in RateLimit-* headers.
func (rc *request) rateLimit() bool {
	h := rc.h
	if h.Limits == nil || h.RateStore == nil {
		return true
	}
	ctx := rc.r.Context()
	p := rc.principal
	sub := limits.Subject{Gateway: rc.gateway}
	switch {
	case p.account != nil:
		t := p.account.Team
		sub.ServiceAccountID, sub.ServiceAccountTeam = p.account.Account.ID, &t
	case p.grant != nil:
		sub.UserID, sub.CredentialID = p.user.ID, p.grant.ID
	default:
		sub.UserID, sub.CredentialID = p.user.ID, p.keyID
	}
	if rc.gateway.TeamID.Valid {
		t, err := dbgen.New(h.Pool).GetTeamByID(ctx, rc.gateway.TeamID.UUID)
		if err != nil {
			rc.internal(err)
			return false
		}
		sub.GatewayTeam = &t
	}
	sp := rc.span("mcp.rate_limit", trace.SpanKindInternal)
	d, err := h.Limits.Check(ctx, h.RateStore, sub)
	if err != nil {
		observability.Fail(sp, "error")
	} else if d.Exceeded != "" {
		observability.Annotate(sp, observability.AttrRateLimit.String(d.Exceeded))
	}
	sp.End()
	if err != nil {
		rc.internal(err)
		return false
	}
	retry := ratelimit.RetryAfter(d.Reset)
	if d.Own != nil {
		hd := rc.w.Header()
		hd.Set("RateLimit-Limit", strconv.FormatInt(d.Own.Limit, 10))
		hd.Set("RateLimit-Remaining", strconv.FormatInt(d.Own.Remaining, 10))
		hd.Set("RateLimit-Reset", strconv.Itoa(retry))
	}
	if d.Exceeded == "" {
		return true
	}
	observability.MCPRateLimited.WithLabelValues(d.Exceeded).Inc()
	rc.w.Header().Set("Retry-After", strconv.Itoa(retry))
	name := strings.TrimSuffix(d.Exceeded, "_per_minute")
	limitedCode := int64(codeRateLimited)
	if rc.modern {
		limitedCode = codeRateLimitedModern
	}
	n := writeRPC(rc.w, http.StatusTooManyRequests, rc.msg.ID, nil, &rpcError{Code: limitedCode,
		Message: fmt.Sprintf("Rate limit exceeded (%s); try again in %d s", strings.ReplaceAll(name, "_", " "), retry),
		Data:    map[string]any{"reason": "rate_limited", "limit": d.Exceeded, "limitPerMinute": d.LimitPerMinute, "retryAfterSeconds": retry}})
	rc.outcome = calls.OutcomeRateLimited
	if recorded(rc.msg.Method) && len(rc.msg.ID) > 0 {
		rc.record(calls.Call{Outcome: calls.OutcomeRateLimited, ErrorClass: d.Exceeded, ExposedName: rc.requestedName()}, n)
	}
	return false
}

func recorded(method string) bool {
	switch method {
	case methodToolsList, methodToolsCall, methodPromptsList, methodPromptsGet, methodResources, methodTemplates, methodRead:
		return true
	}
	return false
}

// resolveGateway finds the gateway and checks the key and the person may
// use it. An unknown or disabled gateway, a team gateway of an archived
// team, one the key is not limited to, or one they may not use, is 404
// (recorded as denied for lists and calls of an existing gateway).
func (rc *request) resolveGateway(slug string) bool {
	return rc.resolveGatewayAttempt(slug, nil)
}

// prior is the explicit live-check record. Before transport its IdentitySent
// is nil; only a completed forwarding attempt supplies attempted-call metadata.
func (rc *request) resolveGatewayAttempt(slug string, prior *calls.Call) bool {
	ctx := rc.r.Context()
	g, err := rc.h.Gateways.Resolve(ctx, slug)
	if err != nil {
		if !isNotFound(err) {
			rc.liveInternal(err, prior)
			return false
		}
		refuse(rc.w, http.StatusNotFound, "Gateway not found")
		if prior != nil {
			rec := *prior
			rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "gateway_not_found"
			rc.record(rec, 0)
		}
		return false
	}
	rc.gateway = g
	denied := ""
	if !rc.principal.inScope(g.ID) {
		denied = DeniedKeyScope
	} else if denied, err = rc.h.Gateways.Unserved(ctx, g); err != nil {
		rc.liveInternal(err, prior)
		return false
	}
	if denied == "" {
		var c gateways.Caller
		if sa := rc.principal.account; sa != nil {
			c, err = rc.h.Gateways.ServiceAccountCaller(ctx, g, sa.Team.ID, sa.Account.Role)
		} else {
			c, err = rc.h.Gateways.CallerOf(ctx, g, rc.principal.user)
		}
		if err != nil {
			rc.liveInternal(err, prior)
			return false
		}
		rc.caller = c
		if !c.Allowed() {
			denied = "no_access"
		}
	}
	if denied == "" {
		return true
	}
	n := int64(0)
	if rc.msg.Method != "" {
		n = writeRPC(rc.w, http.StatusNotFound, rc.msg.ID, nil, &rpcError{Code: codeRefused, Message: "Gateway not found"})
	} else {
		refuse(rc.w, http.StatusNotFound, "Gateway not found")
	}
	if recorded(rc.msg.Method) && len(rc.msg.ID) > 0 {
		rec := calls.Call{ExposedName: rc.requestedName()}
		if prior != nil {
			rec = *prior
		}
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, denied
		rc.record(rec, n)
	}
	return false
}

func isNotFound(err error) bool {
	e, ok := apperr.As(err)
	return ok && e.Status == http.StatusNotFound
}

func (rc *request) internal(err error) {
	rc.outcome = "error"
	if errors.Is(err, context.Canceled) && rc.r.Context().Err() != nil {
		// The client went away (a probe that gave up, a closed session): not
		// the gateway's failure.
		rc.h.log().InfoContext(rc.r.Context(), "mcp request cancelled by the client", "request_id", httpx.RequestID(rc.r.Context()))
	} else {
		rc.h.log().ErrorContext(rc.r.Context(), "mcp request failed", "err", err, "request_id", httpx.RequestID(rc.r.Context()))
	}
	writeRPC(rc.w, http.StatusInternalServerError, rc.msg.ID, nil, &rpcError{Code: codeInternal, Message: "Something went wrong"})
}

// clientName is clientInfo.name when this request carries it (initialize,
// or the _meta of 2026-07-28 requests).
func (rc *request) clientName() string {
	var p struct {
		ClientInfo *struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(rc.msg.Params) == 0 || json.Unmarshal(rc.msg.Params, &p) != nil {
		return ""
	}
	if p.ClientInfo != nil {
		return p.ClientInfo.Name
	}
	var info struct {
		Name string `json:"name"`
	}
	if raw, ok := p.Meta[metaClientInfo]; ok && json.Unmarshal(raw, &info) == nil {
		return info.Name
	}
	return ""
}

// requestedName is params.name of a call, or params.uri of a read, for
// records (bounded by calls.Record).
func (rc *request) requestedName() string {
	var p struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	switch rc.msg.Method {
	case methodToolsCall, methodPromptsGet:
		_ = json.Unmarshal(rc.msg.Params, &p)
		return p.Name
	case methodRead:
		_ = json.Unmarshal(rc.msg.Params, &p)
		return p.URI
	}
	return ""
}

// record stores the exchange's metadata, and its captured payload when the
// call was forwarded and the gateway or server captures payloads.
func (rc *request) record(c calls.Call, responseBytes int64) {
	rc.outcome = c.Outcome
	c.RequestID, c.Method, c.Gateway = httpx.RequestID(rc.r.Context()), rc.msg.Method, rc.gateway
	p := rc.principal
	c.PrincipalKind, c.APIKeyID, c.KeyName = p.kind, p.keyID, p.keyName
	switch {
	case p.account != nil:
		c.ServiceAccountID, c.ServiceAccountName, c.ServiceAccountTeamID = p.account.Account.ID, p.account.Account.Name, p.account.Team.ID
	case p.grant != nil:
		c.UserID, c.OAuthGrantID, c.OAuthClientName, c.OAuthClientKind = p.user.ID, p.grant.ID, p.grant.ClientName, p.grant.ClientKind
	default:
		c.UserID = p.user.ID
	}
	c.ClientName = rc.clientName()
	c.TraceID = observability.SampledTraceID(rc.r.Context())
	if rc.stream != nil {
		responseBytes = rc.stream.bytes() // progress events and the response
	}
	c.Latency, c.RequestBytes, c.ResponseBytes = time.Since(rc.start), rc.requestBytes, responseBytes
	ctx, cancel := context.WithTimeout(context.WithoutCancel(rc.r.Context()), 5*time.Second)
	defer cancel()
	if rc.forwarded && c.Server != nil {
		observability.ObserveCall(rc.gateway.Slug, c.Server.Slug, c.Latency)
	}
	var after calls.After
	var prepared *capture.Prepared
	if rc.capture != nil && rc.h.Capture != nil {
		var err error
		if prepared, err = rc.h.Capture.Prepare(ctx, *rc.capture); err != nil {
			rc.h.Capture.Failed(ctx, err)
		} else {
			after = rc.h.Capture.Hook(prepared)
		}
		rc.capture = nil
	}
	captureErr, err := calls.Record(ctx, rc.h.Pool, c, after)
	if err != nil {
		rc.h.log().WarnContext(ctx, "could not record an MCP call", "err", err, "request_id", c.RequestID)
	} else if prepared != nil {
		rc.h.Capture.Recorded(ctx, prepared, captureErr)
	}
	rc.h.log().DebugContext(ctx, "mcp call", "gateway", rc.gateway.Slug, "method", c.Method, "name", c.ExposedName,
		"outcome", c.Outcome, "error_class", c.ErrorClass, "latency_ms", c.Latency.Milliseconds(), "request_id", c.RequestID)
}

func (rc *request) reply(result any) int64 {
	return writeRPC(rc.w, http.StatusOK, rc.msg.ID, rc.shape(result), nil)
}

func (rc *request) fail(code int64, msg string) int64 {
	return writeRPC(rc.w, http.StatusOK, rc.msg.ID, nil, &rpcError{Code: code, Message: msg})
}

func (rc *request) failData(code int64, msg string, data any) int64 {
	return writeRPC(rc.w, http.StatusOK, rc.msg.ID, nil, &rpcError{Code: code, Message: msg, Data: data})
}

func (rc *request) dispatch() {
	switch rc.msg.Method {
	case methodInitialize:
		rc.initialize()
	case methodDiscover:
		if rc.modern {
			rc.discover()
		} else {
			rc.methodNotFound()
		}
	case methodPing:
		if rc.modern {
			// Removed in 2026-07-28.
			rc.methodNotFound()
			return
		}
		rc.reply(struct{}{})
	case methodToolsList:
		rc.list(upstream.KindTool, "tools")
	case methodPromptsList:
		rc.list(upstream.KindPrompt, "prompts")
	case methodToolsCall:
		rc.call(upstream.KindTool)
	case methodPromptsGet:
		rc.call(upstream.KindPrompt)
	case methodResources, methodTemplates, methodRead:
		has, err := rc.hasResources()
		switch {
		case err != nil:
			rc.internal(err)
		case !has:
			rc.methodNotFound()
		case rc.msg.Method == methodResources:
			rc.list(upstream.KindResource, "resources")
		case rc.msg.Method == methodTemplates:
			rc.list(upstream.KindResourceTemplate, "resourceTemplates")
		default:
			rc.read()
		}
	default:
		rc.methodNotFound()
	}
}

// methodNotFound answers an unknown method: 200 as always, and 404 in the
// modern era (streamable-http, "Protocol Version Header").
func (rc *request) methodNotFound() {
	status := http.StatusOK
	if rc.modern {
		status = http.StatusNotFound
	}
	writeRPC(rc.w, status, rc.msg.ID, nil, &rpcError{Code: codeMethodNotFound, Message: "Method not found: " + clip(rc.msg.Method, 100)})
}

// hasResources reports whether the gateway selects any resource or
// resource template (whether or not served now): only then does it
// advertise and serve the resources methods.
func (rc *request) hasResources() (bool, error) {
	all, err := rc.h.Gateways.Offers(rc.r.Context(), rc.gateway, rc.caller)
	if err != nil {
		return false, err
	}
	for _, o := range all {
		if gateways.IsResourceKind(o.Capability.Kind) {
			return true, nil
		}
	}
	return false, nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// initialize negotiates the protocol version (the client's when supported,
// else the newest) and advertises tools and prompts, and resources when the
// gateway selects any (no subscriptions).
func (rc *request) initialize() {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(rc.msg.Params) > 0 && json.Unmarshal(rc.msg.Params, &p) != nil {
		rc.fail(codeInvalidParams, "Invalid initialize parameters")
		return
	}
	version := protocolVersions[0]
	if slices.Contains(protocolVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	caps, err := rc.capabilities()
	if err != nil {
		rc.internal(err)
		return
	}
	rc.reply(map[string]any{
		"protocolVersion": version,
		"capabilities":    caps,
		"serverInfo":      map[string]any{"name": rc.gateway.Slug, "title": rc.gateway.Name, "version": buildinfo.Version},
	})
}

// capabilities are what the gateway advertises to this caller: tools and
// prompts, and resources when the gateway selects any (no subscriptions, no
// list change notifications).
func (rc *request) capabilities() (map[string]any, error) {
	caps := map[string]any{
		"tools":   map[string]any{"listChanged": false},
		"prompts": map[string]any{"listChanged": false},
	}
	has, err := rc.hasResources()
	if err != nil {
		return nil, err
	}
	if has {
		caps["resources"] = map[string]any{"listChanged": false, "subscribe": false}
	}
	return caps, nil
}

// offers reads what the caller may use of kind now, by exposed name.
func (rc *request) offers(kind string) ([]gateways.Offer, error) {
	sp := rc.span("mcp.authorize", trace.SpanKindInternal)
	all, err := rc.h.Gateways.Offers(rc.r.Context(), rc.gateway, rc.caller)
	sp.End()
	if err != nil {
		return nil, err
	}
	out := make([]gateways.Offer, 0, len(all))
	for _, o := range all {
		if o.Capability.Kind == kind {
			if o.Allowed && kind == upstream.KindTool && !rc.principal.toolPolicy.Allows(toolscope.Class(o.Capability.ToolClass), o.ExposedName) {
				o.Allowed = false
				o.Denied = gateways.DeniedToolScope
			}
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b gateways.Offer) int { return strings.Compare(a.ExposedName, b.ExposedName) })
	return out, nil
}

// listed is a stored definition with the exposed name (tools, prompts) or
// URI (resources: uri, templates: uriTemplate); a resource's own name,
// title, description and mimeType stay as approved.
func listed(o gateways.Offer) (json.RawMessage, error) { return listedFor(o, false) }

// listedFor is listed for an era: the modern era allows any JSON Schema as
// outputSchema, so it is passed through; legacy clients get only object
// schemas.
func listedFor(o gateways.Offer, modern bool) (json.RawMessage, error) {
	def := map[string]json.RawMessage{}
	raw := o.EffectiveDefinition
	if len(raw) == 0 {
		raw = o.Capability.Definition
	} // callers constructing an uncurated offer
	if err := json.Unmarshal(raw, &def); err != nil {
		return nil, err
	}
	exposed, _ := json.Marshal(o.ExposedName)
	switch o.Capability.Kind {
	case upstream.KindResource:
		def["uri"] = exposed
	case upstream.KindResourceTemplate:
		def["uriTemplate"] = exposed
	default:
		def["name"] = exposed
	}
	if o.Capability.Kind == upstream.KindTool && o.Capability.ToolClass != nil {
		annotations := map[string]json.RawMessage{}
		if err := json.Unmarshal(def["annotations"], &annotations); err != nil || annotations == nil {
			annotations = map[string]json.RawMessage{}
		}
		readOnly, _ := json.Marshal(*o.Capability.ToolClass == registry.ClassRead)
		destructive, _ := json.Marshal(*o.Capability.ToolClass == registry.ClassDestructive)
		annotations["readOnlyHint"], annotations["destructiveHint"] = readOnly, destructive
		def["annotations"], _ = json.Marshal(annotations)
	}
	delete(def, "_meta")
	if raw, ok := def["outputSchema"]; ok && !modern && !objectSchema(raw) {
		// The MCP schema requires an outputSchema of type "object"; strict
		// clients reject the whole list when one isn't (GitHub's server
		// lists ["null","array"] and oneOf schemas). Without it, results
		// still carry structuredContent, just unvalidated by the client.
		delete(def, "outputSchema")
	}
	return json.Marshal(def)
}

// objectSchema reports whether a tool's outputSchema has "type": "object",
// as the MCP schema requires.
func objectSchema(raw json.RawMessage) bool {
	var s struct {
		Type json.RawMessage `json:"type"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	var t string
	return json.Unmarshal(s.Type, &t) == nil && t == "object"
}

// list serves tools/list, prompts/list, resources/list or
// resources/templates/list from the approved definitions, paged by size;
// the cursor is the last exposed name (or URI) of the page.
func (rc *request) list(kind, key string) {
	var p struct {
		Cursor string `json:"cursor"`
	}
	if len(rc.msg.Params) > 0 && json.Unmarshal(rc.msg.Params, &p) != nil {
		n := rc.fail(codeInvalidParams, "Invalid list parameters")
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_params"}, n)
		return
	}
	after := ""
	if p.Cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(p.Cursor)
		if err != nil || len(b) == 0 {
			n := rc.fail(codeInvalidParams, "Invalid cursor")
			rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_cursor"}, n)
			return
		}
		after = string(b)
	}
	offers, err := rc.offers(kind)
	if err != nil {
		rc.internal(err)
		return
	}
	items := []json.RawMessage{}
	size, last, next := 0, "", ""
	for _, o := range offers {
		if !o.Allowed || (after != "" && o.ExposedName <= after) {
			continue
		}
		def, err := listedFor(o, rc.modern)
		if err != nil {
			rc.internal(err)
			return
		}
		if size+len(def) > listPageBytes && len(items) > 0 {
			next = base64.RawURLEncoding.EncodeToString([]byte(last))
			break
		}
		size, last = size+len(def), o.ExposedName
		items = append(items, def)
	}
	result := map[string]any{key: items}
	if next != "" {
		result["nextCursor"] = next
	}
	rc.cacheable(result, listTTLms)
	n := rc.reply(result)
	rc.record(calls.Call{Outcome: calls.OutcomeOK}, n)
}
