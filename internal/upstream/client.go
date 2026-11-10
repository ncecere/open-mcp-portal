// Package upstream is the guarded MCP client the gateway uses to reach the
// remote MCP servers teams register (adapted from Grounded's
// internal/mcpclient; docs/registry.md).
//
// It speaks Streamable HTTP only, in the era each server speaks (era.go): the
// stateless protocol 2026-07-28 (server/discover) when the server is of it, the
// initialize handshake for older servers, learned once per server and cached.
// Discovery and legacy servers go through the official Go SDK, advertising no
// client capabilities; calls to modern servers are plain requests (modern.go,
// forward.go) that declare exactly the elicitation the downstream client did
// and relay input_required results untouched. Every exchange goes through the
// address rule in guard.go. The transport sits behind Target and Client so
// gateway-hosted servers can be added later without changing the registry
// (docs/decisions.md, decision 10).
package upstream

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
)

// DefaultMaxResponseBytes caps one HTTP response from a server.
const DefaultMaxResponseBytes = 1 << 20

// Client reaches MCP servers.
type Client struct {
	// AllowPrivate is the development allowance (DEV_AUTH on a loopback
	// APP_URL): private, loopback and link-local addresses, and http for
	// loopback hosts.
	AllowPrivate bool
	// Networks is the allowlist of internal networks and hosts in force,
	// read at every check and dial (nil: none, so public addresses only).
	Networks NetworkPolicy
	// Dial connects to an address the rule approved (nil: a net.Dialer with
	// a 10s timeout). Tests replace it to reach a local server that stands
	// in for an allowlisted address.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// MaxResponseBytes caps one HTTP response (DefaultMaxResponseBytes when 0).
	MaxResponseBytes int64
	Log              *slog.Logger
	// Lookup resolves host names (nil: the system resolver). Tests replace it.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Eras remembers the protocol era learned for each server (era.go; nil:
	// every call probes).
	Eras *EraCache
	// Protection bounds active forwards and circuit state per registered server
	// in this replica. Nil initializes the standard bounded controller once.
	Protection *Protection
	// OnCircuitState receives only a registered target's bounded metric facts.
	// Configure before use; callbacks run outside the controller's mutex.
	OnCircuitState func(Target, float64)
	protectionOnce sync.Once
	retryPause     func(context.Context, time.Duration) error // deterministic tests; nil uses cancellable timers

	// nextID numbers the JSON-RPC requests of the modern era.
	nextID atomic.Int64
}

func (c *Client) maxResponse() int64 {
	if c.MaxResponseBytes > 0 {
		return c.MaxResponseBytes
	}
	return DefaultMaxResponseBytes
}

func (c *Client) resolve() resolver {
	if c.Lookup != nil {
		return c.Lookup
	}
	return defaultResolver
}

func (c *Client) log() *slog.Logger {
	if c.Log == nil {
		return slog.Default()
	}
	return c.Log
}

// Endpoint is the network identity of an independently configured extra.
// Provider/person/machine credentials and TLS are deliberately not representable.
type Endpoint struct {
	ID, URL                       string
	Credentials                   []Credential
	IdentityHeader, IdentityValue string
}

// Target is where and how to reach one server.
type Target struct {
	URL       string
	Endpoints []Endpoint // ordered extras; Forward only, never implicit discovery routing
	// Credentials are the server's own static credential parts (header,
	// bearer, basic and query; credentials.go), sent on every request to it.
	Credentials []Credential
	// PersonSecret is the bare value of a person's own secret when
	// Credentials carries it (a person_secret server, decision 72): the part
	// in Credentials holds the prefix too, so the bare value is named here for
	// Secrets and for redaction.
	PersonSecret string
	// IdentityHeader and IdentityValue carry the caller's signed identity
	// on forwarded calls (empty for discovery and health checks). The
	// gateway never forwards a client's own credential.
	IdentityHeader, IdentityValue string
	// Provider and ProviderToken are a person's delegated credential (the
	// auth provider's slug and the bare access token), sent in
	// MCP-Gateway-Provider and MCP-Gateway-Provider-Token only on forwarded
	// calls whose capability requires that provider (decision 27).
	Provider, ProviderToken string
	// BearerToken is a person's own token for an MCP server in oauth mode
	// (docs/phase7-upstream-oauth.md), sent as Authorization: Bearer only to
	// that server's URL. The identity token then goes in
	// MCP-Gateway-Identity.
	BearerToken string
	// ParamHeaders are a tools/call's Mcp-Param-* headers (ParamHeaders),
	// added only to the tools/call request itself.
	ParamHeaders map[string]string
	// BeforeTransport runs immediately before each outbound MCP HTTP
	// exchange, including negotiation and session cleanup. The bool is true
	// only for a single-dispatch JSON-RPC POST: tools/call or a task lifecycle
	// method (tasks/get, tasks/update, tasks/cancel). An error prevents the exchange;
	// errors.Is/As on the returned error can recover its cause. It may be
	// called concurrently by the SDK and must be safe for concurrent use.
	BeforeTransport func(context.Context, bool) error
	// BeforeAttempt runs before negotiation/transport for each forwarded
	// operation attempt, so quota/authority refusal precedes approval spend.
	BeforeAttempt func(context.Context, int) error
	// MaxConcurrent is a fail-fast replica-local forward cap (0: unlimited).
	MaxConcurrent    int32
	ServerSlug       string
	forwarding       bool     // inspect only MCP forwards, never OAuth token requests
	redactionSecrets []string // prior endpoints' values: scrub only, never send
	// NoReplay permits at most one tools/call transport attempt per Forward,
	// even if authorization fails or the response is lost. Negotiation may
	// still recover before that attempt. This does not provide exactly-once
	// execution: a failed exchange may have executed on the server.
	NoReplay bool
	// Timeout bounds the whole exchange (connect and every list page).
	Timeout time.Duration
	// ServerID names the registered server, for the era cache (empty: the
	// URL alone).
	ServerID string
	// MaxBody overrides the cap on one HTTP response body (0: the client's
	// MaxResponseBytes); streamed calls get more room for progress events.
	MaxBody int64
	// TLS is the server's own TLS settings: a CA bundle that replaces the
	// system roots for it and a client certificate for mTLS (tls.go; nil: the
	// system roots and no client certificate). Host name verification and TLS
	// 1.2 as the minimum apply either way.
	TLS *TLSIdentity
}

// session is one connection to a server.
type session struct {
	cs   *mcp.ClientSession
	ex   *exchange
	done func()
}

func (s *session) close() {
	_ = s.cs.Close()
	s.done()
}

// open connects to a server for discovery in the era it speaks (era.go):
// server/discover (2026-07-28) or the initialize handshake for older servers.
func (c *Client) open(ctx context.Context, t Target) (*session, Protocol, error) {
	proto, cached, err := c.negotiate(ctx, t)
	if err != nil {
		return nil, Protocol{}, err
	}
	sess, stale, err := c.connect(ctx, t, proto, nil)
	if err != nil && cached && stale {
		c.ForgetEra(t)
		if proto, _, err = c.negotiate(ctx, t); err != nil {
			return nil, Protocol{}, err
		}
		sess, _, err = c.connect(ctx, t, proto, nil)
	}
	if err != nil {
		return nil, Protocol{}, err
	}
	return sess, c.learned(t, sess.cs, proto), nil
}

// learned is the protocol a session actually negotiated, remembered.
func (c *Client) learned(t Target, cs *mcp.ClientSession, was Protocol) Protocol {
	p := was
	if res := cs.InitializeResult(); res != nil && res.ProtocolVersion != "" {
		p = Protocol{Era: EraLegacy, Version: res.ProtocolVersion}
		if res.ProtocolVersion >= ModernVersion {
			p.Era = EraModern
		}
	}
	c.remember(t, p)
	return p
}

// connect opens an SDK session pinned to an era: the SDK would otherwise try
// discover and then fall back to initialize on any error, which is not the
// rule in era.go. The portal declares no client capability (no roots,
// sampling or elicitation) and refuses multi-round-trip input requests here:
// sessions are for discovery and legacy servers. stale: it failed the way a
// server of another era fails.
func (c *Client) connect(ctx context.Context, t Target, proto Protocol, onProgress func(context.Context, *mcp.ProgressNotificationClientRequest)) (*session, bool, error) {
	ex := &exchange{}
	hc, done := c.httpClient(t, ex)
	client := mcp.NewClient(&mcp.Implementation{Name: "open-mcp-portal", Title: "Open MCP Portal", Version: buildinfo.Version}, &mcp.ClientOptions{
		Logger:                      slog.New(slog.DiscardHandler),
		Capabilities:                &mcp.ClientCapabilities{},
		MultiRoundTrip:              &mcp.MultiRoundTripOptions{Disabled: true},
		ProgressNotificationHandler: onProgress,
	})
	tr := &mcp.StreamableClientTransport{Endpoint: t.URL, HTTPClient: hc, MaxRetries: -1, DisableStandaloneSSE: true,
		MaxEventSize: int(c.bodyCap(t))}
	version := legacyOffer
	if proto.Era == EraModern {
		version = proto.Version
		if version == "" {
			version = ModernVersion
		}
	}
	cs, err := client.Connect(ctx, tr, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		stale := false
		if m := parseRPC([]byte(ex.lastDetail())); modernError(ex.lastStatus(), m) && proto.Era == EraLegacy {
			stale = true
		}
		if st := ex.lastStatus(); proto.Era == EraLegacy && (st == http.StatusBadRequest || st == http.StatusNotFound || st == http.StatusMethodNotAllowed) {
			stale = stale || methodNotFoundBody(ex.lastDetail())
		}
		done()
		return nil, stale, c.classify(ctx, t, ex, err)
	}
	return &session{cs: cs, ex: ex, done: done}, false, nil
}

// methodNotFoundBody reports whether an error body is a JSON-RPC "method not
// found" (a modern server answering initialize).
func methodNotFoundBody(body string) bool {
	m := parseRPC([]byte(body))
	return m != nil && m.Error != nil && m.Error.Code == codeMethodNotFound
}

func (c *Client) bodyCap(t Target) int64 {
	if t.MaxBody > 0 {
		return t.MaxBody
	}
	return c.maxResponse()
}
