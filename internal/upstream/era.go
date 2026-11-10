package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Protocol eras (docs/mcp-protocol.md, "The portal as a client").
//
// MCP 2026-07-28 removed the initialize handshake and sessions: a "modern"
// server is stateless and every request names its protocol version. Earlier
// revisions are "legacy". An upstream server speaks one or the other (or both),
// and which is a property of the server, not of a request, so the portal
// learns it once per server and remembers it for a few minutes:
//
//  1. Try modern first: a server/discover request with the modern headers.
//  2. A result (or a recognized modern JSON-RPC error: header mismatch,
//     missing capability, unsupported version, or "method not found" with
//     HTTP 404) means a modern server. An unsupported-version error lists the
//     versions it supports, and the newest one we also speak is retried.
//  3. Anything else from a 400, 404 or 405, and any other answer that isn't
//     a modern error, means a legacy server: initialize follows. That includes a
//     400 with an empty or plain-text body, which is what servers from before
//     the revision answer to the new headers. (The deprecated HTTP+SSE transport
//     isn't supported: a 404 or 405 that stays after the initialize attempt is
//     the error, not_found, it always was.)
//  4. 401, 403, 429 and 5xx are errors, never a reason to fall back.
//
// The Go SDK does its own discover-then-initialize on connect and falls back
// on any error, which would send a modern server's 400 to initialize. So the
// decision is made here, and the SDK session is pinned to it.

// Era is the family of MCP revisions a server speaks.
type Era string

const (
	// EraLegacy is 2025-11-25 and earlier: initialize, optional sessions.
	EraLegacy Era = "legacy"
	// EraModern is 2026-07-28 and later: stateless, per-request _meta.
	EraModern Era = "modern"
)

// Protocol is what was negotiated with a server.
type Protocol struct {
	Era Era
	// Version is the revision in use. For a legacy server cached before a
	// session was opened it can be empty until the first initialize.
	Version string
}

// ModernVersion is the newest revision the portal speaks as a client.
const ModernVersion = "2026-07-28"

// legacyOffer is the version offered in initialize.
const legacyOffer = "2025-11-25"

// JSON-RPC error codes of the modern era that mark a modern server.
const (
	codeHeaderMismatch      = -32020
	codeMissingCapabilities = -32021
	codeUnsupportedVersion  = -32022
	codeMethodNotFound      = -32601
)

// DefaultEraTTL is how long a learned era is trusted.
const DefaultEraTTL = 5 * time.Minute

const maxEraEntries = 4096

// EraCache remembers the era learned for each server, in memory, so every
// call doesn't probe again. The key is the server's ID with its URL: a new URL
// is a new key, and so is learned again. Entries expire after TTL, and
// a call that finds the cached era wrong forgets it.
type EraCache struct {
	// TTL is how long an entry lives (DefaultEraTTL when 0).
	TTL time.Duration

	mu  sync.Mutex
	now func() time.Time
	m   map[string]eraEntry
}

type eraEntry struct {
	p  Protocol
	at time.Time
}

// NewEraCache makes an empty cache.
func NewEraCache() *EraCache { return &EraCache{m: map[string]eraEntry{}} }

// SetClock replaces the clock (tests).
func (c *EraCache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *EraCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *EraCache) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultEraTTL
}

func (c *EraCache) get(key string) (Protocol, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || c.clock().Sub(e.at) >= c.ttl() {
		delete(c.m, key)
		return Protocol{}, false
	}
	return e.p, true
}

func (c *EraCache) put(key string, p Protocol) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]eraEntry{}
	}
	now := c.clock()
	if old, ok := c.m[key]; ok && old.p.Era == p.Era && p.Version == "" {
		p.Version = old.p.Version
	}
	if len(c.m) >= maxEraEntries {
		for k, e := range c.m {
			if now.Sub(e.at) >= c.ttl() {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxEraEntries {
			c.m = map[string]eraEntry{}
		}
	}
	c.m[key] = eraEntry{p: p, at: now}
}

func (c *EraCache) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func eraKey(t Target) string { return t.ServerID + "|" + t.URL }

func (c *Client) remember(t Target, p Protocol) {
	if c.Eras != nil {
		c.Eras.put(eraKey(t), p)
	}
}

// ForgetEra drops what is remembered about a server's era.
func (c *Client) ForgetEra(t Target) {
	if c.Eras != nil {
		c.Eras.forget(eraKey(t))
	}
}

// negotiate returns the era of a server: from the cache, else by probing.
// cached says it came from the cache (and may be stale).
func (c *Client) negotiate(ctx context.Context, t Target) (p Protocol, cached bool, err error) {
	// The policy may have changed since the URL was saved.
	if _, err := c.NormalizeURL(ctx, t.URL); err != nil {
		return Protocol{}, false, notAllowed(err)
	}
	if c.Eras != nil {
		if p, ok := c.Eras.get(eraKey(t)); ok {
			return p, true, nil
		}
	}
	p, err = c.probe(ctx, t)
	if err != nil {
		return Protocol{}, false, err
	}
	c.remember(t, p)
	return p, false, nil
}

// Negotiate learns (and remembers) the era of a server, probing when it is
// not cached.
func (c *Client) Negotiate(ctx context.Context, t Target) (Protocol, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	p, _, err := c.negotiate(ctx, t)
	return p, err
}

// modernVersions and legacyVersions are what the SDK speaks, newest first.
func modernVersions() []string {
	var out []string
	for _, v := range mcp.SupportedProtocolVersions() {
		if v >= ModernVersion {
			out = append(out, v)
		}
	}
	return out
}

func legacyVersions() []string {
	var out []string
	for _, v := range mcp.SupportedProtocolVersions() {
		if v < ModernVersion {
			out = append(out, v)
		}
	}
	return out
}

func newest(ours, theirs []string) string {
	for _, v := range ours {
		if slices.Contains(theirs, v) {
			return v
		}
	}
	return ""
}

// modernError reports whether a failed answer is a recognized modern
// JSON-RPC error (streamable-http, "Backward Compatibility"): header
// mismatch, missing capability, unsupported version, or "method not found"
// with HTTP 404.
func modernError(status int, m *rpcMessage) bool {
	if m == nil || m.Error == nil {
		return false
	}
	switch m.Error.Code {
	case codeHeaderMismatch, codeMissingCapabilities, codeUnsupportedVersion:
		return true
	case codeMethodNotFound:
		return status == http.StatusNotFound
	}
	return false
}

// errStatus stands for an HTTP status the exchange recorded; classify
// reads the status itself.
var errStatus = errors.New("upstream: unexpected HTTP status")

// probe asks a server which era it speaks.
func (c *Client) probe(ctx context.Context, t Target) (Protocol, error) {
	version := ModernVersion
	// How many times each version was tried: a server that rejects a version
	// it lists gets one more try (it may have been a passing refusal), then
	// it is an error.
	tried := map[string]int{}
	for {
		tried[version]++
		ex := &exchange{}
		hc, done := c.httpClient(t, ex)
		r, err := c.roundTrip(ctx, hc, t, rpcRequest{Method: "server/discover", Version: version,
			Params: map[string]any{"_meta": modernMeta(version, nil, Trace{}, nil)}}, nil)
		done()
		if err != nil {
			return Protocol{}, c.classify(ctx, t, ex, err)
		}
		switch {
		case r.status == http.StatusUnauthorized || r.status == http.StatusForbidden || r.status == http.StatusTooManyRequests ||
			r.status == http.StatusRequestTimeout || r.status >= 500:
			return Protocol{}, c.classify(ctx, t, ex, errStatus)
		case r.status >= 200 && r.status < 300 && r.msg != nil && r.msg.Error == nil && len(r.msg.Result) > 0:
			var res struct {
				SupportedVersions []string `json:"supportedVersions"`
			}
			if json.Unmarshal(r.msg.Result, &res) != nil || res.SupportedVersions == nil {
				return Protocol{Era: EraLegacy}, nil // a result, but not a discovery document
			}
			return selectProtocol(t, res.SupportedVersions)
		case modernError(r.status, r.msg):
			switch r.msg.Error.Code {
			case codeUnsupportedVersion:
				var data struct {
					Supported []string `json:"supported"`
				}
				_ = json.Unmarshal(r.msg.Error.Data, &data)
				if len(data.Supported) == 0 {
					return Protocol{}, rpcFailure(t, r.status, r.msg.Error)
				}
				if v := newest(modernVersions(), data.Supported); v != "" {
					if tried[v] >= 2 {
						return Protocol{}, &Error{Class: ClassBadResponse, Message: "The server doesn't accept protocol version " + v + " it lists."}
					}
					version = v
					continue
				}
				return selectProtocol(t, data.Supported)
			case codeMethodNotFound:
				// A modern server without server/discover (it is optional).
				return Protocol{Era: EraModern, Version: ModernVersion}, nil
			}
			return Protocol{}, rpcFailure(t, r.status, r.msg.Error)
		default:
			// Not a modern answer: a server from before the revision.
			return Protocol{Era: EraLegacy}, nil
		}
	}
}

// selectProtocol picks the newest revision both sides speak from a server's
// supportedVersions: a modern one first, else a legacy one.
func selectProtocol(t Target, supported []string) (Protocol, error) {
	if v := newest(modernVersions(), supported); v != "" {
		return Protocol{Era: EraModern, Version: v}, nil
	}
	if v := newest(legacyVersions(), supported); v != "" {
		return Protocol{Era: EraLegacy, Version: v}, nil
	}
	return Protocol{}, &Error{Class: ClassBadResponse, Message: fmt.Sprintf(
		"The server supports none of the protocol versions the portal speaks (it lists %s).", t.safe(strings.Join(clipList(supported, 8), ", ")))}
}

func clipList(l []string, n int) []string {
	out := make([]string, 0, min(len(l), n))
	for _, s := range l[:min(len(l), n)] {
		out = append(out, clip(s, 20))
	}
	return out
}
