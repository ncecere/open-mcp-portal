package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Client ID Metadata Documents: a client_id that is an https URL names a
// JSON document describing the client (its name, home page, logo and
// redirect URIs). The URL is someone else's choice, so it is fetched like an
// MCP server's (internal/upstream's address guard): public addresses, and
// internal ones only when the allowlist of internal networks allows them;
// loopback, link-local and metadata addresses never (except with the
// development allowance). The connection is pinned at dial time; no
// redirects, no proxy from the environment, a short timeout and a size cap.
// Documents are cached in memory for their Cache-Control max-age, between
// a minute and an hour (10 minutes without one).
const (
	maxDocBytes     = 16 << 10
	docTimeout      = 5 * time.Second
	docCacheMin     = time.Minute
	docCacheDefault = 10 * time.Minute
	docCacheMax     = time.Hour
	maxCachedDocs   = 1000
)

var errDocRedirect = errors.New("oauth: metadata documents may not redirect")

func noRedirect(*http.Request, []*http.Request) error { return errDocRedirect }

type cachedDoc struct {
	client Client
	until  time.Time
}

// metadataDocs fetches and caches metadata documents.
type metadataDocs struct {
	client    *http.Client
	transport *http.Transport
	// devHTTP lets a document live at a plain http URL on a loopback host
	// (the development allowance: DEV_AUTH on a loopback APP_URL).
	devHTTP bool
	now     func() time.Time
	// allow is asked before every fetch that isn't answered from the cache
	// (nil: always); it limits fetches per source address (source.go).
	allow func(ctx context.Context) error
	// log is where fetches are logged (nil: slog.Default()).
	log   func() *slog.Logger
	mu    sync.Mutex
	cache map[string]cachedDoc
}

func newMetadataDocs(dial func(ctx context.Context, network, address string) (net.Conn, error), devHTTP bool) *metadataDocs {
	tr := &http.Transport{
		Proxy:                 nil, // never HTTP(S)_PROXY: the dialer must see the real destination
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   docTimeout,
		ResponseHeaderTimeout: docTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &metadataDocs{
		client:    &http.Client{Transport: tr, Timeout: docTimeout, CheckRedirect: noRedirect},
		transport: tr, devHTTP: devHTTP, now: time.Now, cache: map[string]cachedDoc{},
	}
}

// SetMetadataTLS sets the TLS configuration of metadata document fetches
// (tests: to trust a test server's certificate). The address guard stays.
func (s *Service) SetMetadataTLS(c *tls.Config) { s.docs.transport.TLSClientConfig = c }

// validMetadataURL: an https URL with a path (not just "/"), no user info,
// query or fragment, and no dot segments. With devHTTP, plain http on a
// loopback host too.
func validMetadataURL(raw string, devHTTP bool) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxURILen || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && devHTTP && loopbackHost(u.Hostname()):
	default:
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ValidClientIDURL reports whether raw can be a trusted client's ID: the
// https URL of a metadata document, with a path.
func ValidClientIDURL(raw string) bool { return validMetadataURL(raw, false) }

func docError(msg string) *Error { return pageError("invalid_client", msg) }

// get returns the client a metadata document describes.
func (d *metadataDocs) get(ctx context.Context, id string) (Client, error) {
	d.mu.Lock()
	hit, ok := d.cache[id]
	d.mu.Unlock()
	if ok && d.now().Before(hit.until) {
		return hit.client, nil
	}
	if !validMetadataURL(id, d.devHTTP) {
		return Client{}, docError("The client_id must be an https URL with a path, without a query or fragment.")
	}
	if d.allow != nil {
		if err := d.allow(ctx); err != nil {
			return Client{}, err
		}
	}
	c, ttl, err := d.fetch(ctx, id)
	if err != nil {
		return Client{}, err
	}
	d.store(id, c, ttl)
	return c, nil
}

// Fetch outcomes, as logged.
const (
	docOK             = "ok"
	docBadURL         = "bad_url"
	docBlocked        = "blocked_address"
	docRedirect       = "redirect"
	docUnreachable    = "unreachable"
	docHTTPStatus     = "http_status"
	docNotJSON        = "not_json"
	docUnreadable     = "unreadable"
	docTooLarge       = "too_large"
	docInvalidJSON    = "invalid_json"
	docIDMismatch     = "client_id_mismatch"
	docInvalidContent = "invalid_metadata"
)

// fetch reads and checks a document. Every fetch is logged at info level
// with the document's host, the HTTP status and the outcome (like MCP server
// discovery); never the document, its path or the fetch error's text.
func (d *metadataDocs) fetch(ctx context.Context, id string) (Client, time.Duration, error) {
	start := d.now()
	c, ttl, status, outcome, err := d.fetchDoc(ctx, id)
	d.logger().InfoContext(ctx, "oauth client metadata document fetched", "host", hostOf(id), "status", status,
		"outcome", outcome, "duration_ms", d.now().Sub(start).Milliseconds())
	return c, ttl, err
}

func (d *metadataDocs) logger() *slog.Logger {
	if d.log != nil {
		if l := d.log(); l != nil {
			return l
		}
	}
	return slog.Default()
}

// fetchDoc fetches a document: the client, how long to cache it, the HTTP
// status (0 without an answer) and the outcome.
func (d *metadataDocs) fetchDoc(ctx context.Context, id string) (Client, time.Duration, int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, docTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return Client{}, 0, 0, docBadURL, docError("The client_id isn't a URL the portal can fetch.")
	}
	req.Header.Set("Accept", "application/json")
	res, err := d.client.Do(req)
	if err != nil {
		if errors.Is(err, upstream.ErrBlockedAddress) {
			return Client{}, 0, 0, docBlocked, docError("The client's metadata document is on an address the portal doesn't fetch from " +
				"(loopback, link-local, or an internal network no platform admin has allowed).")
		}
		if errors.Is(err, errDocRedirect) {
			status := 0
			if res != nil { // the redirect itself, its body already closed
				status = res.StatusCode
			}
			return Client{}, 0, status, docRedirect, docError("The client's metadata document redirects, which the portal doesn't follow.")
		}
		return Client{}, 0, 0, docUnreachable, docError("The portal couldn't fetch the client's metadata document at " + hostOf(id) + ".")
	}
	defer res.Body.Close()
	status := res.StatusCode
	fail := func(outcome, msg string) (Client, time.Duration, int, string, error) {
		return Client{}, 0, status, outcome, docError(msg)
	}
	if status != http.StatusOK {
		return fail(docHTTPStatus, "The client's metadata document answered HTTP "+strconv.Itoa(status)+".")
	}
	if mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
		return fail(docNotJSON, "The client's metadata document isn't JSON (Content-Type application/json).")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDocBytes+1))
	if err != nil {
		return fail(docUnreadable, "The portal couldn't read the client's metadata document.")
	}
	if len(body) > maxDocBytes {
		return fail(docTooLarge, "The client's metadata document is larger than 16 KiB.")
	}
	var m ClientMetadata
	if err := json.Unmarshal(body, &m); err != nil {
		return fail(docInvalidJSON, "The client's metadata document isn't valid JSON.")
	}
	if m.ClientID != id {
		return fail(docIDMismatch, "The client_id in the client's metadata document must equal the document's URL.")
	}
	c, bad := m.check()
	if bad != nil {
		return fail(docInvalidContent, "The client's metadata document is invalid: "+bad.Description)
	}
	c.ID, c.Kind = id, KindMetadata
	return c, cacheFor(res.Header.Get("Cache-Control")), status, docOK, nil
}

// cacheFor is how long to keep a document: its max-age, clamped.
func cacheFor(cacheControl string) time.Duration {
	ttl := docCacheDefault
	for _, part := range strings.Split(cacheControl, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(strings.ToLower(part)), "=")
		switch k {
		case "no-store", "no-cache":
			return docCacheMin
		case "max-age":
			if n, err := strconv.Atoi(strings.Trim(v, `"`)); err == nil {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	return min(max(ttl, docCacheMin), docCacheMax)
}

// store caches a document, dropping expired entries (and, when still full,
// others) to stay bounded.
func (d *metadataDocs) store(id string, c Client, ttl time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if len(d.cache) >= maxCachedDocs {
		for k, v := range d.cache {
			if now.After(v.until) {
				delete(d.cache, k)
			}
		}
		for k := range d.cache {
			if len(d.cache) < maxCachedDocs {
				break
			}
			delete(d.cache, k)
		}
	}
	d.cache[id] = cachedDoc{client: c, until: now.Add(ttl)}
}
