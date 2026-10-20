package agentidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Fetching and caching a platform's JWKS (docs/agent-platforms.md "Keys").
//
// The fetch goes through the portal's outbound address guard
// (upstream.Client: public addresses, or hosts a platform admin or the
// deployment allowed; never loopback, link-local or metadata addresses;
// connections pinned to the approved addresses), refuses redirects and
// proxies, and is bounded in time (fetchTimeout), size (maxJWKSBytes) and
// shape (status 200, a JSON content type, at most maxKeys usable keys).
//
// Keys are cached per replica for min(Cache-Control max-age, maxCacheTTL),
// at least minCacheTTL and, without a max-age, defaultCacheTTL. A token with
// a kid that isn't cached causes one refetch, at most maxUnknownRefetches a
// minute for the platform, so a flood of unknown kids costs a bounded number
// of fetches (not one per request). When a refresh fails the cached keys keep
// serving for staleMax past their expiry (stale-while-error) and then
// nothing verifies (fail closed); a failed fetch is not retried for
// failureBackoff. Every replica has its own cache, so the platform sees at
// most one fetch per replica per interval.
const (
	fetchTimeout         = 5 * time.Second
	maxJWKSBytes         = 64 << 10
	maxKeys              = 32
	maxKidLen            = 128
	minCacheTTL          = 10 * time.Second
	defaultCacheTTL      = 60 * time.Second
	maxCacheTTL          = 5 * time.Minute
	staleMax             = 15 * time.Minute
	staleLogEvery        = time.Minute // at most one stale-keys warning a minute per platform
	failureBackoff       = 10 * time.Second
	maxUnknownRefetches  = 2
	unknownRefetchWindow = time.Minute
)

// JWKS fetch problems (the platform page's "last fetch" and the Test result).
const (
	FetchNotAllowed  = "not_allowed"
	FetchRedirect    = "redirect"
	FetchTimeout     = "timeout"
	FetchUnreachable = "unreachable"
	FetchStatus      = "http_status"
	FetchContentType = "content_type"
	FetchTooLarge    = "too_large"
	FetchInvalid     = "invalid_json"
	FetchNoKeys      = "no_usable_keys"
)

// FetchError is a failed JWKS fetch.
type FetchError struct {
	// Code is one of the Fetch* values (bounded: it is stored and shown).
	Code string
	// HTTPStatus is the platform's answer for FetchStatus.
	HTTPStatus int
}

func (e *FetchError) Error() string {
	if e.HTTPStatus > 0 {
		return "jwks fetch: " + e.Code + " (HTTP " + strconv.Itoa(e.HTTPStatus) + ")"
	}
	return "jwks fetch: " + e.Code
}

var errRedirect = errors.New("agentidentity: redirects are not followed")

// keySet is a fetched JWKS: the usable ES256 public keys by kid.
type keySet struct {
	keys      map[string]*ecdsa.PublicKey
	kids      []string // sorted
	url       string
	fetchedAt time.Time
	expiresAt time.Time
}

// platformKeys is one platform's cache on this replica.
type platformKeys struct {
	// fetchMu serialises fetches (one at a time per platform).
	fetchMu sync.Mutex

	mu          sync.Mutex
	set         *keySet
	lastFailure time.Time
	unknown     []time.Time // when unknown-kid refetches ran
	staleLogged time.Time   // when the stale-keys warning was last logged
}

func (s *Service) keysOf(id uuid.UUID) *platformKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	pk, ok := s.cache[id]
	if !ok {
		pk = &platformKeys{}
		s.cache[id] = pk
	}
	return pk
}

// httpClient is the guarded client of one fetch.
func (s *Service) httpClient() (*http.Client, func()) {
	var tlsCfg *tls.Config
	if s.TLS != nil {
		tlsCfg = s.TLS.Clone()
	}
	tr := &http.Transport{
		Proxy:                 nil, // never HTTP(S)_PROXY: the dialer must see the real destination
		DialContext:           s.Client.GuardedDial(),
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   fetchTimeout,
		ResponseHeaderTimeout: fetchTimeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}, tr.CloseIdleConnections
}

var maxAgeRE = regexp.MustCompile(`(?i)(?:^|[\s,])max-age=(\d{1,9})(?:$|[\s,;])`)

// cacheTTL is how long a response may be cached.
func cacheTTL(cacheControl string) time.Duration {
	lower := strings.ToLower(cacheControl)
	ttl := defaultCacheTTL
	if m := maxAgeRE.FindStringSubmatch(cacheControl); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		ttl = time.Duration(n) * time.Second
	} else if strings.Contains(lower, "no-store") || strings.Contains(lower, "no-cache") {
		ttl = 0
	}
	return min(max(ttl, minCacheTTL), maxCacheTTL)
}

// fetchJWKS reads the platform's key set. It never caches or stores anything.
func (s *Service) fetchJWKS(ctx context.Context, p dbgen.AgentPlatform) (*keySet, *FetchError) {
	// The allowlist may have changed since the URL was saved, and a row may
	// predate the https rule: both are checked again here.
	if _, err := s.checkJWKSURL(ctx, p.JwksUrl); err != nil {
		return nil, &FetchError{Code: FetchNotAllowed}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout+time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.JwksUrl, nil)
	if err != nil {
		return nil, &FetchError{Code: FetchUnreachable}
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	req.Header.Set("User-Agent", "open-mcp-portal")
	hc, done := s.httpClient()
	defer done()
	res, err := hc.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, upstream.ErrBlockedAddress):
			return nil, &FetchError{Code: FetchNotAllowed}
		case errors.Is(err, errRedirect):
			return nil, &FetchError{Code: FetchRedirect}
		case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
			return nil, &FetchError{Code: FetchTimeout}
		}
		return nil, &FetchError{Code: FetchUnreachable}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, &FetchError{Code: FetchStatus, HTTPStatus: res.StatusCode}
	}
	if mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || (mt != "application/json" && mt != "application/jwk-set+json") {
		return nil, &FetchError{Code: FetchContentType}
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, &FetchError{Code: FetchUnreachable}
	}
	if len(body) > maxJWKSBytes {
		return nil, &FetchError{Code: FetchTooLarge}
	}
	keys, kids, err := parseJWKS(body)
	if err != nil {
		return nil, &FetchError{Code: FetchInvalid}
	}
	if len(keys) == 0 {
		return nil, &FetchError{Code: FetchNoKeys}
	}
	now := s.now()
	return &keySet{keys: keys, kids: kids, url: p.JwksUrl, fetchedAt: now, expiresAt: now.Add(cacheTTL(res.Header.Get("Cache-Control")))}, nil
}

// parseJWKS keeps the usable keys of a JWKS document: public P-256 keys with
// a kid, for signing (use sig or none) with ES256 (alg ES256 or none). Keys
// of another type, private keys, keys without a kid and kids that appear
// twice are dropped, never trusted.
func parseJWKS(body []byte) (map[string]*ecdsa.PublicKey, []string, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Keys == nil {
		return nil, nil, errors.New("not a JWKS")
	}
	keys := map[string]*ecdsa.PublicKey{}
	dup := map[string]bool{}
	for _, raw := range doc.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil {
			continue
		}
		pub, ok := k.Key.(*ecdsa.PublicKey)
		switch {
		case !ok || !k.IsPublic() || !k.Valid() || pub.Curve != elliptic.P256():
			continue
		case k.KeyID == "" || len(k.KeyID) > maxKidLen:
			continue
		case k.Use != "" && k.Use != "sig", k.Algorithm != "" && k.Algorithm != string(jose.ES256):
			continue
		}
		if _, seen := keys[k.KeyID]; seen {
			dup[k.KeyID] = true
			continue
		}
		keys[k.KeyID] = pub
	}
	for kid := range dup {
		delete(keys, kid)
	}
	if len(keys) > maxKeys {
		return nil, nil, errors.New("too many keys")
	}
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	return keys, kids, nil
}

// unknownBudget reports whether another unknown-kid refetch may run now, and
// forgets the ones outside the window. The caller holds pk.mu.
func (pk *platformKeys) unknownBudget(now time.Time) bool {
	pk.unknown = slices.DeleteFunc(pk.unknown, func(t time.Time) bool { return now.Sub(t) >= unknownRefetchWindow })
	return len(pk.unknown) < maxUnknownRefetches
}

// keyFor returns the public key for kid of platform p, fetching the JWKS
// when the cache has none or doesn't know the kid (within the limits above).
// The errors are *Rejection.
func (s *Service) keyFor(ctx context.Context, p dbgen.AgentPlatform, kid string) (*ecdsa.PublicKey, error) {
	pk := s.keysOf(p.ID)
	now := s.now()
	set := pk.snapshot(p.JwksUrl)
	if set != nil && now.Before(set.expiresAt) {
		if k, ok := set.keys[kid]; ok {
			return k, nil
		}
	}
	// Needs a fetch (or a verdict that none is allowed): one at a time.
	pk.fetchMu.Lock()
	defer pk.fetchMu.Unlock()
	now = s.now()
	set = pk.snapshot(p.JwksUrl)
	fresh := set != nil && now.Before(set.expiresAt)
	if fresh {
		if k, ok := set.keys[kid]; ok {
			return k, nil // another request fetched it meanwhile
		}
	}
	pk.mu.Lock()
	failedRecently := !pk.lastFailure.IsZero() && now.Sub(pk.lastFailure) < failureBackoff
	allowed := true
	if fresh {
		// An unknown kid: a refetch, within the budget.
		if allowed = pk.unknownBudget(now); allowed {
			pk.unknown = append(pk.unknown, now)
		}
	} else {
		allowed = !failedRecently
	}
	pk.mu.Unlock()
	if !fresh && !allowed {
		return s.stale(pk, set, kid, now)
	}
	if fresh && !allowed {
		return nil, reject(ReasonUnknownKid, "the key id isn't published")
	}
	fetched, ferr := s.fetchJWKS(ctx, p)
	s.recordFetch(ctx, p, fetched, ferr)
	pk.mu.Lock()
	if ferr != nil {
		pk.lastFailure = now
		pk.mu.Unlock()
		if fresh {
			// A fresh set that doesn't know the kid, and no new one: unknown.
			return nil, reject(ReasonUnknownKid, "the key id isn't published")
		}
		return s.stale(pk, set, kid, now)
	}
	pk.lastFailure = time.Time{}
	pk.set = fetched
	pk.mu.Unlock()
	if k, ok := fetched.keys[kid]; ok {
		return k, nil
	}
	return nil, reject(ReasonUnknownKid, "the key id isn't published")
}

// stale serves a key from an expired set while the platform can't be
// reached, for staleMax after the set expired; later, or for a kid the set
// doesn't hold, the verification fails. The warning is logged at most once a
// minute per platform (a platform that is down would otherwise log once per
// relayed request).
func (s *Service) stale(pk *platformKeys, set *keySet, kid string, now time.Time) (*ecdsa.PublicKey, error) {
	if set != nil && now.Before(set.expiresAt.Add(staleMax)) {
		if k, ok := set.keys[kid]; ok {
			if pk.staleLogDue(now) {
				s.Log.Warn("agent platform JWKS can't be refreshed; using the cached keys", "keys", len(set.keys), "expired", set.expiresAt)
			}
			return k, nil
		}
		return nil, reject(ReasonUnknownKid, "the key id isn't published")
	}
	return nil, reject(ReasonJWKSUnavailable, "the platform's keys can't be fetched")
}

// staleLogDue reports whether the stale-keys warning is due (once a minute)
// and notes that it is being logged.
func (pk *platformKeys) staleLogDue(now time.Time) bool {
	pk.mu.Lock()
	defer pk.mu.Unlock()
	if !pk.staleLogged.IsZero() && now.Sub(pk.staleLogged) < staleLogEvery && !now.Before(pk.staleLogged) {
		return false
	}
	pk.staleLogged = now
	return true
}

func (pk *platformKeys) snapshot(url string) *keySet {
	pk.mu.Lock()
	defer pk.mu.Unlock()
	if pk.set != nil && pk.set.url != url {
		pk.set = nil // the URL was edited
	}
	return pk.set
}

// recordFetch stores the result of a fetch as the platform's last fetch (best
// effort: a failure to store never fails a verification).
func (s *Service) recordFetch(ctx context.Context, p dbgen.AgentPlatform, set *keySet, ferr *FetchError) {
	params := dbgen.SetAgentPlatformJWKSResultParams{ID: p.ID, JwksUrl: p.JwksUrl, Ok: ptrBool(ferr == nil), KeyIds: []string{}}
	if ferr != nil {
		code := ferr.Code
		params.Error = &code
	} else {
		params.KeyIds = set.kids
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := s.q.SetAgentPlatformJWKSResult(sctx, params); err != nil {
		s.Log.Warn("could not store an agent platform's JWKS fetch result", "err", err)
	}
}

func ptrBool(b bool) *bool { return &b }
