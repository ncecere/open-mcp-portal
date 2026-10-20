package httpx

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// ProxyWarnEvery is the most often ProxyWatch logs its warning.
const ProxyWarnEvery = time.Minute

// ProxyWatch notices a deployment behind a proxy that never told the
// portal about it (docs/deploy.md, TRUSTED_PROXIES). With TRUSTED_PROXIES
// empty, ClientIP ignores X-Forwarded-For (safe), so behind an ingress every
// request appears to come from the ingress: per-address rate limits and
// audit addresses name the proxy. That is silent, so a request that carries
// X-Forwarded-For or Forwarded from a peer outside TRUSTED_PROXIES is counted
// and logged once a minute at most. Nothing about the request changes.
type ProxyWatch struct {
	log *slog.Logger
	now func() time.Time

	mu         sync.Mutex
	lastWarned time.Time
	total      int64
}

// NewProxyWatch returns a watch logging to log (nil: the default logger).
func NewProxyWatch(log *slog.Logger) *ProxyWatch {
	if log == nil {
		log = slog.Default()
	}
	return &ProxyWatch{log: log, now: time.Now}
}

// ProxyMessage is the warning's text.
const ProxyMessage = "requests carry X-Forwarded-For (or Forwarded) but TRUSTED_PROXIES is empty: client addresses " +
	"in rate limits, audit entries and logs are the proxy's; set TRUSTED_PROXIES to the ingress's network (docs/deploy.md)"

// Observe counts a request that carries a forwarding header, and logs the
// warning when the last one is a minute old. Call it only when
// TRUSTED_PROXIES is empty.
func (p *ProxyWatch) Observe(ctx context.Context, r *http.Request) {
	if p == nil || (len(r.Header.Values("X-Forwarded-For")) == 0 && len(r.Header.Values("Forwarded")) == 0) {
		return
	}
	p.mu.Lock()
	p.total++
	now := p.now()
	if !p.lastWarned.IsZero() && now.Sub(p.lastWarned) < ProxyWarnEvery {
		p.mu.Unlock()
		return
	}
	p.lastWarned = now
	total := p.total
	p.mu.Unlock()
	p.log.WarnContext(ctx, ProxyMessage, "peer", remoteAddr(r).String(), "requests_so_far", total)
}

// Total is how many requests have carried a forwarding header.
func (p *ProxyWatch) Total() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total
}
