package httpapi

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/observability"
)

// statusRecorder captures the status code while still supporting streaming
// (Flush) and connection hijacking.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijacking not supported")
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

var quietRoutes = map[string]bool{"GET /healthz": true, "GET /readyz": true}

// chain applies request IDs, security headers, panic recovery and access
// logging around the router.
func chain(mux *http.ServeMux, d Deps) http.Handler {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	// A deployment behind a proxy with TRUSTED_PROXIES empty is told once a
	// minute (httpx.ProxyWatch); a development install on a loopback APP_URL
	// is not.
	var proxies *httpx.ProxyWatch
	if len(d.Config.TrustedProxies) == 0 && !d.Config.LoopbackAppURL() {
		proxies = httpx.NewProxyWatch(log)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		proxies.Observe(r.Context(), r)
		reqID := httpx.NewID(12)
		// The request's server span (off: no span, nothing read); /mcp/ requests
		// are traced by the gateway.
		ctx, span := observability.StartHTTP(r)
		ctx, slot := observability.WithTraceSlot(ctx)
		r = r.WithContext(httpx.WithRequestID(ctx, reqID))

		h := w.Header()
		h.Set("X-Request-ID", reqID)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-Frame-Options", "DENY")

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				log.ErrorContext(r.Context(), "panic serving request",
					"panic", p, "request_id", reqID, "stack", string(debug.Stack()))
				if !rec.wrote {
					httpx.Error(rec, http.StatusInternalServerError, "internal", "Something went wrong")
				}
				rec.status = http.StatusInternalServerError
			}
			if rec.status >= 500 && httpx.ClientGone(r) {
				// The client went away first: not a server error (httpx.Internal).
				rec.status = httpx.StatusClientClosedRequest
			}
			observability.ObserveHTTP(r.Pattern, r.Method, rec.status, time.Since(start))
			span.End(r.Pattern, rec.status)
			level := slog.LevelInfo
			if quietRoutes[r.Pattern] {
				level = slog.LevelDebug
			}
			// ServeMux sets r.Pattern on the request it routes; the route
			// pattern (never the raw path, which holds IDs) is logged.
			log.Log(slot.LogContext(r.Context()), level, "http request",
				"method", r.Method, "route", r.Pattern, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(), "request_id", reqID,
				"client_ip", httpx.ClientIP(r, d.Config.TrustedProxies))
		}()
		mux.ServeHTTP(rec, r)
	})
}
