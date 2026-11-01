// Package httpx holds the HTTP conventions shared by every handler:
// the JSON envelopes, request decoding, request IDs and client IP resolution.
//
// Success responses are {"data": ...}; errors are
// {"error": {"code": "...", "message": "..."}}.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
)

type envelope struct {
	Data any `json:"data"`
}

type errorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// JSON writes a success envelope.
func JSON(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, envelope{Data: data})
}

// Error writes an error envelope. Messages must be safe to show to users.
func Error(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: ErrorDetail{Code: code, Message: message}})
}

// ErrorDetails writes an error envelope with structured details.
func ErrorDetails(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, errorBody{Error: ErrorDetail{Code: code, Message: message, Details: details}})
}

// StatusClientClosedRequest is the status recorded for a request whose
// client went away before the answer was ready (nginx's 499). It isn't a
// server error: it stays out of the 5xx metrics and the error SLO.
const StatusClientClosedRequest = 499

// ClientGone reports whether the request's client disconnected (or
// cancelled it), as opposed to a deadline or a server-side failure.
func ClientGone(r *http.Request) bool {
	return errors.Is(r.Context().Err(), context.Canceled)
}

// Internal logs err with the request ID and writes a generic 500. When the
// client has gone away the failure is almost always the cancellation
// itself, so it is logged at info as a client cancellation and recorded
// as 499 instead.
func Internal(w http.ResponseWriter, r *http.Request, err error) {
	if ClientGone(r) {
		slog.InfoContext(r.Context(), "client closed request", "err", err, "request_id", RequestID(r.Context()), "path", r.URL.Path)
		Error(w, StatusClientClosedRequest, "client_closed_request", "The request was cancelled.")
		return
	}
	slog.ErrorContext(r.Context(), "internal error", "err", err, "request_id", RequestID(r.Context()), "path", r.URL.Path)
	Error(w, http.StatusInternalServerError, "internal", "Something went wrong. Include the request ID if you report this.")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// MaxBodyBytes is the default limit for JSON request bodies.
const MaxBodyBytes = 1 << 20

// Decode reads exactly one JSON object into dst, rejecting unknown fields.
// On failure it writes a 400 and returns false.
func Decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		Error(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			Error(w, http.StatusRequestEntityTooLarge, "body_too_large", "Request body is too large")
			return false
		}
		Error(w, http.StatusBadRequest, "invalid_json", "Request body is not valid JSON for this operation")
		return false
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		Error(w, http.StatusBadRequest, "invalid_json", "Request body must contain a single JSON object")
		return false
	}
	return true
}

type requestIDKey struct{}

// WithRequestID stores a request ID in the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request ID, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewID returns a random URL-safe identifier with n bytes of entropy.
func NewID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ClientIP returns the caller's address. X-Forwarded-For is only honoured when
// the direct peer is a trusted proxy; the right-most untrusted hop wins so a
// client cannot spoof its address by sending its own header.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := remoteAddr(r)
	if !peer.IsValid() {
		return ""
	}
	if !isTrusted(peer, trusted) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if !isTrusted(addr, trusted) {
			return addr.String()
		}
	}
	return peer.String()
}

func remoteAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Fail renders an *apperr.Error with its status and code; anything else is
// logged and becomes a generic 500.
func Fail(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := apperr.DirectoryGuard(err); ok {
		err = e
	}
	if e, ok := apperr.As(err); ok {
		if e.RetryAfter > 0 {
			secs := int((e.RetryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		}
		if e.Details != nil {
			ErrorDetails(w, e.Status, e.Code, e.Message, e.Details)
			return
		}
		Error(w, e.Status, e.Code, e.Message)
		return
	}
	Internal(w, r, err)
}
