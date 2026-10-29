package upstream

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const MaxReadRetries = 2
const MaxAutomaticRetryAfter = 2 * time.Second

// parseRetryAfter keeps only a duration; raw upstream headers never enter
// errors, audit or labels. Oversized/negative/fractional values are invalid.
func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64 {
		return 0, false
	}
	digits := true
	for _, r := range raw {
		if r < '0' || r > '9' {
			digits = false
			break
		}
	}
	if n, err := strconv.ParseInt(raw, 10, 64); digits && err == nil {
		if n < 0 || n > int64((1<<63-1)/time.Second) {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	if when, err := http.ParseTime(raw); err == nil {
		return max(when.Sub(now), 0), true
	}
	return 0, false
}

// retryFacts distinguishes known pre-request failures / explicit transient
// statuses from ambiguous failures after sending. A streamed operation or a
// valid RPC answer is never automatically replayed, whatever its HTTP status.
func retryFacts(e *Error, ex *exchange, cause error) (retryable, preRequest bool, after time.Duration) {
	if e.cause != nil || e.Reason != "" || e.RPCCode != 0 {
		return false, false, 0
	}
	ex.mu.Lock()
	streaming, delay, valid, present, detail := ex.streaming, ex.retryAfter, ex.retryAfterValid, ex.retryAfterPresent, ex.detail
	written, handshake, dial := ex.operationWritten, ex.handshakeFailed, ex.dialFailed
	ex.mu.Unlock()
	if streaming || strings.Contains(detail, `"jsonrpc"`) {
		return false, false, 0
	}
	if present && (!valid || delay > MaxAutomaticRetryAfter) {
		return false, false, 0
	}
	switch e.HTTPStatus {
	case http.StatusTooManyRequests:
		return valid, false, delay
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true, false, delay
	case 0:
		// Trace evidence (or a preserved dial cause) is required, and never
		// after any operation write. A TLS label alone proves no such thing.
		if written {
			return false, false, 0
		}
		if e.Class == ClassTLS && handshake {
			return true, true, 0
		}
		if e.Class != ClassUnavailable && e.Class != ClassTimeout {
			return false, false, 0
		}
		var op *net.OpError
		known := dial || (errors.As(cause, &op) && op.Op == "dial")
		return known, known, 0
	}
	return false, false, 0
}

func (c *Client) pauseRetry(ctx context.Context, after time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// At least a short jitter even with Retry-After:0; never amplify a busy
	// server with an immediate tight loop. Larger valid short delays are honored.
	delay := max(after, 100*time.Millisecond+time.Duration(rand.Int64N(int64(200*time.Millisecond))))
	if c.retryPause != nil {
		return c.retryPause(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func mayRetry(ctx context.Context, t Target, req ForwardRequest, err error, progress bool, attempt int) (*Error, bool) {
	if ctx.Err() != nil || !req.Retryable || t.NoReplay || progress || attempt >= MaxReadRetries ||
		len(strings.TrimSpace(string(req.InputResponses))) != 0 || req.RequestState != "" {
		return nil, false
	}
	var e *Error
	if !errors.As(err, &e) || !e.retryable {
		return nil, false
	}
	return e, true
}
