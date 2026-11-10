package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// Error classes (the API's McpErrorClass).
const (
	ClassUnavailable = "unavailable"
	ClassAuth        = "auth"
	ClassNotFound    = "not_found"
	ClassRateLimited = "rate_limited"
	ClassBadRequest  = "bad_request"
	ClassBadResponse = "bad_response"
	ClassConfig      = "config"
	ClassTimeout     = "timeout"
	ClassTooLarge    = "too_large"
	ClassNotAllowed  = "not_allowed"
	ClassServerBusy  = "server_busy"
	ClassCircuitOpen = "circuit_open"
	// ClassTLS is declared in tlsfail.go.
)

// Error is a failed exchange with a server: a class and a message safe to
// show the team (never a header value or a raw body).
type Error struct {
	Class      string
	HTTPStatus int
	Message    string
	// RPCCode is the server's JSON-RPC error code when it answered with an
	// error (0 otherwise).
	RPCCode int64
	// Challenge holds the WWW-Authenticate values of a 401 or 403 answer
	// (an OAuth-protected server's error and scope; never shown).
	Challenge []string
	// Reason is the data.reason of the -32010 answer a call gets when the
	// failure was the portal's own doing rather than the server's, including
	// local admission and machine authentication; empty for remote failures.
	Reason string
	// RetryAfter is a bounded local/upstream delay, never a raw header value.
	RetryAfter time.Duration
	// LimitPerMinute is a local configured ceiling, never shared remaining usage.
	LimitPerMinute int64
	// PriorAttempts counts completed forward iterations before this refusal;
	// a local denial on a retry must not erase earlier dispatch metadata.
	PriorAttempts int
	// BeforeDispatch proves refusal before any upstream forward/negotiation
	// in this iteration. It does not undo dispatch in PriorAttempts.
	BeforeDispatch bool
	retryable      bool
	preRequest     bool // positively identified dial/handshake failure before operation write // only explicit bounded transport/HTTP failures, not local guards
	// cause preserves a local transport guard failure without exposing its
	// potentially sensitive message.
	cause error
}

func (e *Error) Error() string { return e.Message }

// Unwrap preserves local transport guard failures for errors.Is/As.
func (e *Error) Unwrap() error { return e.cause }

// classify turns a transport or protocol error into an *Error.
func (c *Client) classify(ctx context.Context, t Target, ex *exchange, err error) error {
	classified := c.classifyCause(ctx, t, ex, err)
	var original *Error
	if !errors.As(classified, &original) {
		return classified
	}
	e := *original // Never mutate a shared sentinel or another exchange's error.
	e.retryable, e.preRequest, e.RetryAfter = retryFacts(&e, ex, err)
	return &e
}

func (c *Client) classifyCause(ctx context.Context, t Target, ex *exchange, err error) error {
	// The SDK sometimes formats a transport error with %v, losing its chain.
	// Keep the original guard failure on the exchange, not in that string.
	if guardErr := ex.guardFailure(); guardErr != nil {
		return &Error{Class: ClassUnavailable, Message: guardErr.Error(), cause: guardErr}
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	status := ex.lastStatus()
	// The server's own reason, when its error body gave one (redacted).
	why := ""
	if d := errorDetail(ex.lastDetail()); d != "" {
		why = " The server said: " + t.safe(d)
	}
	var rpc *jsonrpc.Error
	var netErr *url.Error
	tlsErr := tlsFailure(t, err)
	switch {
	case errors.Is(err, ErrBlockedAddress) || strings.Contains(err.Error(), ErrBlockedAddress.Error()):
		return &Error{Class: ClassNotAllowed, Message: messageNotAllowed}
	case errors.Is(err, ErrResponseTooLarge) || strings.Contains(err.Error(), ErrResponseTooLarge.Error()):
		return &Error{Class: ClassTooLarge, Message: fmt.Sprintf("The server's response was larger than %d bytes.", c.maxResponse())}
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return &Error{Class: ClassTimeout, Message: "The server didn't answer in time."}
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return &Error{Class: ClassUnavailable, Message: "The call was cancelled."}
	case tlsErr != nil && status == 0:
		c.log().InfoContext(ctx, "mcp server TLS failure", "class", tlsErr.Class)
		return tlsErr
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &Error{Class: ClassAuth, HTTPStatus: status, Message: clipMessage(fmt.Sprintf("The server refused the credentials (HTTP %d).", status) + why),
			Challenge: ex.lastChallenge()}
	case status == http.StatusNotFound:
		return &Error{Class: ClassNotFound, HTTPStatus: status, Message: clipMessage("The server answered 404: check the URL." + why)}
	case status == http.StatusTooManyRequests:
		return &Error{Class: ClassRateLimited, HTTPStatus: status, Message: clipMessage("The server is rate limiting requests (HTTP 429)." + why)}
	case status == http.StatusBadRequest:
		return &Error{Class: ClassBadRequest, HTTPStatus: status, Message: clipMessage("The server refused the request (HTTP 400)." + why)}
	case status >= 400:
		return &Error{Class: ClassUnavailable, HTTPStatus: status, Message: clipMessage(fmt.Sprintf("The server answered HTTP %d.", status) + why)}
	case errors.As(err, &netErr):
		c.log().InfoContext(ctx, "mcp server unreachable", "err", t.safe(err.Error()))
		return &Error{Class: ClassUnavailable, Message: unreachableMessage(err)}
	case errors.As(err, &rpc):
		class := ClassBadResponse
		if rpc.Code == jsonrpc.CodeInvalidParams || rpc.Code == jsonrpc.CodeInvalidRequest {
			class = ClassBadRequest
		}
		return &Error{Class: class, RPCCode: rpc.Code, Message: "The server returned an error: " + t.safe(rpc.Message)}
	case errors.Is(err, io.ErrUnexpectedEOF):
		return &Error{Class: ClassBadResponse, Message: "The server's response was cut off."}
	}
	// Logged without the header value, should an error ever quote it.
	c.log().WarnContext(ctx, "mcp server exchange failed", "err", t.safe(err.Error()))
	return &Error{Class: ClassUnavailable, Message: unreachableMessage(err)}
}

// errorDetail reads a short reason from the start of an error response's
// body: a JSON error_description, message, error.message, error or detail
// field, else the first line of a plain-text body. HTML and binary bodies
// give nothing. The result is not yet redacted.
func errorDetail(body string) string {
	body = strings.TrimSpace(strings.ToValidUTF8(body, ""))
	if body == "" || strings.HasPrefix(body, "<") {
		return ""
	}
	// Server-sent events: use the first data line.
	if strings.HasPrefix(body, "event:") || strings.HasPrefix(body, "data:") {
		for _, line := range strings.Split(body, "\n") {
			if d, ok := strings.CutPrefix(strings.TrimSpace(line), "data:"); ok {
				body = strings.TrimSpace(d)
				break
			}
		}
	}
	if strings.HasPrefix(body, "{") {
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(body), &m) != nil {
			return "" // cut off or not JSON after all: nothing reliable
		}
		str := func(raw json.RawMessage) string {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				return s
			}
			var o struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(raw, &o) == nil {
				return o.Message
			}
			return ""
		}
		for _, k := range []string{"error_description", "message", "error", "detail", "title"} {
			if s := strings.TrimSpace(str(m[k])); s != "" {
				return s
			}
		}
		return ""
	}
	line, _, _ := strings.Cut(body, "\n")
	for _, r := range line {
		if r < 0x20 && r != '\t' {
			return ""
		}
	}
	return strings.TrimSpace(line)
}

// clipMessage bounds a message to MaxMessage characters.
func clipMessage(msg string) string {
	if r := []rune(msg); len(r) > MaxMessage {
		return string(r[:MaxMessage-1]) + "…"
	}
	return msg
}

// safe is SafeMessage with every secret the target carries redacted: the
// server's own credential parts (and their encoded forms), the identity
// token, the provider token and the person's bearer token.
func (t Target) safe(msg string) string {
	return SafeMessage(msg, t.Secrets()...)
}

// MaxMessage bounds a stored or returned message (in characters).
const MaxMessage = 300

// Secrets that must never be stored, even if a server echoes them in an
// error message: bearer tokens, OpenAI-style keys and key=value secrets.
var secretPattern = regexp.MustCompile(`(?i)\bbearer\s+\S+|\bsk-[A-Za-z0-9_\-*.]{6,}|\b(api[_-]?key|token|secret|password)\s*[=:]\s*\S+`)

// SafeMessage makes a message fit to store and show: the given secret values
// (a server's credential parts, tokens; empty ones are skipped, and each one
// also in its URL-encoded form) and anything that looks like a secret
// redacted, whitespace collapsed, at most MaxMessage characters.
func SafeMessage(msg string, secrets ...string) string {
	msg = strings.ToValidUTF8(msg, "")
	for _, secret := range expandSecrets(secrets) {
		msg = strings.ReplaceAll(msg, secret, "[redacted]")
	}
	msg = secretPattern.ReplaceAllString(msg, "[redacted]")
	msg = strings.Join(strings.Fields(msg), " ")
	if utf8.RuneCountInString(msg) > MaxMessage {
		msg = string([]rune(msg)[:MaxMessage-1]) + "…"
	}
	return msg
}
