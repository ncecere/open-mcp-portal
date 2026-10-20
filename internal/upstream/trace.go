package upstream

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Trace context (MCP 2026-07-28, basic/index "_meta"): traceparent,
// tracestate and baggage in a request's _meta follow W3C Trace Context and
// W3C Baggage. The portal passes a downstream request's through to the
// server unchanged when they are well-formed and bounded, and sends none
// when the client sent none (the portal's own tracing is v0.3).

// Bounds on what is passed on.
const (
	maxTraceparent = 55
	maxTracestate  = 512
	maxBaggage     = 2048
)

// Trace is the trace context of one call.
type Trace struct {
	Traceparent, Tracestate, Baggage string
}

// Empty reports whether there is nothing to send.
func (t Trace) Empty() bool { return t.Traceparent == "" && t.Tracestate == "" && t.Baggage == "" }

var (
	traceparentRE = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
	// A tracestate list member: key=value with the characters the W3C
	// grammar allows (a key is lowercase letters, digits and _-*/@).
	tracestateMemberRE = regexp.MustCompile(`^[a-z][a-z0-9_\-*/]{0,255}(@[a-z][a-z0-9_\-*/]{0,13})?=[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}$`)
	// A baggage member: a token key, = and a value of visible ASCII without
	// whitespace, quotes, commas, semicolons and backslashes (properties after
	// ";" are allowed within the bound).
	baggageMemberRE = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+=[\\x21\\x23-\\x2b\\x2d-\\x3a\\x3c-\\x5b\\x5d-\\x7e]*(;[\\x21-\\x7e]*)*$")
)

// ValidTraceparent reports whether s is a W3C traceparent: version,
// 16-byte trace id and 8-byte parent id (neither all zero), flags.
func ValidTraceparent(s string) bool {
	if len(s) != maxTraceparent || !traceparentRE.MatchString(s) {
		return false
	}
	parts := strings.Split(s, "-")
	if parts[0] == "ff" || strings.Trim(parts[1], "0") == "" || strings.Trim(parts[2], "0") == "" {
		return false
	}
	return true
}

// ValidTracestate reports whether s is a W3C tracestate (at most 32
// members, 512 characters).
func ValidTracestate(s string) bool {
	if s == "" || len(s) > maxTracestate {
		return false
	}
	members := strings.Split(s, ",")
	if len(members) > 32 {
		return false
	}
	for _, m := range members {
		if !tracestateMemberRE.MatchString(strings.Trim(m, " \t")) {
			return false
		}
	}
	return true
}

// ValidBaggage reports whether s is a W3C baggage header value of at most
// 2048 characters and 64 members.
func ValidBaggage(s string) bool {
	if s == "" || len(s) > maxBaggage {
		return false
	}
	members := strings.Split(s, ",")
	if len(members) > 64 {
		return false
	}
	for _, m := range members {
		if !baggageMemberRE.MatchString(strings.Trim(m, " \t")) {
			return false
		}
	}
	return true
}

// TraceFromMeta reads the trace context from a request's params._meta,
// keeping only well-formed values (a tracestate only with a traceparent).
func TraceFromMeta(meta map[string]json.RawMessage) Trace {
	str := func(key string) string {
		var s string
		if json.Unmarshal(meta[key], &s) != nil {
			return ""
		}
		return s
	}
	var t Trace
	if s := str("traceparent"); ValidTraceparent(s) {
		t.Traceparent = s
		if ts := str("tracestate"); ValidTracestate(ts) {
			t.Tracestate = ts
		}
	}
	if b := str("baggage"); ValidBaggage(b) {
		t.Baggage = b
	}
	return t
}

// WithParent is the trace context to send when the portal's own span
// (traceparent, tracestate) is the parent of the call: its traceparent and
// tracestate replace the client's, and the client's baggage stays as it was
// sent (the portal adds none). A traceparent that is not well-formed (or empty:
// the span is not sampled, or tracing is off) changes nothing.
func (t Trace) WithParent(traceparent, tracestate string) Trace {
	if !ValidTraceparent(traceparent) {
		return t
	}
	t.Traceparent, t.Tracestate = traceparent, ""
	if ValidTracestate(tracestate) {
		t.Tracestate = tracestate
	}
	return t
}

func (t Trace) addTo(meta map[string]any) {
	if t.Traceparent != "" {
		meta["traceparent"] = t.Traceparent
	}
	if t.Tracestate != "" {
		meta["tracestate"] = t.Tracestate
	}
	if t.Baggage != "" {
		meta["baggage"] = t.Baggage
	}
}
