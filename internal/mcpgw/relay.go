package mcpgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Relaying a server's elicitation (docs/mcp-protocol.md "The portal as a
// client"). A modern upstream server may answer tools/call, prompts/get and
// resources/read with resultType input_required: it needs the person's input
// (MRTR). When the downstream request is modern and its client declared
// elicitation, the portal declares exactly that much elicitation to the
// server (per request, stateless: nothing is remembered), and hands the
// server's elicitation requests on to the client:
//
//   - inputRequests: the server's elicitation/create requests, validated and
//     rebuilt (bounded: at most maxRelayRequests of them and maxRelayBytes in
//     all, unique keys, only the modes the client declared, URL mode only
//     with https or, in development, loopback http). Sampling and roots
//     requests (deprecated) are not relayed: the call fails with a tool error.
//   - requestState: the portal's own sealed state (requeststate.go): the
//     person, gateway, method, exposed name, a digest of the parameters, the
//     upstream server, the keys relayed and the server's own requestState,
//     for ten minutes. The client can't read it or move it to another call.
//
// The client retries the original request (a new JSON-RPC id) with the
// state and inputResponses. The portal verifies every binding, then calls
// the server again with the original parameters, the client's responses (only
// for the keys it relayed, each shaped as an elicitation result) and the
// server's requestState. A legacy client, or one that declared no
// elicitation, gets nothing relayed: the server was told it can't ask, and if
// it asks anyway the call fails with an error saying so.

// Bounds of what is relayed.
const (
	maxRelayRequests = 8
	maxRelayBytes    = 16 << 10
	maxRelayKey      = 128
	maxRelayMessage  = 4 << 10
	maxRelayURL      = 2 << 10
	// maxUpstreamState bounds the server's own requestState, which the
	// portal's state wraps.
	maxUpstreamState = 8 << 10
	// maxRelayResponses bounds the inputResponses forwarded to the server.
	maxRelayResponses = 64 << 10

	// ClassInputRequired marks calls whose server asked for input: relayed
	// (recorded ok) or refused (recorded as an error).
	ClassInputRequired = "input_required"

	methodElicit = "elicitation/create"

	msgSamplingRoots = "this server asked for something the portal can't provide (sampling/roots)"
)

// elicitModes are the elicitation modes a modern client declared.
type elicitModes struct {
	form, url bool
	// empty: the capability was the empty object (form only, written back
	// as an empty object).
	empty bool
}

func (m elicitModes) any() bool { return m.form || m.url }

// declared is the elicitation capability to declare to the server (nil: none).
func (m elicitModes) declared() json.RawMessage {
	switch {
	case !m.any():
		return nil
	case m.empty:
		return json.RawMessage(`{}`)
	}
	parts := []string{}
	if m.form {
		parts = append(parts, `"form":{}`)
	}
	if m.url {
		parts = append(parts, `"url":{}`)
	}
	return json.RawMessage("{" + strings.Join(parts, ",") + "}")
}

// clientElicitation reads clientCapabilities.elicitation of a modern
// request: an empty object means form only (2026-07-28, "Capabilities").
func (rc *request) clientElicitation() elicitModes {
	var m elicitModes
	if !rc.modern {
		return m
	}
	raw, ok := rc.clientCaps["elicitation"]
	if !ok {
		return m
	}
	var e map[string]json.RawMessage
	if json.Unmarshal(raw, &e) != nil || e == nil {
		return m
	}
	_, m.form = e["form"]
	_, m.url = e["url"]
	if !m.form && !m.url {
		m.form, m.empty = true, true
	}
	return m
}

// paramsMeta is the request's params._meta.
func (rc *request) paramsMeta() map[string]json.RawMessage {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if len(rc.msg.Params) == 0 || json.Unmarshal(rc.msg.Params, &p) != nil {
		return nil
	}
	return p.Meta
}

// forwardRequest builds the call to the server from the downstream request:
// the elicitation capability as wide as the client's, the trace context, and
// the retry of a relayed input request. ok false: it answered the request
// (an invalid retry).
func (rc *request) forwardRequest(method, name string, args json.RawMessage, o gateways.Offer, again retry, rec *calls.Call) (upstream.ForwardRequest, bool) {
	req := upstream.ForwardRequest{Method: method, Name: name, Arguments: args, Elicitation: rc.clientElicitation().declared(),
		Trace: upstream.TraceFromMeta(rc.paramsMeta())}
	if again.relay == nil {
		return req, true
	}
	reject := func(class, msg string) (upstream.ForwardRequest, bool) {
		n := rc.fail(codeInvalidParams, msg)
		rec.Outcome, rec.ErrorClass = calls.OutcomeBadRequest, class
		rc.record(*rec, n)
		return req, false
	}
	if again.relay.server != o.Server.ID.String() {
		return reject(ClassStateMismatch, "Invalid parameters: requestState was issued for a different request. Retry the original request, echoing the requestState you were given for it.")
	}
	responses, err := relayResponses(rc.msg.Params, again.relay.keys)
	if err != nil {
		return reject("invalid_params", "Invalid parameters: "+err.Error())
	}
	req.InputResponses, req.RequestState = responses, again.relay.upstream
	return req, true
}

// relayResponses is the client's inputResponses for the server: only answers
// to the keys the portal relayed (anything else is ignored, as the
// specification allows), each an elicitation result. nil when there are none.
func relayResponses(params json.RawMessage, keys []string) (json.RawMessage, error) {
	var p struct {
		InputResponses json.RawMessage `json:"inputResponses"`
	}
	_ = json.Unmarshal(params, &p)
	raw := bytes.TrimSpace(p.InputResponses)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var all map[string]json.RawMessage
	if json.Unmarshal(raw, &all) != nil || all == nil {
		return nil, errors.New("inputResponses must be an object")
	}
	out := map[string]json.RawMessage{}
	for k, v := range all {
		if !slices.Contains(keys, k) {
			continue
		}
		var r struct {
			Action  string          `json:"action"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(v, &r) != nil || (r.Action != "accept" && r.Action != "decline" && r.Action != "cancel") {
			return nil, fmt.Errorf("inputResponses[%q] must be an elicitation result with action accept, decline or cancel", clip(k, 40))
		}
		if c := bytes.TrimSpace(r.Content); len(c) > 0 && string(c) != "null" && c[0] != '{' {
			return nil, fmt.Errorf("inputResponses[%q].content must be an object", clip(k, 40))
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(out)
	if err != nil || len(b) > maxRelayResponses {
		return nil, errors.New("inputResponses are too large")
	}
	return b, nil
}

// relayRefusal is why a server's input requests aren't relayed.
type relayRefusal struct {
	// toolError: the call fails with a tool error naming the cause (the
	// server asked for something the portal doesn't offer); otherwise it is
	// a bad response from the server.
	toolError bool
	message   string
}

func (e *relayRefusal) Error() string { return e.message }

func badInput(format string, a ...any) error {
	return &relayRefusal{message: fmt.Sprintf(format, a...)}
}

// relayedRequests validates a server's inputRequests and rebuilds them for
// the client, returning them with their keys (sorted).
func relayedRequests(raw json.RawMessage, modes elicitModes, allowLoopbackHTTP bool) (map[string]any, []string, error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return nil, nil, badInput("The server's input requests are not valid JSON.")
	}
	if compact.Len() > maxRelayBytes {
		return nil, nil, badInput("The server asked for more input than the portal relays (over %d bytes).", maxRelayBytes)
	}
	pairs, err := objectEntries(compact.Bytes())
	if err != nil {
		return nil, nil, badInput("The server's input requests are not an object.")
	}
	if len(pairs) > maxRelayRequests {
		return nil, nil, badInput("The server asked for more input than the portal relays (more than %d requests).", maxRelayRequests)
	}
	seen := map[string]bool{}
	for _, kv := range pairs {
		if seen[kv.key] {
			return nil, nil, badInput("The server's input requests repeat a key.")
		}
		seen[kv.key] = true
	}
	// Sampling and roots (deprecated) are not relayed, whatever else is asked.
	for _, kv := range pairs {
		var r struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(kv.value, &r) == nil && (r.Method == "sampling/createMessage" || r.Method == "roots/list") {
			return nil, nil, &relayRefusal{toolError: true, message: msgSamplingRoots}
		}
	}
	out := make(map[string]any, len(pairs))
	keys := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		if kv.key == "" || len(kv.key) > maxRelayKey || !utf8.ValidString(kv.key) || strings.ContainsFunc(kv.key, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, nil, badInput("The server's input requests have an invalid key.")
		}
		req, err := relayedElicitation(kv.value, modes, allowLoopbackHTTP)
		if err != nil {
			return nil, nil, err
		}
		out[kv.key] = req
		keys = append(keys, kv.key)
	}
	slices.Sort(keys)
	return out, keys, nil
}

// relayedElicitation validates one elicitation/create request and rebuilds
// it with only the fields the client needs (the server's own extras, such as
// _meta or an elicitationId, are dropped).
func relayedElicitation(raw json.RawMessage, modes elicitModes, allowLoopbackHTTP bool) (map[string]any, error) {
	var r struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Method != methodElicit {
		return nil, badInput("The server asked for input the portal doesn't know how to relay (%s).", clip(r.Method, 60))
	}
	var p struct {
		Mode            string          `json:"mode"`
		Message         string          `json:"message"`
		RequestedSchema json.RawMessage `json:"requestedSchema"`
		URL             string          `json:"url"`
	}
	if json.Unmarshal(r.Params, &p) != nil {
		return nil, badInput("The server's elicitation request is not valid.")
	}
	if p.Message == "" || len(p.Message) > maxRelayMessage || !utf8.ValidString(p.Message) {
		return nil, badInput("The server's elicitation request has no usable message.")
	}
	switch p.Mode {
	case "", "form":
		if !modes.form {
			return nil, badInput("The server asked for a form, which the client didn't declare support for.")
		}
		schema := bytes.TrimSpace(p.RequestedSchema)
		var s struct {
			Type       string                     `json:"type"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if len(schema) == 0 || schema[0] != '{' || json.Unmarshal(schema, &s) != nil || (s.Type != "" && s.Type != "object") {
			return nil, badInput("The server's elicitation form has no valid requestedSchema.")
		}
		for _, prop := range s.Properties {
			if o := bytes.TrimSpace(prop); len(o) == 0 || o[0] != '{' {
				return nil, badInput("The server's elicitation form has an invalid property.")
			}
		}
		return map[string]any{"method": methodElicit, "params": map[string]any{"mode": "form", "message": p.Message, "requestedSchema": json.RawMessage(schema)}}, nil
	case "url":
		if !modes.url {
			return nil, badInput("The server asked the person to open a URL, which the client didn't declare support for.")
		}
		if !safeElicitationURL(p.URL, allowLoopbackHTTP) {
			return nil, badInput("The server asked the person to open a URL that isn't https.")
		}
		return map[string]any{"method": methodElicit, "params": map[string]any{"mode": "url", "message": p.Message, "url": p.URL}}, nil
	}
	return nil, badInput("The server's elicitation request has an unknown mode.")
}

// safeElicitationURL applies the specification's rules for URL mode
// ("Safe URL Handling"): an absolute https URL with a host and no user
// info; plain http only for a loopback host in development.
func safeElicitationURL(raw string, allowLoopbackHTTP bool) bool {
	if raw == "" || len(raw) > maxRelayURL || strings.ContainsFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		if !allowLoopbackHTTP {
			return false
		}
		h := u.Hostname()
		if strings.EqualFold(h, "localhost") {
			return true
		}
		ip, err := netip.ParseAddr(h)
		return err == nil && ip.IsLoopback()
	}
	return false
}

type entry struct {
	key   string
	value json.RawMessage
}

// objectEntries lists a JSON object's members in order, keeping duplicate
// keys (a map would hide them).
func objectEntries(b []byte) ([]entry, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	var out []entry
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out = append(out, entry{key, v})
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}

// relayInput answers a call whose server asked for input: relays its
// elicitation requests to a client that declared them, or fails the call
// clearly. It records the call (ok with error class input_required when
// relayed).
func (rc *request) relayInput(o gateways.Offer, rec calls.Call, in *upstream.InputRequired) {
	rec.ErrorClass = ClassInputRequired
	modes := rc.clientElicitation()
	if !rc.modern || !modes.any() {
		// The server was told this client can't answer, and asked anyway.
		rc.inputRefused(o, rec, &relayRefusal{toolError: true,
			message: "this server asked for input, which your client can't give (it didn't declare elicitation support)"})
		return
	}
	requests, keys, err := relayedRequests(in.Requests, modes, rc.h.Registry.Client().AllowPrivate)
	if err != nil {
		rc.inputRefused(o, rec, err)
		return
	}
	if len(in.RequestState) > maxUpstreamState || !utf8.ValidString(in.RequestState) {
		rc.inputRefused(o, rec, badInput("The server's requestState is too large to relay (over %d bytes).", maxUpstreamState))
		return
	}
	box := rc.h.states()
	if box == nil {
		rc.inputRefused(o, rec, badInput("The portal can't hold the server's request state (no encryption key)."))
		return
	}
	claims := rc.stateFor(purposeRelay)
	claims.Server, claims.Keys, claims.Upstream = o.Server.ID.String(), strings.Join(keys, "\n"), in.RequestState
	token, err := box.seal(claims)
	if err != nil {
		rc.internal(err)
		return
	}
	result := map[string]any{"resultType": resultInputRequired, "requestState": token}
	if len(requests) > 0 {
		result["inputRequests"] = requests
	}
	// What the client sees never holds a person's token for the server,
	// should it echo one (the map, not raw JSON, so it is shaped like every
	// other modern result and its resultType stays input_required).
	encoded, err := json.Marshal(result)
	for _, tok := range rc.scrub {
		if err == nil && tok != "" {
			encoded = bytes.ReplaceAll(encoded, []byte(tok), []byte("[REDACTED]"))
		}
	}
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(encoded))
		dec.UseNumber()
		err = dec.Decode(&result)
	}
	if err != nil {
		rc.internal(err)
		return
	}
	n := rc.reply(result)
	rec.Outcome = calls.OutcomeOK
	rc.record(rec, n)
}

// inputRefused fails a call whose server's input request can't be relayed:
// a tool error for a refusal the model can read, an upstream error for a bad
// server. Nothing of the server's request is passed on.
func (rc *request) inputRefused(o gateways.Offer, rec calls.Call, err error) {
	var ref *relayRefusal
	if !errors.As(err, &ref) {
		rc.internal(err)
		return
	}
	rec.ErrorClass = ClassInputRequired
	if ref.toolError && o.Capability.Kind == upstream.KindTool {
		n := rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": ref.message}}, "isError": true})
		rec.Outcome = calls.OutcomeToolError
		rc.record(rec, n)
		return
	}
	if ref.toolError {
		n := rc.failData(codeDenied, ref.message, map[string]any{"reason": ClassInputRequired})
		rec.Outcome = calls.OutcomeDenied
		rc.record(rec, n)
		return
	}
	n := rc.fail(codeInternal, upstream.SafeMessage(ref.message, ""))
	rec.Outcome = calls.OutcomeUpstreamError
	rc.record(rec, n)
}
