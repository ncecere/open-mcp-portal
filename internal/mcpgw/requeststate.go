package mcpgw

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// "Connect your account" as a multi round-trip request (MCP 2026-07-28,
// docs/mcp-protocol.md "Consent"). Where a legacy client gets JSON-RPC
// -32042 (and a modern one that doesn't declare URL elicitation a tool error
// or -32010 with the link, delegated.go), a modern
// client that declares elicitation.url gets an InputRequiredResult: one
// elicitation/create request in URL mode, with the same /connect/... link,
// and a requestState. The person opens the link, the client retries the
// original request echoing requestState, and the gateway re-runs every
// check: connected now, it goes through; not yet, it asks again.
//
// requestState is a sealed (AES-256-GCM) token the client can't read or
// change: its key is derived with HKDF from ENCRYPTION_KEY (and the previous
// key, so a rotation doesn't strand a person mid-consent) under its own info
// string. Inside: a version, the person it was issued to, the gateway, the
// method and the exposed name or URI, a digest of the request's parameters,
// and its issue and expiry times (ten minutes). It holds no credential, no
// URL and nothing about the provider; the client's retry must carry the same
// person, gateway, method, name and parameters (the SHA-256 of the canonical
// JSON of params without _meta, inputResponses and requestState). It bounds
// the replay window and stops reuse across people and requests; it is not
// single-use, and needn't be: a retry only ever re-runs the checks.

const (
	stateInfo    = "open-mcp-portal/mcp-request-state/v1"
	stateVersion = byte(1)
	// stateTTL is how long a person has to open the link and retry.
	stateTTL       = 10 * time.Minute
	purposeConsent = "consent"
	// purposeRelay seals an upstream server's own requestState (relay.go).
	purposeRelay = "relay"
	// maxStateLen bounds the requestState a client may send back (a relay
	// state holds the upstream's, at most maxUpstreamState).
	maxStateLen = 16 << 10

	// ClassStateInvalid, ClassStateExpired and ClassStateMismatch are the
	// error classes of calls refused for their requestState.
	ClassStateInvalid  = "request_state_invalid"
	ClassStateExpired  = "request_state_expired"
	ClassStateMismatch = "request_state_mismatch"
	// ClassDeclined is a call whose person declined or cancelled the
	// consent.
	ClassDeclined = "authorization_declined"
)

var (
	errStateInvalid  = errors.New("mcpgw: the requestState is not valid")
	errStateExpired  = errors.New("mcpgw: the requestState has expired")
	errStateMismatch = errors.New("mcpgw: the requestState is for another request")
)

// stateClaims is what a requestState carries.
type stateClaims struct {
	Purpose   string `json:"u"`
	Principal string `json:"p"`
	Gateway   string `json:"g"`
	Method    string `json:"m"`
	Name      string `json:"n"`
	Digest    string `json:"d"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	// The fields of a relay state (purposeRelay, relay.go): the upstream
	// server the input requests came from, the keys of the requests relayed
	// (a retry may answer only those) and the upstream's own requestState.
	// Never a credential.
	Server string `json:"s,omitempty"`
	// Keys are the relayed keys joined by newlines (a key has no control
	// character).
	Keys     string `json:"k,omitempty"`
	Upstream string `json:"us,omitempty"`
}

// stateBox seals and opens requestState tokens.
type stateBox struct {
	aeads []cipher.AEAD // the current key first
	now   func() time.Time
}

func newStateBox(b *secrets.Box) (*stateBox, error) {
	keys, err := b.Derive(stateInfo)
	if err != nil {
		return nil, err
	}
	s := &stateBox{now: time.Now}
	for _, k := range keys {
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.aeads = append(s.aeads, aead)
	}
	return s, nil
}

// states is the handler's requestState box (nil when it has no key).
func (h *Handler) states() *stateBox {
	h.stateOnce.Do(func() {
		if h.Secrets == nil {
			return
		}
		sb, err := newStateBox(h.Secrets)
		if err != nil {
			h.log().Error("mcp requestState is unavailable", "err", err)
			return
		}
		if h.now != nil {
			sb.now = h.now
		}
		h.state = sb
	})
	return h.state
}

// seal issues a token for c, valid for stateTTL from now.
func (s *stateBox) seal(c stateClaims) (string, error) {
	now := s.now()
	c.IssuedAt, c.ExpiresAt = now.Unix(), now.Add(stateTTL).Unix()
	plain, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	aead := s.aeads[0]
	out := make([]byte, 0, 1+aead.NonceSize()+len(plain)+aead.Overhead())
	out = append(out, stateVersion)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, stateAAD)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

var stateAAD = []byte(stateInfo)

// open verifies and decrypts a token: errStateInvalid for anything that
// isn't one of ours (tampered, truncated, sealed with another key or of
// another version) and errStateExpired once its time has passed.
func (s *stateBox) open(token string) (stateClaims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) == 0 || raw[0] != stateVersion {
		return stateClaims{}, errStateInvalid
	}
	for _, aead := range s.aeads {
		if len(raw) < 1+aead.NonceSize()+aead.Overhead() {
			continue
		}
		nonce, sealed := raw[1:1+aead.NonceSize()], raw[1+aead.NonceSize():]
		plain, err := aead.Open(nil, nonce, sealed, stateAAD)
		if err != nil {
			continue
		}
		var c stateClaims
		if json.Unmarshal(plain, &c) != nil {
			return stateClaims{}, errStateInvalid
		}
		if !s.now().Before(time.Unix(c.ExpiresAt, 0)) {
			return stateClaims{}, errStateExpired
		}
		return c, nil
	}
	return stateClaims{}, errStateInvalid
}

// paramsDigest is the SHA-256 (hex) of a request's method and the canonical
// JSON of its params without the parts that change between a request and
// its retry: _meta, inputResponses and requestState.
func paramsDigest(method string, params json.RawMessage) string {
	var obj map[string]json.RawMessage
	if len(bytes.TrimSpace(params)) > 0 {
		_ = json.Unmarshal(params, &obj)
	}
	canon := map[string]any{}
	for k, raw := range obj {
		switch k {
		case "_meta", "inputResponses", "requestState":
			continue
		}
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if dec.Decode(&v) != nil {
			v = string(raw)
		}
		canon[k] = v
	}
	b, _ := json.Marshal(canon) // map keys are sorted
	sum := sha256.Sum256(append([]byte(method+"\n"), b...))
	return hex.EncodeToString(sum[:])
}

// principalID is who a requestState is bound to: the person (consent is
// theirs, whichever credential they use).
func (rc *request) principalID() string {
	if rc.relayedPerson() {
		return "agent:" + rc.principal.account.Account.ID.String() + ":" + rc.principal.relay.person.ID.String()
	}
	if sa := rc.principal.account; sa != nil {
		return "service_account:" + sa.Account.ID.String()
	}
	return "user:" + rc.principal.user.ID.String()
}

// stateFor is the claims a token for this request binds.
func (rc *request) stateFor(purpose string) stateClaims {
	return stateClaims{Purpose: purpose, Principal: rc.principalID(), Gateway: rc.gateway.ID.String(), Method: rc.msg.Method,
		Name: rc.requestedName(), Digest: paramsDigest(rc.msg.Method, rc.msg.Params)}
}

// urlElicitation reports whether the modern request's client declared URL
// mode elicitation (an empty elicitation object means form mode only).
func (rc *request) urlElicitation() bool {
	if !rc.modern {
		return false
	}
	var e map[string]json.RawMessage
	raw, ok := rc.clientCaps["elicitation"]
	if !ok || json.Unmarshal(raw, &e) != nil {
		return false
	}
	_, ok = e["url"]
	return ok
}

// retry is what a modern request's multi round-trip fields say.
type retry struct {
	// verified: the request carries a requestState we issued for it.
	verified bool
	// declined: an input response says the person declined or cancelled
	// the consent (a consent state only; a relayed elicitation's decline
	// goes to the server that asked).
	declined bool
	// relay is set for a verified relay state: the retry of an upstream's
	// input request (relay.go).
	relay *relayState
}

// relayState is what a verified relay state carries.
type relayState struct {
	server   string
	keys     []string
	upstream string
}

// checkRetry reads requestState and inputResponses of a modern tools/call,
// prompts/get or resources/read. A requestState must be one we sealed for
// this person, gateway, method, name and parameters, unexpired; anything
// else is -32602 and the request is recorded and answered here (ok false).
// inputResponses are otherwise ignored, except that a decline or cancel is
// remembered (honored only with a verified state).
func (rc *request) checkRetry(rec calls.Call) (retry, bool) {
	var r retry
	if !rc.modern {
		return r, true
	}
	var p struct {
		RequestState   json.RawMessage `json:"requestState"`
		InputResponses json.RawMessage `json:"inputResponses"`
	}
	_ = json.Unmarshal(rc.msg.Params, &p)
	reject := func(class, msg string) (retry, bool) {
		n := rc.fail(codeInvalidParams, msg)
		rec.Outcome, rec.ErrorClass = calls.OutcomeBadRequest, class
		rc.record(rec, n)
		return r, false
	}
	var responses map[string]json.RawMessage
	if len(p.InputResponses) > 0 && string(p.InputResponses) != "null" && json.Unmarshal(p.InputResponses, &responses) != nil {
		return reject("invalid_params", "Invalid parameters: inputResponses must be an object")
	}
	if len(p.RequestState) == 0 || string(p.RequestState) == "null" {
		return r, true
	}
	var token string
	if json.Unmarshal(p.RequestState, &token) != nil || token == "" || len(token) > maxStateLen {
		return reject(ClassStateInvalid, "Invalid parameters: requestState is not valid. Retry the original request without it.")
	}
	box := rc.h.states()
	if box == nil {
		return reject(ClassStateInvalid, "Invalid parameters: requestState is not valid. Retry the original request without it.")
	}
	c, err := box.open(token)
	switch {
	case errors.Is(err, errStateExpired):
		return reject(ClassStateExpired, "Invalid parameters: requestState has expired. Retry the original request without it.")
	case err != nil || (c.Purpose != purposeConsent && c.Purpose != purposeRelay) || c.Principal != rc.principalID():
		return reject(ClassStateInvalid, "Invalid parameters: requestState is not valid. Retry the original request without it.")
	}
	want := rc.stateFor(c.Purpose)
	if c.Gateway != want.Gateway || c.Method != want.Method || c.Name != want.Name || c.Digest != want.Digest {
		return reject(ClassStateMismatch, "Invalid parameters: requestState was issued for a different request. Retry the original request, echoing the requestState you were given for it.")
	}
	r.verified = true
	if c.Purpose == purposeRelay {
		r.relay = &relayState{server: c.Server, keys: strings.Split(c.Keys, "\n"), upstream: c.Upstream}
		return r, true
	}
	for _, raw := range responses {
		var resp struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(raw, &resp) == nil && (resp.Action == "decline" || resp.Action == "cancel") {
			r.declined = true
		}
	}
	return r, true
}

// declined answers a retry whose person declined or cancelled the consent:
// a tool error "authorization declined" for a tool call (the model sees it),
// a refusal for a prompt or a read, which have no tool error. Nothing is
// forwarded.
func (rc *request) declined(o gateways.Offer) {
	rec := calls.Call{ExposedName: rc.requestedName(), Server: &o.Server, CapabilityID: o.Capability.ID, ErrorClass: ClassDeclined, ToolClass: o.Capability.ToolClass}
	if o.Requires != nil {
		rec.ProviderSlug = o.Requires.Provider.Slug
	}
	const msg = "authorization declined"
	if o.Capability.Kind == upstream.KindTool {
		n := rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true})
		rec.Outcome = calls.OutcomeToolError
		rc.record(rec, n)
		return
	}
	n := rc.failData(codeDenied, msg, map[string]any{"reason": ClassDeclined})
	rec.Outcome = calls.OutcomeDenied
	rc.record(rec, n)
}

// consentInputRequired answers a modern request whose client declared URL
// elicitation with the consent link as an input request (ok false: the
// caller falls back to the plain answer, as when the gateway has no key).
func (rc *request) consentInputRequired(o gateways.Offer, c *providers.ConsentNeeded, rec *calls.Call, class string) bool {
	box := rc.h.states()
	if box == nil || !rc.urlElicitation() {
		return false
	}
	token, err := box.seal(rc.stateFor(purposeConsent))
	if err != nil {
		rc.h.log().Error("mcp requestState could not be sealed", "err", err)
		return false
	}
	key := "connect_" + c.Provider.Slug
	n := rc.reply(map[string]any{
		"resultType": resultInputRequired,
		"inputRequests": map[string]any{key: map[string]any{
			"method": "elicitation/create",
			"params": map[string]any{"mode": "url", "url": c.URL, "message": rc.consentMessage(o, c)},
		}},
		"requestState": token,
	})
	if class == "" {
		class = c.Reason
	}
	rec.Outcome, rec.ErrorClass = calls.OutcomeNeedsAuthorization, class
	rc.record(*rec, n)
	return true
}

// consentMessage says what the link is for, naming the provider (or the
// server's own sign-in), its scopes, the capability and the gateway.
func (rc *request) consentMessage(o gateways.Offer, c *providers.ConsentNeeded) string {
	name, scopes := c.Provider.Name, scopeNote(c.Scopes)
	var what string
	switch {
	case c.Provider.ServerBound():
		verb := "Sign in to"
		switch c.Reason {
		case providers.ReasonMissingScopes:
			verb = "Grant more access to"
		case providers.ReasonNeedsReconsent:
			verb = "Sign in again to"
		}
		what = fmt.Sprintf("%s %s%s", verb, name, scopes)
	case c.Reason == providers.ReasonServerNotAllowed:
		what = fmt.Sprintf("Allow %s to use your %s account%s", serverLabel(o), name, scopes)
	default:
		verb := "Connect your"
		switch c.Reason {
		case providers.ReasonMissingScopes:
			verb = "Grant more access to your"
		case providers.ReasonNeedsReconsent:
			verb = "Reconnect your"
		}
		what = fmt.Sprintf("%s %s account%s", verb, name, scopes)
	}
	if c.Reason == providers.ReasonServerNotAllowed && !c.Provider.ServerBound() {
		return fmt.Sprintf("%s for %s in the %s gateway.", what, o.ExposedName, rc.gateway.Name)
	}
	return fmt.Sprintf("%s to use %s in the %s gateway.", what, o.ExposedName, rc.gateway.Name)
}
