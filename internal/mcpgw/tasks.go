package mcpgw

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/gateways/curation"
	"github.com/ncecere/open-mcp-portal/internal/mcptasks"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// The Tasks extension relay (docs/mcp-tasks.md, decision 86). This file holds
// what creation (tasks_create.go) and the lifecycle methods (tasks_ops.go)
// share: the per-request declaration, the root and binding of a task, the
// dependency identity, the public task shape and the redaction that every task
// status, result, input request, error and message passes through.
//
// A task handle is a lookup key, never authority: every operation
// authenticates the request, re-resolves the caller's current access and the
// offer it was created from, and only then touches the task.

const taskNotFoundMessage = "Task not found"

// tasksEnabled: tasks are served only with a store AND the approval runtime,
// whose read-only no-rule check guards every lifecycle operation.
func (rc *request) tasksEnabled() bool { return rc.h.Tasks != nil && rc.h.Approvals != nil }

// tasksDeclared reports whether THIS request declares the Tasks extension
// (clientCapabilities.extensions[...] an object). Nothing is remembered from an
// earlier request, and a legacy request never declares it.
func (rc *request) tasksDeclared() bool {
	if !rc.modern {
		return false
	}
	raw, ok := rc.clientCaps["extensions"]
	if !ok {
		return false
	}
	var extensions map[string]json.RawMessage
	if json.Unmarshal(raw, &extensions) != nil || extensions == nil {
		return false
	}
	var settings map[string]json.RawMessage
	return json.Unmarshal(extensions[upstream.TasksExtension], &settings) == nil && settings != nil
}

// validateTaskName applies the streamable-http header rule to a task method:
// Mcp-Name must be present and equal params.taskId (the portal handle here).
// Like the other modern header checks this is a request-shape rule, evaluated
// before any lookup and independent of whether the task exists.
func validateTaskName(h http.Header, params json.RawMessage) *eraError {
	raw := h.Get(headerName)
	if raw == "" {
		return badHeader("the %s header is required for the task methods", headerName)
	}
	got, ok := decodeHeaderValue(raw)
	if !ok {
		return badHeader("the %s header is not a valid header value", headerName)
	}
	var p struct {
		TaskID json.RawMessage `json:"taskId"`
	}
	var want string
	if json.Unmarshal(params, &p) == nil && json.Unmarshal(p.TaskID, &want) == nil && got != want {
		// Never echo either value: both are handles.
		return badHeader("%s header value does not match params.taskId", headerName)
	}
	return nil
}

// taskMissingCapability answers a task method whose request did not declare the
// extension: -32021 naming it (HTTP 400, as the other modern request errors).
func (rc *request) taskMissingCapability() {
	n := writeRPC(rc.w, http.StatusBadRequest, rc.msg.ID, nil, &rpcError{Code: codeMissingCapability, Message: "Missing required client capability",
		Data: map[string]any{"requiredCapabilities": map[string]any{"extensions": map[string]any{upstream.TasksExtension: map[string]any{}}}}})
	rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "missing_capability"}, n)
}

// codeMissingCapability is MissingRequiredClientCapability (2026-07-28).
const codeMissingCapability = -32021

// taskNotFound is the ONE answer for an unknown, malformed, foreign, expired or
// no-longer-authorized handle. class is recorded for the operator only.
func (rc *request) taskNotFound(rec calls.Call, class string) {
	n := rc.fail(codeInvalidParams, taskNotFoundMessage)
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, class
	rc.record(rec, n)
}

// taskRoot is the starting credential root of this authenticated request:
// an API key's UUID, a connected client's stable grant UUID (never the
// short-lived access token), or a service account's key UUID. Never from task
// parameters.
func (rc *request) taskRoot() mcptasks.Root {
	p := rc.principal
	root := mcptasks.Root{GatewayID: rc.gateway.ID}
	switch {
	case p.account != nil:
		root.PrincipalKind, root.PrincipalID = mcptasks.PrincipalServiceAccount, p.account.Account.ID
		root.CredentialKind, root.CredentialID = mcptasks.CredentialServiceKey, p.keyID
	case p.grant != nil:
		root.PrincipalKind, root.PrincipalID = mcptasks.PrincipalUser, p.user.ID
		root.CredentialKind, root.CredentialID = mcptasks.CredentialOAuthGrant, p.grant.ID
	default:
		root.PrincipalKind, root.PrincipalID = mcptasks.PrincipalUser, p.user.ID
		root.CredentialKind, root.CredentialID = mcptasks.CredentialAPIKey, p.keyID
	}
	return root
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// noCuration is the fixed digest of "no curation applies".
var noCuration = sha256.Sum256([]byte("omp-task-no-curation"))

// curationDigest identifies the effective curation of an offer.
func curationDigest(p *curation.Policy) string {
	if p == nil {
		return hex.EncodeToString(noCuration[:])
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "" // never a valid digest: the binding is refused
	}
	sum := sha256.Sum256(append([]byte("omp-task-curation:"), raw...))
	return hex.EncodeToString(sum[:])
}

// dependencyDigest identifies WHAT the credential for a task's server is made
// of — the auth mode, the static credential parts' kind and name, the person
// secret's placement, the provider and scopes (and shared connection) a
// delegated credential comes from, a machine client's non-secret configuration
// and whether identity and TLS are used — and never a token, secret value, hint
// or generation. A rotated secret or a refreshed token is the same dependency;
// a different provider, connection, placement or client is not.
func (rc *request) dependencyDigest(o gateways.Offer, cred *providers.Credential, secret *personsecrets.Secret, t upstream.Target) (string, error) {
	type credFacts struct {
		ProviderID        uuid.UUID `json:"providerId"`
		Resource          string    `json:"resource,omitempty"`
		ServiceConnection uuid.UUID `json:"serviceConnection,omitempty"`
		ServerBound       bool      `json:"serverBound"`
	}
	facts := struct {
		Mode         string      `json:"mode"`
		Static       [][2]string `json:"static,omitempty"`
		PersonSecret *[3]string  `json:"personSecret,omitempty"`
		RequiresID   uuid.UUID   `json:"requiresId,omitempty"`
		Scopes       []string    `json:"scopes,omitempty"`
		Credential   *credFacts  `json:"credential,omitempty"`
		Machine      string      `json:"machine,omitempty"`
		Identity     bool        `json:"identity"`
		TLS          bool        `json:"tls"`
	}{Mode: registry.AuthModeOf(o.Server), Identity: o.Server.SendIdentity, TLS: t.TLS != nil}
	for _, c := range t.Credentials {
		facts.Static = append(facts.Static, [2]string{c.Kind, c.Name})
	}
	if secret != nil {
		facts.PersonSecret = &[3]string{secret.Placement, secret.Name, secret.Prefix}
	}
	if o.Requires != nil {
		facts.RequiresID = o.Requires.Provider.ID
		facts.Scopes = slices.Clone(o.Requires.Scopes)
		slices.Sort(facts.Scopes)
	}
	if cred != nil {
		facts.Credential = &credFacts{ProviderID: cred.Provider.ID, Resource: cred.Resource, ServiceConnection: cred.ServiceConnectionID,
			ServerBound: cred.Provider.ServerBound()}
	}
	if machineMode(o) {
		id, err := rc.h.Registry.MachineIdentity(rc.r.Context(), o.Server)
		if err != nil {
			return "", err
		}
		facts.Machine = id
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("omp-task-dependency:"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// taskBinding is the snapshot identity of the offer a task is created from.
func (rc *request) taskBinding(o gateways.Offer, argumentsDigest, dependency string) mcptasks.Binding {
	root := rc.taskRoot()
	return mcptasks.Binding{PrincipalKind: root.PrincipalKind, PrincipalID: root.PrincipalID,
		CredentialKind: root.CredentialKind, CredentialID: root.CredentialID, GatewayID: root.GatewayID,
		ServerID: o.Server.ID, CapabilityID: o.Capability.ID, ExposedName: o.ExposedName,
		ServerURL: o.Server.URL, ServerRevision: o.Server.Revision, ToolClass: derefString(o.Capability.ToolClass),
		DefinitionFingerprint: o.Capability.Fingerprint, CurationDigest: curationDigest(o.Curation),
		ArgumentsDigest: argumentsDigest, DependencyDigest: dependency}
}

// sameOffer reports whether a freshly resolved offer is the one a task was
// created from: the identical capability, server, revision, full URL,
// definition fingerprint, tool class and effective curation.
func sameOffer(o gateways.Offer, b mcptasks.Binding) bool {
	return o.Allowed && o.Capability.Kind == upstream.KindTool &&
		o.Capability.ID == b.CapabilityID && o.Server.ID == b.ServerID && o.ExposedName == b.ExposedName &&
		o.Server.Revision == b.ServerRevision && o.Server.URL == b.ServerURL &&
		o.Capability.Fingerprint == b.DefinitionFingerprint && derefString(o.Capability.ToolClass) == b.ToolClass &&
		curationDigest(o.Curation) == b.CurationDigest
}

// taskRedactor removes every value a task response must not carry: the actual
// upstream task ID, the credential values sent for the original exchange (kept
// sealed only to scrub), and the fresh credentials of THIS exchange. It works
// on decoded JSON strings and keys, so a value cannot hide behind JSON
// escaping, and refuses to ship an encoding that still holds one.
type taskRedactor struct {
	values []string
}

const (
	taskRedaction = "[REDACTED]"
	// Credential values shorter than this are not treated as secrets: they
	// would only mangle ordinary text. The upstream task ID is always scrubbed.
	minRedactedSecret = 4
)

// newTaskRedactor collects the values to remove. id is the upstream task ID
// (scrubbed whatever its length); groups are credential values.
func newTaskRedactor(id string, groups ...[]string) *taskRedactor {
	seen := map[string]bool{}
	r := &taskRedactor{}
	add := func(v string) {
		for _, form := range []string{v, url.QueryEscape(v), url.PathEscape(v)} {
			if form != "" && !seen[form] {
				seen[form] = true
				r.values = append(r.values, form)
			}
		}
	}
	add(id)
	for _, group := range groups {
		for _, v := range group {
			if len(v) >= minRedactedSecret {
				add(v)
			}
		}
	}
	// Longest first, so a value containing another is removed whole.
	sort.SliceStable(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
	return r
}

// taskCredentialValues are the credential values this exchange actually
// sends: every part of the target (static parts, person secret, identity,
// provider token, bearer, TLS key), the identity token as signed and the
// tokens the request already scrubs. Never capture.Secrets: that holds the
// downstream client's own bearer.
func (rc *request) taskCredentialValues(t upstream.Target, token string) []string {
	out := append([]string(nil), t.Secrets()...)
	out = append(out, rc.scrub...)
	if token != "" {
		out = append(out, token)
	}
	return out
}

func (r *taskRedactor) text(s string) string {
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, taskRedaction)
	}
	return s
}

func (r *taskRedactor) hits(s string) bool {
	for _, v := range r.values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

func (r *taskRedactor) walk(v any) any {
	switch x := v.(type) {
	case string:
		return r.text(x)
	case json.Number:
		if r.hits(x.String()) {
			return taskRedaction
		}
		return x
	case []any:
		for i := range x {
			x[i] = r.walk(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[r.text(k)] = r.walk(e)
		}
		return out
	}
	return v
}

// json scrubs a raw JSON value (decoded: strings, keys and numbers).
func (r *taskRedactor) json(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, io.ErrUnexpectedEOF
	}
	return marshalNoEscape(r.walk(v))
}

func marshalNoEscape(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// clean is the last gate before bytes leave: no value may remain in the
// encoding, raw or JSON-escaped.
func (r *taskRedactor) clean(encoded []byte) bool {
	s := string(encoded)
	for _, v := range r.values {
		if strings.Contains(s, v) {
			return false
		}
		if quoted, err := json.Marshal(v); err == nil && len(quoted) > 2 && strings.Contains(s, string(quoted[1:len(quoted)-1])) {
			return false
		}
	}
	return true
}

// validRedactionValues reports whether a set of values fits what a task seals.
func validRedactionValues(values []string) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	total := 0
	for _, v := range values {
		if len(v) < minRedactedSecret || seen[v] {
			continue
		}
		if !utf8.ValidString(v) || len(v) > mcptasks.MaxRedactionSecretBytes {
			return nil, false
		}
		seen[v] = true
		total += len(v)
		out = append(out, v)
	}
	if len(out) > mcptasks.MaxRedactionSecrets || total > mcptasks.MaxRedactionSecretsBytes {
		return nil, false
	}
	return out, true
}

// publicTask builds the portal's own Task from validated fields only: the
// portal handle, the portal's timeline, the REMAINING local lifetime in whole
// milliseconds (never the upstream's, never null) and the stored bounded poll
// interval. The upstream ID, timestamps and TTL are never copied. ok false: the
// task has no lifetime left.
func publicTask(handle string, snap mcptasks.Snapshot, status, message string, red *taskRedactor, now time.Time) (map[string]any, bool) {
	remaining := snap.ExpiresAt().Sub(now).Milliseconds()
	if remaining <= 0 {
		return nil, false
	}
	created := snap.CreatedAt().UTC()
	updated := snap.UpstreamUpdatedAt().UTC()
	if updated.Before(created) {
		updated = created
	}
	out := map[string]any{
		"taskId": handle, "status": status,
		"createdAt": created.Format(time.RFC3339Nano), "lastUpdatedAt": updated.Format(time.RFC3339Nano),
		"ttlMs": remaining, "pollIntervalMs": snap.PollMillis(),
	}
	if message != "" {
		if m := strings.TrimSpace(red.text(message)); m != "" {
			out["statusMessage"] = m
		}
	}
	return out, true
}
