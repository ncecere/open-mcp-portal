package mcpgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// callParams are tools/call and prompts/get parameters.
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// notFound is what a refused or unknown call sees (MCP: unknown tools are
// invalid params).
func notFound(kind, name string) string {
	if kind == upstream.KindPrompt {
		return fmt.Sprintf("Unknown prompt: %s", clip(name, 200))
	}
	return fmt.Sprintf("Unknown tool: %s", clip(name, 200))
}

// call forwards tools/call or prompts/get after re-checking the
// capability. A refusal never reaches the server.
func (rc *request) call(kind string) {
	var p callParams
	if len(rc.msg.Params) == 0 || json.Unmarshal(rc.msg.Params, &p) != nil || p.Name == "" {
		n := rc.fail(codeInvalidParams, "Invalid parameters: name is required")
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_params"}, n)
		return
	}
	args := bytes.TrimSpace(p.Arguments)
	if len(args) > 0 && !bytes.Equal(args, []byte("null")) && args[0] != '{' {
		n := rc.fail(codeInvalidParams, "Invalid parameters: arguments must be an object")
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_params", ExposedName: p.Name}, n)
		return
	}
	again, ok := rc.checkRetry(calls.Call{ExposedName: p.Name})
	if !ok {
		return
	}
	offers, err := rc.offers(kind)
	if err != nil {
		rc.internal(err)
		return
	}
	var offer *gateways.Offer
	for i := range offers {
		if offers[i].ExposedName == p.Name {
			offer = &offers[i]
		}
	}
	if offer == nil || !offer.Allowed {
		n := rc.fail(codeInvalidParams, notFound(kind, p.Name))
		c := calls.Call{Outcome: calls.OutcomeDenied, ErrorClass: "unknown", ExposedName: p.Name}
		if offer != nil {
			c.ErrorClass, c.Server, c.CapabilityID = offer.Denied, &offer.Server, offer.Capability.ID
			if offer.Requires != nil {
				c.ProviderSlug = offer.Requires.Provider.Slug
			}
		}
		rc.record(c, n)
		return
	}
	if rc.modern && kind == upstream.KindTool {
		if eerr := validateParamHeaders(rc.r.Header, offer.Capability.Definition, args); eerr != nil {
			n := writeRPC(rc.w, eerr.status, rc.msg.ID, nil, &rpcError{Code: eerr.code, Message: eerr.message})
			rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "header_mismatch", ExposedName: p.Name, Server: &offer.Server,
				CapabilityID: offer.Capability.ID}, n)
			return
		}
	}
	if again.declined {
		rc.declined(*offer)
		return
	}
	rc.forward(kind, *offer, args, again)
}

// forward sends the call to the server with the caller's signed identity, in
// the era the server speaks, and relays what comes back: its result, or an
// elicitation it needs the person to answer (relay.go). A tools/call with a
// progress token from a client that accepts SSE is answered as a stream
// (stream.go).
func (rc *request) forward(kind string, o gateways.Offer, args json.RawMessage, again retry) {
	ctx := rc.r.Context()
	rec := calls.Call{ExposedName: o.ExposedName, Server: &o.Server, CapabilityID: o.Capability.ID}
	if !rc.presenceOK(o, &rec) {
		return
	}
	cred, ok := rc.delegated(o, &rec)
	if !ok {
		return
	}
	target, err := rc.h.Registry.Target(ctx, o.Server)
	if err != nil {
		rc.upstreamFailed(rec, err)
		return
	}
	who := identityFor{tool: o.ExposedName}
	method := upstream.MethodToolsCall
	if kind == upstream.KindPrompt {
		who, method = identityFor{prompt: o.ExposedName}, upstream.MethodPromptsGet
	}
	token, ok := rc.prepareTarget(&target, who, o, cred, &rec)
	if !ok {
		return
	}
	if kind == upstream.KindPrompt {
		var sargs map[string]string
		if len(args) > 0 && !bytes.Equal(args, []byte("null")) {
			if err := json.Unmarshal(args, &sargs); err != nil {
				n := rc.fail(codeInvalidParams, "Invalid parameters: prompt arguments must be strings")
				rec.Outcome, rec.ErrorClass = calls.OutcomeBadRequest, "invalid_params"
				rc.record(rec, n)
				return
			}
		}
	}
	rc.captureCall(o, args, target, token, cred)
	if kind == upstream.KindTool {
		// SEP-2243 parameter headers, from the approved definition.
		target.ParamHeaders = upstream.ParamHeaders(o.Capability.Definition, args)
	}
	fwd, ok := rc.forwardRequest(method, o.Capability.Name, args, o, again, &rec)
	if !ok {
		return
	}
	if progress, ok := rc.wantsStream(); ok && kind == upstream.KindTool {
		st := rc.startStream(progress)
		defer st.close()
		fwd.ProgressToken, fwd.OnProgress = progress, st.progress
		target.MaxBody = maxStreamBytes
	}
	rc.forwardCall(o, rec, cred, target, fwd)
}

// forwardCall makes the call and answers with its outcome.
func (rc *request) forwardCall(o gateways.Offer, rec calls.Call, cred *providers.Credential, target upstream.Target, fwd upstream.ForwardRequest) {
	ctx := rc.r.Context()
	client := rc.h.Registry.Client()
	out, _, ok := rc.exchange(o, &rec, cred, target, func(t upstream.Target) (any, bool, error) {
		res, err := client.Forward(ctx, t, fwd)
		if err != nil {
			return nil, false, err
		}
		return res, false, nil
	})
	if !ok {
		return
	}
	fr := out.(*upstream.ForwardResult)
	if fr.Input != nil {
		rc.relayInput(o, rec, fr.Input)
		return
	}
	switch {
	case fr.Tool != nil:
		rc.relay(rec, fr.Tool, fr.Tool.IsError)
	case fr.Prompt != nil:
		rc.relay(rec, fr.Prompt, false)
	default:
		// A read: the contents' URIs go back in the exposed form.
		for _, c := range fr.Read.Contents {
			if c != nil {
				c.URI = gateways.ExposedURI(o.Server.Slug, c.URI)
			}
		}
		rc.relay(rec, fr.Read, false)
	}
}

// relay answers with a server's result (without upstreamMetaKeys, at most
// MaxResponseBytes) and records the exchange.
func (rc *request) relay(rec calls.Call, result any, isError bool) {
	encoded, err := json.Marshal(result)
	if err == nil {
		encoded, err = scrubMetaFor(encoded, rc.modern)
	}
	for _, tok := range rc.scrub {
		if err == nil && tok != "" {
			encoded = bytes.ReplaceAll(encoded, []byte(tok), []byte("[REDACTED]"))
		}
	}
	if err != nil || len(encoded) > MaxResponseBytes {
		n := rc.fail(codeInternal, "The server's response is too large")
		rec.Outcome, rec.ErrorClass = calls.OutcomeTooLarge, upstream.ClassTooLarge
		rc.record(rec, n)
		return
	}
	rc.captureResult(encoded)
	n := rc.reply(json.RawMessage(encoded))
	rec.Outcome = calls.OutcomeOK
	if isError {
		rec.Outcome = calls.OutcomeToolError
	}
	rc.record(rec, n)
}

// upstreamMetaKeys are _meta entries about the upstream itself that clients
// of a gateway don't need: the gateway is the server they talk to.
var upstreamMetaKeys = []string{"io.modelcontextprotocol/serverInfo"}

// scrubMeta removes upstreamMetaKeys from a result's _meta (and an empty
// _meta), leaving everything else as the upstream sent it, for a legacy
// client.
func scrubMeta(encoded []byte) ([]byte, error) { return scrubMetaFor(encoded, false) }

// scrubMetaFor is scrubMeta for an era: a modern client can read any JSON
// value as structuredContent, a legacy one only an object.
func scrubMetaFor(encoded []byte, modern bool) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &obj); err != nil {
		return encoded, nil // not an object: nothing to scrub
	}
	changed := false
	// structuredContent must be a JSON object (MCP schema); strict clients
	// reject a result whose isn't (GitHub's server returns arrays). The
	// same data is in the text content, so drop it.
	if sc, ok := obj["structuredContent"]; ok && !modern && !isJSONObject(sc) {
		delete(obj, "structuredContent")
		changed = true
	}
	raw, ok := obj["_meta"]
	if !ok {
		if !changed {
			return encoded, nil
		}
		return json.Marshal(obj)
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil {
		if !changed {
			return encoded, nil
		}
		return json.Marshal(obj)
	}
	for _, k := range upstreamMetaKeys {
		if _, ok := meta[k]; ok {
			delete(meta, k)
			changed = true
		}
	}
	if !changed {
		return encoded, nil
	}
	if len(meta) == 0 {
		delete(obj, "_meta")
	} else {
		m, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}
		obj["_meta"] = m
	}
	return json.Marshal(obj)
}

// isJSONObject reports whether raw is a JSON object.
func isJSONObject(raw json.RawMessage) bool {
	var o map[string]json.RawMessage
	return json.Unmarshal(raw, &o) == nil && o != nil
}

// upstreamFailed answers a failed exchange with a JSON-RPC error (the
// message is safe to show: internal/upstream redacts secrets).
func (rc *request) upstreamFailed(rec calls.Call, err error) {
	var ue *upstream.Error
	if !errors.As(err, &ue) {
		rc.internal(err)
		return
	}
	code := int64(codeInternal)
	rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, ue.Class
	if rc.r.Context().Err() != nil && ue.Class != upstream.ClassTimeout {
		rec.ErrorClass = "client_cancelled" // the client went away; the call to the server was cancelled
	}
	switch {
	case ue.Class == upstream.ClassTimeout:
		rec.Outcome = calls.OutcomeTimeout
	case ue.Class == upstream.ClassTooLarge:
		rec.Outcome = calls.OutcomeTooLarge
	case ue.RPCCode == codeInvalidParams:
		code, rec.Outcome = codeInvalidParams, calls.OutcomeBadRequest
	case ue.RPCCode == codeResourceNotFound:
		code, rec.Outcome, rec.ErrorClass = rc.resourceNotFoundCode(), calls.OutcomeBadRequest, upstream.ClassNotFound
	}
	if ue.RPCCode != 0 {
		rc.captureError(code, ue.Message)
	}
	n := rc.fail(code, ue.Message)
	rc.record(rec, n)
}

// identityFor is what a token is for: the exposed tool or prompt name, or
// the exposed resource URI read (exactly one).
type identityFor struct {
	tool, prompt, resource string
}

// identityToken signs who is calling, for the server's URL: a person
// (principal_type user: their ID, email, name and teams) or a service
// account (principal_type service_account: its ID, name and team, no
// email). client is the connected OAuth client's name (with
// client_verified), else the request's clientInfo.name, else the key's name.
func (rc *request) identityToken(what identityFor, o gateways.Offer, cred *providers.Credential) (string, error) {
	p := rc.principal
	c := identity.Claims{Audience: o.Server.URL, Gateway: rc.gateway.Slug, Tool: what.tool, Prompt: what.prompt, Resource: what.resource}
	if cred != nil && !serverBound(cred) {
		// Only calls that carry a platform provider's token name the
		// provider (an oauth server's own token is its bearer).
		c.Provider = cred.Provider.Slug
	}
	if sa := p.account; sa != nil && !p.relayedPerson() {
		c.PrincipalType, c.Subject, c.Name, c.Teams = identity.PrincipalServiceAccount, sa.Account.ID.String(), sa.Account.Name, []string{sa.Team.Slug}
	} else {
		u := p.actingUser()
		teamRows, err := dbgen.New(rc.h.Pool).ListTeamsForUser(rc.r.Context(), u.ID)
		if err != nil {
			return "", err
		}
		slugs := make([]string, len(teamRows))
		for i, t := range teamRows {
			slugs[i] = t.Slug
		}
		c.PrincipalType, c.Subject, c.Email, c.Name, c.Teams = identity.PrincipalUser, u.ID.String(), u.Email, u.DisplayName, slugs
	}
	switch {
	case p.relayedPerson():
		// An agent's call for the person: the person is the principal, the
		// agent is the actor, and the client is the relay account.
		c.Client, c.Act = p.account.Account.Name, p.actClaim()
	case p.grant != nil:
		// Only a metadata-document client's name is vouched for by its host;
		// a client that registered itself chose its own name.
		verified := p.grant.ClientKind == oauth.KindMetadata
		c.Client, c.ClientVerified = p.grant.ClientName, &verified
	default:
		if c.Client = rc.clientName(); c.Client == "" {
			c.Client = p.keyName
		}
	}
	return rc.h.Identity.Sign(rc.r.Context(), c)
}
