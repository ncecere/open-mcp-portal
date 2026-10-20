package mcpgw

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Delegated credentials at call time (docs/phase5-delegated-credentials.md
// "Runtime", decisions 27-29). After every other check passed, a call of a
// capability with an effective requirement:
//
//  1. from a service account is refused (-32010, data.reason
//     service_account; recorded denied);
//  2. of a turned-off provider is refused (-32010 provider_disabled;
//     recorded denied);
//  3. without an active connection covering the scopes, or with one the
//     person hasn't allowed this server to use (at the origin its URL has
//     now; reason server_not_allowed), gets a consent link
//     (-32042 URLElicitationRequiredError, the link also in the message;
//     a modern client that declared URL elicitation gets an
//     input_required result instead, one that didn't a tool error or
//     -32010 with the link; recorded needs_authorization) and
//     nothing is forwarded;
//  4. with a token expiring within a minute refreshes it first; a provider
//     that can't be reached is -32010 provider_unavailable (recorded
//     upstream_error) and nothing is forwarded;
//  5. is forwarded with MCP-Gateway-Provider and MCP-Gateway-Provider-Token
//     and the identity token's provider claim.
//
// Calls without a requirement (or with the override none) never get these.

// Error classes of refused calls (mcp_calls.error_class).
const (
	DeniedServiceAccount   = "service_account"
	DeniedProviderDisabled = "provider_disabled"
	ProviderUnavailable    = "provider_unavailable"
)

func kindNoun(kind string) string {
	switch kind {
	case upstream.KindPrompt:
		return "prompt"
	case upstream.KindResource, upstream.KindResourceTemplate:
		return "resource"
	}
	return "tool"
}

// serverLabel names the server and its team, as the consent page does.
func serverLabel(o gateways.Offer) string {
	return fmt.Sprintf("%s (%s)", o.Server.Name, o.TeamSlug)
}

func scopeNote(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	return " (" + strings.Join(scopes, ", ") + ")"
}

// delegated gets the person's provider token for o when it requires one.
// It answers and records the call itself when the call can't go ahead (ok
// false). cred is nil for capabilities without a requirement.
func (rc *request) delegated(o gateways.Offer, rec *calls.Call) (cred *providers.Credential, ok bool) {
	req := o.Requires
	if req == nil {
		return nil, true
	}
	rec.ProviderSlug = req.Provider.Slug
	noun := kindNoun(o.Capability.Kind)
	if rc.principal.isServiceAccount() {
		msg := fmt.Sprintf("This %s needs a person's %s account; service accounts can't use it", noun, req.Provider.Name)
		if req.Provider.ServerBound() {
			msg = fmt.Sprintf("This %s needs a person to sign in to %s; service accounts can't use it", noun, req.Provider.Name)
		}
		n := rc.failData(codeDenied, msg, map[string]any{"reason": DeniedServiceAccount, "provider": req.Provider.Slug})
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, DeniedServiceAccount
		rc.record(*rec, n)
		return nil, false
	}
	if rc.h.Providers == nil {
		rc.providerDisabled(req, rec)
		return nil, false
	}
	c, err := rc.h.Providers.Credential(rc.r.Context(), req, rc.callContext(o))
	var consent *providers.ConsentNeeded
	var down *providers.UnavailableError
	switch {
	case err == nil:
		return &c, true
	case errors.Is(err, providers.ErrProviderDisabled):
		rc.providerDisabled(req, rec)
	case errors.As(err, &consent):
		rc.needsAuthorization(o, consent, rec, "")
	case errors.As(err, &down):
		rc.providerUnavailable(o, rec)
	default:
		rc.internal(err)
	}
	return nil, false
}

func (rc *request) providerUnavailable(o gateways.Offer, rec *calls.Call) {
	req := o.Requires
	n := rc.failData(codeDenied, fmt.Sprintf("%s couldn't be reached to renew your access. Try again shortly.", req.Provider.Name),
		map[string]any{"reason": ProviderUnavailable, "provider": req.Provider.Slug})
	rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, ProviderUnavailable
	rc.record(*rec, n)
}

func (rc *request) providerDisabled(req *registry.Requirement, rec *calls.Call) {
	msg := fmt.Sprintf("%s accounts are turned off on this gateway; ask a platform admin", req.Provider.Name)
	if req.Provider.ServerBound() {
		msg = fmt.Sprintf("Signing in to %s is turned off on this gateway; ask a platform admin", req.Provider.Name)
	}
	n := rc.failData(codeDenied, msg,
		map[string]any{"reason": DeniedProviderDisabled, "provider": req.Provider.Slug})
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, DeniedProviderDisabled
	rc.record(*rec, n)
}

// needsAuthorization answers URLElicitationRequiredError (MCP 2025-11-25)
// with one URL elicitation. Legacy clients only state their capabilities on
// initialize, which the stateless gateway doesn't keep, so every legacy
// client gets it, and the
// message carries the link too for clients that only show errors. The URL
// holds an opaque ID only: it signs nobody in, and works only in the
// person's own browser session.
//
// A modern request (2026-07-28) from a client that declared URL elicitation
// gets the same link as a multi round-trip input request instead
// (requeststate.go); nothing in the link, or elsewhere, changes. A modern
// request from a client that did not declare it gets no -32042 (the revision
// says not to send it to such a client): a tool call answers a tool error
// (isError) and a prompt or resource read a -32010 error, both with the
// link in the message.
func (rc *request) needsAuthorization(o gateways.Offer, c *providers.ConsentNeeded, rec *calls.Call, class string) {
	if rc.relayedPerson() {
		// An agent has no browser: no link, no -32042, no input request.
		rc.needsConnection(o, c, rec)
		return
	}
	if rc.consentInputRequired(o, c, rec, class) {
		return
	}
	name, scopes := c.Provider.Name, scopeNote(c.Scopes)
	var msg, elicit string
	switch {
	case c.Provider.ServerBound():
		// An oauth server's own sign-in, labelled with the server's name.
		verb := "sign in to"
		if c.Reason == providers.ReasonMissingScopes {
			verb = "grant more access to"
		} else if c.Reason == providers.ReasonNeedsReconsent {
			verb = "sign in again to"
		}
		msg = fmt.Sprintf("%s needs you to %s %s%s. Open %s, then try again.", o.ExposedName, verb, name, scopes, c.URL)
		elicit = fmt.Sprintf("Sign in to %s%s to use %s in the %s gateway.", name, scopes, o.ExposedName, rc.gateway.Name)
	case c.Reason == providers.ReasonServerNotAllowed:
		msg = fmt.Sprintf("%s needs you to allow %s to use your %s account%s. Open %s to review and allow it, then try again.",
			o.ExposedName, serverLabel(o), name, scopes, c.URL)
		elicit = fmt.Sprintf("Allow %s to use your %s account%s for %s in the %s gateway.", serverLabel(o), name, scopes, o.ExposedName, rc.gateway.Name)
	case c.Reason == providers.ReasonMissingScopes:
		msg = fmt.Sprintf("%s needs more access to your %s account%s. Open %s to grant it, then try again.", o.ExposedName, name, scopes, c.URL)
	case c.Reason == providers.ReasonNeedsReconsent:
		msg = fmt.Sprintf("%s needs you to reconnect your %s account%s. Open %s to reconnect it, then try again.", o.ExposedName, name, scopes, c.URL)
	default:
		msg = fmt.Sprintf("%s needs your %s account%s. Open %s to connect it, then try again.", o.ExposedName, name, scopes, c.URL)
	}
	if elicit == "" {
		elicit = fmt.Sprintf("Connect your %s account%s to use %s in the %s gateway.", name, scopes, o.ExposedName, rc.gateway.Name)
	}
	if class == "" {
		class = c.Reason
	}
	var n int64
	switch {
	case rc.modern && o.Capability.Kind == upstream.KindTool:
		n = rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true})
	case rc.modern:
		n = rc.failData(codeDenied, msg, map[string]any{"reason": class, "provider": c.Provider.Slug})
	default:
		data := map[string]any{"elicitations": []map[string]any{{
			"mode": "url", "elicitationId": c.RequestID, "url": c.URL, "message": elicit,
		}}}
		n = rc.failData(codeURLElicitationRequired, msg, data)
	}
	rec.Outcome, rec.ErrorClass = calls.OutcomeNeedsAuthorization, class
	rc.record(*rec, n)
}
