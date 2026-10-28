package mcpgw

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/trace"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Calls to MCP servers in person_secret mode (docs/person-secrets.md,
// decision 72). Each person's own secret, entered under Account › My
// connections, goes in the placement the server's team chose (a header, a
// bearer token or a query parameter), only to the server's stored URL (the
// secret is bound to its origin, and Resolve refuses one that isn't). After
// every other check passed, and after the provider credential step, a call
// of such a server:
//
//  1. from a service account is refused (-32010, data.reason service_account;
//     recorded denied): shared team secrets are roadmap #26;
//  2. without an active secret of the acting person gets the consent answer
//     in the three shapes of decision 59 with a link to the page where they
//     enter it (-32042 for a legacy client; an input_required result for a
//     modern client that declared URL elicitation; a tool error, or -32010 for
//     a prompt or a read, for one that didn't), recorded needs_authorization
//     with class secret_missing or secret_rejected, and nothing is forwarded:
//     there is never a fallback to another credential;
//  3. is forwarded with the secret and the identity token (which moves to
//     MCP-Gateway-Identity when the secret occupies Authorization);
//  4. answered 401 or 403 by the server marks the secret rejected (no retry:
//     the server said no, and nothing ran) and asks again.

// Error classes of person secret calls (mcp_calls.error_class).
const (
	ClassSecretMissing  = personsecrets.ReasonMissing
	ClassSecretRejected = personsecrets.ReasonRejected
)

// personSecret returns the acting person's secret for a call to a
// person_secret server (nil, true for any other server). ok false: it
// answered and recorded the call itself.
func (rc *request) personSecret(o gateways.Offer, rec *calls.Call) (*personsecrets.Secret, bool) {
	if _, ok := registry.PersonSecretConfig(o.Server); !ok {
		return nil, true
	}
	noun := kindNoun(o.Capability.Kind)
	if rc.principal.account != nil {
		n := rc.failData(codeDenied, fmt.Sprintf("This %s needs a person's own key for %s; service accounts can't use it", noun, serverLabel(o)),
			map[string]any{"reason": DeniedServiceAccount})
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, DeniedServiceAccount
		rc.record(*rec, n)
		return nil, false
	}
	if rc.h.PersonSecrets == nil {
		rc.internal(errors.New("person secrets are not configured"))
		return nil, false
	}
	sp := rc.span("mcp.person_secret", trace.SpanKindInternal)
	sec, err := rc.h.PersonSecrets.Resolve(rc.r.Context(), rc.secretContext(o))
	var need *personsecrets.NeedsSecret
	switch {
	case err == nil:
		sp.End()
		rc.personSecretUsed = &sec
		return &sec, true
	case errors.As(err, &need):
		sp.End()
		rc.needsSecret(o, need, rec)
	case errors.Is(err, personsecrets.ErrInactive):
		sp.End()
		n := rc.refuseText(o.Capability.Kind == upstream.KindTool, "Your Open MCP Portal account is suspended, so the call wasn't run.", "person_suspended", "")
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "person_suspended"
		rc.record(*rec, n)
	default:
		observability.Fail(sp, "unavailable")
		sp.End()
		rc.internal(err)
	}
	return nil, false
}

func (rc *request) secretContext(o gateways.Offer) personsecrets.CallContext {
	return personsecrets.CallContext{User: rc.principal.user, Server: o.Server, Gateway: rc.gateway, CapabilityID: o.Capability.ID,
		Kind: o.Capability.Kind, ExposedName: o.ExposedName, Title: o.Capability.Title}
}

// withPersonSecret adds the person's secret to the forwarded call's target
// (before prepareTarget, which decides where the identity token goes by what
// the target's credentials occupy) and to what the server's answer is scrubbed
// of: the bare secret, the value with its prefix and the URL-encoded forms.
func (rc *request) withPersonSecret(t *upstream.Target, sec *personsecrets.Secret) bool {
	if sec == nil {
		return true
	}
	if !t.WithPersonSecret(sec.Placement, sec.Name, sec.Prefix, sec.Value) {
		rc.internal(errors.New("a person secret has an unknown placement"))
		return false
	}
	for _, v := range []string{sec.Prefix + sec.Value, sec.Value} {
		rc.scrub = append(rc.scrub, v, url.QueryEscape(v), url.PathEscape(v))
	}
	return true
}

// secretRefused handles an upstream 401 or 403 on a call that carried a
// person's secret: the secret is marked rejected (the value sent; one entered
// since is not touched) and the person is asked again. No retry.
func (rc *request) secretRefused(o gateways.Offer, rec *calls.Call) {
	ctx := rc.r.Context()
	if _, err := rc.h.PersonSecrets.Reject(ctx, *rc.personSecretUsed); err != nil {
		rc.internal(err)
		return
	}
	err := rc.h.PersonSecrets.NeedAgain(ctx, rc.secretContext(o))
	var need *personsecrets.NeedsSecret
	if errors.As(err, &need) {
		rc.needsSecret(o, need, rec)
		return
	}
	rc.internal(err)
}

// secretRefusal reports whether err is the server refusing the secret it was
// sent (HTTP 401 or 403) on a call that carried one.
func (rc *request) secretRefusal(err error) bool {
	var ue *upstream.Error
	return rc.personSecretUsed != nil && errors.As(err, &ue) && (ue.HTTPStatus == http.StatusUnauthorized || ue.HTTPStatus == http.StatusForbidden)
}

// needsSecret asks the person to enter or replace their key, with a link in
// the three response shapes of decision 59.
func (rc *request) needsSecret(o gateways.Offer, n *personsecrets.NeedsSecret, rec *calls.Call) {
	class := n.Reason
	label, server := n.Label, fmt.Sprintf("%s (%s)", n.Server.Name, n.Server.TeamSlug)
	rec.Outcome, rec.ErrorClass = calls.OutcomeNeedsAuthorization, class
	verb := "Enter"
	if n.Reason == personsecrets.ReasonRejected {
		verb = "Enter again"
	}
	msg := fmt.Sprintf("%s needs your own %s for %s. Open %s to enter it, then try again.", o.ExposedName, label, server, n.URL)
	if n.Reason == personsecrets.ReasonRejected {
		msg = fmt.Sprintf("%s: %s refused your %s. Open %s to enter it again, then try again.", o.ExposedName, server, label, n.URL)
	}
	elicit := fmt.Sprintf("%s your %s for %s to use %s in the %s gateway.", verb, label, server, o.ExposedName, rc.gateway.Name)
	if rc.secretInputRequired(n, elicit, rec) {
		return
	}
	var out int64
	switch {
	case rc.modern && o.Capability.Kind == upstream.KindTool:
		out = rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true})
	case rc.modern:
		out = rc.failData(codeDenied, msg, map[string]any{"reason": class, "server": n.Server.Slug})
	default:
		out = rc.failData(codeURLElicitationRequired, msg, map[string]any{"elicitations": []map[string]any{{
			"mode": "url", "elicitationId": n.RequestID, "url": n.URL, "message": elicit,
		}}})
	}
	rc.record(*rec, out)
}

// secretInputRequired answers a modern request whose client declared URL
// elicitation with the link as an input request (false: the caller falls back
// to the plain answer, as when the gateway has no key).
func (rc *request) secretInputRequired(n *personsecrets.NeedsSecret, message string, rec *calls.Call) bool {
	box := rc.h.states()
	if box == nil || !rc.urlElicitation() {
		return false
	}
	token, err := box.seal(rc.stateFor(purposeConsent))
	if err != nil {
		rc.h.log().Error("mcp requestState could not be sealed", "err", err)
		return false
	}
	out := rc.reply(map[string]any{
		"resultType": resultInputRequired,
		"inputRequests": map[string]any{"secret_" + strings.ReplaceAll(n.Server.Slug, "-", "_"): map[string]any{
			"method": "elicitation/create",
			"params": map[string]any{"mode": "url", "url": n.URL, "message": message},
		}},
		"requestState": token,
	})
	rc.record(*rec, out)
	return true
}

// scrubText removes every value the call must not echo (a person's own
// secret or an oauth token) from a text the server controls.
func (rc *request) scrubText(s string) string {
	for _, tok := range rc.scrub {
		if tok != "" {
			s = strings.ReplaceAll(s, tok, "[REDACTED]")
		}
	}
	return s
}
