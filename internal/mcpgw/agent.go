package mcpgw

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/agentidentity"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Calls relayed by a trusted agent platform (decisions 65 and 66,
// docs/agent-platforms.md, docs/threat-model.md "The agent platform relay").
//
// A service account marked as a relay for a platform may present that
// platform's identity token in MCP-Gateway-Identity next to its key:
//
//   - no token: the call is the service account's, as always;
//   - a token that fails any check (internal/agentidentity), or is another
//     platform's: the request is refused (403) and nothing runs. The caller
//     is never "downgraded" to the account silently, and never upgraded;
//   - a valid token without a person (a shared thread, no thread): the call
//     is the service account's own, with the agent and platform recorded;
//   - a valid token naming a person: the person is looked up by (person.iss,
//     person.sub) at every request. An unknown or suspended person is a tool
//     error ("no active account"), never a fall back to the account.
//     Otherwise the call is authorised as the person limited to what the relay
//     account could reach (gateways.Intersect), uses the person's delegated
//     credentials, never starts a consent flow (agentNeedsConnection), is
//     refused when its capability requires a present person and the token says
//     the person isn't (presenceOK), and carries the act claim downstream.
//
// A capability that requires a present person is also refused on a relay
// account when the call names nobody (a valid token with no person, or no
// token at all): presenceOK.
//
// A token on any other credential (a personal key, a connected client, a
// service account that is not a relay) is ignored: the call is that
// credential's own. It is counted and logged so a misconfiguration or a
// replay attempt is visible.

// Why a call for a person is refused before it runs (error classes).
const (
	DeniedPersonNoAccount = "person_no_account"
	DeniedPersonSuspended = "person_suspended"
)

// relayContext is what a verified agent token adds to a request.
type relayContext struct {
	platform dbgen.AgentPlatform
	agent    agentidentity.Identity
	// person is the user the agent acts for, when the token named one that
	// is active now (nil: the relay account's own call, or refused).
	person *dbgen.User
	// user is the user the token named even when they can't be used (for the
	// record of a refusal).
	user *dbgen.User
	// refused is why a named person can't be used ("": they can).
	refused string
}

// actingUser is the person a request is for: a person with a key or a
// connected client, or the person an agent acts for.
func (p principal) actingUser() dbgen.User {
	if p.relay != nil && p.relay.person != nil {
		return *p.relay.person
	}
	return p.user
}

// relayedPerson reports whether the request is an agent's call for a person.
func (p principal) relayedPerson() bool { return p.relay != nil && p.relay.person != nil }

// isServiceAccount reports whether the request is a service account's own
// call (not an agent's call for a person).
func (p principal) isServiceAccount() bool { return p.account != nil && !p.relayedPerson() }

func (rc *request) relayedPerson() bool { return rc.principal.relayedPerson() }

// ignoredLog throttles the log of ignored tokens to one per credential and
// minute (the counter has every one).
var ignoredLog sync.Map

func ignoredLogDue(key string, now time.Time) bool {
	last, ok := ignoredLog.Load(key)
	if ok && now.Sub(last.(time.Time)) < time.Minute {
		return false
	}
	ignoredLog.Store(key, now)
	return true
}

func countToken(result string) { observability.AgentTokens.WithLabelValues(result).Inc() }

// agentToken applies an MCP-Gateway-Identity header to an authenticated
// principal (see the rules above). ok false: the request was answered.
func (h *Handler) agentToken(w http.ResponseWriter, r *http.Request, p *principal) bool {
	vals := r.Header.Values(identity.HeaderIdentity)
	if len(vals) == 0 {
		return true
	}
	ctx := r.Context()
	reqID := httpx.RequestID(ctx)
	acct := p.account
	if acct == nil || !acct.Account.RelayPlatformID.Valid {
		countToken("ignored_not_relay")
		credential, id := p.kind, ""
		switch {
		case acct != nil:
			id = acct.Account.ID.String()
		case p.grant != nil:
			id = p.grant.ID.String()
		default:
			id = p.keyID.String()
		}
		if ignoredLogDue(credential+":"+id, time.Now()) {
			h.log().WarnContext(ctx, "an agent identity token came with a credential that is not a relay account's; it was ignored",
				"credential", credential, "credential_id", id, "request_id", reqID)
		}
		return true
	}
	fail := func(reason, detail string) bool { return h.refuseToken(w, r, acct, reason, detail) }
	if h.Agents == nil {
		return fail(agentidentity.ReasonUntrustedIssuer, "agent platforms are not configured")
	}
	if len(vals) != 1 {
		return fail(agentidentity.ReasonMalformed, "more than one token")
	}
	id, err := h.Agents.Verify(ctx, vals[0])
	var rj *agentidentity.Rejection
	switch {
	case errors.As(err, &rj):
		return fail(rj.Reason, rj.Detail)
	case err != nil:
		h.log().ErrorContext(ctx, "verifying an agent identity token failed", "err", err, "request_id", reqID)
		refuse(w, http.StatusInternalServerError, "Something went wrong")
		return false
	case id.Platform.ID != acct.Account.RelayPlatformID.UUID:
		// A valid token of a platform this account does not relay for.
		return fail(agentidentity.ReasonOtherPlatform, "the token's platform is not the one this account relays for")
	}
	rl := &relayContext{platform: id.Platform, agent: id}
	p.relay = rl
	if id.Person == nil {
		countToken("accepted_no_person")
		return true
	}
	u, err := dbgen.New(h.Pool).GetUserByIdentity(ctx, dbgen.GetUserByIdentityParams{OIDCIssuer: id.Person.Issuer, OIDCSubject: id.Person.Subject})
	switch {
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		rl.refused = DeniedPersonNoAccount
		countToken("person_no_account")
	case err != nil:
		h.log().ErrorContext(ctx, "looking up the person of an agent call failed", "err", err, "request_id", reqID)
		refuse(w, http.StatusInternalServerError, "Something went wrong")
		return false
	case u.Status != "active":
		rl.user, rl.refused = &u, DeniedPersonSuspended
		countToken("person_suspended")
	default:
		rl.user, rl.person = &u, &u
		countToken("accepted")
	}
	return true
}

// refuseToken refuses a request whose agent token failed a check: HTTP 403,
// counted as rejected_<reason> and logged with the reason (never the token).
// Always false: the request was answered.
func (h *Handler) refuseToken(w http.ResponseWriter, r *http.Request, acct *serviceaccounts.Principal, reason, detail string) bool {
	countToken("rejected_" + reason)
	h.log().WarnContext(r.Context(), "an agent identity token was refused", "reason", reason, "detail", detail,
		"service_account_id", acct.Account.ID.String(), "request_id", httpx.RequestID(r.Context()))
	w.Header().Set("Content-Type", "application/json")
	refuse(w, http.StatusForbidden, "The agent identity token was refused ("+reason+"). The request was not run.")
	return false
}

// toolBound checks, once the request is read, that a verified token's tool
// claim fits it (M-1): on a tools/call the claim is present and equals
// params.name, the tool the client called (the name this portal exposes); on
// every other method it is absent. A token minted for one tool, or for a
// handshake, is then no use for another call. A mismatch refuses the request
// like any bad relay token (403, tool_mismatch, nothing runs). ok false: the
// request was answered. Requests without a verified token are not affected.
func (h *Handler) toolBound(w http.ResponseWriter, r *http.Request, p principal, msg message) bool {
	rl := p.relay
	if rl == nil {
		return true
	}
	call := msg.Method == methodToolsCall
	name := ""
	if call {
		var params struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		name = params.Name
	}
	if rl.agent.ToolMatches(call, name) {
		return true
	}
	detail := "the token has a tool claim on a request that isn't a tool call"
	if call {
		detail = "the token's tool claim is missing or isn't the tool called"
	}
	return h.refuseToken(w, r, p.account, agentidentity.ReasonToolMismatch, detail)
}

// refusePerson answers a request for a person who can't be used: a tool
// error for tool calls, -32010 for the rest, a plain 202 for notifications
// (nothing to answer). It records the refusal. true: it answered.
func (rc *request) refusePerson() bool {
	rl := rc.principal.relay
	if rl == nil || rl.refused == "" {
		return false
	}
	if rc.msg.Method == "" || len(rc.msg.ID) == 0 {
		rc.w.WriteHeader(http.StatusAccepted)
		return true
	}
	msg := "This agent acts for a person who has no active Open MCP Portal account, so the call wasn't run. Ask them to sign in to the portal once."
	if rl.refused == DeniedPersonSuspended {
		msg = "This agent acts for a person whose Open MCP Portal account is suspended, so the call wasn't run."
	}
	n := rc.refuseText(rc.msg.Method == methodToolsCall, msg, rl.refused, "")
	if recorded(rc.msg.Method) {
		rc.record(calls.Call{Outcome: calls.OutcomeDenied, ErrorClass: rl.refused, ExposedName: rc.requestedName()}, n)
	} else {
		rc.outcome = calls.OutcomeDenied
	}
	return true
}

// refuseText answers a refused request: a tool result with isError for a
// tool call (the model reads it), else a -32010 error with data.reason. It
// returns the size written.
func (rc *request) refuseText(tool bool, msg, reason, provider string) int64 {
	if tool {
		return rc.reply(map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true})
	}
	data := map[string]any{"reason": reason}
	if provider != "" {
		data["provider"] = provider
	}
	return rc.failData(codeDenied, msg, data)
}

// actClaim is the downstream token's act claim of a relayed person call (nil
// otherwise).
func (p principal) actClaim() *identity.Actor {
	rl := p.relay
	if rl == nil || rl.person == nil {
		return nil
	}
	return &identity.Actor{Subject: rl.agent.AgentID, Name: rl.agent.AgentName, Issuer: rl.platform.Issuer,
		PrincipalType: identity.PrincipalAgent, PersonPresent: rl.agent.PersonPresent}
}

// intersect limits a person's access to a gateway by the relay account's.
func (rc *request) intersect(g dbgen.Gateway, personCaller gateways.Caller) (gateways.Caller, error) {
	sa := rc.principal.account
	relay, err := rc.h.Gateways.ServiceAccountCaller(rc.r.Context(), g, sa.Team.ID, sa.Account.Role)
	if err != nil {
		return gateways.Caller{}, err
	}
	return gateways.Intersect(personCaller, relay), nil
}

// presenceOK refuses a call whose capability requires a present person
// unless the person is present (recorded denied, person_not_present). It
// applies to every call on a relay-marked service account (M-2 of the
// security review): the call must be relayed for a person and the token must
// say that person is present. A valid token that names nobody (a team
// agent's shared thread or background run), a relay key with no token at all
// and a person who isn't present are all refused, because a call nobody
// watches is what the setting is for. Calls that don't arrive on a relay
// account (a person's own key or app, an ordinary service account, a token
// ignored on such a credential) are never affected. true: the call may go on.
func (rc *request) presenceOK(o gateways.Offer, rec *calls.Call) bool {
	acct := rc.principal.account
	if acct == nil || !acct.Account.RelayPlatformID.Valid || !registry.PresentPersonRequired(o.Server, o.Capability) {
		return true
	}
	if rl := rc.principal.relay; rl != nil && rl.person != nil && rl.agent.PersonPresent {
		return true
	}
	why := "it can't run in scheduled or background work. Run it in a conversation with them."
	if rl := rc.principal.relay; rl == nil || rl.person == nil {
		why = "this call names nobody (a shared thread, background work, or no identity token). Run it in a conversation with a person."
	}
	subject := fmt.Sprintf("This %s", kindNoun(o.Capability.Kind))
	if rec.ExposedName != "" {
		subject = rec.ExposedName
	}
	msg := fmt.Sprintf("%s needs the person to be present: %s", subject, why)
	n := rc.refuseText(o.Capability.Kind == upstream.KindTool, msg, calls.ClassPersonNotPresent, "")
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, calls.ClassPersonNotPresent
	rc.record(*rec, n)
	return false
}

// needsConnection answers a relayed call whose person must connect an
// account: a tool error naming the provider and where to connect, and never
// a link, -32042 or an input request, whatever the client declared (an agent
// has no browser). Nothing is forwarded.
func (rc *request) needsConnection(o gateways.Offer, c *providers.ConsentNeeded, rec *calls.Call) {
	name, scopes := c.Provider.Name, scopeNote(c.Scopes)
	const where = "under Account › My connections in Open MCP Portal, then try again."
	var msg string
	switch {
	case c.Provider.ServerBound():
		verb := "Sign in to"
		switch c.Reason {
		case providers.ReasonMissingScopes:
			verb = "Grant more access to"
		case providers.ReasonNeedsReconsent:
			verb = "Sign in again to"
		}
		msg = fmt.Sprintf("%s needs your own sign-in to %s%s. %s %s %s", o.ExposedName, name, scopes, verb, name, where)
	case c.Reason == providers.ReasonServerNotAllowed:
		// Link-free (decision 66): the person allows the server themselves,
		// on the portal's My connections page (decision 68), no call needed.
		msg = fmt.Sprintf("%s needs you to allow %s to use your %s account%s, which you haven't. Allow %s %s, then try again.",
			o.ExposedName, serverLabel(o), name, scopes, o.Server.Name, "under Account › My connections in Open MCP Portal")
	default:
		verb := "Connect your"
		switch c.Reason {
		case providers.ReasonMissingScopes:
			verb = "Grant more access to your"
		case providers.ReasonNeedsReconsent:
			verb = "Reconnect your"
		}
		msg = fmt.Sprintf("%s needs your %s account%s. %s %s account %s", o.ExposedName, name, scopes, verb, name, where)
	}
	n := rc.refuseText(o.Capability.Kind == upstream.KindTool, msg, calls.ClassNeedsConnection, c.Provider.Slug)
	rec.Outcome, rec.ErrorClass = calls.OutcomeNeedsAuthorization, calls.ClassNeedsConnection
	rc.record(*rec, n)
}
