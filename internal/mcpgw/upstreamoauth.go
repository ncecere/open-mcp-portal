package mcpgw

import (
	"errors"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
	"github.com/ncecere/open-mcp-portal/internal/upstream/oauthmeta"
)

// Calls to MCP servers in oauth mode (docs/phase7-upstream-oauth.md
// "Runtime", decisions 39 and 43). The person's own token for the server
// (a connection to its server-bound provider, obtained as in delegated.go)
// goes in Authorization: Bearer, only to the server's stored URL, which must
// equal its OAuth resource; the identity token moves to MCP-Gateway-Identity
// (or isn't sent when the server's sendIdentity is off). There is never an
// MCP-Gateway-Provider header or a provider claim. An upstream 401 gets one
// refresh and retry, then the connection needs consent again (-32042); a 403
// insufficient_scope asks for the challenged scopes (step-up) when they were
// reviewed, else it is -32010.

// Error classes of oauth servers' refused calls.
const (
	ClassUpstreamUnauthorized = "upstream_unauthorized"
	ClassInsufficientScope    = "insufficient_scope"
	DeniedResourceMismatch    = "resource_mismatch"
)

// machineMode reports whether the call's server authenticates the portal
// itself with a machine token (decision 73): its bearer is the portal's, the
// same for every caller.
func machineMode(o gateways.Offer) bool {
	return registry.AuthModeOf(o.Server) == registry.AuthMachineOAuth
}

// ReasonMachineAuthUnavailable is the data.reason of a call refused because
// the portal could not get a machine token (the server's authorization server
// is unreachable or failing): the call did not reach the server.
const ReasonMachineAuthUnavailable = upstream.ReasonMachineAuthUnavailable

// targetFailed answers a call whose target could not be built: a machine
// token that could not be had because the authorization server is unavailable
// is -32010 with data.reason machine_auth_unavailable (recorded
// upstream_error, with the error class); everything else (a refused client is
// class auth) is an upstream error.
func (rc *request) targetFailed(rec calls.Call, err error) {
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Reason != ReasonMachineAuthUnavailable {
		rc.upstreamFailed(rec, err)
		return
	}
	n := rc.failData(codeDenied, "The portal could not get the access token this server needs. Try again shortly.",
		map[string]any{"reason": ReasonMachineAuthUnavailable})
	rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, ue.Class
	rc.record(rec, n)
}

// serverBound reports whether cred is an oauth server's own sign-in.
func serverBound(cred *providers.Credential) bool {
	return cred != nil && cred.Provider.ServerBound()
}

// prepareTarget sets a forwarded call's credentials on t: the identity
// token (unless the server doesn't want it) and the person's token. It
// returns the identity token ("" when none is sent), or ok false when it
// answered the call itself.
func (rc *request) prepareTarget(t *upstream.Target, who identityFor, o gateways.Offer, cred *providers.Credential, rec *calls.Call) (string, bool) {
	if serverBound(cred) && cred.Resource != o.Server.URL {
		// The token is only ever sent to its own resource.
		n := rc.failData(codeDenied, "This server's sign-in no longer matches its URL; ask its team to save its sign-in again",
			map[string]any{"reason": DeniedResourceMismatch, "provider": cred.Provider.Slug})
		rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, DeniedResourceMismatch
		rc.record(*rec, n)
		return "", false
	}
	token := ""
	if o.Server.SendIdentity {
		var err error
		if token, err = rc.identityToken(who, o, cred); err != nil {
			rc.internal(err)
			return "", false
		}
		t.IdentityHeader, t.IdentityValue = identity.Header(t.AuthorizationHeader(), token)
		if serverBound(cred) {
			t.IdentityHeader, t.IdentityValue = identity.HeaderIdentity, token
		}
	}
	// Recorded with the call (decision 64): whether the identity token was
	// attached to the request to the server.
	sent := token != ""
	rec.IdentitySent = &sent
	withCredential(t, cred)
	// A shared credential belongs to the team, not the calling client: scrub
	// both provider-header and server-bound tokens, including progress. Keep
	// the existing personal provider-header live-result behavior unchanged.
	shared := cred != nil && cred.ServiceConnectionID != uuid.Nil
	if serverBound(cred) || shared {
		rc.scrub = append(rc.scrub, cred.AccessToken)
	}
	if shared && token != "" {
		rc.scrub = append(rc.scrub, token)
	}
	if t.BearerToken != "" && !serverBound(cred) {
		// A machine token (registry.Target): the server may echo it.
		rc.scrub = append(rc.scrub, t.BearerToken)
	}
	return token, true
}

// withCredential adds the person's token to a forwarded call: an oauth
// server's own token as the bearer, a platform provider's in
// MCP-Gateway-Provider(-Token).
func withCredential(t *upstream.Target, cred *providers.Credential) {
	switch {
	case cred == nil:
	case serverBound(cred):
		t.BearerToken = cred.AccessToken
	default:
		t.Provider, t.ProviderToken = cred.Provider.Slug, cred.AccessToken
	}
}

// exchangeFn makes the call with a target.
type exchangeFn func(upstream.Target) (any, bool, error)

// exchange makes a forwarded call, handling an oauth server's 401 and 403
// challenges. ok false: it answered and recorded the call itself.
func (rc *request) exchange(o gateways.Offer, rec *calls.Call, cred *providers.Credential, t upstream.Target, do exchangeFn) (any, bool, bool) {
	ctx := rc.r.Context()
	for attempt := 0; ; attempt++ {
		// Credential acquisition and a post-401 renewal can both wait. Recheck
		// every attempt, without changing the original merged args or binding.
		var prior *calls.Call
		if attempt > 0 {
			// Only a completed first transport (401) establishes IdentitySent.
			prior = rec
		}
		if o.Capability.Kind == upstream.KindTool && !rc.liveTool(o, prior) {
			return nil, false, false
		}
		result, isError, err := do(t)
		if err == nil {
			return result, isError, true
		}
		if rc.approvalTransportFailed(*rec, err) || rc.grantExpiryFailed(*rec, err) {
			return nil, false, false
		}
		var ue *upstream.Error
		if rc.secretRefusal(err) {
			// The server refused the person's own secret (decision 72).
			rc.secretRefused(o, rec)
			return nil, false, false
		}
		if !serverBound(cred) && errors.As(err, &ue) && attempt == 0 && ue.HTTPStatus == 401 && machineMode(o) {
			// The server refused the portal's machine token: nothing ran, so
			// get another (one request however many calls were refused) and
			// retry once; a second 401 is class auth.
			next, rerr := rc.h.Registry.RenewMachineToken(ctx, o.Server, t.BearerToken)
			if rerr != nil {
				rc.targetFailed(*rec, rerr)
				return nil, false, false
			}
			t.BearerToken = next
			rc.scrub = append(rc.scrub, next)
			if rc.capture != nil {
				rc.capture.Secrets = append(rc.capture.Secrets, next)
			}
			continue
		}
		if !serverBound(cred) || !errors.As(err, &ue) {
			rc.upstreamFailed(*rec, err)
			return nil, false, false
		}
		ch := oauthmeta.Bearer(ue.Challenge)
		cc := rc.callContext(o)
		switch {
		case ue.HTTPStatus == 401 && ch != nil && ch.Error() != "insufficient_scope":
			// invalid_token, none, or (GitHub) invalid_request: the token
			// wasn't accepted, and a 401 means nothing was executed.
			var next providers.Credential
			var err error
			if rc.principal.account != nil {
				next, err = rc.h.Providers.ServiceUpstreamRejected(ctx, o.Requires, rc.serviceCallContext(o), *cred, attempt == 0 && cred.Refreshable)
			} else {
				next, err = rc.h.Providers.UpstreamRejected(ctx, o.Requires, cc, *cred, attempt == 0 && cred.Refreshable)
			}
			var serviceErr *providers.ServiceCredentialError
			var consent *providers.ConsentNeeded
			var down *providers.UnavailableError
			switch {
			case err == nil:
				// Refreshed: retry once with the new token.
				cred = &next
				t.BearerToken = next.AccessToken
				rc.scrub = append(rc.scrub, next.AccessToken)
				if rc.capture != nil {
					rc.capture.Secrets = append(rc.capture.Secrets, next.AccessToken)
				}
				continue
			case errors.As(err, &serviceErr):
				rc.serviceConnectionDenied(o, serviceErr, rec)
			case errors.Is(err, providers.ErrProviderNotAllowed):
				rc.providerNotAllowed(o.Requires, rec)
			case errors.As(err, &consent):
				rc.needsAuthorization(o, consent, rec, ClassUpstreamUnauthorized)
			case errors.As(err, &down):
				rc.providerUnavailable(o, rec)
			case errors.Is(err, providers.ErrProviderDisabled):
				rc.providerDisabled(o.Requires, rec)
			default:
				rc.internal(err)
			}
			return nil, false, false
		case ue.HTTPStatus == 403 && ch != nil && ch.Error() == "insufficient_scope":
			var err error = providers.ErrInsufficientScope
			if rc.principal.account == nil {
				err = rc.h.Providers.StepUp(ctx, o.Requires, cc, ch.Scopes())
			}
			var consent *providers.ConsentNeeded
			switch {
			case errors.As(err, &consent):
				rc.needsAuthorization(o, consent, rec, ClassInsufficientScope)
			case errors.Is(err, providers.ErrInsufficientScope):
				// Challenges are untrusted: an upstream can put credentials in
				// scope/error text. Only StepUp's reviewed scopes may reach consent;
				// an unfulfillable challenge has no public challenge-derived data.
				n := rc.failData(codeDenied, "The upstream refused the call: it needs access that this gateway can't ask for",
					map[string]any{"reason": ClassInsufficientScope, "provider": o.Requires.Provider.Slug})
				rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, ClassInsufficientScope
				rc.record(*rec, n)
			default:
				rc.internal(err)
			}
			return nil, false, false
		}
		rc.upstreamFailed(*rec, err)
		return nil, false, false
	}
}

func (rc *request) callContext(o gateways.Offer) providers.CallContext {
	return providers.CallContext{User: rc.principal.user, Gateway: rc.gateway, CapabilityID: o.Capability.ID, Kind: o.Capability.Kind,
		ServerID: o.Server.ID, ServerOrigin: registry.OriginOf(o.Server.URL), ExposedName: o.ExposedName, Title: o.Capability.Title}
}
