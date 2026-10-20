package mcpgw

import (
	"errors"
	"fmt"

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
		t.IdentityHeader, t.IdentityValue = identity.Header(t.HeaderName, token)
		if serverBound(cred) {
			t.IdentityHeader, t.IdentityValue = identity.HeaderIdentity, token
		}
	}
	// Recorded with the call (decision 64): whether the identity token was
	// attached to the request to the server.
	sent := token != ""
	rec.IdentitySent = &sent
	withCredential(t, cred)
	if serverBound(cred) {
		rc.scrub = append(rc.scrub, cred.AccessToken)
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
		result, isError, err := do(t)
		if err == nil {
			return result, isError, true
		}
		var ue *upstream.Error
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
			next, err := rc.h.Providers.UpstreamRejected(ctx, o.Requires, cc, *cred, attempt == 0 && cred.Refreshable)
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
			err := rc.h.Providers.StepUp(ctx, o.Requires, cc, ch.Scopes())
			var consent *providers.ConsentNeeded
			switch {
			case errors.As(err, &consent):
				rc.needsAuthorization(o, consent, rec, ClassInsufficientScope)
			case errors.Is(err, providers.ErrInsufficientScope):
				n := rc.failData(codeDenied, fmt.Sprintf("%s refused the call: it needs access%s that this gateway can't ask for",
					o.Requires.Provider.Name, scopeNote(ch.Scopes())),
					map[string]any{"reason": ClassInsufficientScope, "provider": o.Requires.Provider.Slug, "scopes": ch.Scopes()})
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
