package mcpgw

import (
	"encoding/json"
	"fmt"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// maxReadURI bounds the URI of a read.
const maxReadURI = 8 << 10

// resourceNotFound is what a refused or unknown read sees.
func resourceNotFound(uri string) string {
	return fmt.Sprintf("Resource not found: %s", clip(uri, 200))
}

// resourceNotFoundCode is "resource not found": -32602 (invalid params) in
// the modern era, MCP's own -32002 before it.
func (rc *request) resourceNotFoundCode() int64 {
	if rc.modern {
		return codeInvalidParams
	}
	return codeResourceNotFound
}

// readTarget is the selected resource or template a read is allowed by.
type readTarget struct {
	offer    gateways.Offer
	original string // the URI on the server
}

// matchRead finds what allows a read of the exposed uri: a selected
// resource with exactly that URI, or a selected template it expands, on the
// server named by the URI's slug. Allowed offers win; otherwise the first
// matching offer says why it was refused (nil: nothing matches).
func matchRead(offers []gateways.Offer, uri string) (*readTarget, bool) {
	slug, original, ok := gateways.SplitExposedURI(uri)
	if !ok {
		return nil, false
	}
	var refused *readTarget
	for _, o := range offers {
		if o.Server.Slug != slug {
			continue
		}
		var match bool
		switch o.Capability.Kind {
		case upstream.KindResource:
			match = o.Capability.Name == original
		case upstream.KindResourceTemplate:
			match = gateways.MatchTemplate(o.Capability.Name, original)
		}
		if !match {
			continue
		}
		t := &readTarget{offer: o, original: original}
		if o.Allowed {
			return t, true
		}
		if refused == nil {
			refused = t
		}
	}
	return refused, false
}

// read forwards resources/read after re-checking that a selected resource
// or template allows the URI. A refusal never reaches the server.
func (rc *request) read() {
	var p struct {
		URI string `json:"uri"`
	}
	if len(rc.msg.Params) == 0 || json.Unmarshal(rc.msg.Params, &p) != nil || p.URI == "" || len(p.URI) > maxReadURI {
		n := rc.fail(codeInvalidParams, "Invalid parameters: uri is required")
		rc.record(calls.Call{Outcome: calls.OutcomeBadRequest, ErrorClass: "invalid_params"}, n)
		return
	}
	again, ok := rc.checkRetry(calls.Call{ExposedName: p.URI})
	if !ok {
		return
	}
	all, err := rc.h.Gateways.Offers(rc.r.Context(), rc.gateway, rc.caller)
	if err != nil {
		rc.internal(err)
		return
	}
	target, allowed := matchRead(all, p.URI)
	if !allowed {
		n := rc.fail(rc.resourceNotFoundCode(), resourceNotFound(p.URI))
		c := calls.Call{Outcome: calls.OutcomeDenied, ErrorClass: "unknown", ExposedName: p.URI}
		if target != nil {
			o := target.offer
			c.ErrorClass, c.Server, c.CapabilityID = o.Denied, &o.Server, o.Capability.ID
			if o.Requires != nil {
				c.ProviderSlug = o.Requires.Provider.Slug
			}
		}
		rc.record(c, n)
		return
	}
	if again.declined {
		rc.declined(target.offer)
		return
	}
	rc.forwardRead(p.URI, *target, again)
}

// forwardRead reads the resource from its server with the caller's signed
// identity and gives the contents' URIs back in the exposed form.
func (rc *request) forwardRead(exposed string, t readTarget, again retry) {
	ctx := rc.r.Context()
	o := t.offer
	rec := calls.Call{ExposedName: exposed, Server: &o.Server, CapabilityID: o.Capability.ID}
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
	token, ok := rc.prepareTarget(&target, identityFor{resource: exposed}, o, cred, &rec)
	if !ok {
		return
	}
	rc.captureCall(o, readArguments(exposed), target, token, cred)
	fwd, ok := rc.forwardRequest(upstream.MethodResourcesRead, t.original, nil, o, again, &rec)
	if !ok {
		return
	}
	rc.forwardCall(o, rec, cred, target, fwd)
}
