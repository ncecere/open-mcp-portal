package mcpgw

import (
	"bytes"
	"encoding/json"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// liveTool closes the time spent obtaining credentials/consent against live
// access and selection policy. A changed policy must start a fresh call; never
// forward arguments merged under an older policy. No list snapshot is trusted.
// prior is non-nil only after an actual forwarding attempt returned 401.
// prepareTarget alone does not prove that an identity was sent.
func (rc *request) liveTool(old gateways.Offer, prior *calls.Call) bool {
	rec := calls.Call{ExposedName: old.ExposedName, Server: &old.Server, CapabilityID: old.Capability.ID, ToolClass: old.Capability.ToolClass}
	if prior != nil {
		rec = *prior
	}
	if !rc.resolveGatewayAttempt(rc.gateway.Slug, &rec) {
		return false
	}
	offers, err := rc.offers(upstream.KindTool)
	if err != nil {
		rc.liveInternal(err, &rec)
		return false
	}
	for _, o := range offers {
		if o.Capability.ID != old.Capability.ID || o.ExposedName != old.ExposedName || !o.Allowed {
			continue
		}
		before, _ := json.Marshal(old.Curation)
		after, _ := json.Marshal(o.Curation)
		if o.Server.Revision == old.Server.Revision && o.Capability.Fingerprint == old.Capability.Fingerprint && bytes.Equal(before, after) {
			return true
		}
	}
	n := rc.fail(codeInvalidParams, "The tool or its gateway policy changed; retry the original request")
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, "curation_changed"
	rc.record(rec, n)
	return false
}

// liveInternal records an aborted live check, including cancellation between
// opening SSE and starting transport. A prepared target alone is not forwarded.
func (rc *request) liveInternal(err error, prior *calls.Call) {
	rc.internal(err)
	if prior != nil {
		rec := *prior
		rec.Outcome, rec.ErrorClass = calls.OutcomeUpstreamError, "internal"
		if rc.r.Context().Err() != nil {
			rec.ErrorClass = "client_cancelled"
		}
		rc.record(rec, 0)
	}
}
