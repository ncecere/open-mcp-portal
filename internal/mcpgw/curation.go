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
func (rc *request) liveTool(old gateways.Offer) bool {
	if !rc.resolveGateway(rc.gateway.Slug) {
		return false
	}
	offers, err := rc.offers(upstream.KindTool)
	if err != nil {
		rc.internal(err)
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
	rc.record(calls.Call{Outcome: calls.OutcomeDenied, ErrorClass: "curation_changed", ExposedName: old.ExposedName, Server: &old.Server, CapabilityID: old.Capability.ID, ToolClass: old.Capability.ToolClass}, n)
	return false
}
