package httpapi

import (
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// Requires a present person (decision 66, docs/agent-platforms.md): a
// capability's override of its server's switch. Editors and above; the
// server's switch itself is a field of updateTeamMcpServer.

func (a *api) presentPersonRoutes() []route {
	return []route{
		{"PUT", "/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/present-person", a.session(a.setTeamMcpCapabilityPresentPerson)},
	}
}

func (a *api) setTeamMcpCapabilityPresentPerson(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	capID, ok := pathUUID(w, r, "capabilityId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.CapabilityPresentPersonOverride](w, r)
	if !ok {
		return
	}
	c, revision, err := a.Registry.SetCapabilityPresence(r.Context(), a.actor(r), r.PathValue("team"), serverID, capID,
		registry.PresenceInput{Mode: string(in.Mode)}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, revision, toAPICapability(c))
}
