package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func (a *api) classificationRoutes() []route {
	return []route{
		{"PUT", "/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/class", a.session(a.setTeamMcpCapabilityClass)},
		{"PUT", "/v1/teams/{team}/mcp-servers/{serverId}/capabilities/classes", a.session(a.setTeamMcpCapabilityClasses)},
	}
}

// RawMessage distinguishes omitted toolClass from the intentional null that
// clears it. Keep decoding strict (including unknown fields) as usual.
type capabilityClassBody struct {
	ToolClass     json.RawMessage `json:"toolClass"`
	ViaSuggestion bool            `json:"viaSuggestion,omitempty"`
}

func classInput(id uuid.UUID, raw json.RawMessage, via bool) (registry.ClassInput, error) {
	if len(raw) == 0 {
		return registry.ClassInput{}, apperr.Invalid("invalid_tool_class", "toolClass is required (use null to clear)")
	}
	var c *apitypes.ToolClass
	if err := json.Unmarshal(raw, &c); err != nil || (c != nil && !c.Valid()) {
		return registry.ClassInput{}, apperr.Invalid("invalid_tool_class", "toolClass must be read, write, destructive or null")
	}
	return registry.ClassInput{CapabilityID: id, ToolClass: (*string)(c), ViaSuggestion: via}, nil
}

func (a *api) setTeamMcpCapabilityClass(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	capID, ok := pathUUID(w, r, "capabilityId")
	if !ok {
		return
	}
	body, rev, ok := decodeRevised[capabilityClassBody](w, r)
	if !ok {
		return
	}
	in, err := classInput(capID, body.ToolClass, body.ViaSuggestion)
	if failed(w, r, err) {
		return
	}
	c, revision, err := a.Registry.SetCapabilityClass(r.Context(), a.actor(r), r.PathValue("team"), serverID, in, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, revision, toAPICapability(c))
}

func (a *api) setTeamMcpCapabilityClasses(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	body, rev, ok := decodeRevised[struct {
		Items []struct {
			CapabilityID  uuid.UUID       `json:"capabilityId"`
			ToolClass     json.RawMessage `json:"toolClass"`
			ViaSuggestion bool            `json:"viaSuggestion,omitempty"`
		} `json:"items"`
	}](w, r)
	if !ok {
		return
	}
	items := make([]registry.ClassInput, len(body.Items))
	for i, it := range body.Items {
		in, err := classInput(it.CapabilityID, it.ToolClass, it.ViaSuggestion)
		if failed(w, r, err) {
			return
		}
		items[i] = in
	}
	cs, revision, err := a.Registry.SetCapabilityClasses(r.Context(), a.actor(r), r.PathValue("team"), serverID, items, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, revision, toAPICapabilities(cs))
}
