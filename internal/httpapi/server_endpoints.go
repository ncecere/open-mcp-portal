package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func (a *api) endpointPayload(w http.ResponseWriter, r *http.Request, keys map[string]json.RawMessage) bool {
	raw, present := keys["endpoints"]
	if !present {
		return true
	}
	if a.actor(r).IsToken() {
		a.refuseToken(w, r, "endpoints")
		return false
	}
	invalid := func() bool {
		failed(w, r, apperr.Invalid("invalid_endpoints", "endpoints must be an array; use [] to clear. Optional endpoint fields cannot be null."))
		return false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return invalid()
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return invalid()
	}
	for _, item := range items {
		if item == nil {
			return invalid()
		}
		for _, key := range []string{"id", "url", "enabled", "credentials"} {
			if v, ok := item[key]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return invalid()
			}
		}
	}
	return true
}

func fromAPIEndpoints(items *[]apitypes.McpServerEndpointInput) *[]registry.EndpointInput {
	if items == nil {
		return nil
	}
	out := make([]registry.EndpointInput, len(*items))
	for i, e := range *items {
		out[i] = registry.EndpointInput{URL: e.Url, Enabled: e.Enabled, Credentials: fromAPICredentialsPtr(e.Credentials)}
		if e.Id != nil {
			out[i].ID = *e.Id
		}
	}
	return &out
}

func toAPIEndpoints(items []registry.EndpointView) *[]apitypes.McpServerEndpoint {
	out := make([]apitypes.McpServerEndpoint, len(items))
	for i, e := range items {
		parts := toAPICredentials(e.Credentials)
		out[i] = apitypes.McpServerEndpoint{Id: e.ID, Position: e.Position, Url: e.URL, Enabled: e.Enabled, AuthMode: apitypes.McpServerEndpointAuthMode(e.AuthMode), Credentials: *parts}
	}
	return &out
}
