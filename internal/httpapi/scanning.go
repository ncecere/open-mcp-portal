package httpapi

import (
	"github.com/ncecere/open-mcp-portal/internal/definitionscan"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"net/http"
)

func (a *api) adminGetScanningSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.Registry.GetScanningSettings(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, 200, s.Revision, s)
}
func (a *api) adminUpdateScanningSettings(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.ScanningSettingsUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Registry.UpdateScanningSettings(r.Context(), a.actor(r), string(in.DefinitionMode), rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, 200, s.Revision, s)
}
func (a *api) adminListScanningRules(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, 200, map[string]any{"rulesetVersion": definitionscan.Version, "rules": definitionscan.Catalog()})
}
func (a *api) definitionFindings(w http.ResponseWriter, r *http.Request, admin, rescan bool) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	data, err := a.Registry.DefinitionFindings(r.Context(), a.actor(r), r.PathValue("team"), id, admin, rescan)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, 200, data)
}
func (a *api) teamListDefinitionFindings(w http.ResponseWriter, r *http.Request) {
	a.definitionFindings(w, r, false, false)
}
func (a *api) teamRescanDefinitions(w http.ResponseWriter, r *http.Request) {
	a.definitionFindings(w, r, false, true)
}
func (a *api) adminListDefinitionFindings(w http.ResponseWriter, r *http.Request) {
	a.definitionFindings(w, r, true, false)
}
func (a *api) adminRescanDefinitions(w http.ResponseWriter, r *http.Request) {
	a.definitionFindings(w, r, true, true)
}
