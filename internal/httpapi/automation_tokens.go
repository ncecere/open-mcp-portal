package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func toAPIToken(t automation.Token) apitypes.AutomationToken {
	now := time.Now()
	row := t.Row
	scopes := make([]apitypes.AutomationTokenScope, len(row.Scopes))
	for i, s := range row.Scopes {
		scopes[i] = apitypes.AutomationTokenScope(s)
	}
	out := apitypes.AutomationToken{Id: row.ID, Kind: apitypes.AutomationTokenKind(row.Kind), Name: row.Name, Prefix: row.Prefix, Scopes: scopes,
		Status: apitypes.AutomationTokenStatus(t.Status(now)), CreatedAt: row.CreatedAt, CreatedByName: row.CreatedByName, ExpiresAt: row.ExpiresAt,
		LastUsedAt: row.LastUsedAt, RevokedAt: row.RevokedAt}
	if row.TeamID.Valid {
		out.Team = teamRef(row.TeamID.UUID, t.TeamSlug, t.TeamName)
	}
	if t.BlockedReason(now) != "" {
		b := apitypes.AutomationTokenBlockedReason(t.BlockedReason(now))
		out.BlockedReason = &b
	}
	return out
}

func (a *api) getToken(w http.ResponseWriter, r *http.Request) {
	actor := a.actor(r)
	t, err := a.Automation.Get(r.Context(), actor.TokenID)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIToken(t))
}

func (a *api) adminListAutomationTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.Automation.ListPlatform(r.Context(), a.actor(r))
	writeList(w, r, ts, err, toAPIToken)
}

func (a *api) listTeamAutomationTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.Automation.ListTeam(r.Context(), a.actor(r), r.PathValue("team"))
	writeList(w, r, ts, err, toAPIToken)
}

func tokenInput(in apitypes.AutomationTokenCreate) automation.CreateInput {
	ci := automation.CreateInput{Name: in.Name}
	for _, s := range in.Scopes {
		ci.Scopes = append(ci.Scopes, string(s))
	}
	if in.ExpiresInDays != nil {
		if *in.ExpiresInDays == 0 {
			ci.Days = -1 // an explicit 0 is not "the default": invalid_expiry
		} else {
			ci.Days = *in.ExpiresInDays
		}
	}
	return ci
}

func writeCreatedToken(w http.ResponseWriter, r *http.Request, c automation.Created, err error) {
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, apitypes.AutomationTokenCreated{Token: toAPIToken(c.Token), Secret: c.Secret})
}

func (a *api) adminCreateAutomationToken(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AutomationTokenCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	c, err := a.Automation.CreatePlatform(r.Context(), a.actor(r), tokenInput(in))
	writeCreatedToken(w, r, c, err)
}

func (a *api) createTeamAutomationToken(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AutomationTokenCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	c, err := a.Automation.CreateTeam(r.Context(), a.actor(r), r.PathValue("team"), tokenInput(in))
	writeCreatedToken(w, r, c, err)
}

func (a *api) adminRevokeAutomationToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "tokenId")
	if !ok {
		return
	}
	writeOK(w, r, a.Automation.RevokePlatform(r.Context(), a.actor(r), id))
}

func (a *api) revokeTeamAutomationToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "tokenId")
	if !ok {
		return
	}
	writeOK(w, r, a.Automation.RevokeTeam(r.Context(), a.actor(r), r.PathValue("team"), id))
}

// tokenMayUpdateServer is the field rule of updateTeamMcpServer for
// automation tokens (docs/automation-tokens.md): a token is not a person who
// accepted the capture notice, so it may not change capturePayloads; and on a
// server that already holds credentials it may not re-point it or change what
// it sends: url, auth header or credential parts, auth mode, OAuth setup, requirement or
// sendIdentity (a leaked token could otherwise steal a header value or
// teammates' tokens). Refused with 403 token_not_allowed and details.field.
func (a *api) tokenMayUpdateServer(w http.ResponseWriter, r *http.Request, actor authz.Actor, id uuid.UUID, in apitypes.McpServerUpdate, keys map[string]json.RawMessage) bool {
	v, err := a.Registry.GetTeam(r.Context(), actor, r.PathValue("team"), id)
	if failed(w, r, err) {
		return false
	}
	sv := v.Server
	refuse := func(field string) bool {
		a.refuseToken(w, r, field)
		return false
	}
	// Who is accountable for a server, how sensitive it is and whether it is being
	// retired are decisions about trust: a person's, never a token's, whatever
	// the server holds (decision 88).
	for _, field := range []string{"governance", "rateLimitPerMinute", "maxConcurrent", "endpoints"} {
		if _, ok := keys[field]; ok {
			return refuse(field)
		}
	}
	// A client key and a CA are credentials and trust settings: a token never
	// sends them, whatever the server holds (decision 74).
	if _, ok := keys["tls"]; ok {
		return refuse("tls")
	}
	if in.CapturePayloads != nil && *in.CapturePayloads != sv.CapturePayloads {
		return refuse("capturePayloads")
	}
	if in.AuthMode != nil && string(*in.AuthMode) == registry.AuthPersonSecret && registry.AuthModeOf(sv) != registry.AuthPersonSecret {
		// A token never switches a server to asking people for their own keys,
		// even one with nothing to steal yet: that sends their keys to its URL.
		return refuse("authMode")
	}
	if _, ok := keys["personSecret"]; ok {
		return refuse("personSecret")
	}
	// A machine client is a secret like no other the token could set: never
	// from an automation token, even on a server without credentials (a
	// token must not choose where a client secret goes; decision 73).
	if _, ok := keys["machineOAuth"]; ok {
		return refuse("machineOAuth")
	}
	if in.AuthMode != nil && string(*in.AuthMode) == registry.AuthMachineOAuth && sv.AuthMode != registry.AuthMachineOAuth {
		return refuse("authMode")
	}
	if !v.HasAuth() && sv.AuthMode == "none" && !sv.AuthProviderID.Valid && !(v.TLS != nil && v.TLS.Client != nil) {
		return true // no credentials yet: nothing to steal or redirect
	}
	for _, f := range []string{"authHeaderName", "authValue", "credentials", "authMode", "oauth", "requirement"} {
		if _, ok := keys[f]; ok {
			return refuse(f)
		}
	}
	if in.Url != nil && *in.Url != sv.URL {
		return refuse("url")
	}
	if in.SendIdentity != nil && *in.SendIdentity != sv.SendIdentity {
		return refuse("sendIdentity")
	}
	return true
}

// refuseToken answers an automation token that tried to change field: 403
// token_not_allowed with details.field.
func (a *api) refuseToken(w http.ResponseWriter, r *http.Request, field string) {
	a.Automation.Count(automation.ResultNotAllowed)
	e := apperr.New(http.StatusForbidden, "token_not_allowed", "An automation token can't change "+field+" of this server: sign in to do it")
	e.Details = map[string]any{"field": field}
	httpx.Fail(w, r, e)
}
