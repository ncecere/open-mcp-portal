package httpapi

import (
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// Machine OAuth (decision 73, docs/machine-oauth.md): a server whose
// authorization server authenticates the portal itself with the client
// credentials grant. The secret is write-only here: it is read from a request
// and never put in a response.

// fromAPIMachineInput is a server's machine client input.
func fromAPIMachineInput(in *apitypes.McpServerMachineOAuthInput) *registry.MachineOAuthInput {
	if in == nil {
		return nil
	}
	out := &registry.MachineOAuthInput{TokenURL: in.TokenUrl, ClientID: in.ClientId, ClientSecret: in.ClientSecret,
		TokenAuthMethod: strPtr(in.TokenAuthMethod), Audience: in.Audience, Resource: in.Resource}
	if in.Scopes != nil {
		scopes := []string(*in.Scopes)
		out.Scopes = &scopes
	}
	return out
}

// toAPIMachineOAuth is a machine_oauth server's client (nil for other modes):
// never the client secret.
func toAPIMachineOAuth(v registry.ServerView) *apitypes.McpServerMachineOAuth {
	m := v.Machine
	if m == nil {
		return nil
	}
	hint := m.ClientID
	if r := []rune(m.ClientID); len(r) > 6 {
		hint = string(r[len(r)-6:])
	}
	return &apitypes.McpServerMachineOAuth{TokenUrl: m.TokenURL, ClientIdHint: hint, HasClientSecret: true, ClientSecretHint: m.SecretHint,
		TokenAuthMethod: apitypes.McpServerMachineOAuthTokenAuthMethod(m.TokenAuthMethod), Scopes: nonNilStrings(m.Scopes),
		Audience: optStr(m.Audience), Resource: optStr(m.Resource)}
}

// toAPIMachineDetection is detect-auth's answer about the client credentials
// grant.
func toAPIMachineDetection(m *registry.MachineDetection) *apitypes.DetectAuthMachine {
	if m == nil {
		return nil
	}
	out := &apitypes.DetectAuthMachine{TokenEndpoint: m.TokenEndpoint, GrantTypesListed: m.GrantTypesListed, ClientCredentials: m.ClientCredentials,
		Resource: m.Resource, TokenAuthMethods: []apitypes.DetectAuthMachineTokenAuthMethods{}}
	for _, method := range m.AuthMethods {
		out.TokenAuthMethods = append(out.TokenAuthMethods, apitypes.DetectAuthMachineTokenAuthMethods(method))
	}
	return out
}

// tokenMayCreateServer is the secret-mode rule of createTeamMcpServer for
// automation tokens: a token may not create a server in machine_oauth or
// person_secret mode or send machineOAuth or personSecret (a client secret,
// and the token endpoint it goes to, are a person's to enter, and so is
// where people's own keys are sent). Refused with 403 token_not_allowed and
// details.field.
func (a *api) tokenMayCreateServer(w http.ResponseWriter, r *http.Request, in registry.CreateInput) bool {
	field := ""
	switch {
	case in.MachineOAuth != nil:
		field = "machineOAuth"
	case in.PersonSecret != nil:
		field = "personSecret"
	case in.AuthMode == registry.AuthMachineOAuth || in.AuthMode == registry.AuthPersonSecret:
		field = "authMode"
	default:
		return true
	}
	a.Automation.Count(automation.ResultNotAllowed)
	e := apperr.New(http.StatusForbidden, "token_not_allowed", "An automation token can't set "+field+" of a server: sign in to do it")
	e.Details = map[string]any{"field": field}
	httpx.Fail(w, r, e)
	return false
}
