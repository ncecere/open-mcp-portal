package registry

import (
	"encoding/json"
	"reflect"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func endpointValuesRequired() error {
	return unprocessable("auth_value_required", "Enter every credential value for this endpoint's destination; primary values, keep flags and hints cannot authorize another origin.", map[string]any{"field": "endpoints.credentials"})
}

func (s *Service) planEndpointCredential(serverID, id uuid.UUID, mode, origin string, old dbgen.McpServerEndpoint, exists bool, input *[]CredentialInput) ([]byte, []CredentialView, bool, error) {
	if mode == AuthNone {
		if input != nil && len(*input) > 0 {
			return nil, nil, false, apperr.Invalid("invalid_endpoint", "A no-auth endpoint cannot contain static credentials")
		}
		return nil, []CredentialView{}, exists && len(old.CredentialsCipher) > 0, nil
	}
	if mode != AuthStaticHeader {
		return nil, nil, false, unsupportedFailover()
	}
	if input == nil {
		if !exists || old.AuthMode != mode || old.CredentialOrigin != origin {
			return nil, nil, false, endpointValuesRequired()
		}
		views, _, err := s.existingEndpointCredential(serverID, old) // Verify even retained envelopes.
		if err != nil {
			return nil, nil, false, err
		}
		return old.CredentialsCipher, views, false, nil
	}
	if len(*input) == 0 {
		return nil, nil, false, endpointValuesRequired()
	}
	if err := checkCredentialShape(*input); err != nil {
		return nil, nil, false, err
	}
	var previous []CredentialInput
	var views []CredentialView
	var err error
	for _, part := range *input {
		if !part.Keep {
			continue
		}
		if !exists || old.AuthMode != mode || old.CredentialOrigin != origin {
			return nil, nil, false, endpointValuesRequired()
		}
		views, previous, err = s.existingEndpointCredential(serverID, old)
		if err != nil {
			return nil, nil, false, err
		}
		break
	}
	resolved := make([]CredentialInput, len(*input))
	fresh := !exists
	for i, p := range *input {
		if !p.Keep {
			resolved[i] = p
			fresh = true
			continue
		}
		found := false
		for _, oldPart := range previous {
			if credKey(oldPart.Kind, oldPart.Name) == credKey(p.Kind, p.Name) {
				p.Value, p.Secondary, p.Keep = oldPart.Value, oldPart.Secondary, false
				resolved[i] = p
				found = true
				break
			}
		}
		if !found {
			return nil, nil, false, endpointValuesRequired()
		}
	}
	if !fresh && reflect.DeepEqual(resolved, previous) {
		return old.CredentialsCipher, views, false, nil
	}
	cipher, after, err := sealEndpointCredentials(s.box, serverID, id, origin, resolved)
	return cipher, after, true, err
}

func (s *Service) existingEndpointCredential(serverID uuid.UUID, row dbgen.McpServerEndpoint) ([]CredentialView, []CredentialInput, error) {
	var views []CredentialView
	if err := json.Unmarshal(row.CredentialShapes, &views); err != nil {
		return nil, nil, endpointCredentialFailure()
	}
	parts, err := openEndpointCredentials(s.box, serverID, row.ID, row.CredentialOrigin, row.CredentialsCipher, views)
	return views, parts, err
}
