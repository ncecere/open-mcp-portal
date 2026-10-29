package registry

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// endpointNetwork opens only this endpoint's entered credential. No primary
// credential/provider/TLS/identity can be inherited by construction.
func (s *Service) endpointNetwork(ctx context.Context, sv dbgen.McpServer, row dbgen.McpServerEndpoint) (upstream.Endpoint, error) {
	if row.ServerID != sv.ID || row.AuthMode != AuthModeOf(sv) {
		return upstream.Endpoint{}, endpointCredentialFailure()
	}
	view, err := endpointRowView(row)
	if err != nil {
		return upstream.Endpoint{}, err
	}
	normalized, err := s.client.NormalizeURL(ctx, row.URL)
	if err != nil {
		return upstream.Endpoint{}, err
	}
	if normalized != row.URL {
		return upstream.Endpoint{}, endpointCredentialFailure()
	}
	ep := upstream.Endpoint{ID: row.ID.String(), URL: row.URL}
	if row.AuthMode == AuthStaticHeader {
		parts, err := openEndpointCredentials(s.box, sv.ID, row.ID, row.CredentialOrigin, row.CredentialsCipher, view.Credentials)
		if err != nil {
			return upstream.Endpoint{}, err
		}
		for _, p := range parts {
			ep.Credentials = append(ep.Credentials, upstream.Credential{Kind: p.Kind, Name: p.Name, Value: p.Value, Secondary: p.Secondary})
		}
	}
	return ep, nil
}
