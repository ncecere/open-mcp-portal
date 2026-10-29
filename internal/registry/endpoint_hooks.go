package registry

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func endpointTokenRefusal() error {
	e := apperr.New(403, "token_not_allowed", "Sign in as a server team owner or admin to change additional endpoints")
	e.Details = map[string]any{"field": "endpoints"}
	return e
}

// prepareEndpointChange runs destination normalization/early refusals outside
// mutation transactions and before OAuth discovery/revocation side effects.
// planEndpointRows must still run again with live rows/role under the server lock.
func (s *Service) prepareEndpointChange(ctx context.Context, q *dbgen.Queries, cur dbgen.McpServer, newURL, mode string, provider, tls bool, role string, input *[]EndpointInput, create bool) (*[]EndpointInput, error) {
	if input != nil {
		if err := checkEndpointRole(role); err != nil {
			return nil, err
		}
	}
	var stored []dbgen.McpServerEndpoint
	var err error
	if !create {
		stored, err = q.ListMCPServerEndpoints(ctx, cur.ID)
		if err != nil {
			return nil, err
		}
	}
	count := len(stored)
	if input != nil {
		count = len(*input)
	}
	if count > 0 {
		if err := checkEndpointMode(mode, provider, tls); err != nil {
			return nil, err
		}
	}
	prepared := input
	if input != nil {
		normalized, err := s.normalizeEndpoints(ctx, *input)
		if err != nil {
			return nil, err
		}
		prepared = &normalized
	}
	candidate := cur
	candidate.URL, candidate.AuthMode, candidate.AuthHeaderName = newURL, mode, nil
	candidate.AuthProviderID.Valid = provider
	if _, err := s.planEndpointRows(candidate, stored, tls, role, prepared, create); err != nil {
		return nil, err
	}
	return prepared, nil
}

func endpointServerAfter(cur dbgen.McpServer, p dbgen.UpdateMCPServerParams, mode string) dbgen.McpServer {
	cur.URL, cur.AuthMode, cur.AuthHeaderName, cur.AuthProviderID = p.URL, mode, p.AuthHeaderName, p.AuthProviderID
	return cur
}
