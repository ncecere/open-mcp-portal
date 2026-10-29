package registry

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func endpointModeFailure() error {
	return &upstream.Error{Class: upstream.ClassConfig, Reason: "failover_not_supported", Message: "Additional endpoints do not support this server's credential mode, provider requirement or TLS settings."}
}

// forwardTarget alone adds extras. Discovery/setup of the canonical primary
// must not silently route elsewhere, and unsupported modes must fail before
// machine/OAuth credential acquisition has any network side effect.
func (s *Service) forwardTarget(ctx context.Context, sv dbgen.McpServer) (upstream.Target, error) {
	rows, err := s.q.ListMCPServerEndpoints(ctx, sv.ID)
	if err != nil {
		return upstream.Target{}, err
	}
	if len(rows) > 0 {
		if err := checkEndpointServer(sv, false); err != nil {
			return upstream.Target{}, endpointModeFailure()
		}
		tls, err := loadTLS(ctx, s.q, sv.ID)
		if err != nil {
			return upstream.Target{}, err
		}
		if tls != nil {
			return upstream.Target{}, endpointModeFailure()
		}
		if len(rows) > MaxExtraEndpoints {
			return upstream.Target{}, endpointCredentialFailure()
		}
	}
	t, err := s.target(ctx, sv)
	if err != nil {
		return t, err
	}
	seen := map[string]bool{endpointURLKey(sv.URL): true}
	for _, row := range rows {
		view, err := endpointRowView(row)
		if err != nil {
			return t, err
		}
		if row.ServerID != sv.ID || row.AuthMode != AuthModeOf(sv) || seen[endpointURLKey(row.URL)] {
			return t, endpointCredentialFailure()
		}
		seen[endpointURLKey(row.URL)] = true
		if !row.Enabled {
			continue
		}
		_ = view // Shape/origin was checked even for disabled entries.
		ep, err := s.endpointNetwork(ctx, sv, row)
		if err != nil {
			return t, err
		}
		t.Endpoints = append(t.Endpoints, ep)
	}
	return t, nil
}
