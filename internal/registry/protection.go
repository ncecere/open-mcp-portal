package registry

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Operational limits narrow availability, not credential scope or catalog
// content. Editors/publisher tokens cannot acquire an owner-only capability
// merely by posting new fields to the existing server update operation.
func (s *Service) checkProtection(ctx context.Context, q *dbgen.Queries, role string, rate *int64, concurrent *int32, changed bool) error {
	if !changed {
		return nil
	}
	if !authz.RoleAtLeast(role, authz.RoleAdmin) {
		return apperr.Forbidden("Only the server team's owners and admins can change upstream protection")
	}
	if concurrent != nil && (*concurrent < 1 || *concurrent > upstream.MaxServerConcurrency) {
		return apperr.Invalid("invalid_concurrency", "maxConcurrent must be 1-10000 or null")
	}
	return s.limits.CheckServerValue(ctx, q, rate)
}
