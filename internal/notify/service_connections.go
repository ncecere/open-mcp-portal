package notify

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// ServiceConnectionReconsent emits a team-owned event without a personal
// recipient. Delivery resolves the owning team's live active admins/owners.
func (s *Service) ServiceConnectionReconsent(ctx context.Context, q *dbgen.Queries, id, team uuid.UUID, slug, name string, generation int64) {
	d := apitypes.ConnectionNeedsReconsentData{Reason: apitypes.RefreshFailed}
	d.Provider.Slug, d.Provider.Name = slug, clip(name, 200)
	Emit(ctx, q, Event{Type: ConnectionNeedsReconsent, DedupKey: fmt.Sprintf("service_connection.needs_reconsent:%s:%d", id, generation), TeamID: team, SubjectType: "service_connection", SubjectID: id.String(), Data: d})
}
