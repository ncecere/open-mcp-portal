package auditstream

import (
	"context"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"strconv"
)

// Four fixed label combinations; aggregate maxima avoid unbounded series as
// administrators remove/re-register collectors. Names never enter labels.
func (s Sealer) observeConsumers(ctx context.Context) {
	rows, err := s.Pool.Query(ctx, `SELECT p.profile,r.required,coalesce(max(greatest(0,s.last_seq-c.acked_seq)),0)::float8 FROM (VALUES ('summary'),('full')) p(profile) CROSS JOIN (VALUES (true),(false)) r(required) CROSS JOIN omp_audit.state s LEFT JOIN omp_audit.consumers c ON c.profile=p.profile AND c.required=r.required GROUP BY p.profile,r.required`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var profile string
		var required bool
		var lag float64
		if rows.Scan(&profile, &required, &lag) != nil {
			return
		}
		observability.AuditStreamConsumerLag.WithLabelValues(profile, strconv.FormatBool(required)).Set(lag)
	}
}
