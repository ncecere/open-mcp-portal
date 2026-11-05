package retention

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// validateAuditPeriod runs under the settings row lock, shared by platform and
// team updates, so concurrent changes cannot jointly violate the interlock.
func validateAuditPeriod(ctx context.Context, tx pgx.Tx, periods Periods) error {
	var floor int32
	if err := tx.QueryRow(ctx, `SELECT min_days FROM omp_audit.retention_floor WHERE singleton`).Scan(&floor); err != nil {
		return err
	}
	calls := periods[CallMetadata]
	rows, err := tx.Query(ctx, `SELECT retention_overrides FROM public.teams`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		p, err := decodePeriods(raw)
		if err != nil {
			return err
		}
		if p[CallMetadata] > calls {
			calls = p[CallMetadata]
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if periods[AuditLog] < floor || periods[AuditLog] < calls {
		return invalid(AuditLog, "audit_interlock", "Audit retention must cover the deployment floor and every call metadata period")
	}
	return nil
}
