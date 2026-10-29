package approvals

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// readContext authorizes a non-spending check at a consistent committed
// snapshot. No authority table/actor row locks are taken: unrelated credential
// refreshes and concurrent MCP calls must not serialize behind an approval
// writer fence when no approval rule governs them. A rule/authority commit
// before this snapshot changes the captured epoch and refuses the attempt;
// commits after it do not retroactively revoke this already-admitted check.
// Governed tools still require Consume's exclusive final fence and audited CAS.
func (s *Service) readContext(ctx context.Context, epoch int64, expires time.Time, check func(context.Context, *dbgen.Queries) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := dbgen.New(tx)
	current, err := q.GetApprovalContext(ctx)
	if err != nil {
		return safeError(err)
	}
	if current != epoch {
		return ErrContextChanged
	}
	if !credentialLive(s.clock(), expires) {
		return ErrUnavailable
	}
	if check != nil {
		if err = check(ctx, q); err != nil {
			return safeError(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return safeError(err)
	}
	if !credentialLive(s.clock(), expires) {
		return ErrUnavailable
	}
	return nil
}

// CheckUngoverned is a non-spending, read-only policy check for lifecycle
// operations whose original tool dispatch had no approval rule. Unlike Begin,
// a newly matching rule refuses the operation without creating a receipt,
// preview, notification or approval request. A successful check does not replace
// current credential/gateway/offer/deadline checks or authorize arbitrary input.
// Its captured epoch is per exchange, never frozen for a durable task's lifetime.
func (s *Service) CheckUngoverned(ctx context.Context, binding Binding, expires time.Time) error {
	_, err := s.beginUnrestricted(ctx, BeginInput{Binding: binding, CredentialExpiresAt: expires})
	return err
}

func (s *Service) beginUnrestricted(ctx context.Context, in BeginInput) (Plan, error) {
	err := s.readContext(ctx, in.Binding.Epoch, in.CredentialExpiresAt, func(ctx context.Context, q *dbgen.Queries) error {
		live, err := s.requesterLive(ctx, q, in.Binding)
		if err != nil {
			return err
		}
		if !live {
			return ErrUnavailable
		}
		rule, err := s.selectedRule(ctx, q, in.Binding)
		if err != nil {
			return err
		}
		if rule != nil {
			return ErrContextChanged
		}
		return nil
	})
	if err != nil {
		return Plan{}, err
	}
	return Plan{Binding: in.Binding, CredentialExpiresAt: in.CredentialExpiresAt}, nil
}
