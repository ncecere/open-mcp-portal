package limits

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// ServerEffective applies the owning team's override/default and platform
// ceiling to one server's own setting. Nil means unlimited, never a grant.
func (s Settings) ServerEffective(own *int64, team Overrides) *int64 {
	v := own
	if v == nil {
		v = team.get(ServerPerMinute)
	}
	if v == nil {
		v = s.Default(ServerPerMinute)
	}
	return Cap(v, s.Ceiling(ServerPerMinute))
}

// CheckServerValue validates an explicit override against the current (not
// cached) ceiling inside the caller's mutation transaction.
func (s *Service) CheckServerValue(ctx context.Context, q *dbgen.Queries, v *int64) error {
	if !inRange(v) {
		return outOfRange(ServerPerMinute)
	}
	if v == nil {
		return nil
	}
	row, err := q.GetLimitSettings(ctx)
	if err != nil {
		return err
	}
	if c := decodeSettings(row).Ceiling(ServerPerMinute); c != nil && *v > *c {
		return invalid(ServerPerMinute, "above_ceiling", fmt.Sprintf("A server's limit can be at most %d per minute (the ceiling)", *c))
	}
	return nil
}

// CheckServer charges a forwarded operation attempt, not its internal
// negotiation/health HTTP requests. Call again before an automatic retry.
// It never exposes shared remaining counts in Decision.Own.
func (s *Service) CheckServer(ctx context.Context, st ratelimit.Store, sv dbgen.McpServer, team dbgen.Team) (Decision, error) {
	if sv.ID == uuid.Nil || team.ID != sv.TeamID {
		return Decision{}, fmt.Errorf("server limit: invalid owning team")
	}
	set, err := s.Current(ctx)
	if err != nil {
		return Decision{}, err
	}
	v := set.ServerEffective(sv.RateLimitPerMinute, TeamOverrides(team))
	if v == nil {
		return Decision{}, nil
	}
	counts, reset, err := st.Hit(ctx, []string{"v:" + sv.ID.String()})
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Reset: reset}
	if len(counts) != 1 {
		return Decision{}, fmt.Errorf("server limit: invalid counter result")
	}
	if counts[0] > *v {
		d.Exceeded, d.LimitPerMinute = ServerPerMinute, *v
	}
	return d, nil
}
