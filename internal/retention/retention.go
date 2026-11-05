// Package retention deletes old data on a schedule
// (docs/phase6-operations.md "Retention", decision 33): call records,
// captured payloads, the audit log and usage rollups, each after a platform
// period (retention_settings); teams can override the call and payload
// periods (teams.retention_overrides). A call that involves two teams (a
// gateway of one, a server of another) is kept for the shorter of their
// periods; with neither, the platform period applies.
//
// A leader-elected loop (advisory lock omp.retention) deletes in batches,
// payloads first, then calls (never newer than the usage rollup watermark),
// audit entries and rollups. Legal holds and dry runs are out of scope.
package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Kinds.
const (
	CallMetadata     = "call_metadata"
	CapturedPayloads = "captured_payloads"
	AuditLog         = "audit_log"
	UsageRollups     = "usage_rollups"
)

// Kind describes one kind of data.
type Kind struct {
	Kind                      string
	BuiltIn, MinDays, MaxDays int32
	Overridable               bool
}

// Kinds are in the API's fixed order (and the order they are purged:
// payloads before their calls).
var Kinds = []Kind{
	{Kind: CallMetadata, BuiltIn: 90, MinDays: 1, MaxDays: 3650, Overridable: true},
	{Kind: CapturedPayloads, BuiltIn: 14, MinDays: 1, MaxDays: 90, Overridable: true},
	{Kind: AuditLog, BuiltIn: 400, MinDays: 30, MaxDays: 3650},
	{Kind: UsageRollups, BuiltIn: 400, MinDays: 90, MaxDays: 3650},
}

// Find returns a kind's description.
func Find(kind string) (Kind, bool) {
	for _, k := range Kinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return Kind{}, false
}

// Periods are days per kind.
type Periods map[string]int32

// Run is one pass of the loop.
type Run struct {
	StartedAt  time.Time         `json:"startedAt"`
	FinishedAt time.Time         `json:"finishedAt"`
	Deleted    map[string]int64  `json:"deleted"`
	Errors     map[string]string `json:"errors"`
}

// Settings are the platform periods (built-in where unset) and the last run.
type Settings struct {
	Periods   Periods
	Revision  int64
	UpdatedAt time.Time
	LastRun   *Run
}

func decodePeriods(raw []byte) (Periods, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("retention must be an object")
	}
	out := Periods{}
	for key, raw := range fields {
		k, ok := Find(key)
		if !ok {
			return nil, fmt.Errorf("unknown retention kind %s", key)
		}
		var n int32
		if string(raw) == "null" {
			return nil, fmt.Errorf("null retention %s", key)
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, err
		}
		if n < k.MinDays || n > k.MaxDays {
			return nil, fmt.Errorf("invalid retention %s", key)
		}
		out[key] = n
	}
	return out, nil
}
func decodeSettings(row dbgen.RetentionSetting) (Settings, error) {
	stored, err := decodePeriods(row.Periods)
	if err != nil {
		return Settings{}, err
	}
	s := Settings{Periods: Periods{}, Revision: row.Revision, UpdatedAt: row.UpdatedAt}
	for _, k := range Kinds {
		d, ok := stored[k.Kind]
		if !ok {
			d = k.BuiltIn
		}
		s.Periods[k.Kind] = d
	}
	if len(row.LastRun) > 0 {
		var r Run
		if json.Unmarshal(row.LastRun, &r) == nil {
			s.LastRun = &r
		}
	}
	return s, nil
}

// TeamOverrides decodes a team's overrides.
func TeamOverrides(t dbgen.Team) (Periods, error) { return decodePeriods(t.RetentionOverrides) }

var (
	errAdminOnly    = apperr.Forbidden("Only platform admins can do this")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")
)

func invalid(kind, reason, msg string) error {
	e := apperr.New(http.StatusUnprocessableEntity, "invalid_period", msg)
	e.Details = map[string]any{"kind": kind, "reason": reason}
	return e
}

func unknownKind(kind string) error {
	e := apperr.New(http.StatusBadRequest, "invalid_period", "Unknown kind: "+kind)
	e.Details = map[string]any{"kind": kind, "reason": "unknown_kind"}
	return e
}

// Config tunes the loop.
type Config struct {
	// Interval between runs (RETENTION_INTERVAL).
	Interval time.Duration
	// BatchSize rows per transaction (RETENTION_BATCH_SIZE).
	BatchSize int32
	// MaxBatches per kind per run.
	MaxBatches int
}

// Hooks are extra clean-ups a run does (expired consent requests, rate
// counters); their errors are logged.
type Hook func(ctx context.Context) (int64, error)

// Service manages retention settings and runs the loop.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	log  *slog.Logger
	cfg  Config
	// Hooks run after the purge.
	Hooks []Hook
	// Observe is told what a run deleted per kind and which kinds succeeded
	// (metrics), and whether this replica led the run.
	Observe func(run Run, leader bool)
	now     func() time.Time
}

// New returns a Service.
func New(pool *pgxpool.Pool, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}
	if cfg.MaxBatches <= 0 {
		cfg.MaxBatches = 100
	}
	s := &Service{pool: pool, log: log, cfg: cfg, now: time.Now}
	if pool != nil {
		s.q = dbgen.New(pool)
	}
	return s
}

// Get returns the platform settings (platform admins and auditors).
func (s *Service) Get(ctx context.Context, a authz.Actor) (Settings, error) {
	if !a.CanReadPlatform() {
		return Settings{}, errPlatformRead
	}
	row, err := s.q.GetRetentionSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	return decodeSettings(row)
}

// Current returns the platform settings without an authorization check.
func (s *Service) Current(ctx context.Context) (Settings, error) {
	row, err := s.q.GetRetentionSettings(ctx)
	if err != nil {
		return Settings{}, err
	}
	return decodeSettings(row)
}

// Change sets one kind's days.
type Change struct {
	Kind string
	Days int32
}

// Update replaces the listed kinds (platform admins). 422 invalid_period
// (out_of_range, duplicate). Audited as settings.retention_update.
func (s *Service) Update(ctx context.Context, a authz.Actor, changes []Change, expectedRevision int64) (Settings, error) {
	if !a.IsPlatformAdmin() {
		return Settings{}, errAdminOnly
	}
	seen := map[string]bool{}
	for _, c := range changes {
		k, ok := Find(c.Kind)
		switch {
		case !ok:
			return Settings{}, unknownKind(c.Kind)
		case seen[c.Kind]:
			return Settings{}, invalid(c.Kind, "duplicate", c.Kind+" is listed twice")
		case c.Days < k.MinDays || c.Days > k.MaxDays:
			return Settings{}, invalid(c.Kind, "out_of_range", fmt.Sprintf("%s must be %d to %d days", c.Kind, k.MinDays, k.MaxDays))
		}
		seen[c.Kind] = true
	}
	var out Settings
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		cur, err := q.LockRetentionSettings(ctx)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		before, err := decodeSettings(cur)
		if err != nil {
			return err
		}
		after := Periods{}
		for k, v := range before.Periods {
			after[k] = v
		}
		for _, c := range changes {
			after[c.Kind] = c.Days
		}
		if err := validateAuditPeriod(ctx, tx, after); err != nil {
			return err
		}
		raw, err := json.Marshal(after)
		if err != nil {
			return err
		}
		row, err := q.UpdateRetentionPeriods(ctx, dbgen.UpdateRetentionPeriodsParams{Periods: raw, UpdatedBy: by(a)})
		if err != nil {
			return err
		}
		out, err = decodeSettings(row)
		if err != nil {
			return err
		}
		e := a.Audit("settings.retention_update", "platform_settings", "retention")
		e.Before, e.After = map[string]any{"periods": before.Periods}, map[string]any{"periods": out.Periods}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// TeamPeriod is one overridable kind of a team.
type TeamPeriod struct {
	Kind
	Override           *int32
	Default, Effective int32
}

// TeamView is a team's periods.
type TeamView struct {
	TeamID   uuid.UUID
	TeamSlug string
	Revision int64
	Periods  []TeamPeriod
}

func teamView(t dbgen.Team, st Settings) (TeamView, error) {
	o, err := TeamOverrides(t)
	if err != nil {
		return TeamView{}, err
	}
	out := TeamView{TeamID: t.ID, TeamSlug: t.Slug, Revision: t.Revision}
	for _, k := range Kinds {
		if !k.Overridable {
			continue
		}
		p := TeamPeriod{Kind: k, Default: st.Periods[k.Kind], Effective: st.Periods[k.Kind]}
		if v, ok := o[k.Kind]; ok {
			p.Override, p.Effective = &v, v
		}
		out.Periods = append(out.Periods, p)
	}
	return out, nil
}

// GetTeam returns a team's periods: members, and platform admins and
// auditors (others: 404).
func (s *Service) GetTeam(ctx context.Context, a authz.Actor, ref string) (TeamView, error) {
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return TeamView{}, err
	}
	role, err := teams.MemberRole(ctx, s.q, t.ID, a.UserID)
	if err != nil {
		return TeamView{}, err
	}
	if role == "" && !a.CanReadPlatform() {
		return TeamView{}, errTeamNotFound
	}
	st, err := s.Current(ctx)
	if err != nil {
		return TeamView{}, err
	}
	return teamView(t, st)
}

// AdminGetTeam returns any team's periods (platform admins and auditors).
func (s *Service) AdminGetTeam(ctx context.Context, a authz.Actor, ref string) (TeamView, error) {
	if !a.CanReadPlatform() {
		return TeamView{}, errPlatformRead
	}
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return TeamView{}, err
	}
	st, err := s.Current(ctx)
	if err != nil {
		return TeamView{}, err
	}
	return teamView(t, st)
}

// TeamChange sets (Days) or clears (nil) a team's override.
type TeamChange struct {
	Kind string
	Days *int32
}

// UpdateTeam sets or clears a team's overrides (platform admins);
// expectedRevision is the team's, and the change bumps it. 422
// invalid_period (not_overridable, out_of_range, duplicate). Audited as
// team.retention_update.
func (s *Service) UpdateTeam(ctx context.Context, a authz.Actor, ref string, changes []TeamChange, expectedRevision int64) (TeamView, error) {
	if !a.IsPlatformAdmin() {
		return TeamView{}, errAdminOnly
	}
	seen := map[string]bool{}
	for _, c := range changes {
		k, ok := Find(c.Kind)
		switch {
		case !ok:
			return TeamView{}, unknownKind(c.Kind)
		case seen[c.Kind]:
			return TeamView{}, invalid(c.Kind, "duplicate", c.Kind+" is listed twice")
		case !k.Overridable:
			return TeamView{}, invalid(c.Kind, "not_overridable", c.Kind+" can't be overridden per team")
		case c.Days != nil && (*c.Days < k.MinDays || *c.Days > k.MaxDays):
			return TeamView{}, invalid(c.Kind, "out_of_range", fmt.Sprintf("%s must be %d to %d days", c.Kind, k.MinDays, k.MaxDays))
		}
		seen[c.Kind] = true
	}
	var out TeamView
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		platform, err := q.LockRetentionSettings(ctx)
		if err != nil {
			return err
		}
		st, err := decodeSettings(platform)
		if err != nil {
			return err
		}
		t, err := teams.Resolve(ctx, q, ref)
		if err != nil {
			return err
		}
		if t, err = q.LockTeam(ctx, t.ID); err != nil {
			return err
		}
		if t.Revision != expectedRevision {
			return apperr.Stale()
		}
		before, err := TeamOverrides(t)
		if err != nil {
			return err
		}
		after := Periods{}
		for k, v := range before {
			after[k] = v
		}
		for _, c := range changes {
			if c.Days == nil {
				delete(after, c.Kind)
			} else {
				after[c.Kind] = *c.Days
			}
		}
		if after[CallMetadata] > st.Periods[AuditLog] {
			return invalid(CallMetadata, "audit_interlock", "Call metadata retention cannot exceed audit retention")
		}
		raw, err := json.Marshal(after)
		if err != nil {
			return err
		}
		updated, err := q.SetTeamRetentionOverrides(ctx, dbgen.SetTeamRetentionOverridesParams{ID: t.ID, Overrides: raw})
		if err != nil {
			return err
		}
		e := a.Audit("team.retention_update", "team", t.ID.String())
		e.TeamID = t.ID
		e.Before, e.After = map[string]any{"overrides": before}, map[string]any{"overrides": after}
		e.Metadata = map[string]any{"name": t.Name}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		row, err := q.GetRetentionSettings(ctx)
		if err != nil {
			return err
		}
		st, err = decodeSettings(row)
		if err != nil {
			return err
		}
		out, err = teamView(updated, st)
		return err
	})
	return out, err
}

// CallPeriods are the days a call and its payload are kept: the shortest
// of the effective periods of the teams involved (existing teams among
// gatewayTeam and serverTeam), else the platform periods.
func (s *Service) CallPeriods(ctx context.Context, gatewayTeam, serverTeam uuid.NullUUID) (calls, payloads int32, err error) {
	st, err := s.Current(ctx)
	if err != nil {
		return 0, 0, err
	}
	calls, payloads = -1, -1
	for _, id := range []uuid.NullUUID{gatewayTeam, serverTeam} {
		if !id.Valid {
			continue
		}
		t, err := s.q.GetTeamByID(ctx, id.UUID)
		if err != nil {
			if store.NotFound(err) == store.ErrNotFound {
				continue
			}
			return 0, 0, err
		}
		o, err := TeamOverrides(t)
		if err != nil {
			return 0, 0, err
		}
		c, p := st.Periods[CallMetadata], st.Periods[CapturedPayloads]
		if v, ok := o[CallMetadata]; ok {
			c = v
		}
		if v, ok := o[CapturedPayloads]; ok {
			p = v
		}
		if calls < 0 || c < calls {
			calls = c
		}
		if payloads < 0 || p < payloads {
			payloads = p
		}
	}
	if calls < 0 {
		calls = st.Periods[CallMetadata]
	}
	if payloads < 0 {
		payloads = st.Periods[CapturedPayloads]
	}
	return calls, payloads, nil
}
