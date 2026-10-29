// Package limits holds the rate limits on /mcp/{slug}
// (docs/phase6-operations.md "Rate limits", decision 31): their platform
// defaults and ceilings (limit_settings), teams' overrides
// (teams.limit_overrides), gateways' own values
// (gateways.rate_limit_per_minute), and the check run on every
// authenticated request, counted in a shared internal/ratelimit store.
//
//   - person_per_minute: every request by one person, any credential and
//     gateway (no override).
//   - credential_per_minute: per personal API key or OAuth connection (no
//     override). Service account keys count toward their account.
//   - service_account_per_minute: per service account, all its keys (team
//     override, up to the ceiling).
//   - gateway_per_minute: per gateway, all callers (team override as the
//     default of the team's gateways, and each gateway's own value, up to the
//     ceiling).
//
// Values are 1 to Max per minute, or nil (unlimited; for a ceiling, none).
// Lowering a ceiling keeps stored values: they are capped when used.
package limits

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
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

// Keys.
const (
	PersonPerMinute         = "person_per_minute"
	CredentialPerMinute     = "credential_per_minute"
	ServiceAccountPerMinute = "service_account_per_minute"
	GatewayPerMinute        = "gateway_per_minute"
	ServerPerMinute         = "server_per_minute"
)

// Max is the most any value may be.
const Max = 1_000_000

// CacheTTL is how long a replica uses its copy of the platform settings; the
// replica that saves a change applies it at once.
const CacheTTL = 30 * time.Second

// Def describes one key.
type Def struct {
	Key, Label, Description string
	// Overridable keys have a ceiling and team overrides.
	Overridable bool
	BuiltIn     *int64
}

func ptr(n int64) *int64 { return &n }

// Defs are the keys, in the API's fixed order.
var Defs = []Def{
	{Key: PersonPerMinute, Label: "Per person", BuiltIn: ptr(600),
		Description: "Every request by one person to any gateway, with any API key or connected app"},
	{Key: CredentialPerMinute, Label: "Per API key or connected app", BuiltIn: ptr(300),
		Description: "Requests with one personal API key or one connected app (OAuth connection)"},
	{Key: ServiceAccountPerMinute, Label: "Per service account", Overridable: true, BuiltIn: ptr(1200),
		Description: "Requests by one service account, all its keys together"},
	{Key: GatewayPerMinute, Label: "Per gateway", Overridable: true,
		Description: "Requests to one gateway from all callers together"},
	{Key: ServerPerMinute, Label: "Per upstream server", Overridable: true,
		Description: "Forwarded tool, prompt and resource attempts to one server from all gateways and callers, including automatic retries"},
}

// Find returns the definition of key.
func Find(key string) (Def, bool) {
	for _, d := range Defs {
		if d.Key == key {
			return d, true
		}
	}
	return Def{}, false
}

// Value is a key's platform setting.
type Value struct {
	Default *int64 `json:"default"`
	Ceiling *int64 `json:"ceiling"`
}

// Settings are the platform settings: every key, built-in where unset.
type Settings struct {
	Items     map[string]Value
	Revision  int64
	UpdatedAt time.Time
}

func decodeSettings(row dbgen.LimitSetting) Settings {
	stored := map[string]Value{}
	_ = json.Unmarshal(row.Items, &stored)
	s := Settings{Items: map[string]Value{}, Revision: row.Revision, UpdatedAt: row.UpdatedAt}
	for _, d := range Defs {
		v, ok := stored[d.Key]
		if !ok {
			v = Value{Default: d.BuiltIn}
		}
		if !d.Overridable {
			v.Ceiling = nil
		}
		s.Items[d.Key] = v
	}
	return s
}

// Default is a key's platform default (nil: unlimited).
func (s Settings) Default(key string) *int64 { return s.Items[key].Default }

// Ceiling is a key's ceiling (nil: none).
func (s Settings) Ceiling(key string) *int64 { return s.Items[key].Ceiling }

// Cap applies a ceiling to a value: nil (unlimited) becomes the ceiling.
func Cap(v, ceiling *int64) *int64 {
	switch {
	case ceiling == nil:
		return v
	case v == nil || *v > *ceiling:
		return ceiling
	}
	return v
}

// Overrides are a team's values for overridable keys (absent: inherit).
type Overrides map[string]int64

// TeamOverrides decodes a team's limit overrides.
func TeamOverrides(t dbgen.Team) Overrides {
	out := Overrides{}
	_ = json.Unmarshal(t.LimitOverrides, &out)
	return out
}

func (o Overrides) get(key string) *int64 {
	if v, ok := o[key]; ok {
		return &v
	}
	return nil
}

// TeamEffective is what applies to a team for an overridable key: its
// override, else the default, capped at the ceiling. Other keys: the
// default.
func (s Settings) TeamEffective(o Overrides, key string) *int64 {
	d, _ := Find(key)
	if !d.Overridable {
		return s.Default(key)
	}
	v := o.get(key)
	if v == nil {
		v = s.Default(key)
	}
	return Cap(v, s.Ceiling(key))
}

// GatewayEffective is a gateway's limit: its own value, else (team
// gateways) the team's override, else the default, capped at the ceiling.
// team is nil for platform gateways.
func (s Settings) GatewayEffective(own *int64, team Overrides) *int64 {
	v := own
	if v == nil && team != nil {
		v = team.get(GatewayPerMinute)
	}
	if v == nil {
		v = s.Default(GatewayPerMinute)
	}
	return Cap(v, s.Ceiling(GatewayPerMinute))
}

var (
	errAdminOnly    = apperr.Forbidden("Only platform admins can do this")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")
)

// invalid is 422 invalid_limit with details.key and details.reason.
func invalid(key, reason, msg string) error {
	e := apperr.New(http.StatusUnprocessableEntity, "invalid_limit", msg)
	e.Details = map[string]any{"key": key, "reason": reason}
	return e
}

func outOfRange(key string) error {
	e := apperr.New(http.StatusBadRequest, "invalid_limit", fmt.Sprintf("%s must be between 1 and %d per minute, or null", key, Max))
	e.Details = map[string]any{"key": key, "reason": "out_of_range"}
	return e
}

func unknownKey(key string) error {
	e := apperr.New(http.StatusBadRequest, "invalid_limit", "Unknown limit: "+key)
	e.Details = map[string]any{"key": key, "reason": "unknown_key"}
	return e
}

func inRange(v *int64) bool { return v == nil || (*v >= 1 && *v <= Max) }

// Service manages limit settings and checks requests.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	log  *slog.Logger
	now  func() time.Time

	mu      sync.Mutex
	cached  *Settings
	expires time.Time
}

// New returns a Service.
func New(pool *pgxpool.Pool, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{pool: pool, log: log, now: time.Now}
	if pool != nil {
		s.q = dbgen.New(pool)
	}
	return s
}

// Current returns the platform settings, read again when the copy is older
// than CacheTTL. When they can't be read, the last copy applies (or the
// error, before the first read).
func (s *Service) Current(ctx context.Context) (Settings, error) {
	s.mu.Lock()
	c, fresh := s.cached, s.now().Before(s.expires)
	s.mu.Unlock()
	if c != nil && fresh {
		return *c, nil
	}
	row, err := s.q.GetLimitSettings(ctx)
	if err != nil {
		if c != nil {
			s.log.WarnContext(ctx, "rate limits: reading the settings failed; using the last copy", "err", err)
			return *c, nil
		}
		return Settings{}, err
	}
	return s.set(decodeSettings(row)), nil
}

func (s *Service) set(st Settings) Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached, s.expires = &st, s.now().Add(CacheTTL)
	return st
}

// PlatformItem is one key as Admin › Limits shows it.
type PlatformItem struct {
	Def
	Value
	CappedTeams, CappedGateways, CappedServers int64
}

// PlatformView is the platform settings with capped counts.
type PlatformView struct {
	Items     []PlatformItem
	Revision  int64
	UpdatedAt time.Time
}

func platformView(ctx context.Context, q *dbgen.Queries, st Settings) (PlatformView, error) {
	out := PlatformView{Revision: st.Revision, UpdatedAt: st.UpdatedAt, Items: make([]PlatformItem, len(Defs))}
	for i, d := range Defs {
		it := PlatformItem{Def: d, Value: st.Items[d.Key]}
		if c := it.Ceiling; c != nil && d.Overridable {
			n, err := q.CountCappedTeams(ctx, dbgen.CountCappedTeamsParams{Key: d.Key, Ceiling: *c})
			if err != nil {
				return out, err
			}
			it.CappedTeams = n
			if d.Key == GatewayPerMinute {
				if it.CappedGateways, err = q.CountCappedGateways(ctx, *c); err != nil {
					return out, err
				}
			} else if d.Key == ServerPerMinute {
				if it.CappedServers, err = q.CountCappedServers(ctx, *c); err != nil {
					return out, err
				}
			}
		}
		out.Items[i] = it
	}
	return out, nil
}

// Get returns the platform settings (platform admins and auditors).
func (s *Service) Get(ctx context.Context, a authz.Actor) (PlatformView, error) {
	if !a.CanReadPlatform() {
		return PlatformView{}, errPlatformRead
	}
	row, err := s.q.GetLimitSettings(ctx)
	if err != nil {
		return PlatformView{}, err
	}
	return platformView(ctx, s.q, decodeSettings(row))
}

// Change replaces one key's platform default and ceiling.
type Change struct {
	Key              string
	Default, Ceiling *int64
}

// Update replaces the listed keys (platform admins). 422 invalid_limit
// (default_above_ceiling, not_overridable, duplicate). Audited as
// settings.limits_update.
func (s *Service) Update(ctx context.Context, a authz.Actor, changes []Change, expectedRevision int64) (PlatformView, error) {
	if !a.IsPlatformAdmin() {
		return PlatformView{}, errAdminOnly
	}
	seen := map[string]bool{}
	for _, c := range changes {
		d, ok := Find(c.Key)
		switch {
		case !ok:
			return PlatformView{}, unknownKey(c.Key)
		case seen[c.Key]:
			return PlatformView{}, invalid(c.Key, "duplicate", c.Key+" is listed twice")
		case !inRange(c.Default) || !inRange(c.Ceiling):
			return PlatformView{}, outOfRange(c.Key)
		case c.Ceiling != nil && !d.Overridable:
			return PlatformView{}, invalid(c.Key, "not_overridable", d.Label+" has no ceiling: teams can't override it")
		case c.Ceiling != nil && (c.Default == nil || *c.Default > *c.Ceiling):
			return PlatformView{}, invalid(c.Key, "default_above_ceiling", "The default can't be above the ceiling")
		}
		seen[c.Key] = true
	}
	var out PlatformView
	var next Settings
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockLimitSettings(ctx)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		before := decodeSettings(cur)
		items := map[string]Value{}
		for k, v := range before.Items {
			items[k] = v
		}
		for _, c := range changes {
			items[c.Key] = Value{Default: c.Default, Ceiling: c.Ceiling}
		}
		raw, err := json.Marshal(items)
		if err != nil {
			return err
		}
		row, err := q.UpdateLimitSettings(ctx, dbgen.UpdateLimitSettingsParams{Items: raw, UpdatedBy: by(a)})
		if err != nil {
			return err
		}
		next = decodeSettings(row)
		e := a.Audit("settings.limits_update", "platform_settings", "limits")
		e.Before, e.After = map[string]any{"items": before.Items}, map[string]any{"items": next.Items}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = platformView(ctx, q, next)
		return err
	})
	if err != nil {
		return PlatformView{}, err
	}
	s.set(next)
	return out, nil
}

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// TeamItem is one key as a team's limits show it.
type TeamItem struct {
	Def
	Override, Default, Ceiling, Effective *int64
}

// TeamView is a team's limits.
type TeamView struct {
	TeamID   uuid.UUID
	TeamSlug string
	Revision int64
	Items    []TeamItem
}

func teamView(t dbgen.Team, st Settings) TeamView {
	o := TeamOverrides(t)
	out := TeamView{TeamID: t.ID, TeamSlug: t.Slug, Revision: t.Revision, Items: make([]TeamItem, len(Defs))}
	for i, d := range Defs {
		it := TeamItem{Def: d, Default: st.Default(d.Key), Ceiling: st.Ceiling(d.Key), Effective: st.TeamEffective(o, d.Key)}
		if d.Overridable {
			it.Override = o.get(d.Key)
		}
		out.Items[i] = it
	}
	return out
}

// GetTeam returns a team's limits: team members, and platform admins and
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
	return s.teamView(ctx, t)
}

// AdminGetTeam returns any team's limits (platform admins and auditors).
func (s *Service) AdminGetTeam(ctx context.Context, a authz.Actor, ref string) (TeamView, error) {
	if !a.CanReadPlatform() {
		return TeamView{}, errPlatformRead
	}
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return TeamView{}, err
	}
	return s.teamView(ctx, t)
}

func (s *Service) teamView(ctx context.Context, t dbgen.Team) (TeamView, error) {
	row, err := s.q.GetLimitSettings(ctx)
	if err != nil {
		return TeamView{}, err
	}
	return teamView(t, decodeSettings(row)), nil
}

// TeamChange sets (Value) or clears (nil) a team's override.
type TeamChange struct {
	Key   string
	Value *int64
}

// UpdateTeam sets or clears a team's overrides (platform admins);
// expectedRevision is the team's, and the change bumps it. 422
// invalid_limit (not_overridable, above_ceiling, duplicate). Audited as
// team.limits_update.
func (s *Service) UpdateTeam(ctx context.Context, a authz.Actor, ref string, changes []TeamChange, expectedRevision int64) (TeamView, error) {
	if !a.IsPlatformAdmin() {
		return TeamView{}, errAdminOnly
	}
	var out TeamView
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		row, err := q.GetLimitSettings(ctx)
		if err != nil {
			return err
		}
		st := decodeSettings(row)
		seen := map[string]bool{}
		for _, c := range changes {
			d, ok := Find(c.Key)
			switch {
			case !ok:
				return unknownKey(c.Key)
			case seen[c.Key]:
				return invalid(c.Key, "duplicate", c.Key+" is listed twice")
			case !inRange(c.Value):
				return outOfRange(c.Key)
			case !d.Overridable:
				return invalid(c.Key, "not_overridable", d.Label+" can't be overridden per team")
			case c.Value != nil && st.Ceiling(c.Key) != nil && *c.Value > *st.Ceiling(c.Key):
				return invalid(c.Key, "above_ceiling", fmt.Sprintf("%s can be at most %d per minute (the ceiling)", d.Label, *st.Ceiling(c.Key)))
			}
			seen[c.Key] = true
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
		before := TeamOverrides(t)
		after := Overrides{}
		for k, v := range before {
			after[k] = v
		}
		for _, c := range changes {
			if c.Value == nil {
				delete(after, c.Key)
			} else {
				after[c.Key] = *c.Value
			}
		}
		raw, err := json.Marshal(after)
		if err != nil {
			return err
		}
		updated, err := q.SetTeamLimitOverrides(ctx, dbgen.SetTeamLimitOverridesParams{ID: t.ID, Overrides: raw})
		if err != nil {
			return err
		}
		e := a.Audit("team.limits_update", "team", t.ID.String())
		e.TeamID = t.ID
		e.Before, e.After = map[string]any{"overrides": before}, map[string]any{"overrides": after}
		e.Metadata = map[string]any{"name": t.Name}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out = teamView(updated, st)
		return nil
	})
	return out, err
}

// CheckGatewayValue refuses a gateway's own value above the ceiling of
// gateway_per_minute (422 invalid_limit above_ceiling) or out of range.
func (s *Service) CheckGatewayValue(ctx context.Context, q *dbgen.Queries, v *int64) error {
	if !inRange(v) {
		return outOfRange(GatewayPerMinute)
	}
	if v == nil {
		return nil
	}
	row, err := q.GetLimitSettings(ctx)
	if err != nil {
		return err
	}
	if c := decodeSettings(row).Ceiling(GatewayPerMinute); c != nil && *v > *c {
		return invalid(GatewayPerMinute, "above_ceiling", fmt.Sprintf("A gateway's limit can be at most %d per minute (the ceiling)", *c))
	}
	return nil
}

// GatewayLimit is a gateway's effective limit now (nil: unlimited). team is
// the gateway's team for team gateways (nil for platform gateways).
func (s *Service) GatewayLimit(ctx context.Context, own *int64, team *dbgen.Team) (*int64, error) {
	st, err := s.Current(ctx)
	if err != nil {
		return nil, err
	}
	var o Overrides
	if team != nil {
		o = TeamOverrides(*team)
	}
	return st.GatewayEffective(own, o), nil
}
