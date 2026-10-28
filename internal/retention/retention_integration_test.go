package retention_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/retention"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type fixture struct {
	t    *testing.T
	pool *pgxpool.Pool
	user string
}

func (f *fixture) scalar(sql string, args ...any) string {
	f.t.Helper()
	var out string
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&out); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// call inserts a call days old through a gateway of gatewayTeam (""
// platform) to a server of serverTeam ("" none), with a payload when
// payload is set.
func (f *fixture) call(days int, gatewayTeam, serverTeam string, payload bool) string {
	f.t.Helper()
	id := f.scalar(`INSERT INTO mcp_calls (occurred_at, method, gateway_id, gateway_slug, gateway_name, gateway_team_id, server_id, server_team_id,
		user_id, outcome) VALUES (now() - make_interval(days => $1), 'tools/call', gen_random_uuid(), 'gw', 'Gateway', NULLIF($2, '')::uuid,
		CASE WHEN $3 = '' THEN NULL ELSE gen_random_uuid() END, NULLIF($3, '')::uuid, $4, 'ok') RETURNING id::text`, days, gatewayTeam, serverTeam, f.user)
	if payload {
		f.scalar(`INSERT INTO mcp_call_payloads (call_id, occurred_at, gateway_team_id, server_team_id, by_gateway, by_server, arguments_cipher,
			arguments_bytes) SELECT id, occurred_at, gateway_team_id, server_team_id, true, false, '\x00', 1 FROM mcp_calls WHERE id = $1::bigint
			RETURNING call_id::text`, id)
	}
	return id
}

func (f *fixture) exists(table, col, id string) bool {
	return f.scalar(`SELECT EXISTS (SELECT 1 FROM `+table+` WHERE `+col+`::text = $1)::text`, id) == "true"
}

func TestRetentionPass(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	f := &fixture{t: t, pool: pool}
	f.user = f.scalar(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('t', 's', 'a@example.com', 'A') RETURNING id::text`)
	short := f.scalar(`INSERT INTO teams (slug, name, retention_overrides) VALUES ('short', 'Short', '{"call_metadata": 10}') RETURNING id::text`)
	long := f.scalar(`INSERT INTO teams (slug, name, retention_overrides) VALUES ('long', 'Long', '{"call_metadata": 365, "captured_payloads": 30}') RETURNING id::text`)

	shortCall := f.call(20, short, "", false)
	longCall := f.call(20, long, "", true)         // kept; its payload (30 days) too
	mixedCall := f.call(20, long, short, false)    // the shorter period (10) applies
	oldPlatform := f.call(100, "", "", false)      // platform 90
	newPlatform := f.call(50, "", "", true)        // kept; its payload (14) goes
	recent := f.call(5, short, "", true)           // kept with its payload
	longOnlyServer := f.call(200, "", long, false) // a platform gateway to a long team's server: 365 applies
	f.scalar(`INSERT INTO audit_log (occurred_at, actor_kind, action, target_type) VALUES (now() - interval '500 days', 'system', 'x.old', 'team'),
		(now() - interval '100 days', 'system', 'x.kept', 'team') RETURNING 1`)
	f.scalar(`INSERT INTO usage_hourly (hour, gateway_id, gateway_slug, gateway_name, method, principal_kind, outcome, calls, latency_sum_ms,
		latency_buckets, request_bytes, response_bytes) VALUES
		(date_trunc('hour', now() - interval '500 days'), gen_random_uuid(), 'gw', 'G', 'tools/list', 'api_key', 'ok', 1, 1, '{1}', 1, 1),
		(date_trunc('hour', now() - interval '10 days'), gen_random_uuid(), 'gw', 'G', 'tools/list', 'api_key', 'ok', 1, 1, '{1}', 1, 1)
		RETURNING 1`)

	// Call records can't be deleted outside the retention transaction.
	if _, err := pool.Exec(ctx, `DELETE FROM mcp_calls WHERE id = $1::bigint`, shortCall); err == nil || (!strings.Contains(err.Error(), "append-only") && !strings.Contains(err.Error(), "permission denied")) {
		t.Fatalf("delete outside retention: %v", err)
	}

	s := retention.New(pool, retention.Config{BatchSize: 1, MaxBatches: 100}, testutil.Logger())
	var observed []retention.Run
	s.Observe = func(r retention.Run, leader bool) {
		if leader {
			observed = append(observed, r)
		}
	}
	// Before any usage rollup no call is deleted (not rolled up yet), but
	// payloads, audit entries and rollups are.
	run, ran, err := s.Pass(ctx)
	if err != nil || !ran {
		t.Fatal(err, ran)
	}
	if run.Deleted[retention.CallMetadata] != 0 || run.Deleted[retention.CapturedPayloads] != 1 || run.Deleted[retention.AuditLog] != 1 ||
		run.Deleted[retention.UsageRollups] != 1 || len(run.Errors) != 0 {
		t.Fatalf("first pass = %+v", run)
	}
	if f.exists("mcp_call_payloads", "call_id", newPlatform) || !f.exists("mcp_call_payloads", "call_id", longCall) ||
		!f.exists("mcp_call_payloads", "call_id", recent) {
		t.Fatal("payload periods not applied")
	}
	// Rolled up: calls past their period go, in batches of one.
	if _, err := pool.Exec(ctx, `UPDATE usage_rollup_state SET rolled_up_to = now()`); err != nil {
		t.Fatal(err)
	}
	run, _, err = s.Pass(ctx)
	if err != nil || run.Deleted[retention.CallMetadata] != 3 {
		t.Fatalf("second pass = %+v %v", run, err)
	}
	for id, want := range map[string]bool{shortCall: false, mixedCall: false, oldPlatform: false, longCall: true, newPlatform: true,
		recent: true, longOnlyServer: true} {
		if got := f.exists("mcp_calls", "id", id); got != want {
			t.Errorf("call %s exists = %v, want %v", id, got, want)
		}
	}
	if f.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'retention.purge'`) != "2" {
		t.Error("each pass that deleted something is audited")
	}
	if strings.Contains(f.scalar(`SELECT metadata::text FROM audit_log WHERE action = 'retention.purge' ORDER BY id DESC LIMIT 1`), "tools/call") {
		t.Error("the purge audit holds more than counts")
	}
	// Idempotent: nothing left to delete, not audited again.
	run, _, err = s.Pass(ctx)
	if err != nil || len(run.Deleted) != 0 || f.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'retention.purge'`) != "2" {
		t.Fatalf("third pass = %+v %v", run, err)
	}
	st, err := s.Current(ctx)
	if err != nil || st.LastRun == nil || st.LastRun.FinishedAt.IsZero() || len(observed) != 3 {
		t.Fatalf("last run = %+v %v (observed %d)", st.LastRun, err, len(observed))
	}
	// Leader lock: another replica's pass is skipped.
	release, ok, err := store.TryAdvisoryLockText(ctx, pool, retention.LockKey)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, ran, err := s.Pass(ctx); ran || err != nil {
		t.Fatalf("pass ran while another replica held the lock: %v", err)
	}
	release()
}

func TestRetentionSettings(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	f := &fixture{t: t, pool: pool}
	team := f.scalar(`INSERT INTO teams (slug, name) VALUES ('t1', 'T1') RETURNING slug`)
	a := authz.Actor{PlatformRole: authz.PlatformAdmin}
	s := retention.New(pool, retention.Config{}, nil)
	for name, tc := range map[string]struct {
		changes []retention.Change
		reason  string
	}{
		"audit minimum":  {[]retention.Change{{Kind: retention.AuditLog, Days: 29}}, "out_of_range"},
		"payload max":    {[]retention.Change{{Kind: retention.CapturedPayloads, Days: 91}}, "out_of_range"},
		"rollup minimum": {[]retention.Change{{Kind: retention.UsageRollups, Days: 60}}, "out_of_range"},
		"duplicate":      {[]retention.Change{{Kind: retention.AuditLog, Days: 40}, {Kind: retention.AuditLog, Days: 50}}, "duplicate"},
	} {
		_, err := s.Update(ctx, a, tc.changes, 1)
		if err == nil || !strings.Contains(err.Error(), "invalid_period") {
			t.Errorf("%s: %v", name, err)
		}
	}
	st, err := s.Update(ctx, a, []retention.Change{{Kind: retention.CallMetadata, Days: 30}}, 1)
	if err != nil || st.Periods[retention.CallMetadata] != 30 || st.Periods[retention.AuditLog] != 400 || st.Revision != 2 {
		t.Fatalf("update = %+v %v", st, err)
	}
	if _, err := s.Update(ctx, a, nil, 1); err == nil {
		t.Fatal("a stale revision is refused")
	}
	days := int32(5)
	if _, err := s.UpdateTeam(ctx, a, team, []retention.TeamChange{{Kind: retention.AuditLog, Days: &days}}, 1); err == nil ||
		!strings.Contains(err.Error(), "invalid_period") {
		t.Fatalf("audit log is not overridable: %v", err)
	}
	v, err := s.UpdateTeam(ctx, a, team, []retention.TeamChange{{Kind: retention.CapturedPayloads, Days: &days}}, 1)
	if err != nil || v.Revision != 2 || len(v.Periods) != 2 || v.Periods[1].Effective != 5 || v.Periods[0].Effective != 30 {
		t.Fatalf("team = %+v %v", v, err)
	}
	if _, err := s.Get(ctx, authz.Actor{PlatformRole: authz.PlatformNone}); err == nil {
		t.Fatal("people without a platform role can't read the settings")
	}
	calls, payloads, err := s.CallPeriods(ctx, uuidOf(t, f, team), uuidOf(t, f, ""))
	if err != nil || calls != 30 || payloads != 5 {
		t.Fatalf("periods = %d %d %v", calls, payloads, err)
	}
}

// uuidOf is a team's ID by slug ("": none).
func uuidOf(t *testing.T, f *fixture, slug string) uuid.NullUUID {
	if slug == "" {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: uuid.MustParse(f.scalar(`SELECT id::text FROM teams WHERE slug = $1`, slug)), Valid: true}
}
