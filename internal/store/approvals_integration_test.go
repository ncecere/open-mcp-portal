package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func approvalModes(t *testing.T, run func(*testing.T, *pgxpool.Pool)) {
	t.Helper()
	for _, mode := range []string{"0", "1"} {
		t.Run("split="+mode, func(t *testing.T) {
			t.Setenv("OMP_TEST_SPLIT_ROLES", mode)
			db, _ := testutil.NewDB(t)
			run(t, db)
		})
	}
}

func approvalEpoch(t *testing.T, db *pgxpool.Pool) int64 {
	t.Helper()
	n, err := dbgen.New(db).GetApprovalContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// All authority rows are real, and all application DML uses the authenticated
// runtime pool. Only DDL/ACL instrumentation uses OwnerPool.
func seedApprovalAuthority(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	statements := []string{
		`INSERT INTO users(id,oidc_issuer,oidc_subject,email) VALUES ('00000000-0000-0000-0000-000000000001','test','one','one@test.invalid')`,
		`INSERT INTO teams(id,slug,name) VALUES ('00000000-0000-0000-0000-000000000002','approval','Approval')`,
		`INSERT INTO team_members(team_id,user_id,role) SELECT t.id,u.id,'owner' FROM teams t CROSS JOIN users u`,
		`INSERT INTO mcp_servers(id,team_id,slug,name,url) SELECT '00000000-0000-0000-0000-000000000003',id,'approval','Approval','https://example.test/mcp' FROM teams`,
		`INSERT INTO mcp_capabilities(id,server_id,kind,name,definition,fingerprint) SELECT '00000000-0000-0000-0000-000000000004',id,'tool','test','{}',repeat('a',64) FROM mcp_servers`,
		`INSERT INTO gateways(id,slug,name,owner_kind,team_id) SELECT '00000000-0000-0000-0000-000000000005','approval','Approval','team',id FROM teams`,
		`INSERT INTO gateway_capabilities(gateway_id,capability_id) SELECT g.id,c.id FROM gateways g CROSS JOIN mcp_capabilities c`,
		`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) SELECT g.id,'user',u.id FROM gateways g CROSS JOIN users u`,
		`INSERT INTO api_keys(id,user_id,name,prefix,digest,expires_at) SELECT '00000000-0000-0000-0000-000000000006',id,'test','omp_12345678',repeat('a',64),now()+interval '1 day' FROM users`,
		`INSERT INTO api_key_gateways(api_key_id,gateway_id,gateway_slug,gateway_name) SELECT k.id,g.id,g.slug,g.name FROM api_keys k CROSS JOIN gateways g`,
		`INSERT INTO oauth_grants(user_id,gateway_id,client_id,client_kind,client_name,resource) SELECT u.id,g.id,'client','metadata','Client','https://portal.test/mcp/approval' FROM users u CROSS JOIN gateways g`,
		`INSERT INTO oauth_tokens(grant_id,kind,token_hash,resource,expires_at) SELECT id,'access',repeat('a',64),resource,now()+interval '1 hour' FROM oauth_grants`,
		`INSERT INTO service_accounts(id,team_id,name) SELECT '00000000-0000-0000-0000-000000000007',id,'approval' FROM teams`,
		`INSERT INTO service_account_keys(id,service_account_id,name,prefix,digest,expires_at) SELECT '00000000-0000-0000-0000-000000000008',id,'test','omp_sa_12345678',repeat('b',64),now()+interval '1 day' FROM service_accounts`,
		`INSERT INTO service_account_key_gateways(key_id,gateway_id,gateway_slug,gateway_name) SELECT k.id,g.id,g.slug,g.name FROM service_account_keys k CROSS JOIN gateways g`,
		`INSERT INTO auth_providers(id,slug,name,client_id,token_auth_method,authorization_url,token_url) VALUES ('00000000-0000-0000-0000-000000000009','approval','Approval','client','none','https://auth.test/authorize','https://auth.test/token')`,
		`INSERT INTO auth_provider_teams(provider_id,team_id) SELECT p.id,t.id FROM auth_providers p CROSS JOIN teams t`,
		`INSERT INTO auth_provider_servers(provider_id,server_id) SELECT p.id,s.id FROM auth_providers p CROSS JOIN mcp_servers s`,
		`INSERT INTO provider_connections(id,user_id,provider_id,status,access_token_cipher) SELECT '00000000-0000-0000-0000-000000000010',u.id,p.id,'active','token'::bytea FROM users u CROSS JOIN auth_providers p`,
		`INSERT INTO provider_server_grants(connection_id,server_id,origin) SELECT c.id,s.id,'https://example.test' FROM provider_connections c CROSS JOIN mcp_servers s`,
		`INSERT INTO person_secrets(user_id,server_id,origin,secret_cipher) SELECT u.id,s.id,'https://example.test','secret'::bytea FROM users u CROSS JOIN mcp_servers s`,
		`INSERT INTO service_connections(id,team_id,provider_id,name,status,access_token_cipher,connected_by) SELECT '00000000-0000-0000-0000-000000000011',t.id,p.id,'test','active','token'::bytea,u.id FROM teams t CROSS JOIN auth_providers p CROSS JOIN users u`,
		`INSERT INTO service_connection_accounts(connection_id,team_id,provider_id,service_account_id) SELECT c.id,c.team_id,c.provider_id,a.id FROM service_connections c CROSS JOIN service_accounts a`,
		`INSERT INTO service_connection_server_grants(connection_id,server_id,origin) SELECT c.id,s.id,'https://example.test' FROM service_connections c CROSS JOIN mcp_servers s`,
		`INSERT INTO mcp_server_credentials(server_id,position,kind,name,value_cipher) SELECT id,0,'header','X-Test','secret'::bytea FROM mcp_servers`,
		`INSERT INTO mcp_server_machine_oauth(server_id,token_url,client_id,client_secret_cipher) SELECT id,'https://auth.test/token','client','secret'::bytea FROM mcp_servers`,
		`INSERT INTO mcp_server_tls(server_id,ca_pem,ca_sha256) SELECT id,'fixture',repeat('a',64) FROM mcp_servers`,
		`INSERT INTO approval_rules(id,name,target_kind,target_id,classes,created_by) VALUES ('00000000-0000-0000-0000-000000000012','Test','server','00000000-0000-0000-0000-000000000003','{destructive}','00000000-0000-0000-0000-000000000001')`,
		`INSERT INTO approval_rule_approvers(rule_id,kind,user_id) VALUES ('00000000-0000-0000-0000-000000000012','user','00000000-0000-0000-0000-000000000001')`,
	}
	for _, sql := range statements {
		before := approvalEpoch(t, db)
		roleExec(t, db, sql)
		if !strings.HasPrefix(sql, "INSERT INTO oauth_tokens") && approvalEpoch(t, db) <= before {
			t.Fatalf("insert failed to fence: %s", sql)
		}
	}
}

func TestApprovalEpochAuthority(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		changes := []string{
			`UPDATE users SET status='suspended'`, `UPDATE users SET status='active'`,
			`UPDATE users SET platform_role='platform_admin'`, `UPDATE users SET groups='{reviewers}'`,
			`UPDATE teams SET status='archived'`, `UPDATE teams SET status='active'`,
			`UPDATE team_members SET role='admin'`, `UPDATE api_keys SET tool_scope='{}'`,
			`UPDATE api_keys SET expires_at=expires_at+interval '1 minute'`, `UPDATE api_keys SET revoked_at=now()`,
			`UPDATE api_key_gateways SET gateway_id=gen_random_uuid()`,
			`UPDATE oauth_grants SET tool_scope='{}'`, `UPDATE oauth_grants SET authorized_at=now()`,
			`UPDATE oauth_grants SET resource=resource||'/new'`, `UPDATE oauth_grants SET revoked_at=now()`,
			`UPDATE service_accounts SET role='editor'`, `UPDATE service_accounts SET enabled=false`,
			`UPDATE service_accounts SET tool_scope='{}'`, `UPDATE service_accounts SET revision=revision+1`,
			`UPDATE service_account_keys SET tool_scope='{}'`, `UPDATE service_account_keys SET revoked_at=now()`,
			`UPDATE service_account_key_gateways SET gateway_id=gen_random_uuid()`,
			`UPDATE gateways SET enabled=false`, `UPDATE gateways SET revision=revision+1`,
			`UPDATE gateway_grants SET tool_scope='{}'`, `UPDATE gateway_capabilities SET min_team_role='admin'`,
			`UPDATE mcp_servers SET revision=revision+1`, `UPDATE mcp_servers SET timeout_seconds=31`,
			`UPDATE mcp_capabilities SET definition='{"changed":true}',fingerprint=repeat('b',64)`,
			`UPDATE mcp_capabilities SET approved_fingerprint=fingerprint`, `UPDATE mcp_capabilities SET tool_class='destructive'`,
			`UPDATE mcp_capabilities SET requirement_mode='none'`, `UPDATE mcp_capabilities SET gone_at=now(),approved_fingerprint=NULL`,
			`UPDATE auth_providers SET revision=revision+1`, `UPDATE auth_providers SET access_mode='restricted'`,
			`UPDATE capture_settings SET patterns='["private-pattern"]'`,
			`UPDATE oauth_tokens SET resource=resource||'/new'`,
			`UPDATE provider_connections SET scopes='{read}'`,
			`UPDATE provider_connections SET connected_at=clock_timestamp()`,
			`UPDATE provider_connections SET status='needs_reconsent',access_token_cipher=NULL,refresh_token_cipher=NULL`,
			`UPDATE provider_server_grants SET scopes='{read}'`, `UPDATE person_secrets SET status='rejected'`,
			`UPDATE person_secrets SET secret_cipher='new'::bytea`, `UPDATE person_secrets SET origin='https://other.test'`,
			`UPDATE service_connections SET revision=revision+1`, `UPDATE service_connections SET generation=generation+1`,
			`UPDATE service_connections SET scopes='{read}'`, `UPDATE service_connections SET connected_by=NULL`,
			`UPDATE service_connection_server_grants SET scopes='{read}'`,
			`UPDATE mcp_server_credentials SET value_cipher='new'::bytea`,
			`UPDATE mcp_server_machine_oauth SET scopes='{read}'`, `UPDATE mcp_server_tls SET ca_sha256=repeat('b',64)`,
			`UPDATE approval_rules SET enabled=false`, `UPDATE approval_rules SET enabled=true`,
			`UPDATE approval_rule_approvers SET user_id=gen_random_uuid()`,
		}
		for _, sql := range changes {
			before := approvalEpoch(t, db)
			roleExec(t, db, sql)
			if approvalEpoch(t, db) <= before {
				t.Fatalf("authority change not fenced: %s", sql)
			}
			// The same statement either becomes a semantic no-op or is explicitly
			// time/revision/random based. Exercise no-op comparisons separately below.
		}
		for _, table := range []string{"capture_settings", "users", "teams", "team_members", "api_keys", "api_key_gateways", "oauth_grants", "oauth_tokens", "service_accounts", "service_account_keys", "service_account_key_gateways", "gateways", "gateway_grants", "gateway_capabilities", "mcp_servers", "mcp_capabilities", "auth_providers", "auth_provider_teams", "auth_provider_servers", "provider_connections", "provider_server_grants", "person_secrets", "service_connections", "service_connection_accounts", "service_connection_server_grants", "mcp_server_credentials", "mcp_server_machine_oauth", "mcp_server_tls", "approval_rule_approvers", "approval_rules"} {
			// Each row is restored by rolling back; cascades are included.
			before := approvalEpoch(t, db)
			tx, err := db.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			roleExec(t, tx, "DELETE FROM "+table)
			var after int64
			if err := tx.QueryRow(context.Background(), `SELECT omp_private.omp_current_approval_context()`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after <= before {
				t.Errorf("delete not fenced: %s", table)
			}
			_ = tx.Rollback(context.Background())
			if approvalEpoch(t, db) != before {
				t.Fatal("rollback advanced epoch")
			}
		}
	})
}

func TestApprovalEpochIgnoresTouchesAndRefresh(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		before := approvalEpoch(t, db)
		for _, sql := range []string{
			`UPDATE users SET last_login_at=now(),revision=revision+1,claims='{"unrelated":true}'`,
			`UPDATE api_keys SET last_used_at=now()`, `UPDATE oauth_grants SET last_used_at=now()`,
			`UPDATE service_accounts SET last_used_at=now()`, `UPDATE service_account_keys SET last_used_at=now()`,
			`UPDATE mcp_servers SET refreshed_at=now(),last_refresh_error='probe'`,
			`UPDATE mcp_capabilities SET last_seen_at=now()`, `UPDATE auth_providers SET discovered_at=now()`,
			`UPDATE provider_connections SET access_token_cipher='refreshed'::bytea,refresh_token_cipher='refresh'::bytea,expires_at=now()+interval '1 hour',refreshed_at=now(),last_used_at=now()`,
			`UPDATE service_connections SET access_token_cipher='refreshed'::bytea,refresh_token_cipher='refresh'::bytea,expires_at=now()+interval '1 hour',refreshed_at=now(),last_used_at=now(),last_error_class=NULL`,
			`UPDATE person_secrets SET last_used_at=now()`,
			`UPDATE oauth_tokens SET rotated_at=now()`,
			`INSERT INTO oauth_tokens(grant_id,kind,token_hash,resource,expires_at) SELECT id,'refresh',repeat('c',64),resource,now()+interval '1 day' FROM oauth_grants`,
			`UPDATE oauth_tokens SET rotated_at=now() WHERE kind='refresh'`,
			`INSERT INTO oauth_tokens(grant_id,kind,token_hash,resource,expires_at) SELECT id,'access',repeat('d',64),resource,now()-interval '1 second' FROM oauth_grants`,
			`DELETE FROM oauth_tokens WHERE expires_at < now()`,
			`DELETE FROM oauth_tokens WHERE kind='refresh'`,
			`INSERT INTO oauth_tokens(grant_id,kind,token_hash,resource,expires_at) SELECT id,'access',repeat('b',64),resource,now()+interval '1 hour' FROM oauth_grants`,
			`INSERT INTO mcp_health_checks(server_id,ok,trigger,status_since) SELECT id,true,'scheduled',now() FROM mcp_servers`,
			`UPDATE approval_rules SET updated_at=now()`,
		} {
			roleExec(t, db, sql)
			if approvalEpoch(t, db) != before {
				t.Fatalf("touch/refresh fenced: %s", sql)
			}
		}
		// No-op every observed authority field (including binary values).
		rows, err := db.Query(context.Background(), `SELECT c.relname,a.attname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped WHERE t.tgname='approval_authority_changed' ORDER BY c.relname,a.attnum`)
		if err != nil {
			t.Fatal(err)
		}
		var statements []string
		for rows.Next() {
			var table, col string
			if err := rows.Scan(&table, &col); err != nil {
				t.Fatal(err)
			}
			statements = append(statements, fmt.Sprintf("UPDATE %s SET %s=%s", pgx.Identifier{table}.Sanitize(), pgx.Identifier{col}.Sanitize(), pgx.Identifier{col}.Sanitize()))
		}
		rows.Close()
		for _, sql := range statements {
			roleExec(t, db, sql)
			if approvalEpoch(t, db) != before {
				t.Fatalf("no-op fenced: %s", sql)
			}
		}
	})
}

func approvalPending(t *testing.T, db *pgxpool.Pool, created time.Time) dbgen.ApprovalRequest {
	t.Helper()
	q := dbgen.New(db)
	r, err := q.InsertApprovalRequest(context.Background(), dbgen.InsertApprovalRequestParams{
		ID: uuid.New(), RuleID: uuid.New(), RuleRevision: 1, ContextEpoch: approvalEpoch(t, db),
		RequesterKind: "user", RequesterID: uuid.New(), RequesterTeamID: uuid.NullUUID{UUID: uuid.New(), Valid: true},
		GatewayID: uuid.New(), ServerID: uuid.New(), CapabilityID: uuid.New(), ExposedName: "test__tool",
		ArgsDigest: strings.Repeat("a", 64), BindingDigest: strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", ""),
		CapabilityFingerprint: strings.Repeat("c", 64), ServerOrigin: "https://example.test", PreviewCipher: []byte("sealed-not-raw"),
		CreatedAt: created, ExpiresAt: created.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func approvalApproved(t *testing.T, db *pgxpool.Pool) dbgen.ApprovalRequest {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	pending := approvalPending(t, db, now)
	tx, err := db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := dbgen.New(tx)
	if _, err = q.LockApprovalContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := q.ApproveApprovalRequest(context.Background(), dbgen.ApproveApprovalRequestParams{
		ID: pending.ID, BindingDigest: pending.BindingDigest, ExpectedReviewRevision: 1, DecidedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true}, AtTime: &now, ValidUntil: now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	roleExec(t, tx, `INSERT INTO audit_log(actor_kind,action,target_type,target_id) VALUES ('system','approval.approved','approval_request',$1)`, r.ID.String())
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

func approvalUseParams(r dbgen.ApprovalRequest, now *time.Time) dbgen.UseApprovalRequestParams {
	return dbgen.UseApprovalRequestParams{ID: r.ID, BindingDigest: r.BindingDigest, ArgsDigest: r.ArgsDigest, RuleRevision: r.RuleRevision, ExpectedReviewRevision: r.ReviewRevision, ContextEpoch: r.ContextEpoch, AtTime: now}
}

func TestApprovalConditionalUseAndAuditRollback(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		q := dbgen.New(db)
		r := approvalApproved(t, db)
		now := time.Now().UTC()
		wrong := approvalUseParams(r, &now)
		wrong.ArgsDigest = strings.Repeat("d", 64)
		if _, err := q.UseApprovalRequest(ctx, wrong); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("wrong binding used: %v", err)
		}
		wrong = approvalUseParams(r, &now)
		wrong.ExpectedReviewRevision++
		if _, err := q.UseApprovalRequest(ctx, wrong); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("stale review used: %v", err)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tq := dbgen.New(tx)
		if _, err = tq.LockApprovalContext(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = tq.UseApprovalRequest(ctx, approvalUseParams(r, &now)); err != nil {
			t.Fatal(err)
		}
		// A real audit constraint failure aborts and rolls back the consumption.
		if _, err = tx.Exec(ctx, `INSERT INTO audit_log(actor_kind,action,target_type) VALUES ('invalid','approval.used','approval_request')`); err == nil {
			t.Fatal("audit accepted invalid actor")
		}
		if err = tx.Commit(ctx); err == nil {
			t.Fatal("aborted consumption committed")
		}
		still, err := q.GetApprovalRequest(ctx, r.ID)
		if err != nil || still.Status != "approved" {
			t.Fatalf("audit rollback lost approval: %+v %v", still, err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() {
				err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
					q := dbgen.New(tx)
					if _, err := q.LockApprovalContext(ctx); err != nil {
						return err
					}
					if _, err := q.UseApprovalRequest(ctx, approvalUseParams(r, &now)); err != nil {
						return err
					}
					_, err := tx.Exec(ctx, `INSERT INTO audit_log(actor_kind,action,target_type,target_id) VALUES ('system','approval.used','approval_request',$1)`, r.ID.String())
					return err
				})
				if err == nil {
					wins.Add(1)
				} else if !errors.Is(err, pgx.ErrNoRows) && !approvalIsSQLState(err, "55P03") {
					errs <- err
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if wins.Load() != 1 {
			t.Fatalf("consume wins=%d", wins.Load())
		}
		if n := roleCount(t, db, `SELECT count(*) FROM audit_log WHERE action='approval.used'`); n != 1 {
			t.Fatalf("use audits=%d", n)
		}
		roleDenied(t, db, `UPDATE approval_requests SET status='approved',review_revision=review_revision+1,terminal_at=NULL,used_at=NULL`, "P0001")
		detail, err := q.GetApprovalRequest(ctx, r.ID)
		if err != nil || detail.PreviewCipher != nil {
			t.Fatalf("terminal preview disclosed: %v", err)
		}
		// A change-and-revert never recovers an old approved binding.
		stale := approvalApproved(t, db)
		roleExec(t, db, `INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES ('test','epoch','epoch@test.invalid')`)
		roleExec(t, db, `UPDATE users SET status='suspended'`)
		roleExec(t, db, `UPDATE users SET status='active'`)
		if _, err := q.UseApprovalRequest(ctx, approvalUseParams(stale, &now)); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("reverted authority resurrected approval: %v", err)
		}
	})
}

func TestApprovalSchemaRetentionAndRuntimeFence(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		owner := testutil.OwnerPool(t, db)
		q := dbgen.New(db)
		if n := roleCount(t, db, `SELECT count(*) FROM pg_constraint WHERE conrelid IN ('approval_requests'::regclass,'approval_rules'::regclass,'approval_rule_approvers'::regclass) AND contype='f' AND confrelid<>'approval_rules'::regclass`); n != 0 {
			t.Fatal("snapshot FK locks authority tables")
		}
		for _, sql := range []string{`UPDATE omp_private.approval_context SET epoch=epoch-1`, `DELETE FROM omp_private.approval_context`, `TRUNCATE omp_private.approval_context`, `INSERT INTO omp_private.approval_context VALUES (1,1)`} {
			roleDenied(t, owner, sql, "P0001")
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tq := dbgen.New(tx)
		if _, err = tq.LockApprovalContext(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = tq.LockApprovalContextExclusive(ctx); err != nil {
			t.Fatal(err)
		}
		_ = tx.Rollback(ctx)
		if db != owner {
			for _, sql := range []string{`UPDATE omp_private.approval_context SET epoch=2`, `DELETE FROM omp_private.approval_context`, `TRUNCATE omp_private.approval_context`, `INSERT INTO omp_private.approval_context DEFAULT VALUES`, `SELECT omp_private.approval_authority_changed()`} {
				roleDenied(t, db, sql, "42501")
			}
			roleDenied(t, db, `UPDATE omp_private.approval_context SET id=id`, "42501")
			role := db.Config().ConnConfig.User
			roleExec(t, owner, "GRANT UPDATE ON omp_private.approval_context TO "+pgx.Identifier{role}.Sanitize())
			safety, err := store.InspectRoles(ctx, db, "", true)
			if err != nil || safety.Safe() {
				t.Fatalf("unsafe epoch grants missed: %+v %v", safety, err)
			}
			if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
				t.Fatal(err)
			}
			roleDenied(t, db, `UPDATE omp_private.approval_context SET epoch=2`, "42501")
		}
		// Nonexistent UUID snapshots work, rule approvers alone cascade.
		roleExec(t, db, `INSERT INTO approval_rules(id,name,target_kind,target_id,created_by) VALUES ('00000000-0000-0000-0000-000000000012','Snapshot','server',gen_random_uuid(),gen_random_uuid())`)
		roleExec(t, db, `INSERT INTO approval_rule_approvers(rule_id,kind,user_id) VALUES ('00000000-0000-0000-0000-000000000012','user',gen_random_uuid())`)
		roleExec(t, db, `DELETE FROM approval_rules`)
		if roleCount(t, db, `SELECT count(*) FROM approval_rule_approvers`) != 0 {
			t.Fatal("approvers did not cascade")
		}
		old := approvalPending(t, db, time.Now().UTC().Add(-92*24*time.Hour))
		now := time.Now().UTC()
		n, err := q.ExpireApprovalRequests(ctx, dbgen.ExpireApprovalRequestsParams{AtTime: &now, BatchSize: 100})
		if err != nil || n != 1 {
			t.Fatalf("expire=%d %v", n, err)
		}
		if _, err = q.ClearApprovalRequestPreviews(ctx, dbgen.ClearApprovalRequestPreviewsParams{BeforeTime: now.Add(time.Second), BatchSize: 100}); err != nil {
			t.Fatal(err)
		}
		if roleCount(t, db, `SELECT count(*) FROM approval_requests WHERE preview_cipher IS NOT NULL`) != 0 {
			t.Fatal("preview retained")
		}
		roleDenied(t, db, `UPDATE approval_requests SET preview_cipher='restored'::bytea`, "P0001")
		// Retention counts terminal_at, not creation, and is independent of audit.
		n, err = q.PurgeApprovalRequestMetadata(ctx, dbgen.PurgeApprovalRequestMetadataParams{AtTime: now, BatchSize: 100})
		if err != nil || n != 0 {
			t.Fatalf("purged fresh terminal: %d %v", n, err)
		}
		future := now.Add(91 * 24 * time.Hour)
		n, err = q.PurgeApprovalRequestMetadata(ctx, dbgen.PurgeApprovalRequestMetadataParams{AtTime: future, BatchSize: 100})
		if err != nil || n != 1 {
			t.Fatalf("purge=%d %v", n, err)
		}
		if _, err = q.GetApprovalRequest(ctx, old.ID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("metadata retained")
		}
		roleExec(t, db, `INSERT INTO mcp_calls(method,outcome,gateway_id,gateway_slug,gateway_name,principal_kind,service_account_id) VALUES ('tools/call','needs_approval',gen_random_uuid(),'test','Test','service_account',gen_random_uuid()),('tools/list','ok',gen_random_uuid(),'test','Test','service_account',gen_random_uuid())`)
	})
}
