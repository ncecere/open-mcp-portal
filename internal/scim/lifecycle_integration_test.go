package scim

// Regressions for the independent security review of the SCIM candidate
// (F1-F3). Each was first reproduced against the unfixed code.

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type fixture struct {
	t     *testing.T
	ctx   context.Context
	owner interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}
}

func (f fixture) id(sql string, args ...any) uuid.UUID {
	f.t.Helper()
	var x uuid.UUID
	if err := f.owner.QueryRow(f.ctx, sql, args...).Scan(&x); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return x
}

// waitBlocked waits until n backends of this database wait on a lock.
func waitBlocked(t *testing.T, ctx context.Context, f fixture, n int) {
	t.Helper()
	for {
		var got int
		if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND cardinality(pg_blocking_pids(pid))>0`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got >= n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %d blocked backends, have %d", n, got)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// F1: removals from two different mapped groups, both queued behind the
// team lock, must not apply a stale desired role: after both, the person has
// no directory membership.
func TestReconcileSerialisesRemovalsFromDifferentGroups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, _ := testutil.NewDB(t)
	f := fixture{t, ctx, testutil.OwnerPool(t, pool)}
	d := f.id(`INSERT INTO scim_directories(issuer,enabled) VALUES('review',true) RETURNING id`)
	u := f.id(`INSERT INTO users(oidc_issuer,oidc_subject,email,directory_standing) VALUES('review','subject','review@example.test','active') RETURNING id`)
	su := f.id(`INSERT INTO scim_users(directory_id,user_name,external_id,linked_user_id) VALUES($1,'review','subject',$2) RETURNING id`, d, u)
	team := f.id(`INSERT INTO teams(slug,name) VALUES('review','Review') RETURNING id`)
	ga := f.id(`INSERT INTO scim_groups(directory_id,display_name) VALUES($1,'Admins') RETURNING id`, d)
	gb := f.id(`INSERT INTO scim_groups(directory_id,display_name) VALUES($1,'Members') RETURNING id`, d)
	f.id(`WITH a AS (INSERT INTO scim_group_members VALUES($1,$3),($2,$3) RETURNING group_id) SELECT group_id FROM a LIMIT 1`, ga, gb, su)
	f.id(`WITH a AS (INSERT INTO scim_group_mappings(group_id,team_id,role) VALUES($1,$3,'admin'),($2,$3,'member') RETURNING id) SELECT id FROM a LIMIT 1`, ga, gb, team)
	f.id(`WITH a AS (INSERT INTO team_members(team_id,user_id,role) VALUES($1,$2,'admin') RETURNING team_id) SELECT team_id FROM a`, team, u)
	f.id(`WITH a AS (INSERT INTO directory_team_memberships VALUES($1,$2) RETURNING team_id) SELECT team_id FROM a`, team, u)

	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := dbgen.New(blocker).LockTeam(ctx, team); err != nil {
		t.Fatal(err)
	}
	svc := New(pool, []byte("review-pepper-not-a-secret"), "review")
	results := make(chan error, 2)
	patch := func(g uuid.UUID) {
		r := httptest.NewRequest("PATCH", "/scim/v2/Groups/"+g.String(), strings.NewReader(fmt.Sprintf(`{"Operations":[{"op":"remove","path":"members[value eq \"%s\"]"}]}`, su)))
		_, err := svc.updateGroup(ctx, r, Principal{DirectoryID: d}, g, "")
		results <- err
	}
	go patch(ga)
	waitBlocked(t, ctx, f, 1)
	go patch(gb)
	waitBlocked(t, ctx, f, 2)
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal("removal failed:", err)
		}
	}
	var members, memberships int
	if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM scim_group_members), (SELECT count(*) FROM team_members WHERE team_id=$1 AND user_id=$2)`, team, u).Scan(&members, &memberships); err != nil {
		t.Fatal(err)
	}
	if members != 0 || memberships != 0 {
		t.Fatalf("after both removals: group members=%d, team memberships=%d (a stale role survived)", members, memberships)
	}
}

// F2: adoption (standing change, then mapped-team reconciliation) and an
// owner promotion that already holds that team must not deadlock. The
// promotion is refused fast while adoption is in progress, so adoption wins.
func TestAdoptionAndOwnerPromotionDoNotDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, _ := testutil.NewDB(t)
	f := fixture{t, ctx, testutil.OwnerPool(t, pool)}
	d := f.id(`INSERT INTO scim_directories(issuer,enabled) VALUES('review',true) RETURNING id`)
	admin := f.id(`INSERT INTO users(oidc_issuer,oidc_subject,email,platform_role) VALUES('review','admin','admin@example.test','platform_admin') RETURNING id`)
	u := f.id(`INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES('review','adopt','adopt@example.test') RETURNING id`)
	su := f.id(`INSERT INTO scim_users(directory_id,user_name,external_id) VALUES($1,'adopt','adopt') RETURNING id`, d)
	team := f.id(`INSERT INTO teams(slug,name) VALUES('adoption','Adoption') RETURNING id`)
	group := f.id(`INSERT INTO scim_groups(directory_id,display_name) VALUES($1,'Adoption') RETURNING id`, d)
	f.id(`WITH a AS (INSERT INTO scim_group_members VALUES($1,$2) RETURNING group_id) SELECT group_id FROM a`, group, su)
	f.id(`WITH a AS (INSERT INTO scim_group_mappings(group_id,team_id,role) VALUES($1,$2,'member') RETURNING id) SELECT id FROM a`, group, team)
	f.id(`WITH a AS (INSERT INTO team_members(team_id,user_id,role) VALUES($1,$2,'member') RETURNING team_id) SELECT team_id FROM a`, team, u)

	promote, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer promote.Rollback(context.Background())
	pq := dbgen.New(promote)
	if _, err := pq.LockTeam(ctx, team); err != nil {
		t.Fatal(err)
	}
	svc := New(pool, []byte("review-pepper"), "review")
	adopted := make(chan error, 1)
	go func() { adopted <- svc.Adopt(ctx, authz.Actor{UserID: admin, PlatformRole: authz.PlatformAdmin}, su) }()
	waitBlocked(t, ctx, f, 1)
	_, promotionErr := pq.UpdateMemberRole(ctx, dbgen.UpdateMemberRoleParams{TeamID: team, UserID: u, Role: "owner"})
	if promotionErr == nil {
		err = promote.Commit(ctx)
	} else {
		err = promote.Rollback(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	adoptionErr := <-adopted
	deadlock := func(e error) bool {
		var pe *pgconn.PgError
		return errors.As(e, &pe) && pe.Code == "40P01"
	}
	if deadlock(adoptionErr) || deadlock(promotionErr) {
		t.Fatalf("deadlock: adoption=%v promotion=%v", adoptionErr, promotionErr)
	}
	var pe *pgconn.PgError
	if adoptionErr != nil || !errors.As(promotionErr, &pe) || pe.ConstraintName != "team_members_directory_busy" {
		t.Fatalf("want adoption to win and the promotion refused as busy: adoption=%v promotion=%v", adoptionErr, promotionErr)
	}
	var role, standing string
	if err := f.owner.QueryRow(ctx, `SELECT m.role, u.directory_standing FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=$1 AND m.user_id=$2`, team, u).Scan(&role, &standing); err != nil {
		t.Fatal(err)
	}
	if role == "owner" || standing != StandingActive {
		t.Fatalf("after the race: role=%s standing=%s", role, standing)
	}
}

// F3: a status-only manual suspension (as a previous binary writes it) while
// the person is already suspended by the directory is still a manual
// decision: directory reactivation must not lift it.
func TestStatusOnlySuspensionIsManualWhileDirectoryInactive(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	f := fixture{t, ctx, testutil.OwnerPool(t, pool)}
	u := f.id(`INSERT INTO users(oidc_issuer,oidc_subject,email,directory_standing) VALUES('review','legacy','legacy@example.test','inactive') RETURNING id`)
	read := func() (manual, status string) {
		t.Helper()
		if err := f.owner.QueryRow(ctx, `SELECT manual_status, status FROM users WHERE id=$1`, u).Scan(&manual, &status); err != nil {
			t.Fatal(err)
		}
		return
	}
	f.id(`UPDATE users SET status='suspended' WHERE id=$1 RETURNING id`, u)
	if manual, status := read(); manual != "suspended" || status != "suspended" {
		t.Fatalf("status-only suspension not recorded as manual: manual=%s effective=%s", manual, status)
	}
	f.id(`UPDATE users SET directory_standing='active' WHERE id=$1 RETURNING id`, u)
	if manual, status := read(); manual != "suspended" || status != "suspended" {
		t.Fatalf("directory reactivation lifted a manual suspension: manual=%s effective=%s", manual, status)
	}
	// A status-only reactivation is manual too; it lifts only the manual part.
	f.id(`UPDATE users SET directory_standing='inactive' WHERE id=$1 RETURNING id`, u)
	f.id(`UPDATE users SET status='active' WHERE id=$1 RETURNING id`, u)
	if manual, status := read(); manual != "active" || status != "suspended" {
		t.Fatalf("status-only reactivation: manual=%s effective=%s", manual, status)
	}
}

// F4 (review follow-up): a mapping insert takes an implicit FK KEY SHARE lock
// on the team. It must not do that before waiting for the reconcile locks a
// concurrent group PATCH holds while it waits for the same team.
func TestMappingCreateAndGroupPatchDoNotDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, _ := testutil.NewDB(t)
	f := fixture{t, ctx, testutil.OwnerPool(t, pool)}
	d := f.id(`INSERT INTO scim_directories(issuer,enabled) VALUES('review',true) RETURNING id`)
	admin := f.id(`INSERT INTO users(oidc_issuer,oidc_subject,email,platform_role) VALUES('review','admin','admin@example.test','platform_admin') RETURNING id`)
	u := f.id(`INSERT INTO users(oidc_issuer,oidc_subject,email,directory_standing) VALUES('review','subject','review@example.test','active') RETURNING id`)
	su := f.id(`INSERT INTO scim_users(directory_id,user_name,external_id,linked_user_id) VALUES($1,'review','subject',$2) RETURNING id`, d, u)
	team := f.id(`INSERT INTO teams(slug,name) VALUES('review','Review') RETURNING id`)
	ga := f.id(`INSERT INTO scim_groups(directory_id,display_name) VALUES($1,'Admins') RETURNING id`, d)
	gb := f.id(`INSERT INTO scim_groups(directory_id,display_name) VALUES($1,'Members') RETURNING id`, d)
	f.id(`WITH a AS (INSERT INTO scim_group_members VALUES($1,$3),($2,$3) RETURNING group_id) SELECT group_id FROM a LIMIT 1`, ga, gb, su)
	f.id(`INSERT INTO scim_group_mappings(group_id,team_id,role) VALUES($1,$2,'admin') RETURNING id`, ga, team)
	f.id(`INSERT INTO team_members(team_id,user_id,role) VALUES($1,$2,'admin') RETURNING team_id`, team, u)
	f.id(`INSERT INTO directory_team_memberships VALUES($1,$2) RETURNING team_id`, team, u)

	block, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer block.Rollback(context.Background())
	if err := dbgen.New(block).LockDirectoryReconcile(ctx, u.String()); err != nil {
		t.Fatal(err)
	}
	svc := New(pool, []byte("review-test-only"), "review")
	patched, mapped := make(chan error, 1), make(chan error, 1)
	go func() {
		r := httptest.NewRequest("PATCH", "/scim/v2/Groups/"+ga.String(), strings.NewReader(fmt.Sprintf(`{"Operations":[{"op":"remove","path":"members[value eq \"%s\"]"}]}`, su)))
		_, err := svc.updateGroup(ctx, r, Principal{DirectoryID: d}, ga, "")
		patched <- err
	}()
	waitBlocked(t, ctx, f, 1)
	go func() {
		_, err := svc.CreateMapping(ctx, authz.Actor{UserID: admin, PlatformRole: authz.PlatformAdmin}, MappingInput{GroupID: gb, TeamID: team, Role: "member"})
		mapped <- err
	}()
	waitBlocked(t, ctx, f, 2)
	if err := block.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if pe, me := <-patched, <-mapped; pe != nil || me != nil {
		t.Fatalf("PATCH=%v CreateMapping=%v", pe, me)
	}
	var role string
	if err := f.owner.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id=$1 AND user_id=$2`, team, u).Scan(&role); err != nil || role != "member" {
		t.Fatalf("after removal from Admins and mapping Members: role=%q err=%v", role, err)
	}
}
