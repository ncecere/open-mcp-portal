package approvals

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/authz"
)

func newAttentionFixture(t *testing.T, split bool) *serviceFixture {
	t.Helper()
	f := newQueueModeFixture(t, split)
	for i, actor := range []*authz.Actor{&f.admin, &f.auditor, &f.saOwner} {
		actor.UserID = uuid.New()
		actor.PlatformRole = []string{authz.PlatformAdmin, authz.PlatformAuditor, authz.PlatformNone}[i]
		execFixture(t, f.db, `INSERT INTO users(id,oidc_issuer,oidc_subject,email,platform_role) VALUES ($1,'attention',$2,$3,$4)`, actor.UserID, fmt.Sprint(i), fmt.Sprintf("a%d@test.invalid", i), actor.PlatformRole)
	}
	f.sa = uuid.New()
	execFixture(t, f.db, `INSERT INTO teams(id,slug,name) VALUES ($1,'account-team','Accounts')`, f.saTeam)
	execFixture(t, f.db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'owner')`, f.saTeam, f.saOwner.UserID)
	execFixture(t, f.db, `INSERT INTO service_accounts(id,team_id,name,enabled) VALUES ($1,$2,'worker',true)`, f.sa, f.saTeam)
	execFixture(t, f.db, `INSERT INTO gateway_grants(gateway_id,subject_kind,team_id) VALUES ($1,'team',$2)`, f.gateway, f.saTeam)
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	return f
}

// Compare the exact set against the queue's independently evaluated live
// permissions. Every base request is created by Begin with genuine policy.
func assertAttentionQueue(t *testing.T, f *serviceFixture, a authz.Actor, want ...uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	items, total, err := f.s.Attention(ctx, a, nil, 200)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[uuid.UUID]bool{}
	for _, id := range want {
		expected[id] = true
	}
	if total != int64(len(expected)) || len(items) != len(expected) {
		t.Fatalf("attention actor %s: total=%d rows=%d want=%d", a.UserID, total, len(items), len(expected))
	}
	for _, item := range items {
		if !expected[item.ID] || item.ExposedName != f.input.Binding.ExposedName || item.CreatedAt.IsZero() {
			t.Fatalf("unsafe or unexpected item: %+v", item)
		}
	}
	queued := map[uuid.UUID]bool{}
	cursor := ""
	for {
		rows, next, err := f.s.ListRequestsPage(ctx, a, "actionable", cursor, 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if !row.CanDecide || row.Preview != nil {
				t.Fatalf("not actionable metadata: %+v", row)
			}
			queued[row.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(queued) != len(expected) {
		t.Fatalf("queue=%v want=%v", queued, expected)
	}
	for id := range expected {
		if !queued[id] {
			t.Fatalf("queue missing %s", id)
		}
	}
}

func TestAttentionEligibilityMatchesQueue(t *testing.T) {
	for _, split := range []bool{false, true} {
		for _, scenario := range []string{"default", "server-admin", "named", "group", "fallback", "inactive-primary", "self-primary", "sa-exclusion", "sa-opt-in", "named-auditor", "gateway-owner"} {
			t.Run(fmt.Sprintf("split=%v/%s", split, scenario), func(t *testing.T) {
				f := newAttentionFixture(t, split)
				in := f.rule.RuleInput
				switch scenario {
				case "server-admin":
					execFixture(t, f.db, `UPDATE team_members SET role='admin' WHERE team_id=$1 AND user_id=$2`, f.team, f.reviewer.UserID)
				case "named":
					in.Approvers = []Selector{{Kind: "user", UserID: &f.outsider.UserID}}
				case "group":
					group := "Exact:Reviewers"
					execFixture(t, f.db, `UPDATE users SET groups=ARRAY[$2::text] WHERE id=$1`, f.outsider.UserID, group)
					execFixture(t, f.db, `UPDATE users SET groups=ARRAY['exact:reviewers'] WHERE id=$1`, f.auditor.UserID)
					in.Approvers = []Selector{{Kind: "group", GroupName: &group}}
				case "inactive-primary":
					in.Approvers = []Selector{{Kind: "user", UserID: &f.reviewer.UserID}}
				case "fallback":
					group := "empty-primary"
					in.Approvers = []Selector{{Kind: "group", GroupName: &group}}
				case "self-primary":
					in.Approvers = []Selector{{Kind: "user", UserID: &f.requester.UserID}}
				case "sa-exclusion", "sa-opt-in":
					f.input.Binding.RequesterKind, f.input.Binding.RequesterID, f.input.Binding.RequesterTeamID = "service_account", f.sa, &f.saTeam
					in.Approvers = []Selector{{Kind: "user", UserID: &f.saOwner.UserID}}
					in.AllowServiceAccountAdmins = scenario == "sa-opt-in"
					// Even platform admins from the SA's owner team are excluded from
					// fallback unless the rule explicitly opts in.
					execFixture(t, f.db, `UPDATE users SET platform_role='platform_admin' WHERE id=$1`, f.saOwner.UserID)
				case "named-auditor":
					in.Approvers = []Selector{{Kind: "user", UserID: &f.auditor.UserID}}
				case "gateway-owner":
					// A gateway team owner is not a server reviewer or implicit recipient.
					execFixture(t, f.db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'owner'),($1,$3,'member')`, f.team, f.outsider.UserID, f.requester.UserID)
					execFixture(t, f.db, `UPDATE gateways SET owner_kind='team',team_id=$2 WHERE id=$1`, f.gateway, f.team)
					// Explicit server policy overrides default server/gateway owners.
					in.Approvers = []Selector{{Kind: "user", UserID: &f.reviewer.UserID}}
				}
				var err error
				f.rule, err = f.s.ReplaceRule(context.Background(), f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "inactive-primary" {
					execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.reviewer.UserID)
				}
				f.input.Binding.Epoch = mustEpoch(t, f.s)
				p := beginFixture(t, f)
				winner := f.reviewer.UserID
				switch scenario {
				case "named", "group":
					winner = f.outsider.UserID
				case "fallback", "inactive-primary", "self-primary", "sa-exclusion":
					winner = f.admin.UserID
				case "sa-opt-in":
					winner = f.saOwner.UserID
				case "named-auditor":
					winner = f.auditor.UserID
				}
				for _, actor := range []authz.Actor{f.requester, f.reviewer, f.outsider, f.admin, f.auditor, f.saOwner} {
					if scenario == "inactive-primary" && actor.UserID == f.reviewer.UserID {
						continue
					}
					if actor.UserID == winner {
						assertAttentionQueue(t, f, actor, p.Receipt.ID)
					} else {
						assertAttentionQueue(t, f, actor)
					}
				}
			})
		}
	}
}

func TestAttentionExactTotalHistoryTeamExpiryAndEpoch(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprintf("split=%v", split), func(t *testing.T) {
			f := newAttentionFixture(t, split)
			f.input.CredentialExpiresAt = time.Now().Add(time.Second)
			p := beginFixture(t, f)
			// Credential expiry is a dispatch boundary, not review-request expiry.
			f.s.SetClock(func() time.Time { return time.Now().Add(2 * time.Second) })
			seedQueue(t, f, p.Receipt.ID, 245, f.requester.UserID, "user", "pending")
			seedQueue(t, f, p.Receipt.ID, 1200, f.requester.UserID, "user", "cancelled")
			tr := &queueTrace{}
			traceQueue(t, f, false, tr)
			items, total, err := f.s.Attention(context.Background(), f.reviewer, &f.team, 20)
			if err != nil || len(items) != 20 || total != 246 {
				t.Fatalf("bounded exact total: %d %d %v", len(items), total, err)
			}
			for i := 1; i < len(items); i++ {
				if items[i].CreatedAt.Before(items[i-1].CreatedAt) {
					t.Fatal("not oldest first")
				}
			}
			if tr.unboundedDeadline || len(tr.sql) != 5 {
				t.Fatalf("not constant bounded snapshot reads: %d deadline=%v", len(tr.sql), tr.unboundedDeadline)
			}
			if !strings.Contains(strings.ToLower(tr.sql[0]), "repeatable read read only") {
				t.Fatal("not a read-only RR snapshot")
			}
			for _, sql := range tr.sql {
				lower := strings.ToLower(sql)
				for _, forbidden := range []string{"preview", "cipher", "args_digest", "binding_digest", "for update", "for key share", "omp_lock_approval_context"} {
					if strings.Contains(lower, forbidden) {
						t.Fatalf("private projection or authority lock %q: %s", forbidden, sql)
					}
				}
			}
			for _, teamID := range []uuid.UUID{f.saTeam, uuid.Nil} {
				items, total, err = f.s.Attention(context.Background(), f.reviewer, &teamID, 20)
				if err != nil || len(items) != 0 || total != 0 {
					t.Fatalf("wrong server team: %d %d %v", len(items), total, err)
				}
			}
			// Request expiry is independent of context; no mutation is required.
			f.s.SetClock(func() time.Time { return p.Receipt.ExpiresAt.Add(time.Hour) })
			assertAttentionQueue(t, f, f.reviewer)
			f.s.SetClock(time.Now)
			// Semantic authority changes invalidate the whole old epoch immediately.
			execFixture(t, f.db, `UPDATE users SET groups=ARRAY['new-context'] WHERE id=$1`, f.outsider.UserID)
			assertAttentionQueue(t, f, f.reviewer)
		})
	}
}

func TestAttentionHumanAndFreshRole(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprintf("split=%v", split), func(t *testing.T) {
			f := newAttentionFixture(t, split)
			p := beginFixture(t, f)
			for _, kind := range []string{authz.KindAutomationToken, "service_account"} {
				a := f.reviewer
				a.Kind = kind
				items, total, err := f.s.Attention(context.Background(), a, nil, 20)
				if err != nil || len(items) != 0 || total != 0 {
					t.Fatalf("machine attention: %v %d %v", items, total, err)
				}
			}
			// A forged cached admin role cannot gain fallback or bypass primaries.
			a := f.outsider
			a.PlatformRole = authz.PlatformAdmin
			assertAttentionQueue(t, f, a)
			assertAttentionQueue(t, f, f.reviewer, p.Receipt.ID)
			execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.reviewer.UserID)
			_, _, err := f.s.Attention(context.Background(), f.reviewer, nil, 20)
			requireCode(t, err, "forbidden")
			_, _, err = f.s.Attention(context.Background(), authz.Actor{}, nil, 20)
			requireCode(t, err, "forbidden")
			_, _, err = f.s.Attention(context.Background(), f.outsider, nil, 0)
			requireCode(t, err, "invalid_pagination")
		})
	}
}
