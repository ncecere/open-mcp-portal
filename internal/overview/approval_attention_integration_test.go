package overview

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

func TestApprovalAttentionRealServiceOverview(t *testing.T) {
	for _, split := range []bool{false, true} {
		for _, targetKind := range []string{"server", "gateway"} {
			t.Run(fmt.Sprintf("split=%v/%s", split, targetKind), func(t *testing.T) {
				t.Setenv("OMP_TEST_SPLIT_ROLES", fmt.Sprint(map[bool]int{false: 0, true: 1}[split]))
				f := newFx(t)
				ctx := context.Background()
				requester, reviewer, auditor := f.user(authz.PlatformNone), f.user(authz.PlatformNone), f.user(authz.PlatformAuditor)
				secondRequester := f.user(authz.PlatformNone)
				manager := f.user(authz.PlatformAdmin)
				team, other := f.team("approval-team"), f.team("other-team")
				f.run(`INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'member'),($1,$3,'member'),($4,$2,'member'),($1,$5,'owner')`, team, reviewer, auditor, other, manager)
				server := f.server(team, "published", true)
				cap, gateway := uuid.New(), uuid.New()
				f.run(`INSERT INTO mcp_capabilities(id,server_id,kind,name,definition,fingerprint,approved_fingerprint,tool_class) VALUES ($1,$2,'tool','delete','{}',repeat('a',64),repeat('a',64),'destructive')`, cap, server)
				f.run(`INSERT INTO gateways(id,slug,name,owner_kind,enabled) VALUES ($1,'approval-gateway','Approval gateway','platform',true)`, gateway)
				f.run(`INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES ($1,$2)`, gateway, cap)
				f.run(`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES ($1,'user',$2),($1,'user',$3)`, gateway, requester, secondRequester)
				box, err := secrets.New([]byte(strings.Repeat("k", 32)))
				if err != nil {
					t.Fatal(err)
				}
				svc, err := approvals.New(f.pool, box, nil, "https://portal.test")
				if err != nil {
					t.Fatal(err)
				}
				a := authz.Actor{UserID: reviewer, PlatformRole: authz.PlatformNone}
				ruleRef, targetID := team.String(), server
				if targetKind == "gateway" {
					ruleRef, targetID = "", gateway
				}
				_, err = svc.CreateRule(ctx, authz.Actor{UserID: manager, PlatformRole: authz.PlatformAdmin}, ruleRef, approvals.RuleInput{Name: "Real approval", TargetKind: targetKind, TargetID: targetID, Classes: []string{"destructive"}, Enabled: true,
					Approvers: []approvals.Selector{{Kind: "user", UserID: &reviewer}, {Kind: "user", UserID: &auditor}}})
				if err != nil {
					t.Fatal(err)
				}
				epoch, err := svc.Epoch(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var exposed string
				if err = f.pool.QueryRow(ctx, `SELECT slug||'__delete' FROM mcp_servers WHERE id=$1`, server).Scan(&exposed); err != nil {
					t.Fatal(err)
				}
				class := "destructive"
				ids := map[string]bool{}
				for i := 0; i < PerKind+3; i++ {
					p, err := svc.Begin(ctx, approvals.BeginInput{Binding: approvals.Binding{Epoch: epoch, RequesterKind: "user", RequesterID: requester, GatewayID: gateway, ServerID: server, CapabilityID: cap, ExposedName: exposed, ToolClass: &class, CapabilityFingerprint: strings.Repeat("a", 64), ServerOrigin: "https://mcp.example.com"}, Arguments: json.RawMessage(fmt.Sprintf(`{"id":%d}`, i)), CredentialExpiresAt: time.Now().Add(time.Hour)})
					// Begin's per-requester quota is 20. Use a different real requester for
					// the final requests rather than forging attention-only metadata.
					if err != nil {
						t.Fatal(err)
					}
					ids[p.Receipt.ID.String()] = true
					if i == PerKind-1 {
						requester = secondRequester
					}
				}
				f.svc.Approvals = svc.Attention
				card, err := f.svc.Team(ctx, a, team.String())
				if err != nil {
					t.Fatal(err)
				}
				items := find(card.Attention, ApprovalPending)
				if card.Totals[ApprovalPending] != PerKind+3 || len(items) != PerKind || !card.Truncated {
					t.Fatalf("team exact total: %+v", card)
				}
				for _, it := range items {
					if it.Summary != "Tool call needs your approval" || it.Detail != exposed || it.At == nil || it.Link == nil || it.Link.Type != LinkApproval || !ids[it.Link.ID] || it.Subject != nil || it.Count != nil {
						t.Fatalf("unsafe approval item: %+v", it)
					}
				}
				platform, err := f.svc.Admin(ctx, authz.Actor{UserID: auditor, PlatformRole: authz.PlatformAuditor})
				if err != nil || len(find(platform.Attention, ApprovalPending)) != PerKind || platform.Totals[ApprovalPending] != PerKind+3 || !platform.Truncated {
					t.Fatalf("eligible auditor: %+v %v", platform, err)
				}
				unrelated, err := f.svc.Team(ctx, a, other.String())
				if err != nil || len(find(unrelated.Attention, ApprovalPending)) != 0 || unrelated.Totals[ApprovalPending] != 0 {
					t.Fatalf("server team filter: %+v %v", unrelated, err)
				}
				token := authz.Actor{Kind: authz.KindAutomationToken, UserID: auditor, PlatformRole: authz.PlatformAdmin}
				platform, err = f.svc.Admin(ctx, token)
				if err != nil || len(find(platform.Attention, ApprovalPending)) != 0 || platform.Totals[ApprovalPending] != 0 {
					t.Fatalf("token scope widened: %+v %v", platform, err)
				}
				teamToken := a
				teamToken.Kind = authz.KindAutomationToken
				card, err = f.svc.Team(ctx, teamToken, team.String())
				if err != nil || len(find(card.Attention, ApprovalPending)) != 0 || card.Totals[ApprovalPending] != 0 {
					t.Fatalf("team token scope widened: %+v %v", card, err)
				}
				f.svc.Approvals = nil
				card, err = f.svc.Team(ctx, a, team.String())
				if err != nil || len(find(card.Attention, ApprovalPending)) != 0 {
					t.Fatalf("legacy composition: %+v %v", card, err)
				}
			})
		}
	}
}
