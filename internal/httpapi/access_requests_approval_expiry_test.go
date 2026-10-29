package httpapi_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestGatewayGrantExpiryCannotConsumeApprovalAtUnchangedEpoch(t *testing.T) {
	for _, kind := range []string{"user", "group", "team_service_account"} {
		t.Run(kind, func(t *testing.T) {
			var enabled atomic.Bool
			var observed atomic.Int64
			var e *approvalWire
			var expiredAt time.Time
			e = newApprovalWire(t, testutil.ProtocolLegacy, func(_ http.ResponseWriter, _ *http.Request, msg map[string]any) bool {
				if enabled.Load() && (msg["method"] == "initialize" || msg["method"] == "server/discover") {
					observed.Add(1)
					e.svc.SetClock(func() time.Time { return expiredAt })
				}
				return false
			})
			// Reuse the real governed tool/upstream, but require an explicit
			// platform grant instead of implicit team-gateway membership.
			sessionExec(t, e.app, `UPDATE gateways SET owner_kind='platform',team_id=NULL WHERE slug='approvals'`)
			key := e.key.Secret
			base := time.Now().UTC()
			deadline := base.Add(30 * time.Second)
			expiredAt = deadline.Add(time.Microsecond)
			switch kind {
			case "user":
				sessionExec(t, e.app, `INSERT INTO gateway_grants(gateway_id,subject_kind,user_id,expires_at) SELECT id,'user',$1,$2 FROM gateways WHERE slug='approvals'`, e.member.me.User.Id, deadline)
			case "group":
				sessionExec(t, e.app, `INSERT INTO gateway_grants(gateway_id,subject_kind,group_name,expires_at) SELECT id,'group','support',$1 FROM gateways WHERE slug='approvals'`, deadline)
			case "team_service_account":
				sa := createSA(t, e.owner, map[string]any{"name": "expiring-grant-worker"})
				key = createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "worker key"}).Secret
				sessionExec(t, e.app, `INSERT INTO gateway_grants(gateway_id,subject_kind,team_id,expires_at) SELECT g.id,'team',t.id,$1 FROM gateways g CROSS JOIN teams t WHERE g.slug='approvals' AND t.slug='tools'`, deadline)
			}
			e.svc.SetClock(func() time.Time { return base })
			e.call(t, true, key, approvalParams("grant deadline"), urlCaps)
			requests := approvalList(t, e.admin, "actionable")
			if kind != "team_service_account" {
				requests = approvalList(t, e.owner, "actionable")
			}
			if len(requests) != 1 {
				t.Fatalf("review queue: %+v", requests)
			}
			reviewer := e.owner
			if kind == "team_service_account" {
				reviewer = e.admin
			} // owner separation of duties
			r := approvalDetail(t, reviewer, requests[0].ID)
			approved := approvalDecide(t, reviewer, r, "approve")
			if approved.ValidUntil == nil || !approved.ValidUntil.After(expiredAt) {
				t.Fatal("approval itself would expire too")
			}
			before, err := e.svc.Epoch(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			enabled.Store(true)
			out := e.call(t, true, key, approvalParams("grant deadline"), urlCaps)
			after, err := e.svc.Epoch(context.Background())
			if err != nil || before != after || observed.Load() == 0 {
				t.Fatalf("unchanged epoch schedule not exercised: %d/%d negotiations=%d err=%v", before, after, observed.Load(), err)
			}
			if e.posts.Load() != 0 || rpcErrorCode(out) != -32010 {
				t.Fatalf("expired grant consumed/dispatched approval: posts=%d %v", e.posts.Load(), out)
			}
		})
	}
}
