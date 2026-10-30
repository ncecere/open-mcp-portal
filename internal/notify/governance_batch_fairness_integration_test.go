package notify

import (
	"fmt"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func TestGovernanceReturnToReviewDoesNotStarveBehindSelfPublishTeams(t *testing.T) {
	g := newGovLoop(t)
	g.run(`UPDATE platform_settings SET governance_return_overdue=true WHERE id=1`)
	g.run(`UPDATE teams SET publish_policy_override='self_publish' WHERE id=$1`, g.tm)
	g.run(`UPDATE teams SET publish_policy_override='approval_required' WHERE id=$1`, g.u)
	for i := 0; i < registry.GovernanceBatch+1; i++ {
		id := g.overdue(g.tm, fmt.Sprintf("self-first-%d", i))
		g.run(`UPDATE mcp_servers SET review_due_at=$2 WHERE id=$1`, id, g.clock.now().Add(-2*time.Hour))
	}
	target := g.overdue(g.u, "approval-after-self-publish")
	first := g.govern(g.r1)
	if first.ReviewDueTold != registry.GovernanceBatch || first.ReturnedToReview != 0 {
		t.Fatalf("first batch: %+v", first)
	}
	second := g.govern(g.r2)
	if second.ReviewDueTold != 2 || second.ReturnedToReview != 1 {
		t.Fatalf("already-notified self-publish rows starved later servers: %+v", second)
	}
	if got := g.exec(`SELECT publish_state FROM mcp_servers WHERE id=$1`, target); got != "pending" {
		t.Fatalf("later approval-required server stayed %s", got)
	}
	if got := g.exec(`SELECT count(*)::text FROM mcp_servers WHERE team_id=$1 AND publish_state='published'`, g.tm); got != fmt.Sprint(registry.GovernanceBatch+1) {
		t.Fatalf("self-publish servers changed state: %s", got)
	}
	if third := g.govern(g.r1); third.ReviewDueTold != 0 || third.ReturnedToReview != 0 {
		t.Fatalf("processed rows did not leave the candidate batch: %+v", third)
	}
}
