package mcpgw

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func TestAuthorityDeadlineFreezesCredentialAndSunsetForEveryExchange(t *testing.T) {
	for _, source := range []string{"credential", "sunset"} {
		for _, tool := range []bool{false, true} {
			t.Run(source+map[bool]string{false: "/protocol_prompt_resource_or_task", true: "/tool"}[tool], func(t *testing.T) {
				deadline := time.Now().Add(-time.Hour)
				rc := &request{}
				o := gateways.Offer{}
				if source == "credential" {
					rc.principal.expiresAt = &deadline
				} else {
					o.Server.SunsetAt = &deadline
				}
				calls := 0
				target := upstream.Target{BeforeTransport: func(context.Context, bool) error { calls++; return nil }}
				rc.guardAuthorityDeadline(o, &target)
				// Mutating the source cannot extend this attempt's frozen permit.
				deadline = time.Now().Add(time.Hour)
				if err := target.BeforeTransport(context.Background(), tool); !errors.Is(err, errGrantExpired) {
					t.Fatalf("expired %s snapshot widened: %v", source, err)
				}
				if calls != 0 {
					t.Fatal("expired authority reached later transport work")
				}
			})
		}
	}
}

func TestAuthorityDeadlineAfterCommitNeverRestoresSpend(t *testing.T) {
	base := time.Now()
	checks := 0
	attempt := &approvalAttempt{}
	guard := grantExpiryGuard(base.Add(time.Hour), func() time.Time { return base }, func(context.Context, time.Time) (bool, error) {
		checks++
		return checks == 1, nil
	}, func(context.Context, bool) error {
		attempt.spent.Store(true)
		return nil
	})
	if err := guard(context.Background(), true); !errors.Is(err, errGrantExpired) {
		t.Fatalf("missing post-commit deadline refusal: %v", err)
	}
	if !attempt.spent.Load() || checks != 2 {
		t.Fatalf("spend restored or post-commit check missing: spent=%v checks=%d", attempt.spent.Load(), checks)
	}
}
