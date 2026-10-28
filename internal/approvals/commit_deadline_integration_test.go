package approvals

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsumeNeverPermitsDispatchAfterCommitDeadline(t *testing.T) {
	for _, kind := range []string{"credential", "approval"} {
		t.Run(kind, func(t *testing.T) {
			f := newServiceFixture(t)
			plan := approveFixture(t, f, beginFixture(t, f))
			initial := time.Now()
			deadline := *plan.Receipt.ValidUntil
			if kind == "credential" {
				plan.CredentialExpiresAt = initial.Add(time.Minute)
				deadline = plan.CredentialExpiresAt
			}
			var ticks atomic.Int32
			f.s.SetClock(func() time.Time {
				// The third read represents time elapsed finishing commit,
				// after authorization was spent but before any transport permit.
				if ticks.Add(1) >= 3 {
					return deadline
				}
				return initial
			})
			if err := f.s.Consume(context.Background(), plan); !errors.Is(err, ErrSpent) {
				t.Fatalf("elapsed commit returned a transport permit: %v", err)
			}
			if got := requestStatus(t, f, plan.Receipt.ID); got != Used {
				t.Fatalf("committed spend was restored: %s", got)
			}
		})
	}
}

func TestContextGuardChecksCredentialAfterCommit(t *testing.T) {
	f := newServiceFixture(t)
	initial := time.Now()
	expires := initial.Add(time.Minute)
	var ticks atomic.Int32
	f.s.SetClock(func() time.Time {
		if ticks.Add(1) >= 2 {
			return expires
		}
		return initial
	})
	if err := f.s.CheckContext(context.Background(), f.input.Binding.Epoch, expires); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("elapsed commit returned context permit: %v", err)
	}
}
