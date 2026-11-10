package approvals

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
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

// A context check that reads more than the epoch runs in a transaction, and
// time spent committing it counts against the credential.
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
	noop := func(context.Context, *dbgen.Queries) error { return nil }
	if err := f.s.readContext(context.Background(), f.input.Binding.Epoch, expires, noop); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("elapsed commit returned context permit: %v", err)
	}
}

// CheckContext reads only the epoch, in one statement with no transaction to
// commit. Its single credential check comes after that statement returns, so
// a wait for a connection or the read itself counts against the credential;
// a changed epoch is still reported first.
func TestContextGuardChecksCredentialAfterEpochRead(t *testing.T) {
	f := newServiceFixture(t)
	ctx, epoch := context.Background(), f.input.Binding.Epoch
	initial := time.Now()
	expires := initial.Add(time.Minute)
	if err := f.s.CheckContext(ctx, epoch, expires); err != nil {
		t.Fatalf("live credential at the current epoch: %v", err)
	}
	var reads atomic.Int32
	f.s.SetClock(func() time.Time { reads.Add(1); return expires })
	if err := f.s.CheckContext(ctx, epoch, expires); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("credential at its deadline returned context permit: %v", err)
	}
	if reads.Load() != 1 {
		t.Fatalf("clock read %d times, want once after the epoch read", reads.Load())
	}
	if err := f.s.CheckContext(ctx, epoch+1, expires); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("changed epoch with an expired credential = %v, want ErrContextChanged", err)
	}
}
