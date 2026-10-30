package ompcli

import (
	"fmt"
	"testing"
	"time"
)

func TestGrantDeadlineWritesDoNotAssumeSynchronizedClocks(t *testing.T) {
	serverNow := time.Now().UTC()
	deadline := serverNow.Add(90 * 24 * time.Hour)
	previous := clock
	defer func() { clock = previous }()
	for _, offset := range []time.Duration{-30 * 24 * time.Hour, 0, 30 * 24 * time.Hour} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			clock = func() time.Time { return serverNow.Add(offset) }
			if days, err := daysFor(&deadline, true); err == nil || days != nil {
				t.Fatalf("absolute deadline converted using client clock %v: days=%v err=%v", offset, days, err)
			}
			f, h := platformHarness(t)
			mustRefuse(t, f, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com}\n  - {group: new, expiresAt: '"+deadline.Format(time.RFC3339Nano)+"'}\n"), "clock skew")
		})
	}
}
