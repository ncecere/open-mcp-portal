package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLimiterWindows(t *testing.T) {
	l := New()
	now := time.Unix(960, 0) // on a minute
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a", 3, time.Minute); !ok {
			t.Fatalf("event %d refused", i+1)
		}
	}
	if ok, wait := l.Allow("a", 3, time.Minute); ok || wait != time.Minute {
		t.Fatalf("4th = %v %v", ok, wait)
	}
	if ok, _ := l.Allow("b", 3, time.Minute); !ok {
		t.Fatal("keys share a window")
	}
	now = now.Add(20 * time.Second)
	if ok, wait := l.Allow("a", 3, time.Minute); ok || wait != 40*time.Second {
		t.Fatalf("within the window = %v %v", ok, wait)
	}
	now = now.Add(40 * time.Second)
	if ok, _ := l.Allow("a", 3, time.Minute); !ok {
		t.Fatal("the window didn't reset")
	}
}

func TestHitSeveralBuckets(t *testing.T) {
	l := New()
	l.now = func() time.Time { return time.Unix(975, 0) }
	counts, reset, err := l.Hit(context.Background(), []string{"x", "y", "x"})
	if err != nil || reset != 45*time.Second {
		t.Fatal(err, reset)
	}
	if counts[0] != 1 || counts[1] != 1 || counts[2] != 2 {
		t.Fatalf("counts = %v", counts)
	}
}

func TestBucketHashesTheValue(t *testing.T) {
	b := Bucket("oauth:token", "203.0.113.9")
	if strings.Contains(b, "203.0.113.9") || !strings.HasPrefix(b, "oauth:token:") || len(b) != len("oauth:token:")+64 {
		t.Fatalf("bucket = %q", b)
	}
	if RetryAfter(0) != 1 || RetryAfter(1500*time.Millisecond) != 2 {
		t.Fatal("RetryAfter")
	}
}

// Reproduce #85 without a wall-clock wait: twenty allowed requests in the
// final instant of one window do not exhaust the next window's allowance.
func TestTwentyAllowsAcrossBoundary(t *testing.T) {
	now := time.Unix(1019, 999999999)
	l := NewWithClock(func() time.Time { return now })
	for range 20 {
		if ok, _ := l.Allow("person", 20, Window); !ok {
			t.Fatal("early refusal")
		}
	}
	if ok, _ := l.Allow("person", 20, Window); ok {
		t.Fatal("21st in same window allowed")
	}
	now = now.Add(time.Nanosecond)
	if ok, _ := l.Allow("person", 20, Window); !ok {
		t.Fatal("new window refused")
	}
}
