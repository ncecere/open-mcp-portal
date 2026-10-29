package mcptasks

import (
	"errors"
	"testing"
	"time"
)

func TestTaskLifetimeNeverExtendsOrResurrects(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ceiling := now.Add(DefaultMaxTTL)
	short := int64(5 * 60_000)
	deadline, err := Deadline(now, ceiling, now, &short)
	if err != nil || !deadline.Equal(now.Add(5*time.Minute)) {
		t.Fatal("upstream expiry not capped", err)
	}
	long := int64(DefaultMaxTTL / time.Millisecond)
	for _, ttl := range []*int64{nil, &long} {
		next, err := Deadline(now.Add(time.Minute), deadline, now, ttl)
		if err != nil || !next.Equal(deadline) {
			t.Fatal("later TTL extended persisted local deadline", err)
		}
		if _, err := Deadline(deadline, deadline, now, ttl); !errors.Is(err, ErrNotFound) {
			t.Fatal("expired task revived without cleanup")
		}
	}
}

func TestTaskLifetimeWireIntegerDoesNotOverflowDuration(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ceiling := now.Add(DefaultMaxTTL)
	for _, ms := range []int64{maxWireMillis, maxWireMillis - 1, 1 << 48} {
		next, err := Deadline(now, ceiling, now.Add(-time.Hour), &ms)
		if err != nil || !next.Equal(ceiling) {
			t.Fatalf("large safe integer overflowed: %d %v", ms, err)
		}
	}
	for _, ms := range []int64{-1, maxWireMillis + 1, 1<<63 - 1} {
		if _, err := Deadline(now, ceiling, now, &ms); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid lifetime accepted")
		}
	}
	zero := int64(0)
	if _, err := Deadline(now, ceiling, now, &zero); !errors.Is(err, ErrNotFound) {
		t.Fatal("zero TTL at creation remained live")
	}
	if _, err := Deadline(now, ceiling, now.Add(6*time.Minute), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("implausible future upstream timestamp accepted")
	}
}

func TestTaskLifetimeUsesElapsedUTCNotCalendarDSTDays(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 3, 7, 12, 0, 0, 0, location)
	now := created.Add(10 * time.Hour)
	ttl := int64(24 * time.Hour / time.Millisecond)
	next, err := Deadline(now, now.Add(DefaultMaxTTL), created, &ttl)
	if err != nil || !next.Equal(created.Add(24*time.Hour)) {
		t.Fatal("TTL changed across spring DST", err)
	}
	if next.Equal(created.AddDate(0, 0, 1)) {
		t.Fatal("calendar-day arithmetic shortened absolute milliseconds")
	}
}

func TestTaskLimitsAndPollBoundsNeverBecomeUnlimited(t *testing.T) {
	for _, tc := range []struct {
		ttl  time.Duration
		open int
	}{{time.Minute, 1}, {DefaultMaxTTL, DefaultMaxOpen}, {MaxMaxTTL, MaxMaxOpen}} {
		if err := ValidateLimits(tc.ttl, tc.open); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		ttl  time.Duration
		open int
	}{{0, 100}, {time.Minute - time.Nanosecond, 100}, {MaxMaxTTL + time.Nanosecond, 100}, {DefaultMaxTTL, 0}, {DefaultMaxTTL, MaxMaxOpen + 1}} {
		if err := ValidateLimits(tc.ttl, tc.open); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid settings silently became unlimited")
		}
	}
	if got, err := PollInterval(nil); err != nil || got != DefaultPollMillis {
		t.Fatal("missing poll hint lost default")
	}
	for _, tc := range []struct{ value, want int64 }{{0, MinPollMillis}, {1, MinPollMillis}, {5000, 5000}, {maxWireMillis, MaxPollMillis}} {
		if got, err := PollInterval(&tc.value); err != nil || got != tc.want {
			t.Fatal("invalid bounded poll hint", got, err)
		}
	}
	for _, invalid := range []int64{-1, maxWireMillis + 1} {
		if _, err := PollInterval(&invalid); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid poll hint accepted")
		}
	}
}
