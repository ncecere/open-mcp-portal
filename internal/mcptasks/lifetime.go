package mcptasks

import "time"

const (
	DefaultMaxTTL  = 24 * time.Hour
	DefaultMaxOpen = 100
	MinMaxTTL      = time.Minute
	MaxMaxTTL      = 24 * time.Hour
	MinMaxOpen     = 1
	MaxMaxOpen     = 1000

	MinPollMillis     = int64(1000)
	DefaultPollMillis = int64(5000)
	MaxPollMillis     = int64(60_000)
	maxWireMillis     = int64(1<<53 - 1)
	millisPerDay      = int64(86_400_000)
)

// ValidateLimits is configuration validation, not authorization. The serving
// integration must fail invalid startup settings, never turn them into unlimited.
func ValidateLimits(maxTTL time.Duration, maxOpen int) error {
	if maxTTL < MinMaxTTL || maxTTL > MaxMaxTTL || maxOpen < MinMaxOpen || maxOpen > MaxMaxOpen {
		return ErrUnavailable
	}
	return nil
}

// Deadline computes a monotonically non-increasing local deadline. now MUST be
// authoritative database time; current is the already-persisted local deadline
// (initially portal creation + configured maximum). A later upstream TTL/null
// cannot resurrect an expired handle or extend a previously shortened deadline.
// No cleanup is needed for expiry to deny access.
func Deadline(now, current, upstreamCreated time.Time, ttlMillis *int64) (time.Time, error) {
	if now.IsZero() || current.IsZero() || upstreamCreated.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	if !now.Before(current) {
		return time.Time{}, ErrNotFound
	}
	// The original local ceiling is bounded independently, but an implausible
	// future upstream creation time must not be trusted as additional lifetime.
	if upstreamCreated.After(now.Add(5 * time.Minute)) {
		return time.Time{}, ErrUnavailable
	}
	if ttlMillis != nil {
		ms := *ttlMillis
		if ms < 0 || ms > maxWireMillis {
			return time.Time{}, ErrUnavailable
		}
		// Multiplying a wire-safe integer by time.Millisecond can overflow a
		// time.Duration. Split into UTC days/remainder: at most 104,249,991
		// days, fitting even a 32-bit int, and a sub-day bounded duration.
		upstreamExpires := upstreamCreated.UTC().AddDate(0, 0, int(ms/millisPerDay)).Add(time.Duration(ms%millisPerDay) * time.Millisecond)
		if upstreamExpires.Before(current) {
			current = upstreamExpires
		}
	}
	if !now.Before(current) {
		return time.Time{}, ErrNotFound
	}
	return current.UTC(), nil
}

// PollInterval bounds the advertised hint without multiplying an untrusted
// wire integer. An omitted hint uses the default; zero is clamped to the floor.
func PollInterval(millis *int64) (int64, error) {
	if millis == nil {
		return DefaultPollMillis, nil
	}
	v := *millis
	if v < 0 || v > maxWireMillis {
		return 0, ErrUnavailable
	}
	return min(max(v, MinPollMillis), MaxPollMillis), nil
}
