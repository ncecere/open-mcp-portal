package store

import "time"

// touchEvery is how often a credential's last_used_at is written. The Touch*
// statements enforce it against the database clock; TouchDue saves the round
// trip when the row just read already shows a use within it.
const touchEvery = time.Minute

// TouchDue reports whether a last_used_at read with its row is old enough for
// the Touch statement to write. A clock that differs from the database's only
// moves the next write by that difference.
func TouchDue(lastUsed *time.Time) bool {
	return lastUsed == nil || time.Since(*lastUsed) >= touchEvery
}
