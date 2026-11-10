package overview

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// collector gathers items and exact totals.
type collector struct {
	now       time.Time
	items     []Item
	totals    map[string]int64
	truncated bool
}

func newCollector(now time.Time) *collector { return &collector{now: now, totals: map[string]int64{}} }

// add records items of one kind with the kind's exact total (the number of
// servers, or the sum of counts): a kind with a total larger than its listed
// rows is truncated.
func (c *collector) add(kind string, total int64, listed int, items ...Item) {
	if total <= 0 {
		return
	}
	c.totals[kind] = total
	if int64(listed) < total {
		c.truncated = true
	}
	c.items = append(c.items, items...)
}

func (c *collector) sorted() []Item {
	rank := map[string]int{Critical: 0, Warning: 1, Info: 2}
	out := slices.Clone(c.items)
	slices.SortStableFunc(out, func(x, y Item) int {
		if d := rank[x.Severity] - rank[y.Severity]; d != 0 {
			return d
		}
		switch {
		case x.At != nil && y.At == nil:
			return -1
		case x.At == nil && y.At != nil:
			return 1
		case x.At != nil && y.At != nil && !x.At.Equal(*y.At):
			return x.At.Compare(*y.At)
		}
		return strings.Compare(sortName(x), sortName(y))
	})
	if out == nil {
		out = []Item{}
	}
	return out
}

func sortName(i Item) string {
	if i.Subject != nil {
		return strings.ToLower(i.Subject.Name)
	}
	if i.Team != nil {
		return strings.ToLower(i.Team.Name)
	}
	return i.Summary
}

func since(now, at time.Time) string {
	d := now.Sub(at)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", max(int(d.Minutes()), 1))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func expirySeverity(now, earliest time.Time) string {
	if earliest.Sub(now) <= ExpiryWarnWithin {
		return Warning
	}
	return Info
}

func i64(n int64) *int64 { return &n }

// realTime is t, or nil for the epoch the queries use for "none" (an
// aggregate over no rows).
func realTime(t time.Time) *time.Time {
	if t.Unix() <= 0 {
		return nil
	}
	return &t
}

func teamRef(id uuid.UUID, slug, name string) *TeamRef {
	return &TeamRef{ID: id, Slug: slug, Name: name}
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
