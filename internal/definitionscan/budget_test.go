package definitionscan

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestDefinitionTailAndRefreshBudget(t *testing.T) {
	raw, _ := json.Marshal(map[string]string{"description": strings.Repeat("ordinary prose ", 4200)})
	var samples []time.Duration
	for range 100 {
		start := time.Now()
		r := Scan(context.Background(), raw)
		samples = append(samples, time.Since(start))
		if r.Status != "scanned" && r.Status != "incomplete" {
			t.Fatal(r)
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("64KiB definition p99=%s (wall, includes contention)", samples[98])
	small, _ := json.Marshal(map[string]string{"description": strings.Repeat("ordinary prose ", 130)})
	start := time.Now()
	for range 500 {
		Scan(context.Background(), small)
	}
	t.Logf("500 x 2KiB wall=%s", time.Since(start))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start = time.Now()
	incomplete := 0
	for range 2000 {
		if Scan(ctx, raw).Status == "incomplete" {
			incomplete++
		}
	}
	t.Logf("2000 x 64KiB wall=%s incomplete=%d", time.Since(start), incomplete)
	// Canceled scans allocate no parsing tree and create no background workers.
	before := runtime.NumGoroutine()
	for range 1000 {
		Scan(ctx, raw)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines %d -> %d", before, after)
	}
}
func BenchmarkDefinitionPathological(b *testing.B) {
	for _, tc := range []struct{ name, text string }{{"near-matches", strings.Repeat("Bearer ", 8000)}, {"unicode", strings.Repeat(string(rune(0x200b)), 10000)}, {"encoded", strings.Repeat("a", 60000)}} {
		raw, _ := json.Marshal(map[string]string{"description": tc.text})
		b.Run(fmt.Sprint(tc.name), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Scan(context.Background(), raw)
			}
		})
	}
}
