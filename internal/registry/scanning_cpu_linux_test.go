package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func TestScanRefreshAddedCPU(t *testing.T) {
	s, exec := testService(t)
	ctx := context.Background()
	fake := testutil.NewFakeMCP(t)
	for _, name := range []string{"check_outage", "search_tickets", "create_ticket", "status://services", "status://services/{service}", "incident_summary"} {
		fake.Hide(name)
	}
	for i := range 500 {
		name := fmt.Sprintf("tool_%04d", i)
		// Match the existing fake's added tool schema and canonical definition.
		raw, _ := json.Marshal(map[string]any{"name": name, "description": "", "inputSchema": map[string]string{"type": "object"}})
		fake.AddTool(name)
		fake.SetDescription(name, strings.Repeat("ordinary prose ", 140)[:2048-len(raw)])
	}
	fake.SetPageSize(50)
	team := exec(`INSERT INTO teams(slug,name)VALUES('cpu','CPU')RETURNING id::text`)
	id := uuid.MustParse(exec(`INSERT INTO mcp_servers(team_id,slug,name,url,timeout_seconds)VALUES($1,'cpu','CPU',$2,120)RETURNING id::text`, team, fake.URL()))
	sv, err := s.q.GetMCPServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cpu := func() time.Duration {
		var r syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
			t.Fatal(err)
		}
		return time.Duration(r.Utime.Nano() + r.Stime.Nano())
	}
	refresh := func() time.Duration {
		t.Helper()
		start := cpu()
		result, fail, err := s.refresh(ctx, authz.Actor{}, sv)
		elapsed := cpu() - start
		if err != nil || fail != nil {
			t.Fatalf("%v %+v", err, fail)
		}
		if result.Listed != 500 {
			t.Fatal(result.Listed)
		}
		for _, c := range result.Capabilities {
			raw, err := upstream.Canonical(c.Capability.Definition)
			if err != nil || len(raw) != 2048 {
				t.Fatalf("definition size=%d err=%v", len(raw), err)
			}
		}
		return elapsed
	}
	exec(`UPDATE platform_settings SET definition_scan_mode='off' RETURNING id::text`)
	refresh() // Discovery/setup is outside the steady-state comparison.
	off := refresh()
	exec(`UPDATE platform_settings SET definition_scan_mode='shadow' RETURNING id::text`)
	shadow := refresh()
	added := shadow - off
	// At least 2x headroom over 1.51s measured under race instrumentation.
	const threshold = 4 * time.Second
	t.Logf("real 500 x 2048 refresh CPU off=%s shadow=%s added=%s bound=%s (includes in-process fake upstream)", off, shadow, added, threshold)
	if added > threshold {
		t.Fatalf("added refresh CPU %s > %s", added, threshold)
	}
}
