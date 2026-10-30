package httpapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/mcpgw"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
)

// The quota write has finished and released its connection, but dispatch has
// not started. Advancing through the already-frozen sunset must refuse even
// without a policy write (and therefore without an authority epoch change).
type sunsetAdmissionBarrier struct {
	ratelimit.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *sunsetAdmissionBarrier) Hit(ctx context.Context, keys []string) ([]int64, time.Duration, error) {
	counts, reset, err := b.Store.Hit(ctx, keys)
	if err == nil && len(keys) == 1 && strings.HasPrefix(keys[0], "v:") {
		b.once.Do(func() {
			close(b.entered)
			select {
			case <-b.release:
			case <-ctx.Done():
			}
		})
	}
	return counts, reset, err
}

func TestGovernanceSunsetDuringAdmissionNeverTransports(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, method := range []string{"tools/call", "prompts/get", "resources/read"} {
			name := "legacy/" + method
			if modern {
				name = "modern/" + method
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				barrier := &sunsetAdmissionBarrier{entered: make(chan struct{}), release: make(chan struct{})}
				var release sync.Once
				unblock := func() { release.Do(func() { close(barrier.release) }) }
				t.Cleanup(unblock)
				e := newRuntimeEnvHook(t, nil, func(d *httpapi.Deps) {
					h := d.MCP.(*mcpgw.Handler)
					barrier.Store = h.RateStore
					h.RateStore = barrier
				})
				params := map[string]any{"name": "status__whoami"}
				switch method {
				case "prompts/get":
					e.mustSetCaps(e.owner, e.supportTeamPath, sel(e.capID(e.owner, e.server, "prompt", "incident_summary")))
					params = map[string]any{"name": "status__incident_summary", "arguments": map[string]any{"service": "vpn"}}
				case "resources/read":
					e.mustSetCaps(e.owner, e.supportTeamPath, sel(e.capID(e.owner, e.server, "resource", "status://services")))
					params = map[string]any{"uri": "omp://status/status://services"}
				}
				sunset := time.Now().UTC().Add(10 * time.Second).Truncate(time.Millisecond)
				e.patchServer(e.owner, e.server, map[string]any{"rateLimitPerMinute": 100,
					"governance": map[string]any{"lifecycle": "deprecated", "sunsetAt": sunset.Format(time.RFC3339Nano)}})
				before := len(e.fake.HTTPRequests())
				done := make(chan map[string]any, 1)
				go func() {
					var out map[string]any
					if modern {
						_, _, out = rawModern(t, e.app, "support", e.key.Secret, method, params, nil, nil)
					} else {
						_, _, out = rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, method, params), nil)
					}
					done <- out
				}()
				select {
				case <-barrier.entered:
					if !time.Now().Before(sunset) {
						t.Fatal("the intended admission barrier was reached after sunset")
					}
				case out := <-done:
					t.Fatalf("request completed before reaching its quota barrier: %v", out)
				case <-time.After(15 * time.Second):
					t.Fatal("request did not reach its quota barrier")
				}
				<-time.After(time.Until(sunset) + 100*time.Millisecond)
				unblock()
				select {
				case out := <-done:
					if out["error"] == nil || len(e.fake.HTTPRequests()) != before {
						t.Errorf("transported %s after frozen sunset: response=%v upstream requests=%d -> %d", method, out, before, len(e.fake.HTTPRequests()))
					}
				case <-time.After(15 * time.Second):
					t.Fatal("request did not finish after releasing admission")
				}
			})
		}
	}
}
