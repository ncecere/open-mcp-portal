package doctor

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/config"
)

func tracingCheck(cfg config.Config, mode string) (Check, bool) {
	r := &runner{cfg: cfg, opts: Options{Mode: mode}}
	r.tracing()
	if len(r.checks) == 0 {
		return Check{}, false
	}
	return r.checks[0], true
}

// Doctor says tracing is off (info), or names the collector's host and the
// sampler, and never its path, credentials or export headers.
func TestDoctorReportsTracing(t *testing.T) {
	cfg := config.Defaults()
	if c, ok := tracingCheck(cfg, "serve"); !ok || c.Status != Info || !strings.Contains(c.Detail, "off") {
		t.Errorf("off: %+v", c)
	}
	if _, ok := tracingCheck(cfg, "migrate"); ok {
		t.Error("reported for migrate")
	}
	cfg.Tracing.Endpoint = "https://otel.example.com:4318/private/path"
	cfg.Tracing.Headers = "authorization=Bearer sentinel-collector-secret"
	c, _ := tracingCheck(cfg, "serve")
	if c.Status != OK || !strings.Contains(c.Detail, "otel.example.com:4318") || !strings.Contains(c.Detail, "parentbased_traceidratio (0.1)") {
		t.Errorf("on: %+v", c)
	}
	if strings.Contains(c.Detail, "private") || strings.Contains(c.Detail, "sentinel") || strings.Contains(c.Detail, "Bearer") {
		t.Errorf("the report leaks the path or the headers: %q", c.Detail)
	}
	cfg.Tracing.Sampler = "always_on"
	if c, _ := tracingCheck(cfg, "serve"); !strings.Contains(c.Detail, "every request is traced") {
		t.Errorf("always_on: %q", c.Detail)
	}
}
