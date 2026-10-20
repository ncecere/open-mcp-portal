package doctor

import (
	"net/netip"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/config"
)

func proxyCheck(cfg config.Config, mode string) (Check, bool) {
	r := &runner{cfg: cfg, opts: Options{Mode: mode}}
	r.proxies()
	for _, c := range r.checks {
		if c.Name == "trusted proxies" {
			return c, true
		}
	}
	return Check{}, false
}

// Doctor hints (info, never a failure) when APP_URL is https and
// TRUSTED_PROXIES is empty, and says nothing to a correctly configured
// install, a development one or another mode.
func TestDoctorTrustedProxiesHint(t *testing.T) {
	cfg := config.Defaults()
	cfg.AppURL = "https://mcp.example.com"
	if c, ok := proxyCheck(cfg, "serve"); !ok || c.Status != Info || c.Fix == "" {
		t.Errorf("https without TRUSTED_PROXIES: %+v %v", c, ok)
	}
	if _, ok := proxyCheck(cfg, "migrate"); ok {
		t.Error("hinted for migrate")
	}
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if _, ok := proxyCheck(cfg, "serve"); ok {
		t.Error("hinted although TRUSTED_PROXIES is set")
	}
	dev := config.Defaults()
	dev.AppURL = "http://localhost:8088"
	if _, ok := proxyCheck(dev, "serve"); ok {
		t.Error("hinted for a development install")
	}
}
