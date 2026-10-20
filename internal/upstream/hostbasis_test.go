package upstream

import (
	"context"
	"testing"
)

// HostBasis says why "Send identity token" defaults on or off (decision 64):
// public hosts and names that cannot be resolved are not the company's own;
// allow-listed and private hosts are.
func TestHostBasis(t *testing.T) {
	c := &Client{Networks: staticPolicy{testPolicy()}, Lookup: fakeResolver(map[string][]string{
		"mcp.corp.example.com": {"192.168.7.7"},
		"build.example.com":    {"10.20.3.4"},
		"mixed.example.com":    {"8.8.8.8", "10.20.3.4"},
		"public.example.com":   {"8.8.8.8"},
		"deepwiki.example.com": {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
	})}
	for _, tc := range []struct {
		url, want string
	}{
		{"https://public.example.com/mcp", BasisPublicHost},
		{"https://deepwiki.example.com/mcp", BasisPublicHost},
		{"https://8.8.8.8/mcp", BasisPublicHost},
		{"https://[2606:2800:220:1:248:1893:25c8:1946]/mcp", BasisPublicHost},
		// Named by an allow-list entry: internal, without a lookup.
		{"http://mcp.corp.example.com/mcp", BasisInternalHost},
		{"https://anything.svc.cluster.local/mcp", BasisInternalHost},
		// Private addresses, literal or resolved.
		{"https://10.20.3.4/mcp", BasisInternalHost},
		{"https://192.168.0.9/mcp", BasisInternalHost},
		{"https://build.example.com/mcp", BasisInternalHost},
		// One private address among the answers is enough to call it internal.
		{"https://mixed.example.com/mcp", BasisInternalHost},
		// Nothing shows these are internal: treated as public.
		{"https://nowhere.example.com/mcp", BasisUnresolvedHost},
		{"not a url", BasisUnresolvedHost},
		{"", BasisUnresolvedHost},
	} {
		if got := c.HostBasis(context.Background(), tc.url); got != tc.want {
			t.Errorf("HostBasis(%q) = %s, want %s", tc.url, got, tc.want)
		}
	}
	// No allow-list at all (nil policy): only addresses decide.
	bare := &Client{Networks: staticPolicy{nil}, Lookup: fakeResolver(map[string][]string{"mcp.corp.example.com": {"8.8.8.8"}})}
	if got := bare.HostBasis(context.Background(), "https://mcp.corp.example.com/mcp"); got != BasisPublicHost {
		t.Errorf("without an allow-list = %s", got)
	}
}
