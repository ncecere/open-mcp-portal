package registry

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

type fixedPolicy struct{ p *netpolicy.Policy }

func (f fixedPolicy) Current(context.Context) *netpolicy.Policy { return f.p }

// The default of Send identity token (decision 64): off only for a server with
// no authentication on a public (or unresolvable) host.
func TestDefaultSendIdentity(t *testing.T) {
	s := &Service{client: &upstream.Client{
		Networks: fixedPolicy{netpolicy.New([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "mcp.corp.example.com"}})},
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "mcp.deepwiki.example.com":
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			case "intranet.example.com":
				return []netip.Addr{netip.MustParseAddr("10.20.0.5")}, nil
			}
			return nil, errors.New("no such host")
		},
	}}
	for _, tc := range []struct {
		name, mode, url string
		basis           string
		want            bool
	}{
		{"public, no auth", AuthNone, "https://mcp.deepwiki.example.com/mcp", upstream.BasisPublicHost, false},
		{"public literal, no auth", AuthNone, "https://93.184.216.34/mcp", upstream.BasisPublicHost, false},
		{"allow-listed host, no auth", AuthNone, "https://mcp.corp.example.com/mcp", upstream.BasisInternalHost, true},
		{"private address by name, no auth", AuthNone, "https://intranet.example.com/mcp", upstream.BasisInternalHost, true},
		{"private literal, no auth", AuthNone, "https://10.1.2.3/mcp", upstream.BasisInternalHost, true},
		{"unresolvable, no auth", AuthNone, "https://nowhere.example.com/mcp", upstream.BasisUnresolvedHost, false},
		{"public, static header", AuthStaticHeader, "https://mcp.deepwiki.example.com/mcp", "", true},
		{"public, oauth", AuthOAuth, "https://mcp.deepwiki.example.com/mcp", "", true},
		{"unresolvable, oauth", AuthOAuth, "https://nowhere.example.com/mcp", "", true},
	} {
		got := s.defaultSendIdentity(context.Background(), tc.mode, tc.url)
		if got.SendIdentity != tc.want || got.Basis != tc.basis {
			t.Errorf("%s: %+v, want basis %q and sendIdentity %v", tc.name, got, tc.basis, tc.want)
		}
	}
}
