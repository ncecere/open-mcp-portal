package upstream

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

type failingCheckedPolicy struct{ err error }

func (p failingCheckedPolicy) Current(context.Context) *netpolicy.Policy {
	panic("must not fall back to unchecked policy")
}
func (p failingCheckedPolicy) CurrentChecked(context.Context) (*netpolicy.Policy, error) {
	return nil, p.err
}

func TestCheckedPolicyFailsClosedBeforeConnect(t *testing.T) {
	failure := errors.New("policy database failure")
	for _, dev := range []bool{false, true} {
		c := &Client{AllowPrivate: dev, Networks: failingCheckedPolicy{failure},
			Lookup: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			},
			Dial: func(context.Context, string, string) (net.Conn, error) {
				t.Error("connected after policy failure")
				return nil, errors.New("unexpected dial")
			},
		}
		if _, err := c.NormalizeURL(context.Background(), "https://public.example/token"); !errors.Is(err, failure) {
			t.Fatalf("normalize = %v", err)
		}
		if res := c.Check(context.Background(), "https://public.example/token"); res.Allowed || res.Reason != ReasonPolicyFailed {
			t.Fatalf("check = %+v", res)
		}
		if _, err := c.GuardedDial()(context.Background(), "tcp", "public.example:443"); !errors.Is(err, failure) {
			t.Fatalf("dial = %v", err)
		}
	}
}
