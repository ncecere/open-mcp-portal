package notify

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

func TestWebhookOriginValidation(t *testing.T) {
	c := NewWebhookClient(nil, nil)
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	for _, raw := range []string{"https://receiver.example/" + strings.Repeat("x", 700) + "?secret=sentinel", "https://receiver.example/?q=ok"} {
		if err := CheckWebhookURL(context.Background(), c, raw, 2048, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"https://user:sentinel@receiver.example/", "https://receiver.example/#sentinel", "http://receiver.example/?sentinel", "https://127.0.0.1/?sentinel", "https://[::ffff:10.1.2.3]/?sentinel", "https://receiver.example/" + strings.Repeat("x", 2048)} {
		err := CheckWebhookURL(context.Background(), c, raw, 2048, true)
		if err == nil {
			t.Fatalf("accepted forbidden shape")
		}
		if strings.Contains(err.Error(), "sentinel") {
			t.Fatal("URL leaked")
		}
	}
	c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.1.2.3")}, nil
	}
	if CheckWebhookURL(context.Background(), c, "https://receiver.example", 2048, true) == nil {
		t.Fatal("mixed answers accepted")
	}
	c = NewWebhookClient([]netpolicy.Entry{{Kind: netpolicy.KindHost, Value: "receiver.example", AllowHTTP: true}}, nil)
	if err := CheckWebhookURL(context.Background(), c, "http://receiver.example/?query=ok", 2048, false); err != nil {
		t.Fatal(err)
	}
}
