package upstream

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
)

// Host bases: how a server's host is classified for the default of "Send
// identity token" (docs/decisions.md, decision 64; docs/registry.md). The
// classification uses the same address policy as the rest of the registry
// (internal/netpolicy): a host is public when every address it is or resolves
// to is an allocated public unicast address.
const (
	// BasisPublicHost: a public address, and no internal allow-list entry
	// names the host.
	BasisPublicHost = "public_host"
	// BasisInternalHost: a host an internal allow-list entry names, or one
	// that is or resolves to a private (or, with the development allowance,
	// loopback) address: a server the company runs.
	BasisInternalHost = "internal_host"
	// BasisUnresolvedHost: a name that could not be resolved in time. It is
	// treated as public, because nothing shows it is internal.
	BasisUnresolvedHost = "unresolved_host"
)

// HostBasis classifies the host of a server URL that NormalizeURL accepted.
// It checks, in order: a literal address; a host entry of the internal
// allow-list (no lookup needed); then the addresses the name resolves to,
// looked up for at most CheckTimeout. It connects to nothing.
func (c *Client) HostBasis(ctx context.Context, raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return BasisUnresolvedHost
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if PublicAddr(ip) {
			return BasisPublicHost
		}
		return BasisInternalHost
	}
	if _, ok := c.policy(ctx).MatchHost(host); ok {
		return BasisInternalHost
	}
	lctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	ips, err := c.resolve()(lctx, host)
	if err != nil || len(ips) == 0 {
		return BasisUnresolvedHost
	}
	for _, ip := range ips {
		if !PublicAddr(ip) {
			return BasisInternalHost
		}
	}
	return BasisPublicHost
}
