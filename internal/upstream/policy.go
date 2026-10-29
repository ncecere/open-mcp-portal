package upstream

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
)

// NetworkPolicy supplies the allowlist in force (internal/registry keeps a
// cached copy of the platform admins' entries plus the deployment's).
type NetworkPolicy interface {
	Current(ctx context.Context) *netpolicy.Policy
}

// CheckedNetworkPolicy can fail closed when obtaining the live policy fails.
// NetworkPolicy remains compatible with static policies and existing callers.
type CheckedNetworkPolicy interface {
	CurrentChecked(context.Context) (*netpolicy.Policy, error)
}

func (c *Client) policyChecked(ctx context.Context) (*netpolicy.Policy, error) {
	if p, ok := c.Networks.(CheckedNetworkPolicy); ok {
		return p.CurrentChecked(ctx)
	}
	return c.policy(ctx), nil
}

const messageNotAllowed = "The server's address is not allowed: it is loopback, link-local or another blocked range, " +
	"an internal address no platform admin has allowed, or the server redirected."

func (c *Client) policy(ctx context.Context) *netpolicy.Policy {
	if c.Networks == nil {
		return nil
	}
	return c.Networks.Current(ctx)
}

// NormalizeURL checks a server URL against the rule with the allowlist in
// force (NormalizeURLWith).
func (c *Client) NormalizeURL(ctx context.Context, raw string) (string, error) {
	p, err := c.policyChecked(ctx)
	if err != nil {
		return "", err
	}
	return NormalizeURLWith(raw, c.AllowPrivate, p)
}

// notAllowed turns a refused URL into the not_allowed error class.
func notAllowed(err error) *Error {
	msg := messageNotAllowed
	if e, ok := apperr.As(err); ok {
		msg = "The server's URL is not allowed: " + e.Message
	}
	return &Error{Class: ClassNotAllowed, Message: msg}
}

// CheckTimeout bounds the DNS lookup of a URL check.
const CheckTimeout = 3 * time.Second

// Check reasons beyond the URL problems and address verdicts.
const ReasonDNSFailed = "dns_failed"

// ReasonPolicyFailed means the live address policy could not be read.
const ReasonPolicyFailed = "policy_failed"

// AddressCheck is one address of a checked URL.
type AddressCheck struct {
	Address string
	Allowed bool
	Reason  string // a netpolicy address verdict
}

// CheckResult says whether the gateway would reach a URL now, and why.
type CheckResult struct {
	Allowed bool
	// Reason is a URL problem (ReasonScheme, ReasonInvalid...), an address
	// verdict (netpolicy.Reason*), or ReasonDNSFailed.
	Reason  string
	Message string
	// Matched is the allowlist entry the decision rests on (nil: none).
	Matched   *netpolicy.Entry
	Addresses []AddressCheck
}

// Check evaluates a URL as saving it and dialling it would, resolving its
// host (at most CheckTimeout) without connecting. Every resolved address
// must be allowed, as when dialling.
func (c *Client) Check(ctx context.Context, raw string) CheckResult {
	p, err := c.policyChecked(ctx)
	if err != nil {
		return CheckResult{Reason: ReasonPolicyFailed, Message: "The address policy couldn't be read."}
	}
	if _, err := NormalizeURLWith(raw, c.AllowPrivate, p); err != nil {
		res := CheckResult{Reason: ReasonInvalid, Message: err.Error()}
		if e, ok := apperr.As(err); ok {
			res.Message = e.Message
			if d, ok := e.Details.(map[string]any); ok {
				res.Reason, _ = d["reason"].(string)
			}
		}
		if u, err := url.Parse(raw); err == nil {
			if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
				v := p.CheckAddr(u.Hostname(), ip)
				res.Addresses = []AddressCheck{{Address: ip.String(), Allowed: v.Allowed, Reason: v.Reason}}
			}
		}
		return res
	}
	u, _ := url.Parse(raw)
	host := u.Hostname()
	var httpEntry *netpolicy.Entry
	if u.Scheme == "http" {
		if e, ok := p.HTTPAllowed(host); ok {
			httpEntry = &e
		}
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, CheckTimeout)
		defer cancel()
		found, err := c.resolve()(lctx, host)
		if err != nil || len(found) == 0 {
			msg := "The host name has no addresses."
			if err != nil {
				msg = "The host name couldn't be resolved"
				if errors.Is(lctx.Err(), context.DeadlineExceeded) {
					msg += " in time"
				}
				msg += "."
			}
			return CheckResult{Reason: ReasonDNSFailed, Message: msg}
		}
		ips = found
	}
	res := CheckResult{Allowed: true, Matched: httpEntry}
	var refusedBy string
	for _, ip := range ips {
		v := p.CheckAddr(host, ip)
		if c.AllowPrivate {
			v = netpolicy.Verdict{Allowed: true, Reason: netpolicy.ReasonDevelopment}
		}
		res.Addresses = append(res.Addresses, AddressCheck{Address: ip.String(), Allowed: v.Allowed, Reason: v.Reason})
		switch {
		case !v.Allowed:
			res.Allowed = false
			if refusedBy != netpolicy.ReasonBlockedAddress {
				refusedBy = v.Reason
			}
		case res.Matched == nil && v.Entry != nil:
			res.Matched = v.Entry
		}
	}
	if !res.Allowed {
		res.Matched = nil
		res.Reason = refusedBy
		res.Message = MessagePrivateAddress
		if refusedBy == netpolicy.ReasonBlockedAddress {
			res.Message = MessageBlockedAddress
		}
		if len(ips) > 1 || ips[0].String() != host {
			res.Message = "Not every address the host resolves to is allowed. " + res.Message
		}
		return res
	}
	res.Reason, res.Message = allowedReason(c.AllowPrivate, res)
	return res
}

func allowedReason(dev bool, res CheckResult) (string, string) {
	switch {
	case dev:
		return netpolicy.ReasonDevelopment, "Allowed by the development allowance (DEV_AUTH on a loopback APP_URL)."
	case res.Matched != nil && res.Matched.Kind == netpolicy.KindHost:
		return netpolicy.ReasonHostEntry, "Allowed: the host matches " + res.Matched.Value + "."
	case res.Matched != nil:
		return netpolicy.ReasonCIDREntry, "Allowed: inside " + res.Matched.Value + "."
	}
	return netpolicy.ReasonPublic, "Allowed: a public address."
}
