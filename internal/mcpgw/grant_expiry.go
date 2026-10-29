package mcpgw

import (
	"context"
	"errors"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

var errGrantExpired = errors.New("gateway grant snapshot expired")

type grantClockCheck func(context.Context, time.Time) (bool, error)

// guardGrantExpiry applies to tools, prompts AND resources, including protocol
// setup and refresh retries. It wraps approval admission/consumption so the
// authoritative database clock is checked again AFTER a possibly slow commit.
// No checked-out connection, transaction or authority lock survives this hook.
func (rc *request) guardGrantExpiry(target *upstream.Target) {
	if rc.caller.ExpiresAt == nil {
		return
	}
	var check grantClockCheck
	if rc.h != nil && rc.h.Gateways != nil {
		check = rc.h.Gateways.GrantDeadlineLive
	}
	target.BeforeTransport = grantExpiryGuard(*rc.caller.ExpiresAt, time.Now, check, target.BeforeTransport)
}

// Freeze the earliest matched deadline. A new client request may reevaluate
// still-live alternatives; this transport attempt must never extend its permit.
func grantExpiryGuard(deadline time.Time, now func() time.Time, check grantClockCheck, prior func(context.Context, bool) error) func(context.Context, bool) error {
	live := func(ctx context.Context) error {
		if !now().Before(deadline) || check == nil {
			return errGrantExpired
		}
		ok, err := check(ctx, deadline)
		if err != nil || !ok {
			return errGrantExpired
		}
		// The database read itself may have waited for a pool connection.
		if !now().Before(deadline) {
			return errGrantExpired
		}
		return nil
	}
	return func(ctx context.Context, tool bool) error {
		if err := live(ctx); err != nil {
			return err
		}
		if prior != nil {
			if err := prior(ctx, tool); err != nil {
				return err
			}
		}
		return live(ctx)
	}
}

func (rc *request) grantExpiryFailed(rec calls.Call, err error) bool {
	if !errors.Is(err, errGrantExpired) {
		return false
	}
	n := rc.fail(codeDenied, "Gateway access changed; retry the original request to recheck access")
	rec.Outcome, rec.ErrorClass, rec.IdentitySent = calls.OutcomeDenied, "no_access", nil
	rc.record(rec, n)
	return true
}
