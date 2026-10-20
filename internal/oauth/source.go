package oauth

import (
	"context"
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
)

// MetadataFetchesPerMinute is how many client metadata documents one source
// address can make the portal fetch in a minute (cache hits don't count).
// Whoever can reach the portal can name any https URL as a client_id, so the
// fetch is bounded per address whether or not anyone is signed in (H-3).
const MetadataFetchesPerMinute = 20

type sourceKey struct{}

// WithSource records the address a request came from (as the portal sees
// it: TRUSTED_PROXIES applied), so fetches made for it are counted against
// it. Without one, fetches are not limited.
func WithSource(ctx context.Context, address string) context.Context {
	return context.WithValue(ctx, sourceKey{}, address)
}

func sourceOf(ctx context.Context) string {
	s, _ := ctx.Value(sourceKey{}).(string)
	return s
}

// errFetchLimit is the page shown when an address has used up its metadata
// fetches. Only a signed-in person can reach it from the authorization
// endpoint (an anonymous request is sent to sign in before anything is
// fetched), so it names the reason.
func errFetchLimit() *Error {
	e := pageError("slow_down", "Too many apps were looked up from your network in the last minute. Wait a minute and connect the app again.")
	e.Status = http.StatusTooManyRequests
	return e
}

// allowFetch counts a fetch against the request's source address.
func (s *Service) allowFetch(ctx context.Context) error {
	addr := sourceOf(ctx)
	if s.rates == nil || addr == "" {
		return nil
	}
	ok, _, err := ratelimit.Allow(ctx, s.rates, ratelimit.Bucket("oauth:metadata-fetch", addr), MetadataFetchesPerMinute)
	if err != nil {
		return err
	}
	if !ok {
		s.Log.WarnContext(ctx, "oauth client metadata fetch refused: too many from one address")
		return errFetchLimit()
	}
	return nil
}
