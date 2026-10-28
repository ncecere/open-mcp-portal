package httpapi_test

import (
	"net/url"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionCallbackDisplayContext(t *testing.T) {
	e := newProvEnv(t)
	for _, result := range []string{"connected", "missing_scopes", "denied", "error", "expired"} {
		t.Run(result, func(t *testing.T) {
			e.oauth.Set(func(f *testutil.FakeOAuth) {
				f.Deny = result == "denied"
				f.GrantScopes = nil
				if result == "missing_scopes" {
					f.GrantScopes = []string{"read:user"}
				}
			})
			st := startShared(t, e.owner, e.provider.Id, "done-"+result)
			back, err := url.Parse(providerAuthorize(t, e.owner, st.AuthorizeUrl))
			if err != nil {
				t.Fatal(err)
			}
			if result == "error" {
				q := back.Query()
				q.Del("code")
				back.RawQuery = q.Encode()
			}
			if result == "expired" {
				e.scalar(`UPDATE service_connection_auth_states SET expires_at=now()-interval '1 minute' RETURNING 'ok'`)
			}
			to, err := url.Parse(callback(t, e.owner, back.String()))
			if err != nil {
				t.Fatal(err)
			}
			q := to.Query()
			if to.Path != "/connect/done" || q.Get("result") != result || q.Get("context") != "service" {
				t.Fatalf("shared result = %s", to)
			}
			if result == "missing_scopes" && q.Get("missing") != "repo" {
				t.Fatalf("missing scopes = %s", to)
			}
		})
	}
	// The hint belongs only to the service-owned callback, never ordinary consent.
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.Deny = false; f.GrantScopes = nil })
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id}); to != "/connect/done?provider=github&result=connected" {
		t.Fatalf("personal result changed: %s", to)
	}
}
