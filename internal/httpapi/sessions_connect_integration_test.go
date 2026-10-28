package httpapi_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/auth"
)

func TestSessionRevocationCancelsConnect(t *testing.T) {
	for _, how := range []string{"one", "all", "admin", "logout"} {
		t.Run(how, func(t *testing.T) {
			e := newProvEnv(t)
			id := browserSessionID(t, e.member)
			code, ec, start := e.start(e.member, map[string]any{"providerId": e.provider.Id})
			mustCode(t, "start", code, ec, 200, "")
			location := providerAuthorize(t, e.member, start.AuthorizeUrl)
			count := func() int {
				var n int
				if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM provider_auth_states WHERE session_digest=$1`, auth.Digest(id)).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			if count() != 1 {
				t.Fatal("missing pending flow")
			}
			switch how {
			case "one":
				code, ec = e.member.call("DELETE", "/v1/me/sessions/"+id, nil, nil, nil)
			case "all":
				code, ec = e.member.call("POST", "/v1/me/sessions/revoke-all", nil, nil, nil)
			case "admin":
				code, ec = e.admin.call("DELETE", "/v1/admin/users/"+e.member.me.User.Id.String()+"/sessions", nil, nil, nil)
			case "logout":
				code, ec = e.member.call("POST", "/auth/logout", nil, nil, nil)
			}
			mustCode(t, "end session", code, ec, 200, "")
			if count() != 0 {
				t.Fatal("pending flow survived revocation")
			}
			if e.member.get("/v1/me", nil) != 401 {
				t.Fatal("ended session still valid")
			}
			// Even signing the same person in again cannot finish the old flow.
			again := e.app.signIn("blair")
			if result := callback(t, again, location); !strings.Contains(result, "result=expired") {
				t.Fatalf("callback = %s", result)
			}
			if e.oauth.TokenRequests() != 0 {
				t.Fatal("cancelled callback exchanged a code")
			}
		})
	}
}

func TestSignOutOthersKeepsCurrentConnect(t *testing.T) {
	e := newProvEnv(t)
	other := e.app.signIn("blair")
	_, _, start := e.start(e.member, map[string]any{"providerId": e.provider.Id})
	location := providerAuthorize(t, e.member, start.AuthorizeUrl)
	code, ec := e.member.call("POST", "/v1/me/sessions/revoke-all", map[string]any{"keepCurrent": true}, nil, nil)
	mustCode(t, "keep current", code, ec, 200, "")
	if other.get("/v1/me", nil) != 401 {
		t.Fatal("other session survived")
	}
	if result := callback(t, e.member, location); !strings.Contains(result, "result=connected") {
		t.Fatalf("current flow = %s", result)
	}
}
