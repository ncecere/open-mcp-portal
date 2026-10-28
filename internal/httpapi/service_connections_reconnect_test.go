package httpapi_test

import (
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"strings"
	"testing"
)

func TestServiceConnectionReconnectNeverBorrowsPreviousAccountsRefresh(t *testing.T) {
	e := newProvEnv(t)
	c := connectShared(t, e.owner, e.provider.Id, "switch-account")
	if value := e.scalar(`SELECT (refresh_token_cipher IS NOT NULL)::text FROM service_connections WHERE id=$1`, c.Id); value != "true" {
		t.Fatal("initial refresh token missing")
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.IssueRefresh = false; f.Login = "another-shared-account" })
	var st apitypes.ConnectStarted
	code, ec := e.owner.call("POST", sharedBase+"/"+c.Id.String()+"/reconnect", nil, &st, ifMatch(c.Revision))
	mustCode(t, "reconnect", code, ec, 200, "")
	if to := callback(t, e.owner, providerAuthorize(t, e.owner, st.AuthorizeUrl)); !strings.Contains(to, "result=connected") {
		t.Fatalf("callback = %s", to)
	}
	if value := e.scalar(`SELECT (status='active' AND access_token_cipher IS NOT NULL AND refresh_token_cipher IS NULL)::text FROM service_connections WHERE id=$1`, c.Id); value != "true" {
		t.Fatal("new authorization borrowed the previous account's refresh token")
	}
	next := sharedByName(t, e.owner, c.Name)
	if next.AccountLabel == nil || *next.AccountLabel != "another-shared-account" {
		t.Fatalf("shared account label = %+v", next.AccountLabel)
	}
}
