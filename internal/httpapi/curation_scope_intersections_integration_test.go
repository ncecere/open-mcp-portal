package httpapi_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

const scopedEchoAlias = "curated_echo"

func curatedScopedRuntime(t *testing.T) *rtEnv {
	t.Helper()
	e := scopedRuntime(t)
	setCuration(t, e.gwEnv, e.admin, e.shared, "echo", map[string]any{
		"nameOverride": scopedEchoAlias,
		"constraints":  map[string]any{"text": map[string]any{"fixed": "fixed-by-gateway"}},
	})
	return e
}

func assertCuratedScopedForward(t *testing.T, e *rtEnv, modern bool, secret string) {
	t.Helper()
	before := len(e.fake.ToolCalls())
	out := scopeRPC(t, e, modern, "shared", secret, "tools/call", map[string]any{"name": scopedEchoAlias})
	if out["error"] != nil {
		t.Fatalf("allowed curated call: %v", out)
	}
	calls := e.fake.ToolCalls()
	if len(calls) != before+1 || calls[len(calls)-1].Tool != "echo" {
		t.Fatalf("expected one forward under the original name: got %d calls after %d", len(calls), before)
	}
	var args map[string]any
	if err := json.Unmarshal(calls[len(calls)-1].Arguments, &args); err != nil || len(args) != 1 || args["text"] != "fixed-by-gateway" {
		t.Fatalf("forwarded arguments=%s: %v", calls[len(calls)-1].Arguments, err)
	}
}

func TestCuratedToolCredentialScopesUseExposedName(t *testing.T) {
	e := curatedScopedRuntime(t)
	alias := scopedKey(t, e.member, nameScope(scopedEchoAlias))
	original := scopedKey(t, e.member, nameScope("status__echo"))
	read := scopedKey(t, e.member, classScope("read"))
	write := scopedKey(t, e.member, classScope("write"))
	for _, modern := range []bool{false, true} {
		wantScopedList(t, e, modern, "shared", alias.Secret, scopedEchoAlias)
		wantScopedList(t, e, modern, "shared", original.Secret)
		wantScopedList(t, e, modern, "shared", write.Secret, scopedEchoAlias)
		wantScopeDenied(t, e, modern, "shared", original.Secret, scopedEchoAlias)
		wantScopeDenied(t, e, modern, "shared", read.Secret, scopedEchoAlias)
		assertCuratedScopedForward(t, e, modern, alias.Secret)
		assertCuratedScopedForward(t, e, modern, write.Secret)
		before := e.fake.Requests()
		out := scopeRPC(t, e, modern, "shared", alias.Secret, "tools/call", map[string]any{"name": "status__echo"})
		if rpcErrorCode(out) != -32602 || e.fake.Requests() != before {
			t.Fatalf("original name remained callable after renaming: %v", out)
		}
	}
}

func TestCuratedToolGrantUnionStillIntersectsCredentialCeiling(t *testing.T) {
	e := curatedScopedRuntime(t)
	code, ec := e.admin.call("DELETE", e.shared+"/grants/"+e.grant, nil, nil, nil)
	mustCode(t, "remove unrestricted grant", code, ec, 200, "")
	code, ec = e.admin.call("POST", e.shared+"/grants", map[string]any{
		"subjectKind": "user", "userEmail": "blair@localhost", "toolScope": nameScope("status__echo"),
	}, nil, nil)
	mustCode(t, "original-name grant", code, ec, 201, "")
	alias := scopedKey(t, e.member, nameScope(scopedEchoAlias))
	read := scopedKey(t, e.member, classScope("read"))
	for _, modern := range []bool{false, true} {
		wantScopedList(t, e, modern, "shared", alias.Secret)
		wantScopeDenied(t, e, modern, "shared", alias.Secret, scopedEchoAlias)
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE users SET groups=ARRAY['curated-writers'] WHERE email='blair@localhost'`); err != nil {
		t.Fatal(err)
	}
	var grant apitypes.GatewayGrant
	code, ec = e.admin.call("POST", e.shared+"/grants", map[string]any{
		"subjectKind": "group", "group": "curated-writers", "toolScope": classScope("write"),
	}, &grant, nil)
	mustCode(t, "class grant alternative", code, ec, 201, "")
	for _, modern := range []bool{false, true} {
		wantScopedList(t, e, modern, "shared", alias.Secret, scopedEchoAlias)
		assertCuratedScopedForward(t, e, modern, alias.Secret)
		wantScopedList(t, e, modern, "shared", read.Secret)
		wantScopeDenied(t, e, modern, "shared", read.Secret, scopedEchoAlias)
	}
	code, ec = e.admin.call("DELETE", e.shared+"/grants/"+grant.Id.String(), nil, nil, nil)
	mustCode(t, "remove admitting alternative", code, ec, 200, "")
	for _, modern := range []bool{false, true} {
		wantScopedList(t, e, modern, "shared", alias.Secret)
		wantScopeDenied(t, e, modern, "shared", alias.Secret, scopedEchoAlias)
	}
}

func TestCuratedToolServiceAccountCeilingsUseLiveExposedName(t *testing.T) {
	e := curatedScopedRuntime(t)
	code, ec := e.admin.call("POST", e.shared+"/grants", map[string]any{
		"subjectKind": "team", "team": "tools", "toolScope": nameScope(scopedEchoAlias),
	}, nil, nil)
	mustCode(t, "service-account team grant", code, ec, 201, "")
	sa := createSA(t, e.owner, map[string]any{"name": "curated-limits", "toolScope": nameScope(scopedEchoAlias)})
	write := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "write", "toolScope": classScope("write")})
	inherit := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "inherit", "toolScope": nil})
	for _, modern := range []bool{false, true} {
		patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": nameScope(scopedEchoAlias)})
		for _, secret := range []string{write.Secret, inherit.Secret} {
			wantScopedList(t, e, modern, "shared", secret, scopedEchoAlias)
			assertCuratedScopedForward(t, e, modern, secret)
		}
		patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": nameScope("status__echo")})
		for _, secret := range []string{write.Secret, inherit.Secret} {
			wantScopedList(t, e, modern, "shared", secret)
			wantScopeDenied(t, e, modern, "shared", secret, scopedEchoAlias)
		}
		patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": nil})
		wantScopedList(t, e, modern, "shared", write.Secret, scopedEchoAlias)
		// Null at both credential layers still cannot bypass the named gateway grant.
		wantScopedList(t, e, modern, "shared", inherit.Secret, scopedEchoAlias)
	}
}
