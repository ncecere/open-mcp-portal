package scim

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func patchOf(t *testing.T, body string) *patchRequest {
	t.Helper()
	r := httptest.NewRequest("PATCH", "/scim/v2/Users/x", bytes.NewBufferString(body))
	r.Header.Set("Content-Type", contentTypeSCIM)
	p := &patchRequest{}
	if err := decodePatch(r, p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

func TestPatchUserPathsAndClientDialects(t *testing.T) {
	ext := "sub"
	a := userAttrs{UserName: "pat", ExternalID: &ext, Active: true, Email: "old@example.test"}
	p := patchOf(t, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	 {"op":"Replace","path":"emails[type eq \"work\"].value","value":"new@example.test"},
	 {"op":"Add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"x"},
	 {"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:name.givenName","value":"Pat"},
	 {"op":"replace","path":"active","value":"False"},
	 {"op":"remove","path":"externalId"}]}`)
	if err := p.applyUser(&a); err != nil {
		t.Fatal(err)
	}
	if a.Email != "new@example.test" || a.Active || a.GivenName != "Pat" || a.ExternalID != nil {
		t.Fatalf("applied = %+v", a)
	}
	// A path-less replace takes an object (Okta/authentik style).
	p = patchOf(t, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":true,"displayName":"P"}}]}`)
	if err := p.applyUser(&a); err != nil || !a.Active || a.DisplayName != "P" {
		t.Fatalf("path-less = %+v %v", a, err)
	}
	for _, bad := range []string{
		`{"op":"remove","path":"userName"}`, `{"op":"remove","path":"active"}`, `{"op":"replace","path":"groups","value":[]}`,
		`{"op":"replace","path":"nickName","value":"x"}`, `{"op":"replace","path":"active","value":"maybe"}`, `{"op":"remove"}`,
	} {
		p := patchOf(t, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[`+bad+`]}`)
		if err := p.applyUser(&userAttrs{UserName: "x", Active: true}); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestPatchGroupMemberActionsKeepOrder(t *testing.T) {
	id := uuid.New()
	p := patchOf(t, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[
	 {"op":"remove","path":"members[value eq \"`+id.String()+`\"]"},
	 {"op":"add","path":"members","value":[{"value":"`+id.String()+`"}]},
	 {"op":"Remove","path":"members","value":[{"value":"`+id.String()+`"}]},
	 {"op":"replace","path":"displayName","value":"Eng"},
	 {"op":"remove","path":"members"}]}`)
	c, err := p.group()
	if err != nil {
		t.Fatal(err)
	}
	kinds := []int{}
	for _, m := range c.members {
		kinds = append(kinds, m.kind)
	}
	if len(kinds) != 4 || kinds[0] != memberRemove || kinds[1] != memberAdd || kinds[2] != memberRemove || kinds[3] != memberReplace ||
		c.displayName == nil || *c.displayName != "Eng" {
		t.Fatalf("actions = %v name=%v", kinds, c.displayName)
	}
}

func TestFilterAndPagination(t *testing.T) {
	for raw, want := range map[string]string{
		`userName eq "a@b"`: "a@b", `USERNAME Eq "x"`: "x", `urn:ietf:params:scim:schemas:core:2.0:User:userName eq "q\"x"`: `q"x`,
	} {
		attr, v, err := parseFilter(raw, "userName", "externalId")
		if err != nil || attr != "userName" || v != want {
			t.Errorf("%s -> %s %q %v", raw, attr, v, err)
		}
	}
	for _, raw := range []string{`userName co "a"`, `userName eq "a" and active eq true`, `emails eq "x"`, `userName eq a`} {
		if _, _, err := parseFilter(raw, "userName", "externalId"); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	r := httptest.NewRequest("GET", "/scim/v2/Users?startIndex=-3&count=9999", nil)
	lp, err := pagination(r)
	if err != nil || lp.start != 1 || lp.count != maxPageSize {
		t.Fatalf("pagination = %+v %v", lp, err)
	}
}
