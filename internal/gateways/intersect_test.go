package gateways

import (
	"slices"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// A relayed call is the person's access and the relay account's, both (decision 66).
func TestIntersect(t *testing.T) {
	person := func(role string, access ...string) Caller { return Caller{Role: role, Access: access} }
	relay := func(role string) Caller { return Caller{Role: role, Access: []string{AccessServiceAccount}} }
	none := Caller{}
	cases := []struct {
		name         string
		person, rel  Caller
		allowed      bool
		role, access string
	}{
		{"both allowed, the lower role decides: member person, editor relay", person(authz.RoleMember, AccessTeamMember), relay(authz.RoleEditor), true, authz.RoleMember, AccessTeamMember},
		{"an owner through an editor relay is an editor", person(authz.RoleOwner, AccessTeamMember), relay(authz.RoleEditor), true, authz.RoleEditor, AccessTeamMember},
		{"equal roles", person(authz.RoleEditor, AccessTeamMember), relay(authz.RoleEditor), true, authz.RoleEditor, AccessTeamMember},
		{"an editor through a member relay is a member", person(authz.RoleEditor, AccessTeamMember), relay(authz.RoleMember), true, authz.RoleMember, AccessTeamMember},
		{"the person has no access", none, relay(authz.RoleEditor), false, "", ""},
		{"the relay has no access", person(authz.RoleOwner, AccessTeamMember), none, false, "", ""},
		{"neither", none, none, false, "", ""},
		{"a platform gateway has no roles: both need a grant", person("", AccessGroupGrant), Caller{Access: []string{AccessTeamGrant}}, true, "", AccessGroupGrant},
		{"a platform gateway granted to the person only", person("", AccessUserGrant), none, false, "", ""},
	}
	for _, c := range cases {
		got := Intersect(c.person, c.rel)
		if got.Allowed() != c.allowed || got.Role != c.role || (c.allowed && !slices.Equal(got.Access, []string{c.access})) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	// What the role decides, through Evaluate: an admin-only capability stays out of an editor relay's reach even for an owner.
	g := dbgen.Gateway{OwnerKind: OwnerTeam}
	admin, editor := authz.RoleAdmin, authz.RoleEditor
	items := []Selected{{Available: true, MinRole: &admin}, {Available: true, MinRole: &editor}, {Available: true}}
	got := Evaluate(g, items, Intersect(person(authz.RoleOwner, AccessTeamMember), relay(authz.RoleEditor)))
	if got[0].Allowed || got[0].Denied != DeniedRole || !got[1].Allowed || !got[2].Allowed {
		t.Fatalf("evaluated = %+v", got)
	}
}
