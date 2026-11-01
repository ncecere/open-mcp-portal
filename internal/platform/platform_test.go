package platform

import (
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func ptr(s string) *string { return &s }

func TestUserAccessAndAction(t *testing.T) {
	u := dbgen.User{PlatformRole: "none", Status: "active", ManualStatus: "active"}
	cases := []struct {
		in             UserUpdate
		role, status   string
		action, errStr string
	}{
		{UserUpdate{}, "none", "active", "platform.user_update", ""},
		{UserUpdate{PlatformRole: ptr("platform_admin")}, "platform_admin", "active", "platform.user_role_change", ""},
		{UserUpdate{PlatformRole: ptr("platform_auditor")}, "platform_auditor", "active", "platform.user_role_change", ""},
		{UserUpdate{Status: ptr("suspended")}, "none", "suspended", "platform.user_suspend", ""},
		{UserUpdate{PlatformRole: ptr("root")}, "", "", "", "invalid_role"},
		{UserUpdate{Status: ptr("deleted")}, "", "", "", "invalid_status"},
	}
	for _, c := range cases {
		role, status, err := userAccess(u, c.in)
		if c.errStr != "" {
			if err == nil || err.Error()[:len(c.errStr)] != c.errStr {
				t.Errorf("%+v: err = %v", c.in, err)
			}
			continue
		}
		if err != nil || role != c.role || status != c.status {
			t.Errorf("%+v: %s %s %v", c.in, role, status, err)
		}
		if got := userAction(u, role, status); got != c.action {
			t.Errorf("%+v: action %s, want %s", c.in, got, c.action)
		}
	}
	suspended := dbgen.User{PlatformRole: "none", Status: "suspended", ManualStatus: "suspended"}
	if userAction(suspended, "none", "active") != "platform.user_reactivate" {
		t.Error("reactivate action")
	}
}
