package doctor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/doctor"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestDoctorDatabaseRoleSafetyAndUnusedOwnerURL(t *testing.T) {
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	pool, url := testutil.NewDB(t)
	ctx := context.Background()
	cfg := devConfig(url)
	cfg.DatabaseMigrateURL = "invalid-unused-owner-sentinel"
	cfg.DBRequireSplitRoles = true
	rep := doctor.Run(ctx, cfg, doctor.Options{})
	if c, _ := find(rep, "postgres", "roles"); !rep.OK || c.Status != doctor.OK || strings.Contains(c.Detail, "sentinel") {
		t.Fatalf("split doctor: %+v", rep.Checks)
	}
	owner := testutil.OwnerPool(t, pool)
	if _, err := owner.Exec(ctx, "GRANT UPDATE(action) ON audit_log TO "+pgx.Identifier{pool.Config().ConnConfig.User}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	rep = doctor.Run(ctx, cfg, doctor.Options{})
	if c, _ := find(rep, "postgres", "roles"); rep.OK || c.Status != doctor.Fail {
		t.Fatalf("unsafe doctor: %+v", rep.Checks)
	}
	cfg.DBRequireSplitRoles = false
	rep = doctor.Run(ctx, cfg, doctor.Options{})
	if c, _ := find(rep, "postgres", "roles"); !rep.OK || c.Status != doctor.Info {
		t.Fatalf("optional unsafe doctor: %+v", rep.Checks)
	}
	cfg.DatabaseURL = owner.Config().ConnString()
	rep = doctor.Run(ctx, cfg, doctor.Options{})
	if c, _ := find(rep, "postgres", "roles"); !rep.OK || c.Status != doctor.Info {
		t.Fatalf("single owner warning: %+v", rep.Checks)
	}
}
