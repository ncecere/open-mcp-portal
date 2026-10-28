package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestMigrateDoesNotOpenUnusedRuntimeURL(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, pool)
	cfg := config.Defaults()
	cfg.DatabaseMigrateURL = owner.Config().ConnString()
	cfg.DatabaseURL = "not-a-database-URL-with-unused-sentinel-secret"
	if owner != pool {
		cfg.DBRuntimeRole = pool.Config().ConnConfig.User
	}
	if err := app.Run(context.Background(), app.ModeMigrate, cfg, testutil.Logger()); err != nil {
		t.Fatalf("migration used runtime URL: %v", err)
	}
	cfg.DatabaseURL = ""
	if err := app.Run(context.Background(), app.ModeMigrate, cfg, testutil.Logger()); err != nil {
		t.Fatalf("owner-only migration: %v", err)
	}
}

func TestServeRequiredSplitRejectsOwnerWithoutOpeningMigrationURL(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	cfg := config.Defaults()
	cfg.DatabaseURL = testutil.OwnerPool(t, pool).Config().ConnString()
	cfg.DatabaseMigrateURL = "invalid-unused-owner-sentinel"
	cfg.AppURL, cfg.DevAuth = "http://localhost:8088", true
	cfg.EncryptionKey = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
	cfg.APIKeyPepper = "cGVwcGVyLXBlcHBlci1wZXBwZXItcGVwcGVyLTAxMjM="
	cfg.DBRequireSplitRoles = true
	err := app.Run(context.Background(), app.ModeServe, cfg, testutil.Logger())
	if err == nil || !strings.Contains(err.Error(), "unsafe split database roles") || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("serve result: %v", err)
	}
}
