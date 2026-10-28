package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/config"
)

func TestDatabaseRoleConfiguration(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "owner")
	yaml := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(secret, []byte("postgres://owner:secret@db/omp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yaml, []byte("database_migrate_url_file: "+secret+"\ndb_runtime_role: 'quoted role'\ndb_require_split_roles: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lookup := func(key string) (string, bool) { return "", false }
	c, err := config.LoadFrom(yaml, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if c.MigrationURL() != "postgres://owner:secret@db/omp" || c.DBRuntimeRole != "quoted role" || !c.DBRequireSplitRoles {
		t.Fatalf("wrong resolved database role settings")
	}
	if err := c.Validate("migrate"); err != nil {
		t.Fatalf("migration unnecessarily required runtime URL: %v", err)
	}
	c.DatabaseMigrateURL = ""
	c.DatabaseURL = "postgres://legacy@db/omp"
	if c.MigrationURL() != c.DatabaseURL {
		t.Fatal("migration fallback missing")
	}
	for _, name := range []string{strings.Repeat("x", 64), "embedded\x00nul"} {
		c.DBRuntimeRole = name
		if err := c.Validate("migrate"); err == nil {
			t.Fatalf("invalid role accepted")
		}
	}
	c.DBRuntimeRole = ""
	if err := c.Validate("migrate"); err == nil {
		t.Fatal("required split migration accepted without target role")
	}
	defaults := config.Defaults()
	if defaults.DBRuntimeRole != "" || defaults.DBRequireSplitRoles {
		t.Fatal("split roles not opt-in")
	}
	env := map[string]string{"DATABASE_MIGRATE_URL": "unused", "DATABASE_MIGRATE_URL_FILE": secret, "DB_RUNTIME_ROLE": "env-role"}
	c, err = config.LoadFrom(yaml, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil || c.MigrationURL() != "postgres://owner:secret@db/omp" || c.DBRuntimeRole != "env-role" {
		t.Fatalf("env/_FILE precedence: %v", err)
	}
}
