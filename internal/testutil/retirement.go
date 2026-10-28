package testutil

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RemoveRetirementFencesForOldSchema is privileged fixture preparation only:
// historical migration tests must recreate an actual pre-retirement schema.
// Migration 34's Down intentionally never restores retired authority.
func RemoveRetirementFencesForOldSchema(t testing.TB, runtime *pgxpool.Pool) {
	t.Helper()
	owner := OwnerPool(t, runtime)
	ctx := context.Background()
	var name string
	if err := owner.QueryRow(ctx, "SELECT current_database()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "omp_test_") {
		t.Fatal("old-schema fixture requires a disposable test database")
	}
	for _, sql := range []string{
		"DROP TRIGGER IF EXISTS retired_agent_platform_trust ON agent_platforms",
		"DROP TRIGGER IF EXISTS retired_relay_account ON service_accounts",
		"DROP TRIGGER IF EXISTS retired_relay_key ON service_account_keys",
		"DROP FUNCTION IF EXISTS retire_agent_platform_trust()",
		"DROP FUNCTION IF EXISTS retire_relay_account()",
		"DROP FUNCTION IF EXISTS retire_relay_key()",
	} {
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
}
