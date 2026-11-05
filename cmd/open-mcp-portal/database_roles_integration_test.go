package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestDoctorAndRotateKeysNeverOpenOwnerURL(t *testing.T) {
	_, url := testutil.NewDB(t)
	for key, value := range map[string]string{
		"OMP_CONFIG_FILE": "", "APP_URL": "http://localhost:8088", "DEV_AUTH": "true",
		"DATABASE_URL": url, "DATABASE_MIGRATE_URL": "invalid-unused-owner-sentinel",
		"MIGRATE_ON_START": "true", "DB_RUNTIME_ROLE": "", "DB_REQUIRE_SPLIT_ROLES": "false",
		"ENCRYPTION_KEY": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
		"API_KEY_PEPPER": "cGVwcGVyLXBlcHBlci1wZXBwZXItcGVwcGVyLTAxMjM=",
	} {
		t.Setenv(key, value)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--json"}, &out); err != nil {
		t.Fatalf("doctor used owner URL: %v %s", err, out.String())
	}
	if strings.Contains(out.String(), "sentinel") {
		t.Fatal("owner URL leaked")
	}
	out.Reset()
	if err := runRotateKeys([]string{"--dry-run"}, &out); err != nil {
		t.Fatalf("rotate-keys used owner URL: %v", err)
	}
	if strings.Contains(out.String(), "sentinel") {
		t.Fatal("owner URL leaked")
	}
}

func TestAuditRecoveryUsesOwnerAndStatusUsesRuntime(t *testing.T) {
	p, url := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	t.Setenv("OMP_CONFIG_FILE", "")
	t.Setenv("DATABASE_URL", url)
	t.Setenv("DATABASE_MIGRATE_URL", "invalid-unused-owner-sentinel")
	var out bytes.Buffer
	if err := runAuditStream([]string{"status"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stream_id") {
		t.Fatal("missing status")
	}
	if _, err := owner.Exec(context.Background(), `UPDATE omp_audit.state SET system_identifier='1',status='halted_incarnation'`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_MIGRATE_URL", owner.Config().ConnString())
	t.Setenv("DATABASE_URL", "invalid-unused-runtime-sentinel")
	if err := runAuditStream([]string{"rebind"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runAuditStream([]string{"rebase"}, &out); err != nil {
		t.Fatal(err)
	}
}
