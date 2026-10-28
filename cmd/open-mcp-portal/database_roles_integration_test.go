package main

import (
	"bytes"
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
