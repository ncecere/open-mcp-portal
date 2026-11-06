package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ncecere/open-mcp-portal/internal/auditstream"
	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
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

func TestAuditStatusPreservesBigint(t *testing.T) {
	p, url := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	if _, err := o.Exec(context.Background(), `UPDATE omp_audit.state SET last_seq=9007199254740993`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OMP_CONFIG_FILE", "")
	t.Setenv("DATABASE_URL", url)
	t.Setenv("DATABASE_MIGRATE_URL", "invalid-unused-owner-sentinel")
	var out bytes.Buffer
	if err := runAuditStream([]string{"status"}, &out); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["last_seq"]) != "9007199254740993" {
		t.Fatalf("status rounded sequence: %s", fields["last_seq"])
	}
}

func TestAuditCheckpointCommands(t *testing.T) {
	p, url := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	for k, v := range map[string]string{"OMP_CONFIG_FILE": "", "DATABASE_URL": url, "DATABASE_MIGRATE_URL": owner.Config().ConnString(), "ENCRYPTION_KEY": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="} {
		t.Setenv(k, v)
	}
	var out bytes.Buffer
	// A build still reporting the last pre-checkpoint release must not enable.
	prev := buildinfo.Version
	buildinfo.Version = "0.14.0"
	if err := runAuditStream([]string{"enable-checkpoints", "--min-reader-version-ack"}, &out); err == nil || !strings.Contains(err.Error(), "newer than 0.14.0") {
		t.Fatalf("0.14.0 build enabled checkpoints: %v", err)
	}
	buildinfo.Version = "0.15.0"
	t.Cleanup(func() { buildinfo.Version = prev })
	if err := runAuditStream([]string{"enable-checkpoints"}, &out); err == nil || !strings.Contains(out.String(), "one-way") {
		t.Fatal("missing acknowledgement fence")
	}
	if _, err := owner.Exec(context.Background(), `UPDATE omp_audit.state SET status='halted_incarnation'`); err != nil {
		t.Fatal(err)
	}
	if err := runAuditStream([]string{"enable-checkpoints", "--min-reader-version-ack"}, &out); err == nil {
		t.Fatal("enabled while halted")
	}
	if _, err := owner.Exec(context.Background(), `UPDATE omp_audit.state SET status='running'`); err != nil {
		t.Fatal(err)
	}
	// Enable uses only the owner URL.
	t.Setenv("DATABASE_URL", "invalid-unused-runtime-sentinel")
	if err := runAuditStream([]string{"enable-checkpoints", "--min-reader-version-ack"}, &out); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := p.QueryRow(context.Background(), `SELECT min_reader_version FROM omp_audit.state`).Scan(&version); err != nil || version != buildinfo.Version {
		t.Fatalf("version %s %v", version, err)
	}
	t.Setenv("DATABASE_URL", url)
	t.Setenv("DATABASE_MIGRATE_URL", "invalid-unused-owner-sentinel")
	key, _ := secrets.ParseKey("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	box, _ := secrets.New(key)
	if _, err := auditstream.EnsureCheckpointKey(context.Background(), p, box); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			_, _ = (auditstream.Sealer{Pool: p}).Batch(ctx)
		}
	}()
	err := runAuditStream([]string{"rotate-checkpoint-key"}, &out)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runAuditStream([]string{"status"}, &out); err != nil || !strings.Contains(out.String(), "active_key_fingerprint") {
		t.Fatalf("status %v %s", err, out.String())
	}
}

func TestAuditSinkGateCommands(t *testing.T) {
	p, url := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	for k, v := range map[string]string{"OMP_CONFIG_FILE": "", "DATABASE_URL": "invalid-unused-runtime-sentinel", "DATABASE_MIGRATE_URL": owner.Config().ConnString()} {
		t.Setenv(k, v)
	}
	prior := buildinfo.Version
	defer func() { buildinfo.Version = prior }()
	buildinfo.Version = "0.15.0"
	var out bytes.Buffer
	if err := runAuditStream([]string{"enable-sinks"}, &out); err == nil {
		t.Fatal("missing acknowledgement accepted")
	}
	// Disabling before first enable must not pin a development version forever.
	buildinfo.Version = "dev"
	if err := runAuditStream([]string{"disable-sinks"}, &out); err != nil {
		t.Fatal(err)
	}
	var version *string
	if err := p.QueryRow(context.Background(), `SELECT min_reader_version FROM omp_audit_ext.sink_settings`).Scan(&version); err != nil || version != nil {
		t.Fatalf("disable pinned unused gate: %v %v", version, err)
	}
	buildinfo.Version = "0.15.0"
	if err := runAuditStream([]string{"enable-sinks", "--min-reader-version-ack"}, &out); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err := p.QueryRow(context.Background(), `SELECT enabled,min_reader_version FROM omp_audit_ext.sink_settings`).Scan(&enabled, &version); err != nil || !enabled || version == nil || *version != "0.15.0" {
		t.Fatalf("enable: %v %v %v", enabled, version, err)
	}
	buildinfo.Version = "0.16.0"
	if err := runAuditStream([]string{"disable-sinks"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := runAuditStream([]string{"enable-sinks", "--min-reader-version-ack"}, &out); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", url)
	t.Setenv("DATABASE_MIGRATE_URL", "invalid-unused-owner-sentinel")
	out.Reset()
	if err := runAuditStream([]string{"status"}, &out); err != nil {
		t.Fatal(err)
	}
	var status struct {
		SinkSettings struct {
			Enabled bool   `json:"enabled"`
			Version string `json:"min_reader_version"`
		} `json:"sink_settings"`
	}
	if err := json.Unmarshal(out.Bytes(), &status); err != nil || !status.SinkSettings.Enabled || status.SinkSettings.Version != "0.15.0" {
		t.Fatalf("status: %v %s", err, out.String())
	}
	var n int
	if err := p.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action='audit.sinks_gate'`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("gate audit count %d %v", n, err)
	}
}
