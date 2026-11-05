package auditstream

import (
	"fmt"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/ncecere/open-mcp-portal/migrations"
	"github.com/pressly/goose/v3"
)

// Opt-in: creates/removes only two uniquely named containers labelled omp.owner=w38b.
func TestPhysicalPromotion(t *testing.T) {
	if os.Getenv("OMP_TEST_PHYSICAL_PROMOTION") != "1" {
		t.Skip("set OMP_TEST_PHYSICAL_PROMOTION=1 for the owned Docker promotion fixture")
	}
	docker := func(args ...string) string {
		t.Helper()
		out, err := osexec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	prefix := fmt.Sprintf("omp38b-%d", time.Now().UnixNano())
	primary := prefix + "-primary"
	standby := prefix + "-standby"
	for _, name := range []string{primary, standby} {
		t.Cleanup(func() {
			out, err := osexec.Command("docker", "inspect", "--format", "{{index .Config.Labels \"omp.owner\"}}", name).CombinedOutput()
			if err == nil && strings.TrimSpace(string(out)) == "w38b" {
				if out, err = osexec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
					t.Errorf("remove owned container: %v %s", err, out)
				}
			}
		})
	}
	docker("run", "-d", "--name", primary, "--label", "omp.owner=w38b", "--tmpfs", "/var/lib/postgresql/data", "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=promotion-test-only", "postgres:17")
	connect := func(name string) *pgxpool.Pool {
		t.Helper()
		addr := docker("port", name, "5432/tcp")
		p, err := pgxpool.New(ctx, "postgres://postgres:promotion-test-only@"+addr+"/postgres?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		deadline := time.Now().Add(60 * time.Second)
		for p.Ping(ctx) != nil {
			if time.Now().After(deadline) {
				t.Fatal("owned postgres not ready")
			}
			time.Sleep(100 * time.Millisecond)
		}
		return p
	}
	p := connect(primary)
	db := stdlib.OpenDBFromPool(p)
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	db.Close()
	drain(t, p)
	docker("exec", primary, "sh", "-c", `printf '\nhost replication all 0.0.0.0/0 scram-sha-256\n' >> /var/lib/postgresql/data/pg_hba.conf`)
	exec(t, p, `SELECT pg_reload_conf()`)
	ip := docker("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", primary)
	docker("run", "-d", "--name", standby, "--label", "omp.owner=w38b", "--user", "postgres", "--tmpfs", "/var/lib/postgresql/data:uid=999,gid=999,mode=0700", "-p", "127.0.0.1::5432", "-e", "PGPASSWORD=promotion-test-only", "--entrypoint", "bash", "postgres:17", "-ceu", "pg_basebackup -h "+ip+" -U postgres -D /var/lib/postgresql/data -R -X stream -c fast; exec postgres -D /var/lib/postgresql/data")
	r := connect(standby)
	if count(t, r, `SELECT pg_is_in_recovery()::int`) != 1 {
		t.Fatal("not a streaming standby")
	}
	docker("exec", standby, "pg_ctl", "-D", "/var/lib/postgresql/data", "promote", "-w")
	if count(t, r, `SELECT pg_is_in_recovery()::int`) != 0 {
		t.Fatal("promotion did not complete")
	}
	if _, err = (Sealer{r}).Batch(ctx); err != nil {
		t.Fatal(err)
	}
	checkEpoch(t, r)
	if count(t, r, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start' AND epoch_summary->>'reason'='timeline'`) != 1 {
		t.Fatal("promotion failed to start epoch")
	}
	t.Log("physical promotion started a valid epoch; both labelled containers removed by cleanup")
}
