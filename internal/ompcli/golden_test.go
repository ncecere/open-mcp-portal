package ompcli

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/ompcli -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file (run with -update to accept):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func TestGoldenServerPlanAndExport(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	seedServers(t, h, f)
	_, exported, _ := h.run("export")
	golden(t, "export_servers.yaml", exported)
	_, exportedJSON, _ := h.run("export", "--json")
	golden(t, "export_servers.json", exportedJSON)

	st := f.servers["status"]
	st.Name, st.Url, st.Enabled = "Renamed", "https://other.example.com/mcp", false
	f.servers["billing"].PublishState = ompclient.PublishStatePrivate
	file := writeTempFile(t, "omp.yaml", exported+"  - team: bravo\n    slug: newone\n    name: New one\n    url: https://new.example.com/mcp\n    authMode: static_header\n    authHeaderName: Authorization\n    authValueEnv: NEWONE_TOKEN\n    publish: request\n", 0o600)
	h.env["NEWONE_TOKEN"] = secretSentinel
	// The appended server goes under "servers:", the last section of the export.
	code, plan, errOut := h.run("import", "-f", file, "--plan")
	if code != ExitChanges || plan == "" {
		t.Fatalf("exit %d out %q err %q", code, plan, errOut)
	}
	golden(t, "plan_servers.txt", plan)
	_, planJSON, _ := h.run("import", "-f", file, "--plan", "--json")
	golden(t, "plan_servers.json", planJSON)
}

func TestGoldenPlatformPlanAndExport(t *testing.T) {
	f := newFakePortal(t)
	seedPlatform(f)
	// Fixed IDs are not in the output, but keep the options stable anyway.
	f.options[2].CapabilityId = uuid.MustParse("00000000-0000-0000-0000-000000000003")
	h := newHarness(t)
	h.connect(f, f.platformAdmin())
	_, exported, _ := h.run("export")
	golden(t, "export_platform.yaml", exported)
	f.teams["bravo"].Name = "Bravo Renamed"
	f.gateways["support"].Enabled = false
	f.gateways["support"].grants = f.gateways["support"].grants[:1]
	d := int64(10)
	f.limits[0].Default = &d
	file := writeTempFile(t, "omp.yaml", exported, 0o600)
	code, plan, errOut := h.run("import", "-f", file, "--plan")
	if code != ExitChanges || plan == "" {
		t.Fatalf("exit %d out %q err %q", code, plan, errOut)
	}
	golden(t, "plan_platform.txt", plan)
}
