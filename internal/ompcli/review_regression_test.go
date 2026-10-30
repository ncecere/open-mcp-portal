package ompcli

import (
	"strconv"
	"strings"
	"testing"
)

func TestMalformedTrailingYAMLIsRefused(t *testing.T) {
	if _, err := ParseFile([]byte("schema: omp/v1\n---\nservers: [\n")); err == nil {
		t.Fatal("accepted a valid first document followed by malformed YAML")
	}
}

func TestMissingSecretNameRefusesBeforeAnyImportWrite(t *testing.T) {
	f := newFakePortal(t)
	h := newHarness(t)
	h.connect(f, f.publisher("bravo"))
	// The first step can succeed, but the later static server has no env name.
	// Check the complete plan before applying either step.
	path := writeTempFile(t, "omp.yaml", `schema: omp/v1
servers:
- team: bravo
  slug: a-public
  name: Public
  url: https://public.example.com/mcp
- team: bravo
  slug: z-private
  name: Private
  url: https://private.example.com/mcp
  authMode: static_header
  authHeaderName: X-API-Key
`, 0o600)
	before := countWrites(f)
	code, _, errOut := h.run("import", "-f", path)
	if code != ExitUsage || !strings.Contains(errOut, "authValueEnv") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if after := countWrites(f); after != before {
		t.Fatalf("incomplete secret declaration allowed partial apply: %d -> %d", before, after)
	}
}

func TestRegisterTimeoutValidatedBeforeNarrowing(t *testing.T) {
	for _, value := range []string{"-1", "601", "4294967297"} {
		if _, err := strconv.Atoi(value); err != nil {
			continue
		}
		t.Run(value, func(t *testing.T) {
			f := newFakePortal(t)
			h := newHarness(t)
			h.connect(f, f.publisher("bravo"))
			code, _, errOut := h.run("servers", "register", "--slug", "status", "--url", "https://status.example.com/mcp", "--timeout-seconds", value)
			if code != ExitUsage || countWrites(f) != 0 {
				t.Fatalf("timeout %s: exit %d, writes %d: %s", value, code, countWrites(f), errOut)
			}
		})
	}
}
