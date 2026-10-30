package ompcli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/pkg/ompclient"
)

// Lossless authority: omp keeps a selected tool's curation and a grant's
// deadline through every change it makes, declares them in export, and refuses
// (before any write) what it cannot keep.

const (
	curatedPolicy   = `{"nameOverride":"check_team","descriptionOverride":"Our region only","constraints":{"limit":{"allowed":[2,3]},"region":{"fixed":"us"}}}`
	checkDefinition = `{"name":"check","description":"Check","inputSchema":{"type":"object","properties":{"region":{"type":"string"},"limit":{"type":"integer","enum":[2,3,4]}}}}`
)

// curate makes the first selected tool of a gateway a curated one, as the web UI would.
func curate(f *fakePortal, gateway string) *ompclient.GatewayCapability {
	it := &f.gateways[gateway].caps[0]
	fp := "fingerprint-1"
	it.BaseFingerprint, it.Fingerprint = &fp, &fp
	it.Curation = json.RawMessage(curatedPolicy)
	it.OriginalDefinition = json.RawMessage(checkDefinition)
	it.ExposedName = "check_team"
	return it
}

func platformHarness(t *testing.T) (*fakePortal, *harness) {
	t.Helper()
	f := newFakePortal(t)
	seedPlatform(f)
	h := newHarness(t)
	h.connect(f, f.platformAdmin())
	return f, h
}

// writes lists the mutating requests the CLI made.
func writes(f *fakePortal) []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedRequest
	for _, r := range f.requests {
		if r.Method != "GET" {
			out = append(out, r)
		}
	}
	return out
}

func exportOf(t *testing.T, h *harness, args ...string) string {
	t.Helper()
	code, out, errOut := h.run(append([]string{"export"}, args...)...)
	if code != 0 {
		t.Fatalf("export: %d %s", code, errOut)
	}
	return out
}

// withCaps is the exported document with more capabilities selected on its
// first gateway (the curation of the exported ones stays as exported).
func withCaps(t *testing.T, doc string, extra ...CapabilityRef) string {
	t.Helper()
	f, err := ParseFile([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	caps := append(*f.Gateways[0].Capabilities, extra...)
	f.Gateways[0].Capabilities = &caps
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func importFile(t *testing.T, h *harness, doc string, args ...string) (int, string, string) {
	t.Helper()
	path := writeTempFile(t, "omp.yaml", doc, 0o600)
	return h.run(append([]string{"import", "-f", path}, args...)...)
}

func mustRefuse(t *testing.T, f *fakePortal, h *harness, doc, contain string) {
	t.Helper()
	before := len(writes(f))
	for _, args := range [][]string{{"--plan"}, {}} {
		code, out, errOut := importFile(t, h, doc, args...)
		if code != ExitUsage || !strings.Contains(errOut, "refused") || !strings.Contains(errOut, contain) || !strings.Contains(errOut, "Nothing was changed") {
			t.Fatalf("import %v: exit %d\nout: %s\nerr: %s\nwant a refusal mentioning %q", args, code, out, errOut, contain)
		}
	}
	if after := len(writes(f)); after != before {
		t.Fatalf("a refused import wrote: %+v", writes(f)[before:])
	}
}

// ---- curation ---------------------------------------------------------------

func TestExportCarriesCurationAndImportOfItIsZeroDrift(t *testing.T) {
	f, h := platformHarness(t)
	curate(f, "support")
	exported := exportOf(t, h)
	for _, want := range []string{"curation:", "nameOverride: check_team", "descriptionOverride: Our region only", "fixed: us", "allowed:", "- 2", "- 3"} {
		if !strings.Contains(exported, want) {
			t.Errorf("export lacks %q:\n%s", want, exported)
		}
	}
	if code, out, errOut := importFile(t, h, exported, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("export -> plan: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := importFile(t, h, exported); code != 0 {
		t.Fatalf("export -> import: %d %q", code, errOut)
	}
	if n := len(writes(f)); n != 0 {
		t.Fatalf("importing an unchanged export wrote %d times", n)
	}
	if again := exportOf(t, h); again != exported {
		t.Errorf("export is not stable:\n%s\n%s", exported, again)
	}
	var asJSON struct {
		Gateways []struct {
			Capabilities []struct {
				Curation *struct{ NameOverride string }
			}
		}
	}
	if err := json.Unmarshal([]byte(exportOf(t, h, "--json")), &asJSON); err != nil || asJSON.Gateways[0].Capabilities[0].Curation.NameOverride != "check_team" {
		t.Errorf("--json export: %v %+v", err, asJSON)
	}
}

func TestExportedCurationCannotWidenAGatewayElsewhere(t *testing.T) {
	src, h := platformHarness(t)
	curate(src, "support")
	exported := exportOf(t, h)
	// A portal where the tool is selectable but the gateway does not exist (or the tool is not selected).
	dst := newFakePortal(t)
	dst.options = src.options
	h2 := newHarness(t)
	h2.connect(dst, dst.platformAdmin())
	withOwners := strings.ReplaceAll(strings.ReplaceAll(exported, "    name: Bravo\n", "    name: Bravo\n    ownerEmail: b@example.com\n"), "    name: Old\n", "    name: Old\n    ownerEmail: b@example.com\n")
	mustRefuse(t, dst, h2, withOwners, "is not selected yet and the file gives it a curation")
	if len(dst.gateways) != 0 || len(dst.teams) != 0 {
		t.Fatal("the refusal came after something was created")
	}
	// Selecting the tool uncurated is what the refusal asks for, and it is possible.
	plain := strings.Join(trimCuration(strings.Split(withOwners, "\n")), "\n")
	if code, _, errOut := importFile(t, h2, plain); code != 0 {
		t.Fatalf("uncurated import: %d %s", code, errOut)
	}
	if len(dst.gateways["support"].caps) != 1 || len(dst.gateways["support"].caps[0].Curation) != 0 {
		t.Fatal("the tool was not selected plain")
	}
	// Now the declared curation is a difference from the portal's, which omp cannot write.
	mustRefuse(t, dst, h2, withOwners, "differs from the portal's (none)")
}

// trimCuration drops the curation block of an exported document.
func trimCuration(lines []string) []string {
	var out []string
	skip := false
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "curation:") {
			skip = true
			continue
		}
		if skip && strings.HasPrefix(l, "          ") {
			continue
		}
		skip = false
		out = append(out, l)
	}
	return out
}

func TestSelectionChangesKeepTheCuratedToolsPolicy(t *testing.T) {
	f, h := platformHarness(t)
	it := curate(f, "support")
	before := curationSig(*it)
	exported := exportOf(t, h)
	// Add a prompt and a tool; the curated tool is listed without any curation key.
	doc := withCaps(t, exported, CapabilityRef{Server: "status", Kind: "prompt", Name: "summarize"}, CapabilityRef{Server: "billing", Kind: "tool", Name: "bill"})
	if code, out, errOut := importFile(t, h, doc); code != 0 {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}
	ws := writes(f)
	var put recordedRequest
	for _, w := range ws {
		if w.Method == "PUT" {
			put = w
		}
	}
	var sent struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(put.Body, &sent); err != nil || len(sent.Items) != 3 {
		t.Fatalf("PUT body: %v %s", err, put.Body)
	}
	for _, item := range sent.Items {
		for _, forbidden := range []string{"curation", "expectedFingerprint", "minRole"} {
			if _, ok := item[forbidden]; ok {
				t.Errorf("the selection write sent %q: a token cannot write curation, and sending it would be refused or replace the policy: %s", forbidden, put.Body)
			}
		}
	}
	var kept *ompclient.GatewayCapability
	for i := range f.gateways["support"].caps {
		if c := &f.gateways["support"].caps[i]; c.Name == "check" {
			kept = c
		}
	}
	if kept == nil || curationSig(*kept) != before || kept.ExposedName != "check_team" {
		t.Fatalf("the curated tool lost its policy: %+v", kept)
	}
	// And removing the other capabilities again keeps it too, plan first.
	if code, out, _ := importFile(t, h, exported, "--plan"); code != ExitChanges || !strings.Contains(out, "(none)") {
		t.Fatalf("plan back: %d %s", code, out)
	}
	if code, _, errOut := importFile(t, h, exported); code != 0 {
		t.Fatalf("remove: %d %s", code, errOut)
	}
	if kept = &f.gateways["support"].caps[0]; len(f.gateways["support"].caps) != 1 || curationSig(*kept) != before {
		t.Fatalf("the curated tool lost its policy on removal of others: %+v", f.gateways["support"].caps)
	}
}

func TestRemovingACuratedToolIsLoudNotSilent(t *testing.T) {
	f, h := platformHarness(t)
	curate(f, "support")
	doc := "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  capabilities: []\n"
	code, out, errOut := importFile(t, h, doc, "--plan")
	if code != ExitChanges || !strings.Contains(out, "its curation is deleted with it") || !strings.Contains(errOut, "deletes its curation policy") {
		t.Fatalf("plan: %d %q %q", code, out, errOut)
	}
}

func TestDeclaredCurationIsComparedAsThePortalStoresIt(t *testing.T) {
	f, h := platformHarness(t)
	curate(f, "support")
	base := "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  capabilities:\n  - server: status\n    kind: tool\n    name: check\n"
	same := base + "    curation:\n      nameOverride: check_team\n      descriptionOverride: Our region only\n      constraints:\n        region: {fixed: us}\n        # 9 is outside the schema's enum [2,3,4]: the portal narrows allowed lists to it.\n        limit: {allowed: [2, 3, 9]}\n"
	if code, out, errOut := importFile(t, h, same, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("narrowed allowed list should match: %d %q %q", code, out, errOut)
	}
	differs := map[string]string{
		"another fixed value":     "    curation: {nameOverride: check_team, descriptionOverride: Our region only, constraints: {region: {fixed: eu}, limit: {allowed: [2, 3]}}}\n",
		"a dropped constraint":    "    curation: {nameOverride: check_team, descriptionOverride: Our region only, constraints: {limit: {allowed: [2, 3]}}}\n",
		"an empty policy":         "    curation: {}\n",
		"declared as no policy":   "    curation: null\n",
		"a widened allowed list":  "    curation: {nameOverride: check_team, descriptionOverride: Our region only, constraints: {region: {fixed: us}, limit: {allowed: [2, 3, 4]}}}\n",
		"another name":            "    curation: {nameOverride: other, descriptionOverride: Our region only, constraints: {region: {fixed: us}, limit: {allowed: [2, 3]}}}\n",
		"a value off the schema":  "    curation: {nameOverride: check_team, descriptionOverride: Our region only, constraints: {region: {fixed: 5}, limit: {allowed: [2, 3]}}}\n",
		"an argument not in tool": "    curation: {nameOverride: check_team, descriptionOverride: Our region only, constraints: {nope: {fixed: 1}}}\n",
	}
	for name, curation := range differs {
		t.Run(name, func(t *testing.T) {
			mustRefuse(t, f, h, base+curation, "tool status/check")
		})
	}
	// Declared as none is fine for a selection that has no policy; an absent key never matters.
	_, h2 := platformHarness(t)
	if code, out, errOut := importFile(t, h2, base+"    curation: null\n", "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("null on an uncurated tool: %d %q %q", code, out, errOut)
	}
	if code, _, _ := importFile(t, h, base, "--plan"); code != 0 {
		t.Fatal("an absent curation key must leave the policy alone")
	}
}

func TestRefusalMessagesNeverShowConstraintValues(t *testing.T) {
	f, h := platformHarness(t)
	curate(f, "support")
	base := "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  capabilities:\n  - server: status\n    kind: tool\n    name: check\n"
	secret := "sk-live-hunter2-secret"
	code, _, errOut := importFile(t, h, base+"    curation: {constraints: {region: {fixed: "+secret+"}}}\n")
	if code != ExitUsage || strings.Contains(errOut, secret) || strings.Contains(errOut, "fixed: us") {
		t.Fatalf("exit %d, the refusal discloses a value: %s", code, errOut)
	}
	out := exportOf(t, h, "--only", "platform")
	if !strings.Contains(out, "fixed: us") {
		t.Fatal("export is the one place the policy is written (documented as sensitive)")
	}
}

func TestStaleAndUnreadableCurationFailClosed(t *testing.T) {
	f, h := platformHarness(t)
	it := curate(f, "support")
	stale := true
	it.Stale = &stale
	exported := exportOf(t, h)
	if !strings.Contains(exported, "nameOverride: check_team") {
		t.Fatalf("a stale policy is exported as stored:\n%s", exported)
	}
	code, _, errOut := h.run("export")
	if code != 0 || !strings.Contains(errOut, "is stale") {
		t.Errorf("no warning for a stale policy: %q", errOut)
	}
	if code, out, errOut := importFile(t, h, exported, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("stale round trip: %d %q %q", code, out, errOut)
	}

	// The portal says the tool is curated but returns no policy (a limited read).
	it.Curation = nil
	code, out, errOut := h.run("export")
	if code == 0 || !strings.Contains(errOut, "curation_unreadable") || strings.Contains(out, "slug: support") {
		t.Fatalf("export of an unreadable policy: %d %q %q", code, out, errOut)
	}
	// Selection changes still keep it (the portal preserves what is omitted)...
	plain := "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  capabilities:\n  - {server: status, kind: tool, name: check}\n  - {server: status, kind: prompt, name: summarize}\n"
	if code, _, errOut := importFile(t, h, plain); code != 0 {
		t.Fatalf("add with an unreadable policy: %d %s", code, errOut)
	}
	// ...but nothing can be declared about a policy omp cannot see.
	declared := strings.Replace(plain, "{server: status, kind: tool, name: check}", "{server: status, kind: tool, name: check, curation: null}", 1)
	mustRefuse(t, f, h, declared, "did not return it")
}

func TestARejectedCurationWriteIsNeverRetriedWithAFixedUpPolicy(t *testing.T) {
	// A portal that refuses curation from tokens is the contract; make sure omp
	// never sends the field, even when the file declares a matching policy.
	f, h := platformHarness(t)
	curate(f, "support")
	exported := exportOf(t, h)
	doc := withCaps(t, exported, CapabilityRef{Server: "status", Kind: "prompt", Name: "summarize"})
	if code, _, errOut := importFile(t, h, doc); code != 0 {
		t.Fatalf("%d %s", code, errOut)
	}
	for _, w := range writes(f) {
		if strings.Contains(string(w.Body), "curation") || strings.Contains(string(w.Body), "expectedFingerprint") {
			t.Fatalf("a request carried curation: %s %s %s", w.Method, w.Path, w.Body)
		}
	}
}

// ---- concurrency ------------------------------------------------------------

func TestConcurrentGatewayEditIsAConflictNotRebased(t *testing.T) {
	f, h := platformHarness(t)
	gw := f.gateways["support"]
	extra := f.options[1] // the prompt
	// After the CLI read the selection, someone else adds the prompt (the web UI).
	f.afterCapsGet = func(g *fakeGateway) {
		g.caps = append(g.caps, ompclient.GatewayCapability{CapabilityId: extra.CapabilityId, Kind: extra.Kind, Name: extra.Name, ServerSlug: extra.ServerSlug})
		g.Revision++
	}
	doc := "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  capabilities:\n  - {server: billing, kind: tool, name: bill}\n"
	code, _, errOut := importFile(t, h, doc)
	if code != ExitConflict || !strings.Contains(errOut, "revision_conflict") || !strings.Contains(errOut, "run the command again") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if len(gw.caps) != 2 || gw.caps[1].Name != "summarize" {
		t.Fatalf("the concurrent edit was overwritten: %+v", gw.caps)
	}
	var puts []recordedRequest
	for _, w := range writes(f) {
		if w.Method == "PUT" {
			puts = append(puts, w)
		}
	}
	if len(puts) != 1 || puts[0].IfMatch != `"2"` {
		t.Fatalf("the write must carry the revision the plan read (2), once: %+v", puts)
	}
	// Re-planning shows the new truth, and applying it works.
	if code, _, errOut := importFile(t, h, doc); code != 0 {
		t.Fatalf("second run: %d %s", code, errOut)
	}
	if len(gw.caps) != 1 || gw.caps[0].Name != "bill" {
		t.Fatalf("converged to %+v", gw.caps)
	}
}

func TestGatewayChangedBetweenTheListAndTheSelectionReadIsAConflict(t *testing.T) {
	f, h := platformHarness(t)
	f.afterGatewayList = func() { f.gateways["support"].Revision++ }
	doc := "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  capabilities:\n  - {server: billing, kind: tool, name: bill}\n"
	code, _, errOut := importFile(t, h, doc)
	if code != ExitConflict || !strings.Contains(errOut, "changed while the plan was being read") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if n := len(writes(f)); n != 0 {
		t.Fatalf("wrote %d times", n)
	}
}

func TestTheRevisionOnlyAdvancesWithItsOwnWrites(t *testing.T) {
	// A settings change and a selection change in one step: the selection write
	// uses the revision the settings write returned, and nothing else.
	f, h := platformHarness(t)
	doc := "schema: omp/v1\ngateways:\n- slug: support\n  name: Renamed\n  capabilities:\n  - {server: billing, kind: tool, name: bill}\n"
	if code, _, errOut := importFile(t, h, doc); code != 0 {
		t.Fatalf("%d %s", code, errOut)
	}
	ws := writes(f)
	if len(ws) != 2 || ws[0].Method != "PATCH" || ws[0].IfMatch != `"2"` || ws[1].Method != "PUT" || ws[1].IfMatch != `"3"` {
		t.Fatalf("writes: %+v", ws)
	}
}

// ---- grants -----------------------------------------------------------------

func setGrant(f *fakePortal, gw string, i int, expires *time.Time, scope []string) {
	g := &f.gateways[gw].grants[i]
	g.ExpiresAt = expires
	if scope != nil {
		cl := make([]ompclient.ToolClass, len(scope))
		for j, s := range scope {
			cl[j] = ompclient.ToolClass(s)
		}
		g.ToolScope = &ompclient.ToolScope{Classes: &cl}
	}
}

func inDays(d float64) *time.Time {
	t := time.Now().Add(time.Duration(d * float64(24*time.Hour)))
	return &t
}

func grantDoc(grant string) string {
	return "schema: omp/v1\ngateways:\n- slug: support\n  name: Support tools\n  grants:\n" + grant
}

func lastGrantPost(t *testing.T, f *fakePortal) ompclient.GatewayGrantCreate {
	t.Helper()
	var out ompclient.GatewayGrantCreate
	found := false
	for _, w := range writes(f) {
		if w.Method == "POST" && strings.HasSuffix(w.Path, "/grants") {
			found = true
			out = ompclient.GatewayGrantCreate{}
			if err := json.Unmarshal(w.Body, &out); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("no grant was created")
	}
	return out
}

func TestExportAndPlanCarryGrantDeadlines(t *testing.T) {
	f, h := platformHarness(t)
	exp := inDays(10.5)
	setGrant(f, "support", 1, exp, nil)
	exported := exportOf(t, h)
	if !strings.Contains(exported, "expiresAt: \""+exp.UTC().Format(time.RFC3339Nano)+"\"") {
		t.Fatalf("export lacks the deadline:\n%s", exported)
	}
	if !strings.Contains(exported, "toolScope: null") {
		t.Fatalf("an unrestricted grant is declared explicitly:\n%s", exported)
	}
	if code, out, errOut := importFile(t, h, exported, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("zero drift: %d %q %q", code, out, errOut)
	}
	// Leaving the deadline out keeps it; so does a deadline to the day.
	if code, out, _ := importFile(t, h, grantDoc("  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {team: bravo}\n"), "--plan"); code != 0 {
		t.Fatalf("an omitted deadline is not drift: %d %s", code, out)
	}
	// Export is JSON-able too.
	if !strings.Contains(exportOf(t, h, "--json"), `"expiresAt": "`+exp.UTC().Format(time.RFC3339Nano)+`"`) {
		t.Error("--json export lacks the deadline")
	}
}

func TestScopeChangeKeepsTheDeadlineNeverExtendsIt(t *testing.T) {
	f, h := platformHarness(t)
	exp := inDays(10.5)
	setGrant(f, "support", 1, exp, nil) // ann: read-only until +10.5 days
	code, out, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read, write]}}\n"), "--plan")
	if code != ExitChanges || !strings.Contains(out, "toolScope") {
		t.Fatalf("plan: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read, write]}}\n")); code != 0 {
		t.Fatalf("apply: %d %q %q", code, out, errOut)
	}
	post := lastGrantPost(t, f)
	if post.ExpiresInDays == nil || *post.ExpiresInDays != 10 {
		t.Fatalf("the recreated grant must expire no later than before (10 whole days of 10.5): %v", post.ExpiresInDays)
	}
	var ann *ompclient.GatewayGrant
	for i := range f.gateways["support"].grants {
		if g := &f.gateways["support"].grants[i]; g.User != nil {
			ann = g
		}
	}
	if ann == nil || ann.ExpiresAt == nil || ann.ExpiresAt.After(*exp) || ann.ExpiresAt.Before(exp.Add(-25*time.Hour)) {
		t.Fatalf("deadline after the change: %v (was %v)", ann, exp)
	}
	if ann.ToolScope == nil || len(*ann.ToolScope.Classes) != 2 {
		t.Fatalf("scope: %+v", ann.ToolScope)
	}
	// The order is removal, then creation, per grant, and nothing else is touched.
	ws := writes(f)
	if len(ws) != 2 || ws[0].Method != "DELETE" || ws[1].Method != "POST" {
		t.Fatalf("writes: %+v", ws)
	}
	// Converged, including against the exported deadline of before.
	if code, out, _ := importFile(t, h, exportOf(t, h), "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("converged: %d %s", code, out)
	}
}

func TestScopeChangeOfAGrantExpiringInLessThanADayIsRefused(t *testing.T) {
	f, h := platformHarness(t)
	setGrant(f, "support", 1, inDays(0.5), nil)
	mustRefuse(t, f, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read, write]}}\n"), "less than one whole day")
	// The grant is untouched, and so is its deadline.
	if g := f.gateways["support"].grants[1]; g.ExpiresAt == nil || len(f.gateways["support"].grants) != 2 {
		t.Fatalf("grants: %+v", f.gateways["support"].grants)
	}
	// Changing nothing about it is fine.
	if code, _, _ := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n"), "--plan"); code != 0 {
		t.Fatal("an unchanged expiring grant is not drift")
	}
}

func TestAnOmittedScopeAndDeadlineLeaveAnExistingGrantAlone(t *testing.T) {
	f, h := platformHarness(t)
	setGrant(f, "support", 1, inDays(30), nil)
	if code, out, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com}\n"), "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("omitted scope/deadline: %d %q %q", code, out, errOut)
	}
	// An explicit null widens, and says so in the plan.
	code, out, _ := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: null}\n"), "--plan")
	if code != ExitChanges || !strings.Contains(out, `toolScope: "classes=[read] tools=-" -> "unrestricted"`) {
		t.Fatalf("explicit unrestricted: %d %s", code, out)
	}
	// A new grant with no scope is unrestricted and permanent, as documented.
	if code, _, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com}\n  - {group: ops}\n")); code != 0 {
		t.Fatalf("new grant: %d %s", code, errOut)
	}
	post := lastGrantPost(t, f)
	if post.ExpiresInDays != nil || post.ToolScope != nil || post.Group == nil || *post.Group != "ops" {
		t.Fatalf("new grant body: %+v", post)
	}
}

func TestExpiredGrantsAreNeverExtendedOrRecreatedPermanently(t *testing.T) {
	f, h := platformHarness(t)
	past := time.Now().Add(-48 * time.Hour)
	setGrant(f, "support", 1, &past, nil)
	exported := exportOf(t, h)
	if code, _, errOut := h.run("export"); code != 0 || !strings.Contains(errOut, "grants nothing") {
		t.Errorf("no warning for an expired grant: %q", errOut)
	}
	// The file records the expired grant as it is: no drift, no write.
	if code, out, _ := importFile(t, h, exported, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("expired round trip: %d %s", code, out)
	}
	// Declaring it without a deadline (or with a past one, or a changed scope) would recreate it permanently or with no force.
	for name, grant := range map[string]string{
		"no deadline":      "  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n",
		"another past one": "  - {team: bravo}\n  - {userEmail: ann@example.com, expiresAt: '" + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + "'}\n",
		"changed scope":    "  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [write]}, expiresAt: '" + past.UTC().Format(time.RFC3339Nano) + "'}\n",
	} {
		t.Run(name, func(t *testing.T) { mustRefuse(t, f, h, grantDoc(grant), "expired at") })
	}
	if f.gateways["support"].grants[1].ExpiresAt == nil {
		t.Fatal("the grant was changed")
	}
	// Renewal is explicit: a future deadline replaces it (the portal replaces an elapsed row), keeping its ceiling.
	renew := inDays(20.2)
	if code, _, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, expiresAt: '"+renew.UTC().Format(time.RFC3339)+"'}\n")); code != 0 {
		t.Fatalf("renewal: %d %s", code, errOut)
	}
	post := lastGrantPost(t, f)
	if post.ExpiresInDays == nil || *post.ExpiresInDays != 20 || post.ToolScope == nil {
		t.Fatalf("renewal body: %+v", post)
	}
	if n := len(writes(f)); n != 1 {
		t.Fatalf("renewal needs one creation and no removal, got %d writes", n)
	}
	// Omitting an expired grant removes the row, and the plan says what it is.
	f2, h2 := platformHarness(t)
	setGrant(f2, "support", 1, &past, nil)
	code, out, _ := importFile(t, h2, grantDoc("  - {team: bravo}\n"), "--plan")
	if code != ExitChanges || !strings.Contains(out, "(expired ") {
		t.Fatalf("plan: %d %s", code, out)
	}
}

func TestDeclaredDeadlinesOfNewAndExistingGrants(t *testing.T) {
	f, h := platformHarness(t)
	want := inDays(15.4)
	if code, _, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {group: ops, expiresAt: '"+want.UTC().Format(time.RFC3339)+"'}\n")); code != 0 {
		t.Fatalf("new grant with a deadline: %d %s", code, errOut)
	}
	post := lastGrantPost(t, f)
	if post.ExpiresInDays == nil || *post.ExpiresInDays != 15 {
		t.Fatalf("days: %v", post.ExpiresInDays)
	}
	// The result is in the window the file's deadline allows, so the next plan has no drift.
	doc := grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {group: ops, expiresAt: '" + want.UTC().Format(time.RFC3339) + "'}\n")
	if code, out, _ := importFile(t, h, doc, "--plan"); code != 0 || !strings.Contains(out, "No changes") {
		t.Fatalf("converged: %d %s", code, out)
	}
	// Extension is refused; shortening works; an existing permanent grant can be given a deadline.
	later := inDays(40)
	mustRefuse(t, f, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {group: ops, expiresAt: '"+later.UTC().Format(time.RFC3339)+"'}\n"), "never extends")
	sooner := inDays(5.6)
	if code, _, errOut := importFile(t, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {group: ops, expiresAt: '"+sooner.UTC().Format(time.RFC3339)+"'}\n")); code != 0 {
		t.Fatalf("shorten: %d %s", code, errOut)
	}
	if post := lastGrantPost(t, f); post.ExpiresInDays == nil || *post.ExpiresInDays != 5 {
		t.Fatalf("shortened to %v days", post.ExpiresInDays)
	}
	if code, _, errOut := importFile(t, h, grantDoc("  - {team: bravo, expiresAt: '"+inDays(7.3).UTC().Format(time.RFC3339)+"'}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {group: ops}\n")); code != 0 {
		t.Fatalf("permanent to expiring: %d %s", code, errOut)
	}
	if g := f.gateways["support"].grants; len(g) != 3 {
		t.Fatalf("grants: %+v", g)
	}
	// Refusals for what the portal cannot set.
	for name, e := range map[string]string{"past": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "today": time.Now().Add(6 * time.Hour).UTC().Format(time.RFC3339), "far": inDays(400).UTC().Format(time.RFC3339)} {
		t.Run(name, func(t *testing.T) {
			mustRefuse(t, f, h, grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read]}}\n  - {group: new-"+name+", expiresAt: '"+e+"'}\n"), "expire")
		})
	}
}

func TestAFailedCreateAfterTheRemovalRestoresThePreviousGrant(t *testing.T) {
	f, h := platformHarness(t)
	exp := inDays(10.5)
	setGrant(f, "support", 1, exp, nil)
	doc := grantDoc("  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [read, write]}}\n")
	f.grantPostFail = []int{500}
	code, _, errOut := importFile(t, h, doc)
	if code != ExitUnavailable || !strings.Contains(errOut, "was removed to change it") || !strings.Contains(errOut, "the previous grant was created again") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var ann *ompclient.GatewayGrant
	for i := range f.gateways["support"].grants {
		if g := &f.gateways["support"].grants[i]; g.User != nil {
			ann = g
		}
	}
	if ann == nil || ann.ToolScope == nil || len(*ann.ToolScope.Classes) != 1 || ann.ExpiresAt == nil || ann.ExpiresAt.After(*exp) {
		t.Fatalf("the previous grant was not restored as it was (scope read, deadline no later): %+v", ann)
	}
	// If the restoration fails too, the error says what to do and the state is honest.
	f2, h2 := platformHarness(t)
	setGrant(f2, "support", 1, inDays(10.5), nil)
	f2.grantPostFail = []int{500, 500}
	code, _, errOut = importFile(t, h2, doc)
	if code != ExitUnavailable || !strings.Contains(errOut, "could not be created again") || !strings.Contains(errOut, "re-create it by hand") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if n := len(f2.gateways["support"].grants); n != 1 {
		t.Fatalf("expected the one grant that was never touched, got %d", n)
	}
}

func TestAGrantThatCannotBeRecreatedBlocksTheWholeStepNotJustItself(t *testing.T) {
	// A gateway rename and a grant whose deadline leaves no whole day: nothing is written.
	f, h := platformHarness(t)
	setGrant(f, "support", 1, inDays(1.0+3.0/(24*60)), nil) // 1 day 3 minutes: floors to 0 once the slack is counted
	mustRefuse(t, f, h, "schema: omp/v1\ngateways:\n- slug: support\n  name: Renamed gateway\n  grants:\n  - {team: bravo}\n  - {userEmail: ann@example.com, toolScope: {classes: [write]}}\n", "less than one whole day")
}

// ---- negative proof: the hazards are real in this model ----------------------

func rawCall(t *testing.T, f *fakePortal, token, method, path string, body any, ifMatch string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.URL()+path, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// What the CLI used to do, done by hand, loses authority in the same fake the
// CLI tests above pass against. If this test stopped failing the way it does, the
// regression tests above would prove nothing.
func TestTheOldRemoveAndRecreateLosesTheDeadlineAndTheOldRebasePutsOverwrites(t *testing.T) {
	f := newFakePortal(t)
	seedPlatform(f)
	token := f.platformAdmin()
	gw := f.gateways["support"]
	setGrant(f, "support", 1, inDays(10.5), []string{"read"})
	old := gw.grants[1]

	// Old behaviour 1: a scope change was a removal and a creation without a deadline.
	if st, _ := rawCall(t, f, token, "DELETE", "/v1/admin/gateways/"+gw.Id.String()+"/grants/"+old.Id.String(), nil, ""); st != 200 {
		t.Fatal(st)
	}
	st, body := rawCall(t, f, token, "POST", "/v1/admin/gateways/"+gw.Id.String()+"/grants", map[string]any{"subjectKind": "user", "userEmail": "ann@example.com", "toolScope": map[string]any{"classes": []string{"read", "write"}}}, "")
	var created struct{ Data ompclient.GatewayGrant }
	if st != 201 || json.Unmarshal(body, &created) != nil || created.Data.ExpiresAt != nil {
		t.Fatalf("the portal should have created a permanent grant here: %d %s", st, body)
	}

	// Old behaviour 2: re-read the revision just before writing the planned selection.
	planned := []map[string]any{{"capabilityId": f.options[2].CapabilityId.String()}}
	gw.caps = append(gw.caps, ompclient.GatewayCapability{CapabilityId: f.options[1].CapabilityId, Kind: f.options[1].Kind, Name: "summarize", ServerSlug: "status"}) // a concurrent edit
	gw.Revision++
	_, latest := rawCall(t, f, token, "GET", "/v1/admin/gateways/"+gw.Id.String()+"/capabilities", nil, "")
	var caps struct{ Data ompclient.GatewayCapabilities }
	_ = json.Unmarshal(latest, &caps)
	if st, _ := rawCall(t, f, token, "PUT", "/v1/admin/gateways/"+gw.Id.String()+"/capabilities", map[string]any{"items": planned}, `"`+strconv.FormatInt(int64(caps.Data.Revision), 10)+`"`); st != 200 {
		t.Fatalf("the stale selection should have been accepted: %d", st)
	}
	for _, c := range gw.caps {
		if c.Name == "summarize" {
			t.Fatal("the concurrent edit survived: the hazard is not modelled")
		}
	}
}
