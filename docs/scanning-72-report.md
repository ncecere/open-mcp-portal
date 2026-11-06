# Issue 72 implementation review (2026-11-04)

Branch: `feat/72-definition-scanning`, from v0.13.1. Local review candidate;
no push, PR, release, UI or call-path change. Not every acceptance item is complete.

## Implementation and API

`internal/definitionscan` implements version `v1`, JSON traversal, NFKC/folding,
local detectors, limits and panic recovery. `internal/registry` scans before the
refresh transaction, writes evidence through a savepoint in that transaction,
rescans stored definitions and elects a backfill leader (ten servers per minute).
Two concurrent batches per process; 25 ms cooperative per-definition deadline,
two-second batch budget, 64 KiB, depth 32 and 128 findings limits. A regex cannot
be interrupted mid-match; overruns become incomplete.

Migration `00061` (written as `00057`, renumbered at integration because `main` already had 58–59) adds `definition_scan_mode` (shadow default), `scan_revision`,
`definition_scans` (including zero-finding status) and `scan_findings`.
Both child tables cascade with capabilities, servers and teams. Findings are
replaced at rescan, independent of payload/call retention. No ciphertext or call
child table. Existing dynamic `ReconcileRuntimeGrants` gives ordinary public
tables CRUD and sequences USAGE; protected audit/call privileges are unchanged.

All new operations require browser sessions (tokens receive 403 token_not_allowed):

- `GET`/`PUT /v1/admin/settings/scanning`: platform readers/admin writer,
  If-Match, 409 conflict and before/after audit without content.
- `GET /v1/admin/scanning/rules`: platform readers.
- `GET /v1/teams/{team}/mcp-servers/{serverId}/scan-findings`: capability visibility.
- `POST /v1/teams/{team}/mcp-servers/{serverId}/scan`: editors; stored definitions only.
- Admin equivalents of the last two operations under `/v1/admin/mcp-servers/{serverId}`;
  rescan requires platform admin. Generic management rate limits apply.

Rule ids (32), ruleset `v1`:

- `secret.{private_key_pem,bearer,jwt,gateway_credentials,github,gitlab,slack,google,aws_access_key,url_userinfo}`.
- `unicode.{tag_chars,bidi_override,bidi_isolate_unbalanced,bidi_mark,invisible,joiner,variation_selector,control,private_use,mixed_script_name,confusable_name}`.
- `poison.{override_instructions,concealment,sensitive_path,pseudo_tag,precondition,cross_tool_reference,parameter_sink,external_url,encoded_blob}`.
- `length.{description,schema_text}`.

Existing shared secret rules and capture tests are unchanged. Findings do not
alter definitions, fingerprints, approval state or digest inputs.

## Acceptance evidence

| Item | Tests / remaining evidence |
| --- | --- |
| A1 | **Pass locally; scheduled archive pending.** Definition-v1 aggregate CLI now covers all 32 rules/four groups; 245 scored cases, 35 targeted TP, 0 FN and 0 benign FP; four ledger misses excluded. Public pinned-source exploratory report has five findings, no labelled precision/recall. See cleanup evidence below. Previous evidence:  `TestDefinitionCorpus`, `TestDefinitionRemainingGroups`, `TestDefinitionSecretCorpus`, `TestDefinitionBenignRate`, `TestDefinitionKnownMissLedger`, `TestConfusableNames`. Primitive/capture fixtures and assertions unchanged. Authored benign samples are synthetic and narrow. New stage fixtures are test-only; the aggregate corpus CLI still reports primitive findings. The stage ledger separately pins semantic paraphrases, spread selectors and split-field length misses. Existing public workflow/manifest unchanged; no new hosted run or public download claimed. |
| A2 | **Partial.** Added process-CPU and allocation gates, plus a real paginated refresh with 2,000 canonical 64 KiB definitions. Measured/gate deviations and retained gaps below. Previous evidence:  `TestDefinitionTailAndRefreshBudget`, `BenchmarkDefinition`, `BenchmarkDefinitionPathological`; direct gateway import check and empty `git diff v0.13.1 -- internal/mcpgw`. Not complete: strict 8x allocation gate, added-CPU/2x-headroom evidence, call-path benchmark and actual 2,000-definition upstream refresh integration (the test exercises scanner workload only). |
| A3 | `TestDefinitionPersistencePrivacyAndFailure`: public-table dumps excluding only definition, debug logs, service API output, registered metrics, arbitrary key/parameter-name and unmatched-text canaries. `TestDefinitionSchemaConstraints`: pinned columns and invalid ids. `TestScanningPrivacySentinel` adds a matched-secret canary and checks all new read/rescan HTTP responses, settings errors, exported spans, debug logs, metrics and both public/private-schema database dumps in both role modes. |
| A4 | Fixed catalog, KnownRule bounding and unknown-to-other metric label behavior; registered in appCollectors for `TestOpsArtifactsUseRealMetrics`. `TestScanMetricCardinality` enumerates catalog labels, rejects unknown catalog lookup, verifies unknown-to-other collapse and gathered dimensions. The catalog is static; no dynamic registration API exists. |
| A5 | **Pass for unchanged refreshes locally.** `TestScanRefreshBytesIdentical` compares serialized complete refresh results, stored capability rows and review digests across off/shadow, normalizing only the pre-existing `last_seen_at` refresh clock. Definitions, fingerprints, approvals and publish fields remain byte-identical. Previous evidence:  `TestScanRefreshShadowIsNonInterfering`: capability rows equal except pre-existing refresh timestamp; ruleset changes and findings-write constraint failure preserve capability state in persistence test. Existing review-digest tests unchanged. Persistence test directly asserts ruleset-version changes preserve ReviewDigest. A complete refresh-response byte comparison remains outstanding. |
| A6 | `TestLimitsAndPrivacy`, `TestRulePanicIsIncomplete`: cancellation, depth, size and panic return incomplete. |
| A8 | `TestScanningSettingsAPI`, `TestScanningSettingsRevisionAndSession`, authorization matrix and unchanged token matrix: visibility, sessions, audit and 409 conflicts. |
| A10 | Expand-only migration; constraint/cascade tests and standard grant reconciliation. Role-suite results below. Previous-image compatibility not run: existing tooling is kind upgrade smoke; kind is absent. No existing containers/dev databases changed. |
| A11 | Existing x/text promoted for normalization; pinned BSD confusable-skeleton dependency, notice in docs/licenses. No third-party corpus text committed; public manifest and licence-refusal tests unchanged. |
| A12 | Threat-model 7.5, operator setting documentation, design status, roadmap and changelog updated. UI/browser work remains #73. |

## Deviations and review questions

- Arbitrary keys use positional `@N` structural segments rather than reflecting
  escaped/truncated attacker text. They are not literal RFC 6901 member names.
- Separate scan-status table distinguishes missing/incomplete/empty scans.
- Mixed-script detection uses script sets and common East Asian combinations,
  not complete UTS #39 Script_Extensions resolution. Skeletons use pinned 2020
  Unicode data; newer confusables can be missed.
- JWT shapes remain low: high-confidence segment validation is not implemented.
  Description length starts at info pending calibration. Cross-tool and parameter
  sink checks are lexical, without gateway composition or semantic analysis.
- No capability-summary field or operations dashboard panel is added; the
  dedicated endpoint returns per-capability states.

The coordinator should not close #72 without completing or explicitly resolving
these acceptance gaps. Heuristics finding nothing does not mean a definition is safe.

## Measurements and gates

Go 1.26.10, Intel Celeron N5105 (four cores), GOFLAGS=-p=2, worker-only Postgres
port 55453. Concurrent validation makes these local figures contended measurements.
Benchmark command:

```
go test -run '^$' -bench BenchmarkDefinition -benchmem -benchtime=200ms -count=3 ./internal/definitionscan ./internal/scancorpus
```

`/tmp/omp72-benchmarks-end.log` (final implementation): 2 KiB
0.155–0.164 ms/op, 5,592 B/op, 21 allocations; 64 KiB
4.694–4.899 ms/op, about 132,568 B/op, 21 allocations. Near-match input:
7.272–7.598 ms/op, about 447,500 B/op; Unicode input:
3.679–4.472 ms/op, about 108,360 B/op; encoded runs:
13.805–14.802 ms/op, about 133,000–137,500 B/op. These averages do not prove
all proposed tail or memory gates. Wall sample (`/tmp/omp72-tail-end.log`):
p99 6.674 ms, 500 × 2 KiB 75.464 ms wall, 2,000 × 64 KiB 2.005 s
with 1,576 incomplete. No CPU/allocation gate is claimed.

Gate results below include earlier full-suite passes and the later cumulative
mode-0 timeout; the latest full-suite attempt is not green. Logs `/tmp/omp72-*`. No browser was used.
Kubernetes/actionlint gates do not apply: deploy/ and .github/ are unchanged.


## Files by area


API/generated:

- `api/openapi.yaml`
- `internal/httpapi/apitypes/types.gen.go`
- `web/src/api/schema.gen.ts`

integration/HTTP/metrics:

- `go.mod`
- `go.sum`
- `internal/app/app.go`
- `internal/httpapi/authz_matrix_policy_test.go`
- `internal/httpapi/mcp_servers.go`
- `internal/httpapi/scanning.go`
- `internal/httpapi/scanning_integration_test.go`
- `internal/observability/metrics.go`
- `internal/observability/scanning.go`
- `internal/registry/discovery.go`
- `internal/registry/scanning.go`
- `internal/registry/scanning_integration_test.go`

scanner/corpus:

- `internal/definitionscan/budget_test.go`
- `internal/definitionscan/names.go`
- `internal/definitionscan/scan.go`
- `internal/definitionscan/scan_test.go`
- `internal/scancorpus/definitions_test.go`
- `internal/scancorpus/testdata/definition-known-misses.md`

storage/migration:

- `internal/store/dbgen/governance.sql.go`
- `internal/store/dbgen/models.go`
- `internal/store/dbgen/registry.sql.go`
- `internal/store/dbgen/scanning.sql.go`
- `internal/store/queries/scanning.sql`
- `migrations/00061_definition_scanning.sql`


documentation files:

- `CHANGELOG.md`
- `docs/content-scanning.md`
- `docs/decisions.md` (dated note under decision 87; no new number)
- `docs/registry.md`
- `docs/roadmap.md`
- `docs/threat-model.md`
- `docs/licenses/confusables.txt`
- `docs/licenses/scanning.md`
- `docs/scanning-72-report.md`

## Gate commands (whole-second timing resolution)

Environment: Go 1.26.10, `GOFLAGS=-p=2`, worker-only `OMP_TEST_DATABASE_URL`
on port 55453, with `OMP_TEST_REQUIRE_DB=1` for database suites.

| Command | Result | Seconds | Log |
| --- | --- | ---: | --- |
| `make generate` | pass | 22 | `/tmp/omp72-contract-generate.log` |
| `make lint` | pass on final code | 20 | `/tmp/omp72-lint-end.log` |
| `go build ./...` | pass on final code | 6 | `/tmp/omp72-build-end.log` |
| `make test-scanning-corpus` | pass on final code | 5 | `/tmp/omp72-corpus-end.log` |
| `OMP_TEST_SPLIT_ROLES=0 OMP_TEST_REQUIRE_DB=1 make test-ci` | pass (first complete run) | 1030 | retained as `/tmp/omp72-test-role0-earlier.log` after final run |
| `OMP_TEST_SPLIT_ROLES=1 OMP_TEST_REQUIRE_DB=1 make test-ci` | pass | 860 | `/tmp/omp72-test-role1.log` |
| Final mode-0 full rerun after detector fixes | fail: unchanged 20-minute HTTP-package watchdog | 1322 | `/tmp/omp72-test-role0-final.log` and `/tmp/omp72-test-role0.log` |
| `cd web && npm ci` | pass | 5 (npm-reported) | `/tmp/omp72-npm-ci.log` |
| `cd web && npm run typecheck` | pass after final contract generation | 112 | `/tmp/omp72-web-contract-typecheck.log` |
| `cd web && npm test` | fail: one existing picker test timed out at unchanged 20 s; 903 passed | 657 | `/tmp/omp72-web-test.log` |
| `cd web && npm test -- src/test/gateway-capabilities.test.tsx --maxWorkers=1` | pass: 8 tests | 21 | `/tmp/omp72-web-picker-retry.log` |
| `cd web && npm test -- --maxWorkers=2` | pass: all 904 tests, unchanged assertions/timeouts | 734 | `/tmp/omp72-web-test-retry.log` |
| `cd web && npm run build` | pass after final contract generation | 96 | `/tmp/omp72-web-contract-build.log` |
| `cd web && npm run check:styling` | pass | 1 | `/tmp/omp72-web-contract-check-styling.log` |
| `cd web && npm run check:size` | pass | 1 | `/tmp/omp72-web-contract-check-size.log` |

Targeted race commands in both modes used:

```
go test -race -count=1 -timeout=20m ./internal/definitionscan ./internal/registry ./internal/scancorpus ./internal/httpapi -run 'TestScan|TestDefinition|TestLimits|TestCatalogUnique|TestCallPath|TestConfusable|TestRulePanic|TestAuthorizationMatrix|TestTokenMatrix|TestAuthzMatrixClassifies'
```

Pass: mode 0 107 s, mode 1 46 s, logs `/tmp/omp72-targeted-role{0,1}.log`.
The expanded HTTP/database/metrics/digest sentinel checks passed in both modes
(`/tmp/omp72-sentinel-final-role{0,1}.log`: 48/28 s); the public/private-schema
sentinel passed in both (`/tmp/omp72-all-schema-role{0,1}.log`: 24/8 s).
Complete scanner/registry/corpus targeted package race runs passed in both modes
(`/tmp/omp72-final-scanner-role{0,1}.log`: 73/92 s). Later pure-detector edge-case
checks passed with `go test -race -count=1 ./internal/definitionscan ./internal/scancorpus`
(`/tmp/omp72-padding-fix.log`, `/tmp/omp72-selector-length.log`), supplemented by
the final mode-0 attempt (which hit the cumulative HTTP-package watchdog).
Mode 1's full run began before the final pure
prefilter/selector refinements; database/API code was unchanged by those refinements.

No assertion or timeout was weakened. Existing capture, secret-registry and
mcpgw source/test diffs against v0.13.1 are empty. No previous-image or browser
check was run. No publish, push, tag, merge or external communication occurred.


## Final review fixes and remaining gate limitation

The final mode-0 HTTP timeout occurred at the 20-minute cumulative package limit
while `TestStaticCredentialPartsDoNotFollowOriginChange/query` had run for only
one second (its parent for 11 seconds). Another worktree was running a full suite
on this four-core machine. The unchanged test passed in isolation with
`OMP_TEST_SPLIT_ROLES=0 OMP_TEST_REQUIRE_DB=1 go test -race -count=1 -timeout=20m ./internal/httpapi -run '^TestStaticCredentialPartsDoNotFollowOriginChange$'`
in 27 seconds (`/tmp/omp72-static-origin-retry.log`). Both earlier complete role
runs passed, but the final complete tree still needs a full quiet-run gate in
both modes; later changes have targeted evidence rather than a new full pass.
No watchdog or assertion was weakened.

Review also caught repeated compilation of the fixed instruction-verb regex in
ordinary dotted prose. The unmodified 10 KiB split-field ledger fixture exceeded
its 25 ms budget under race instrumentation (`/tmp/omp72-final-phrasing{,-retry}.log`).
Precompiling the matcher and tightening its literal prefilter preserved behavior
and made the same fixture/assertions/deadline pass (`/tmp/omp72-final-detector-race.log`,
34 seconds for scanner/corpus packages). Soft-hyphen prose remains low severity;
cross-tool phrasing covers unprefixed names as well as exposed names.

Backfill was corrected to preserve completed scans, skip current completed
fingerprints, compare names against the complete inventory, and process older
pending definitions first. Unreached background work is not rewritten, so
repeatedly incomplete definitions cannot reset everyone else's queue age.
`TestBackfillSkipsCompletedDefinitions`, `TestBatchBudgetPreservesCompletedScan`,
`TestPendingDefinitionOrder`, `TestPendingBatchLeavesUnreachedDefinitions` and
`TestConfusableCapabilityLocations` prove these properties and resource/template
locations. Their final race checks passed in both role modes (16/12 seconds,
`/tmp/omp72-progress-complete-role{0,1}.log`). The initial timestamp assertion was
corrected to compare an exact UTC instant rather than its local-zone year.

Both explicit rescan endpoints additionally assert an actual `secret.github`
finding from the canary, not merely a content-free response. Definition canaries
live in schema text/keys rather than top-level name/title/description projections,
so the full dump legitimately excludes only the stored definition.
The strengthened sentinel passed in both modes (`/tmp/omp72-detected-canary-role{0,1}.log`,
30/9 seconds). Current API/authorization and final build/corpus results follow.


Final current-tree targeted verification:

- API/session/token/authorization/privacy race checks: mode 0 63 seconds, mode 1
  35 seconds, `/tmp/omp72-api-final-role{0,1}.log`.
- Full scanning/progress/visibility integration subset: mode 0 74 seconds, mode 1
  37 seconds, `/tmp/omp72-final-integration-role{0,1}.log`.
- Final pending-age ordering, completed-result preservation, and confusable-location
  race checks: mode 0 16 seconds, mode 1 12 seconds,
  `/tmp/omp72-progress-complete-role{0,1}.log`.
- Final scanner/corpus race command passed in 34 seconds with the same previously
  failing fixture and deadline (`/tmp/omp72-final-detector-race.log`).
- `make lint`, `go build ./...`, and `make test-scanning-corpus` passed in
  20/6/5 seconds after the final code fixes. Scratch binary: `/tmp/omp72`.

The complete current tree has not passed fresh full quiet-run suites after these
last detector/backfill refinements. The earlier full passes and latest timeout
are retained separately; this report does not substitute targeted checks for
that remaining full-suite gate.

## Post-v0.14.0 cleanup evidence (2026-11-06)

No product scanner, admission behavior, migration or 25 ms deadline changed.
Found nothing ≠ safe. Public source stays scratch-only; the pinned downloader and
licence rules are unchanged. The aggregate CLI now emits separate primitive and
definition reports, with all four definition groups. Positive fixture scores are
for their targeted rule (incidental findings contribute counts only); benign
fixtures score every rule. Public source is scanned as bounded description chunks,
with no labelled precision claim or cross-chunk/inventory-name coverage.
`TestDefinitionAggregateReport` pins catalog coverage and ledger count; existing
must-catch severity, benign rate and exact ledger-set assertions remain unchanged.
The workflow archives both reports and definition/pathological benchmarks; this
local branch has not triggered a hosted scheduled archive.

Resource measurements (`~/.cache/cleanup-72-resources.log`): 500 × 2,043-byte
scans used 74.939 ms process CPU (user + system via getrusage). Race-instrumented
runs used 799.891–822.668 ms. The explicit 2 s CPU threshold has >2x headroom even
under race instrumentation; it replaces the proposed 250 ms threshold for this
instrumented test, and does not assert a 250 ms race budget. Near-matches allocated
447,488 bytes / 56,018 bytes (7.99x); Unicode 108,416 / 30,018 (3.61x); encoded
133,536 / 60,018 (2.22x). The 20x allocation threshold has >2x headroom. **The
proposed 8x bound lacks 2x headroom and is not claimed.** Measurements are Linux
process-local tests, not a whole-portal CPU profile. Scanner allocation/GC costs
are included; scanning off does no scanner work.

The real fake-upstream refresh uses 500 tools, resources, templates and prompts
each (the existing per-kind cap), paginated ten at a time. Every stored definition
is checked after JSONB canonicalization to be exactly 65,536 bytes. The fixture
uses the supported 120 s upstream timeout to accommodate 128 MiB over 200 wire
pages under race instrumentation; scanner budgets remain unchanged. A normal
run completed in 16.57 s, with all 2,000 scans stored and 1,830 incomplete.
Initial fixture attempts (2,000 tools, stripped `_meta` padding, raw JSONB size,
and a 30 s upstream timeout under race) failed and were corrected without changing
production limits or existing assertions. Logs stay in `~/.cache/cleanup-*`.

`TestScanRefreshAddedCPU` additionally measures an actual 500 × 2,048-byte
paginated refresh in off and shadow modes, after warming discovery. Normal
process CPU was 1.312307 s off versus 1.493098 s shadow: **180.791 ms added**,
with a 4 s explicit threshold (>2x the measured race delta). Race role 0
was 3.241061 s off / 4.746493 s shadow / 1.505432 s added; role 1 was
3.220478 s off / 4.480739 s shadow / 1.260261 s added. This includes the in-process fake upstream and
registry/storage work, unlike the scanner-loop measurement above. Every returned
definition is asserted to be exactly 2,048 canonical bytes.

A2 remains partial: no before/after call-path performance benchmark is claimed;
the unchanged import check proves only absence of the scanner dependency.
A10's previous-image compatibility evidence remains as documented above.
Consequently **not every A-item is met**; do not close #72 on this evidence alone.

## Real Chromium accessibility check (#73, 2026-11-06)

Built embedded UI and scratch binary; served on `127.0.0.1:18088` with a fake MCP
upstream on `18091`, disposable `cleanup_browser` on worker Postgres `55453`,
separate LOGIN NOINHERIT `cleanup_owner` / `cleanup_runtime` identities and
`DB_REQUIRE_SPLIT_ROLES=true`. Migration used only the owner URL; serve used only
the runtime URL. Playwright and axe dependencies, extracted Chromium libraries,
script, screenshots and JSON are outside the repository under
`~/.cache/cleanup-browser/`. Cached Chromium 1248 was used; no browser downloaded.
The T3 preview attempt failed because host libraries were missing. Scratch-local
libraries allowed the requested Playwright run without changing host packages.

The initial Capabilities check found WCAG `label-content-name-mismatch` on the
seven counted filter buttons in both viewports. Capability filters now include
the count directly in each visible label, preserving values/counts/filtering and
avoiding the shared FilterBar's separate-span/comma-label mismatch. No shared UI
component or axe assertion was edited. A regression checks count text, accessible
name and actual filter selection. All findings are still untrusted text; found
nothing ≠ safe.

Final run: WCAG 2 A/AA and 2.1 A/AA tags, desktop 1280×800 and phone 390×844.
Axe counts below are rule categories; JSON retains every affected node.

| State | Desktop violations / incompletes / overflow | Phone violations / incompletes / overflow |
| --- | --- | --- |
| Capabilities: findings | 0 / 0 / no | 0 / 0 / no |
| Capabilities: zero findings | 0 / 0 / no | 0 / 0 / no |
| Capabilities: incomplete | 0 / 0 / no | 0 / 0 / no |
| Publish dialog with findings | 0 / 2 / no | 0 / 2 / no |
| Review dialog with findings | 0 / 2 / no | 0 / 2 / no |
| Admin scanning settings and rule catalog | 0 / 0 / no | 0 / 0 / no |

Dialogs retain `aria-hidden-focus` (seven background/focus-guard nodes each) and
`color-contrast` incompletes. Contrast nodes: desktop publish 2 / review 5;
phone publish 2 / review 4. Axe reports backgrounds obscured/overlapping in the
scrolling dialog; it does not establish a contrast failure. These remain manual
review items, **not a complete accessibility pass**. Rescan was reached through
Tab navigation at both sizes. No screen-reader check was performed.

The fake upstream produces the finding; zero and incomplete states use owned
disposable definition fixtures and the real rescan endpoint (ordinary text or
70 KiB oversized text). No API response interception is used. Original definition
and scan rows are restored afterward. Screenshots and per-state node-level JSON
are in `~/.cache/cleanup-browser/results/`, initial evidence in `results/before/`,
and the script is `~/.cache/cleanup-browser/check.cjs` (intentionally untracked).
