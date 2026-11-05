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

Migration `00057` adds `definition_scan_mode` (shadow default), `scan_revision`,
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
| A1 | `TestDefinitionCorpus`, `TestDefinitionRemainingGroups`, `TestDefinitionSecretCorpus`, `TestDefinitionBenignRate`, `TestDefinitionKnownMissLedger`, `TestConfusableNames`. Primitive/capture fixtures and assertions unchanged. Authored benign samples are synthetic and narrow. New stage fixtures are test-only; the aggregate corpus CLI still reports primitive findings. The stage ledger separately pins semantic paraphrases, spread selectors and split-field length misses. Existing public workflow/manifest unchanged; no new hosted run or public download claimed. |
| A2 | `TestDefinitionTailAndRefreshBudget`, `BenchmarkDefinition`, `BenchmarkDefinitionPathological`; direct gateway import check and empty `git diff v0.13.1 -- internal/mcpgw`. Not complete: strict 8x allocation gate, added-CPU/2x-headroom evidence, call-path benchmark and actual 2,000-definition upstream refresh integration (the test exercises scanner workload only). |
| A3 | `TestDefinitionPersistencePrivacyAndFailure`: public-table dumps excluding only definition, debug logs, service API output, registered metrics, arbitrary key/parameter-name and unmatched-text canaries. `TestDefinitionSchemaConstraints`: pinned columns and invalid ids. `TestScanningPrivacySentinel` adds a matched-secret canary and checks all new read/rescan HTTP responses, settings errors, exported spans, debug logs, metrics and both public/private-schema database dumps in both role modes. |
| A4 | Fixed catalog, KnownRule bounding and unknown-to-other metric label behavior; registered in appCollectors for `TestOpsArtifactsUseRealMetrics`. `TestScanMetricCardinality` enumerates catalog labels, rejects unknown catalog lookup, verifies unknown-to-other collapse and gathered dimensions. The catalog is static; no dynamic registration API exists. |
| A5 | `TestScanRefreshShadowIsNonInterfering`: capability rows equal except pre-existing refresh timestamp; ruleset changes and findings-write constraint failure preserve capability state in persistence test. Existing review-digest tests unchanged. Persistence test directly asserts ruleset-version changes preserve ReviewDigest. A complete refresh-response byte comparison remains outstanding. |
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

`/tmp/omp72-final-measurements.log` (final implementation): 2 KiB
0.174–0.190 ms/op, 5,592 B/op, 21 allocations; 64 KiB
4.877–5.068 ms/op, 132,568 B/op, 21 allocations. Near-match input:
5.234–6.068 ms/op, about 447,500 B/op; Unicode input:
2.728–2.947 ms/op, about 108,400 B/op; encoded runs:
14.175–15.236 ms/op, about 133,000–137,500 B/op. These averages do not prove
all proposed tail or memory gates. Wall sample (`/tmp/omp72-tail-final.log`):
p99 10.113 ms, 500 × 2 KiB 86.864 ms wall, 2,000 × 64 KiB 2.005 s
with 1,648 incomplete. No CPU/allocation gate is claimed.

Gate results appended after completion; logs `/tmp/omp72-*`. No browser was used.
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
- `migrations/00057_definition_scanning.sql`


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
| `make generate` | pass | 16 | `/tmp/omp72-generate-final.log` |
| `make lint` | pass | 25 | `/tmp/omp72-lint-reviewed.log` |
| `go build ./...` | pass | 9 | `/tmp/omp72-build-reviewed.log` |
| `make test-scanning-corpus` | pass, including final cross-group miss ledger | 13 | `/tmp/omp72-corpus-ledger-final.log` |
| `OMP_TEST_SPLIT_ROLES=0 OMP_TEST_REQUIRE_DB=1 make test-ci` | pass (first complete run) | 1030 | retained as `/tmp/omp72-test-role0-earlier.log` after final run |
| `OMP_TEST_SPLIT_ROLES=1 OMP_TEST_REQUIRE_DB=1 make test-ci` | pass | 860 | `/tmp/omp72-test-role1.log` |
| Final mode-0 full rerun after detector fixes | pending | — | `/tmp/omp72-test-role0-final.log` |
| `cd web && npm ci` | pass | 5 (npm-reported) | `/tmp/omp72-npm-ci.log` |
| `cd web && npm run typecheck` | pass | 49 | `/tmp/omp72-web-typecheck.log` |
| `cd web && npm test` | fail: one existing picker test timed out at unchanged 20 s; 903 passed | 657 | `/tmp/omp72-web-test.log` |
| `cd web && npm test -- src/test/gateway-capabilities.test.tsx --maxWorkers=1` | pass: 8 tests | 21 | `/tmp/omp72-web-picker-retry.log` |
| `cd web && npm test -- --maxWorkers=2` | pass: all 904 tests, unchanged assertions/timeouts | 734 | `/tmp/omp72-web-test-retry.log` |
| `cd web && npm run build` | pass | 58 | `/tmp/omp72-web-build.log` |
| `cd web && npm run check:styling` | pass | 1 | `/tmp/omp72-web-check-styling.log` |
| `cd web && npm run check:size` | pass | 0 | `/tmp/omp72-web-check-size.log` |

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
this final complete mode-0 run. Mode 1's full run began before the final pure
prefilter/selector refinements; database/API code was unchanged by those refinements.

No assertion or timeout was weakened. Existing capture, secret-registry and
mcpgw source/test diffs against v0.13.1 are empty. No previous-image or browser
check was run. No publish, push, tag, merge or external communication occurred.
