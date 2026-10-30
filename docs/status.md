# Status and handoff

Last updated: 2026-10-30. Open MCP Portal (formerly Open MCP Gateway, decision 46): **v0.9.0 is published and independently verified** (#35's first task-relay stage, #43's Kubernetes release gates and #52's content-scanning design). #35's first-stage acceptance is complete and the issue is closed. The owner directed continued ordered work through every development issue, delegated subagents (Sonnet 5.5) and pre-1.0 releases; **v1.0.0 remains the owner's explicit decision**. #32, #33, #35, #43 and #52 are closed with evidence. A fresh agent should read [agent-handoff.md](agent-handoff.md).
(release notes: [releases/v0.9.0.md](releases/v0.9.0.md), [v0.8.0](releases/v0.8.0.md); earlier: [v0.7.0](releases/v0.7.0.md), [v0.6.0](releases/v0.6.0.md), [v0.5.1](releases/v0.5.1.md), [v0.5.0](releases/v0.5.0.md), [v0.4.0](releases/v0.4.0.md), [v0.3.3](releases/v0.3.3.md), [v0.3.2](releases/v0.3.2.md), [v0.3.1](releases/v0.3.1.md), [v0.3.0](releases/v0.3.0.md), [v0.2.2](releases/v0.2.2.md), [v0.2.1](releases/v0.2.1.md), [v0.2.0](releases/v0.2.0.md), the first release [v0.1.0](releases/v0.1.0.md)).

## v0.10.0 candidate: governance and CLI, not yet released

The reviewed #40 governance and #46 CLI implementations are integrated in the local candidate, including explicit sensitivity confirmation (immutable migrations49/50), parent transfer-lock/batch-fairness/current-owner fixes, and comparison-only CLI policy preservation. The sunset-admission regression first reproduced late dispatch in all six legacy/modern tool/prompt/resource paths; the frozen earliest credential/grant/sunset guard fixed it without restoring committed spend. Real-API regressions also reproduced and fixed CLI clones losing ceilings or sensitivity/retirement policy. An independent Sonnet review found no high/critical issue; its Unicode contact mismatch is fixed and atomic export semantics are explicit.

All four complete mandatory-PostgreSQL suites passed at runtime snapshot `a2eaf687268d5250a8bb3c94b382a97161c7923f`: actual legacy normal/race538s/1,129s and split normal/race582s/1,213s. HTTP took500s/1,058s and557s/1,156s, all under the unchanged20-minute per-package budget. All896 web tests in86 files, typecheck/build/styling/size/npm audit (zero vulnerabilities), generation/freshness/lint/build, Kubernetes/actionlint/pinned ShellCheck,72 smoke self-tests and20 Python tests passed. A missing final advisory executable was corrected by running pinned govulncheck1.9.0: zero reachable/imported-package vulnerabilities, two module-only advisories. Only completed suites count. The earlier failed Unicode test/wrapper result was discarded; strict focused gates subsequently passed both roles before the frozen full run.

Final source/schema50 real-browser/runtime checks passed confirmation, role/stale/no-op guards, metadata omission, ceiling/retirement/overdue and transfer/ciphertext preservation. Fourteen desktop/mobile states had zero axe violations/overflow; the two open confirmation dialogs retain aria-hidden-focus/color-contrast incompletes (the other twelve have none). Actual published-v0.9.0/schema50 doctor/health/readiness/create/read/CAS-write preserved governance and sealed credentials. Migration preserved original task ciphertext/rows; an original-handle upstream check was interrupted by a lost disposable fake and is not credited. After an explicitly fresh fake generation, an actual-v0.9.0-created task reopened under v0.10.0 source with its authenticated root. Matching keys/databases were never regenerated/reset. **Exact-source GitHub gates, native publication and independent image/six-CLI-artifact verification/published runtime remain required.** No new tag or issue closure is implied. See [candidate notes](releases/v0.10.0.md).

The v0.9.0 evidence/image-pin follow-up `bcfb5e7` is complete: all seven CI jobs40998064377 and five Kubernetes jobs40998064220 passed. [Final confirmation](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6514713744). #40/#46 remain open; 26 issues remain (18 development, eight real-world). SCIM remains an unaccepted design draft, with no code or DDL.

## v0.9.0 (2026-10-30): #35 first stage, #43 release gates, #52 design

#43 closed after every new job passed on GitHub-hosted runners at `f3e4c75` (CI 40940744356, k8s-smoke
40940744144, k8s-upgrade incl. the breaking-migration canary 40940784735; k8s-load 40937148348 at `4fef32b`).
Two GitHub-only findings were fixed rather than hidden: an unpinned runner ShellCheck, and an ingress assertion
racing a draining pod with the old configuration. #52 closed with decision 87 and first-slice follow-ups #70–#73.

#35's gateway/upstream wiring (delegated to a Sonnet 5.5 subagent and reviewed line by line) is merged into the
release source with the sealed store, fenced operations and single-use input ledger. **All four complete
mandatory-PostgreSQL suites passed** on the immutable v0.9.0 candidate: normal and race in both actual
legacy and authenticated split-role modes, `OMP_TEST_REQUIRE_DB=1`, `GOFLAGS='-p=2'`, the same 20-minute
per-package budget and every test retained. The HTTP package took 624s/975s (normal/race legacy) and
510s/1,045s (normal/race split). Earlier background runs disappeared without final results; their unfinished
suites are not credited. The completed suites' permanent logs were retained, and the interrupted race
suite was rerun in full. Repeated task-specific races also passed in both role modes.

The actual immutable **published v0.8.0 image passed schema48 compatibility**: doctor (informational newer
schema), health/readiness, login, server reads and a real revision-checked metadata write, running read-only
as UID65532 with an authenticated restricted runtime and no owner/migration URL or mounts. The write
preserved the task-support flag and an actual sealed task row's ciphertext, status, revision and expiry;
the new store reopened the sealed state afterwards. This is expand compatibility, **not task enforcement
or authorization by the old image**.

A source-candidate real-HTTP/Chromium156 smoke passed modern discovery, undeclared synchronous calls,
opaque flat task creation, current-root/unknown isolation, per-request declaration, paced polling, mapped
single-use inputs, completed tool `isError`, cancellation acknowledgement, actual-ID/header routing and
upstream-ID/credential scrubbing. A handle survived a full serving-process restart and was reopened with
its original authenticated root. Six desktop/390px owner/editor/admin browser states had zero axe
violations and no horizontal overflow; **editor-mobile color-contrast remains incomplete**. This is owned-fake
upstream evidence, not real Tasks-client/server interoperability, a natural-expiry soak or independent
whole-product accessibility acceptance.

All **853 web tests**, typecheck/build/styling/size and full npm audit passed (zero vulnerabilities).
Generation/freshness, lint and all-package build passed on the final checkout. Kubernetes validation,
actionlint, pinned ShellCheck, 71 smoke assertion self-tests and 15 Python tests passed; govulncheck found
zero reachable or imported-package vulnerabilities (two module-only advisories). The snapshot had no
`.git`, so actionlint initially refused to discover the project; it and the remaining deployment/advisory
gates were rerun successfully in the real checkout with identical source/workflow bytes. All 1,469 tracked
files were compared to the tested snapshot: only four evidence documents differ, not runtime, tests,
SQL, migrations, generated contracts, web or deployment code.

The release is now **published and independently verified**:

- Immutable source/tag: `f829b93bd90b2ea1536b9c997978a8f8affd737b`, [v0.9.0](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.9.0).
- Verified index: `ghcr.io/ncecere/open-mcp-portal@sha256:8a620e21c84786b9d8f6c326c19003a118456f17c322898174f008122f46f115`.
- [Main CI40990984724](https://github.com/ncecere/open-mcp-portal/actions/runs/40990984724): all seven jobs passed.
- [Kubernetes smoke40990984804](https://github.com/ncecere/open-mcp-portal/actions/runs/40990984804): base and ingress/TLS/OIDC on both CNIs, plus restore, all passed.
- [Upgrade/canary40991091656](https://github.com/ncecere/open-mcp-portal/actions/runs/40991091656): actual v0.8.0/schema47 to candidate/schema48, 152 rollout and 146 rollback requests with zero failures, retaining old keys/sessions/OAuth grants. The scratch breaking-migration canary correctly failed 23 of 144 requests; its failure is the gate's expected negative control, not a passing broken rollout.
- [Load40991094668](https://github.com/ncecere/open-mcp-portal/actions/runs/40991094668): 12,779 requests, zero failed requests/checks, p95 289ms; the shared limit admitted 60 of 120 requests. Peak database connections 13 of 100. This is a loose regression gate, not a capacity benchmark; leader gauges still mean latest-run leadership, not exact simultaneous leader counts.
- [Native publication40993956632](https://github.com/ncecere/open-mcp-portal/actions/runs/40993956632) passed; release published 2026-10-30T02:53:33Z. Independent verification passed in18s: exact source/tag/registry digest, exactly amd64/arm64, tag-specific OIDC workflow identity/issuer/source SHA and transparency proof, all asset checksums, canonical SPDX equality with registry attestations and both SLSAv1 source/ref/version/build claims. Prior v0.8.0/v0.7.0/v0.6.0/v0.5.1 source/image tags remain unchanged. Read-only UID65532/network-none version: `open-mcp-portal 0.9.0 (f829b93bd90b)`.
- The **actual published digest** passed doctor and real HTTP/Chromium156 task smoke in13s as read-only UID65532, authenticated restricted runtime, no owner/migration URL or mounts. It first reopened a real authenticated handle sealed before publication, then repeated discovery/declaration/root-isolation/poll/input-single-use/completion/cancel/ID-routing/redaction checks. All six published desktop/390px states had zero violations/overflow; **published editor-mobile contrast remains incomplete**, as in the source run. No real Tasks client/server, production deployment, natural-expiry soak or independent whole-product security/accessibility acceptance is implied.

[Tag CI40993956605](https://github.com/ncecere/open-mcp-portal/actions/runs/40993956605) passed all seven
jobs, and [tag upgrade40993956611](https://github.com/ncecere/open-mcp-portal/actions/runs/40993956611)
passed. **[#35 is closed with scoped acceptance](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6514201092)**.
The v0.9.0 evidence/pin follow-up `bcfb5e7` passed local checks, all seven CI jobs40998064377 and five Kubernetes jobs40998064220; [final confirmation](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6514713744). That follow-up pinned the independently verified index. A later candidate's zero digest is deliberately not deployable until its own publication is verified.
Release tags are immutable. See [releases/v0.9.0.md](releases/v0.9.0.md).

### History: #35 development notes

The v0.8.0 evidence/pin follow-up `3a2183ce763da08e0e0183ec8b0572a1c947f21e` passed all seven
[main CI jobs40895243972](https://github.com/ncecere/open-mcp-portal/actions/runs/40895243972) and both
[smoke CNIs40895244112](https://github.com/ncecere/open-mcp-portal/actions/runs/40895244112).
[Final confirmation](https://github.com/ncecere/open-mcp-portal/issues/33#issuecomment-6500631495) records it.

The official released 2026-07-28 Tasks spec/Final SEP/schema were confirmed and pinned before design;
[preflight](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6500904668) resolves declaration,
flat result, ack-only mutation and routing/error semantics. Decision86/[design](mcp-tasks.md) retain current
exact-call approvals: ordinary ungoverned modern tools only, no task negotiation for governed/NoReplay calls,
no automatic retry/failover, original principal/credential/definition/curation/origin binding, fresh current
authority and durable bounded sealed mappings. Cancellation acknowledgement is not proof of termination.
The current branch adds an **unwired released-shape parser foundation** (flat create/get variants, ack-only
update/cancel, exact upstream ID, bounded lossless integer/time/payload checks). Ten repeated race runs,
bounded20s fuzzing (89,681 executions), all-package compilation and lint passed in160s. Full upstream/
gateway package races and generated freshness then passed in19s. Opaque32-byte handles passed50 repeated
race runs and20s fuzzing (1,179,125 executions); row/handle/principal/credential/full-URL/definition/curation/
argument/dependency-bound sealed-state, tamper/version/rotation and argument-representation units passed20
repeated races. Monotonic expiry, wire-integer overflow, UTC/DST and bounded polling/configuration units
also passed20 repeated races plus package races/compilation/lint in14s. These are clock-unit proofs, not a
natural-expiry soak, and **unwired primitives, not authorization**. No task negotiation/dispatch or new
release version exists yet. Expand-only migration48 is now applied/frozen; parameterized reservation/
revision/operation fences and the cipher's rotation registry passed three repeated SQL races, full store/
rotation/approval/task-package races in both actual database-role modes, compilation/lint/build/typecheck
and optional discovery-contract races in528s. SQL fixtures are not a sealed relay or single-use input
implementation; no functional task service is enabled. The initial typecheck failure exposed a required-TS/
optional-Go discovery field; the corrected optional contract has a retained regression, not padded fixtures.
A sealed reservation/activation/private-root lookup API passed focused3x and full mcptasks/store/rotation/
approval/upstream/gateway races in both actual database-role modes (423s), including two-pool capacity
contention, durable reopening, wrong-key/swapped-row/rebound-binding refusal and forced expiry. It is not
wired into gateway traffic or input mutations.
A read-only, non-spending `CheckUngoverned` policy primitive
passed focused and full approval-package races in both actual role modes in208s, including rule changes,
expiry/cancellation/suspension and zero receipt/request-audit creation. It is not wired into task traffic.
At that historical foundation checkpoint #35 remained open and unchecked; the source version0.8.0
was not task-support evidence. The completed v0.9.0 acceptance above supersedes that checkpoint.

## v0.8.0 (2026-10-29): separate #33 failover stage, shipped and closed

Decision85 and [upstream-failover.md](upstream-failover.md) record the conservative design before routing code:
canonical primary plus two extras, independent origin-bound static credentials, explicit unsupported-mode/
provider/TLS refusals and primary-only governed/NoReplay calls. A different origin cannot reuse an exact-call
approval. The total attempt/deadline budget, current authority/quota, actual-URL identity audiences and
fallback definition parity remain mandatory.

The shipped implementation includes generated contracts, revision-checked owner/admin-only endpoint mutations, sealed
origin/server/endpoint-bound credentials, endpoint-aware review/audit/health, guarded routing with trusted
definition parity and fresh actual-URL identities. Focused real-HTTP races passed in both protocol eras and
both genuine database role modes: read503 fallback, independent credentials/audiences, proven unsent dial/TLS
write fallback, mismatch/ambiguous/auth/business/governed/continuation negatives, revocation/quota admission
and a spent approval remaining primary-only. Foundation store/rotation/registry races passed in both modes.
The historical relocation42 test now isolates its exact-preservation assertion at schema42 and separately
asserts latest-migration invalidation without changing the root/history.

The source/tag is **v0.8.0, published and verified**. Focused endpoint UI/type/styling/size checks passed.
The initial full 853-test web/deployment/advisory gate passed; real Chromium then exposed a narrow-screen
health Card/table-scroll region sharing the same accessible name. The product Card was renamed and a
retained regression distinguishes the names. The corrected actual browser run passed on schema47 with a
genuinely authenticated restricted runtime: owner UI credential entry/review resubmission, reviewer-visible
actual URL/shape, editor read-only, forward/reverse keyboard, primary/endpoint health and primary503→
secondary200 with independently required credentials and a cryptographically verified secondary-URL JWT.
Both forwarding iterations consumed the shared rate2 bucket; the next call was429 before any new primary
operation or SSE commitment. The final browser rerun also includes full historical endpoint UUID labels.
Six desktop/390px states had zero axe violations/overflow. **Health-mobile contrast and review-dialog aria-
hidden-focus/contrast remain axe incompletes**; an earlier source run also had an owner-mobile contrast
incomplete (not present on the final rerun). None is independent whole-product accessibility acceptance.

The actual immutable v0.7.0 image also passed schema47 doctor (informational newer schema), health/readiness
and a real metadata write as read-only UID65532 with authenticated runtime/no owner URL or mounts. Endpoint
IDs/order/origin/shape/cipher bytes and operational limits were preserved; revision and authority epoch
advanced. This is expand compatibility, **not old-image failover/review/rotation enforcement**.

The final post-browser-fix gate passed in753s: all **853 web tests**, generated freshness, lint/build,
styling/size, actionlint, Kubernetes validation, four Python tests, npm audit (zero vulnerabilities) and
govulncheck (zero reachable/imported-package vulnerabilities; two module-only advisories). All652 runtime/
test/generated SQL/migration/API files match the immutable snapshot12 backend test tree byte-for-byte.

**All four complete mandatory-PostgreSQL suites passed in 3,440 seconds**: normal and race in both actual
legacy and authenticated split-role modes, every test retained, `OMP_TEST_REQUIRE_DB=1`, `GOFLAGS='-p=2'`.
The first full normal run had hit the cumulative 10-minute HTTP-package watchdog while a late OAuth test had
run for one second; it is a failed run, not acceptance. All four passed with the documented CI 20-minute
per-package budget. The normal `make test` target now uses that same budget, removing no tests/roles/
assertions. No runtime/generated SQL/API code changed after the fully validated snapshot. Final versioned-
tree endpoint/relocation/contract races in both role modes plus lint/build/Python checks also passed in103s.

**All release gates passed; [#33 is closed](https://github.com/ncecere/open-mcp-portal/issues/33#issuecomment-6499585660).**

- Immutable source/tag: `c36ed3c6bbb8765004d243d1fc0bb37a8f80d106`.
- Verified image: `ghcr.io/ncecere/open-mcp-portal@sha256:f73129a94cfdc8cc2badc6b2f1e21b74bd0bbc1fd6144afbb50f1986c592c960`.
- [Main CI40884371482](https://github.com/ncecere/open-mcp-portal/actions/runs/40884371482) and
  [tag CI40888211908](https://github.com/ncecere/open-mcp-portal/actions/runs/40888211908): all seven jobs passed.
- [kindnet/Calico smoke40884371510](https://github.com/ncecere/open-mcp-portal/actions/runs/40884371510): both passed at that source.
- [Native publication40888211919](https://github.com/ncecere/open-mcp-portal/actions/runs/40888211919): native
  amd64/arm64 builds/scans/runtime checks, index publication/signing and release passed; published14:10:49Z.
- Independent verification passed in19s: immutable source/registry tag/digest, exactly two architectures,
  strict tag-specific OIDC workflow identity/issuer/source SHA/transparency proof, checksums, canonical SPDX
  assets against registry attestations, both SLSAv1 source/ref/version/build claims and read-only UID65532/
  network-none `open-mcp-portal 0.8.0 (c36ed3c6bbb8)`. Prior v0.7.0/v0.6.0/v0.5.1 tags remain unchanged.
- The actual published digest passed schema47 doctor/health/readiness and Chromium156 smoke in9s as
  read-only UID65532, authenticated restricted runtime, no owner/migration URL or mounts. It opened an owned
  pre-publication endpoint envelope and passed the full UI/review/keyboard/health/secondary-JWT/quota flow
  described above. Six published desktop/390px states had zero axe violations/overflow. **Published owner-
  mobile and health-mobile contrast, and review-dialog aria-hidden-focus/contrast remain incompletes**.
  The source final owner-mobile result had no incomplete; these are distinct results, not a global sign-off.

The example image pin uses the verified digest. The publication-evidence/pin follow-up passed applicable
local checks, main CI and both CNIs as recorded above; it did not move or recreate the immutable source tag.
Migration47 is applied/frozen: any DDL correction needs a new migration. All owned source/published/fake/
browser fixtures were stopped and their labeled tmpfs PostgreSQL destroyed before removing matching keys/
config; existing development services, databases and keys were untouched. No implicit encrypted-state
restore, production deployment, real-client/provider/channel/pilot, natural-expiry/load soak or independent
whole-product security/accessibility acceptance is claimed.

## v0.7.0 (2026-10-29): first #33 upstream-protection stage

Decision84 and [upstream-protection.md](upstream-protection.md) specify the staged scope. Per-server shared
quotas, per-replica concurrency, bounded safe-read retries and circuit breaking are **published and verified**
in [v0.7.0](releases/v0.7.0.md). Migration46 is new and expand-only. Failover
was not part of that release; the parent stayed open until the separate verified v0.8.0 stage above.

Focused mandatory-PostgreSQL race tests passed in both actual role modes, including owner/token boundaries,
ceilings/audit, a quota shared across gateways/replicas, an approval left unspent by quota refusal and read
retry denial after authority revocation. Upstream/gateway/controller/limits/metrics race tests passed.
All **848 web tests**, typecheck/build/styling/size/npm audit, actionlint, Kubernetes validation, Python smoke-
helper tests and govulncheck passed. The first complete backend run retained an existing assertion exposing
incorrect prepared-identity metadata on cancellation after deferred SSE start; an explicit before-dispatch
cancellation guard fixes it, and the unchanged regression passed in both actual role modes. A fresh complete
four-suite mandatory-PostgreSQL rerun **passed all normal/race suites in both actual role modes** (2,781 seconds, `GOFLAGS='-p=2'`). Chromium156 on an
owned schema46/authenticated restricted-runtime fixture passed owner edits/null clearing, editor/foreign-admin
read-only controls, keyboard forward/reverse focus and modern MCP quota 200/200/429 before SSE. Four
desktop/390px states had zero axe violations/incompletes and no overflow. These are local fixture tests,
not real IDE/provider/pilot or whole-product accessibility evidence.

The actual immutable v0.6.0 image passed schema46 doctor (informational newer-schema report), health/readiness
and a journaled metadata write preserving both new operational values. It ran read-only as `65532:65532`,
authenticated as the restricted runtime, with no owner/migration URL or mounts. This proves expanded-schema
compatibility, **not new quota/concurrency/retry/breaker enforcement by the old image**.
After the mechanical v0.7.0 version change, regenerated/freshness checks, both-role required-DB focused
races/advisory checks (88 seconds) and the complete 848-test web/build/deployment gate (524 seconds) passed
again. Production logic matches the four-suite validated snapshot apart from version metadata.
[First-stage acceptance](https://github.com/ncecere/open-mcp-portal/issues/33#issuecomment-6493836494) records the
first-stage evidence: the first three criteria were checked; failover stayed unchecked and #33 open until v0.8.0.
Immutable source/tag: `289b5aedad462a1ae37ea3de9a82987eca6829b1`,
[published release](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.7.0).
Verified image: `ghcr.io/ncecere/open-mcp-portal@sha256:a377ef8d7b8303780eb1ffbd1b11a0358954532c771705dc3e56d94650cc3ed6`.

- [Main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40849249914) and
  [tag CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40851526772) passed all seven jobs,
  including both complete mandatory-PostgreSQL race role modes. Both
  [kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40849249789) passed.
- [Native amd64/arm64 builds, scans, runtime checks, signing and publication](https://github.com/ncecere/open-mcp-portal/actions/runs/40851527305)
  passed. Independent verification checked tag/digest equality, exactly two architectures, strict tag-specific
  GitHub OIDC identity/issuer/workflow SHA and transparency proof, every asset checksum, canonical SPDX equality
  with registry attestations and both SLSAv1 source/version claims. The actual AMD64 image reports
  `open-mcp-portal 0.7.0 (289b5aedad46)` as UID65532, read-only with no network. Prior v0.6.0/v0.5.1 tags are unchanged.
- The actual published image passed schema46 doctor/health/readiness using a genuinely authenticated restricted
  runtime login with no owner membership. Its serving container was read-only `65532:65532`, with no owner/
  migration URL, mounts or old-instance keys/data. Chromium156 repeated owner edits/null clearing, editor/
  foreign-admin read-only controls, keyboard forward/reverse focus and normal scoped-key MCP quota
  200/200/429 before SSE. Four desktop/390px states had zero axe violations and no overflow; **owner-mobile
  color-contrast remains incomplete**. This is not whole-product accessibility acceptance.
- All owned serving, browser, fake-upstream and disposable PostgreSQL fixtures were stopped/removed; matching
  disposable keys/config were removed only after their database was destroyed. Historical services/data/keys
  remain untouched. No production rollout, real IDE/provider/pilot, load/soak or independent whole-product
  security review is claimed. The example overlay pins the independently verified digest above.

The evidence/image-pin follow-up `b22081e9270f002f788b92a385c0f68b041177c2` passed all seven
[main CI jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40855403928) and both
[smoke CNIs](https://github.com/ncecere/open-mcp-portal/actions/runs/40855403905). These are separate from
the immutable source checks above; [final confirmation](https://github.com/ncecere/open-mcp-portal/issues/33#issuecomment-6494386547)
records that follow-up's completion. **At v0.7.0, #33 remained open for failover** with 26 open issues
(18 feature/operations/design, eight real-world verification); v0.8.0 above subsequently closed it. v1.0.0
has not been cut.

## v0.6.0 (2026-10-29): gateway access requests

#32 is [closed with acceptance evidence](https://github.com/ncecere/open-mcp-portal/issues/32#issuecomment-6489315403).
Immutable source: `e613722fceac90de5e17bcf1df19e5c678ca81d9`, [published release](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.6.0).
Verified multiarchitecture image: `ghcr.io/ncecere/open-mcp-portal@sha256:515311b77b6f042367bf7154bcac46f4e7f8a26a5443ca9aff4516fa28a350f7`.

- [Main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40822321446) and
  [immutable tag CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40824289252) passed every job,
  including mandatory PostgreSQL races with actual legacy and authenticated split-role logins.
- Both [kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40822321606) passed.
- [Native amd64/arm64 builds, scans, runtime checks, signing and release](https://github.com/ncecere/open-mcp-portal/actions/runs/40824289277) passed.
  Outside that workflow, verified public tag/digest equality, exactly those two platforms, tag-specific
  GitHub OIDC identity and workflow SHA, certificate/transparency proof, every asset checksum, canonical
  SPDX equality to registry attestations and both provenance source/version claims. The published AMD64
  image reports `open-mcp-portal 0.6.0 (e613722fceac)` as `65532:65532`, read-only without network.
  Prior v0.5.1 source/image tags remain unchanged. The example overlay uses the verified index above.
- The actual published image migrated schema 45 as a non-superuser owner. A separate authenticated
  restricted runtime login, with no owner membership, passed strict doctor and HTTP health/readiness.
  Its read-only serving container had no owner/migration URL or mounted secrets/data from an old instance.
- Published-image Chromium156 checks exercised private submission, steward approval/expiry/note,
  requester history and auditor denial of private details. A normal scoped key obtained modern MCP
  `tools/list` HTTP200 after approval; owner-only forced-expiry instrumentation in the labelled disposable
  DB then required management/MCP HTTP404 without cleanup. This is **not** a natural-expiry soak.
- All seven published browser states had zero axe violations/no horizontal overflow at desktop/390px.
  Incomplete checks remain: modal `aria-hidden-focus`/`color-contrast`, plus mobile-settings contrast.
  Forward/reverse keyboard traversal (24 steps) and Escape passed. No whole-product accessibility claim.
- All owned fixture containers/profiles are removed/closed. Historical keys/data and existing development
  services were not modified. No production deployment or real IDE/provider/channel/pilot acceptance is implied.

The publication-evidence/image-pin follow-up `be9719831e787514ca611745258bacfa6503583f` passed
[main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40827746482) and both
[smoke CNIs](https://github.com/ncecere/open-mcp-portal/actions/runs/40827746404); these are separate from
the already-green immutable release-source checks. #33 and the remaining ordered backlog are not implemented by #32.
At v0.6.0 there were **26 open issues: 18 feature/operations/design and eight real-world verification**;
v0.8.0 subsequently closed #33. v1.0.0 is not cut.

### Fresh-machine implementation and local verification

The fresh-machine checkout was clean at handoff commit `4a5e4c4d26b68ef7232a247a53c0c3bb38b3b2bc`;
fetch confirmed it equals `origin/main`. The local and remote immutable `v0.5.1` tag still resolve to
`10753fec4610cb290454cb2767bdaebdf51120ae`. Final [main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40802200660)
and [tag CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40801468105) subsequently **both passed**, including
both complete database-role race suites. Final [kindnet/Calico smoke](https://github.com/ncecere/open-mcp-portal/actions/runs/40802200599)
and release publication also passed. No tag was moved or check skipped.

Fresh-machine Go 1.26.10/sqlc 1.31.1, Node 22, Docker/Compose, Python and GCC are available. Dependency
installation, generation/freshness, lint/build, all existing web checks, actionlint and Kubernetes validation
passed on the unchanged handoff. All four full normal/race PostgreSQL suites then passed in actual legacy
and authenticated split-role modes using `GOFLAGS='-p=2'` and an owned isolated compiler cache (2,680 seconds).
The owned disposable baseline PostgreSQL container was removed. No old `.env`, credentials, keys or database
was imported, regenerated or modified; no persistent development instance or production deployment is implied.

#32's [design](access-requests.md) and decision 83 cover opt-in discoverability, private user/team requests,
narrow per-gateway stewardship, atomic grant decisions and optional expiry. Migrations `00043`–`00045` are
new expand-only migrations; older serving/background-worker replicas must be drained before enabling requests
or expiring grants.
Focused lifecycle/authorization, concurrency, rollback, notification privacy, database-clock and
approval-dispatch expiry regressions passed with races in both role modes. The full web suite passed
(**844 tests**), as did typecheck/build/styling/size and npm audit. Generation/freshness passed. Browser
checks on an owned disposable instance (Chromium 156) exercised private request submission, steward
decisions, requester status and auditor denial, plus desktop/390px layout. All seven checked states had
zero axe violations and no horizontal overflow; the request modal retains two incomplete checks
(`aria-hidden-focus`, `color-contrast`), so this is not whole-product accessibility acceptance. Forward/reverse
keyboard traversal (24 steps) and Escape were also exercised; dialog-scoped axe still has incomplete contrast.

The actual immutable published v0.5.1 image ran read-only as `65532:65532` on schema 45 with a genuinely
authenticated restricted runtime login and no owner secret in its serving container. Health/readiness and
an HTTP gateway authority write passed; the private journal advanced and new access settings remained
intact. Its doctor reports the newer schema informationally. No old-image expiry enforcement or new-event
delivery is implied: drain older serving and background-worker replicas before enabling these features.

All four complete final normal/race PostgreSQL suites passed in both role modes (3,022 seconds).
Release-version/schema-contract, expiry and duplicate-email exact-requester identity regressions also passed
with races in both actual role modes. The release-candidate full web rerun found an existing DST-sensitive
API-key date fixture; freezing Date (not timers) preserves its exact seven-day assertion. The focused seven
API-key tests passed, then all complete v0.6.0 candidate gates passed (490 seconds): all 844 web tests,
typecheck/build/styling/size/audit, Go vet/format and scratch build/version, actionlint, Kubernetes validation
and smoke-helper Python tests. Release-source GitHub checks/publication verification subsequently passed
as recorded above. CI-pinned govulncheck
reports zero reachable/package vulnerabilities and two module-only advisories; npm audit reports zero.
Owned browser, compatibility and final-suite fixtures are stopped/removed; existing development ports and
any historical database/keys remain untouched.
Earlier full-gate failures identified a
missing access-request audit-label lookup and a stale preference fixture; both were fixed with retained
regressions. Real-browser testing found/fixed a long-button mobile overflow. The OpenAPI response contract
also has an explicit regression against a closed-object `allOf` mismatch. Release acceptance is linked above.
Real-client/provider/channel/pilot and independent whole-product review issues remain open.

## v0.5.1 (2026-10-28): provider-refresh reliability

The final handoff CI exposed a shared-refresh concurrency hang, independently reproduced with an actual
one-connection runtime pool. The reviewed fix and test are merged into main, tagged immutably at
`10753fec4610cb290454cb2767bdaebdf51120ae` and
[published on GitHub](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.5.1).
Narrow transaction-scoped endpoint reads, checked address-policy failures, whole-exchange deadlines and
explicit cancel/drain remove the nested pool acquisition before transaction SQL resumes. Row-lock
serialization, live linked-provider/post-refresh authority checks and commit-before-cache publication remain.
No API or schema migration is added; see [patch notes](releases/v0.5.1.md). The v0.5.0 tag/image remain immutable.

Verification:
- The parent reproduced the pre-fix five-second failure in both database-role modes. The unchanged regression
  now passes with one runtime connection, two cold handlers, singleton/eight concurrent calls, exactly one
  refresh and committed rotation. Denial/missing-policy controls preserve consent and dispatch nothing.
- Independent correctness and security reviews approved without confirmed findings; both ran focused tests,
  including repeated races in the two role modes. Linked-provider, SQL-error, cancellation/late-dial and
  cache-isolation regressions passed. These are scoped agent reviews, not #13's whole-product assessment.
- Full merged normal/race suites passed in **both** legacy and authenticated split-role modes. The legacy
  normal suite passed first; a shared compiler-cache artifact disappeared during the next build, so the
  remaining full suites were rerun using an owned isolated `GOCACHE` (1,145 seconds). No vet/race gate was disabled.
- Generation, lint/build, freshness, Kubernetes validation, actionlint, four smoke-helper tests and all web
  gates passed (**836 tests**). npm audit reports zero vulnerabilities; CI-pinned govulncheck reports zero
  reachable vulnerabilities (two module-only advisories). No new dependency was added.
- [Main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40799601862), both
  [kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40799601853), and
  [native multiarchitecture image build/scan/sign/publication](https://github.com/ncecere/open-mcp-portal/actions/runs/40801468165)
  passed at the release commit.
- Independently verified the tag/index digest, exactly linux/amd64 and linux/arm64, tag-specific GitHub OIDC
  cosign identity/certificate/transparency proof, all asset checksums and equality of both SPDX assets with
  registry attestations. The published arm64 image runs as `65532:65532`, read-only without network,
  reporting `open-mcp-portal 0.5.1 (10753fec4610)`. The verified example-overlay digest is
  `sha256:f0752082128be618003c0a5f0e2917c7b5cabc64b60bdec60d161135519617d2`.

The owned disposable PostgreSQL container is removed; development services/data were untouched. No fresh
browser run was needed for this backend-only patch; the v0.5.0 browser evidence below remains scoped to
those pages. Real IDE/provider/channel/pilot and broader load/soak evidence remain open. No production
deployment is implied. **Original machine-transfer stop point:** no #32 or other feature work had been started at publication. Final main follow-ups
only record release evidence, the verified image pin and the agent/machine handoff.

## v0.5.0 (2026-10-28): exact-call approvals

#31 is shipped and closed with [acceptance evidence](https://github.com/ncecere/open-mcp-portal/issues/31#issuecomment-6484059268).
The immutable annotated tag points to `01cd127f888727b5b60897be7a059f2acd4da4f6`; the release is
[published on GitHub](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.5.0).
Implementation is integrated, independently reviewed and validated. Migrations `00035`–`00042`
provide exact-call requests/rules, nonblocking authority journaling, stable binding-key rotation and protected
private-schema storage. Browser/session APIs, all three MCP client response shapes, single-use dispatch,
no post-spend replay, private notifications and eligible attention are implemented. See
[release notes](releases/v0.5.0.md) and [design](tool-approvals.md).

Verification evidence:
- Full required-PostgreSQL normal and race suites passed in legacy and genuinely authenticated split-role
  modes (four runs, 1,425 seconds). Subsequent exact-Unicode binding regressions passed in both modes.
- Generation, lint, build, generated-code freshness and all web gates passed; **836 web tests**. Final
  release-version/deployment checks, actionlint and the smoke-helper regressions passed. CI exposed a
  minute-boundary assumption in the OAuth rate-limit fixture and an approval-matrix setup failure.
  Controlled maintenance contention reproduces the latter; historical CI backend logs cannot identify its
  exact blocker. Deterministic regressions preserve the limits and production fail-closed fence. After these test-only
  fixes, merged normal suites in both modes and repeated focused races passed (1,447 seconds).
- CI-pinned govulncheck reports zero reachable vulnerabilities (two module advisories are unreachable);
  npm audit reports zero vulnerabilities. The existing transitive Seroval dependency was updated to 1.7.3
  for newly reported advisories; all 836 web tests/gates were rerun. GitHub reported zero open Dependabot alerts.
- The parent rebuilt untouched v0.4.0 from its tag and independently ran strict split-role startup, HTTP
  readiness and a journaled HTTP authority write against schema 42. No old-image approval enforcement is implied.
- Owned disposable browser checks covered rule creation, URL review, redaction, exact MCP dispatch, spent
  receipts, auditor metadata-only access and consuming a pre-relocation request afterward. At 390px,
  queue/receipt/rules/editor pages have no horizontal overflow and axe reports zero violations/incomplete
  checks. Preview keyboard scrolling works. The desktop shortcut contrast is 7.30:1.

[Main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40788841938), both
[kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40788844565), and
[native image build/scan/sign/publication](https://github.com/ncecere/open-mcp-portal/actions/runs/40791058998)
passed at the release commit. Independently verified the exact tag/index digest, amd64+arm64 platforms,
tag-specific GitHub OIDC cosign identity, trusted certificate and transparency-log inclusion. Asset checksums
match and both SPDX assets equal the registry attestations. The published arm64 image runs as `65532:65532`,
read-only with no network, reporting `open-mcp-portal 0.5.0 (01cd127f8887)`. Verified digest, pinned in the
example overlay:
`sha256:6ecbdda5ac21cf7257208c878f954d36ac7903ecb1aa0e671a9a2e516f3bdc3a`.

No production deployment or external IDE/provider/pilot acceptance is claimed. Development services/data
were untouched; owned scratch PostgreSQL containers, browser sessions, private fixture configuration and
scratch app/fake servers were cleaned up. The release tag remains immutable; subsequent main commits record
publication evidence and the verified example digest.

The redundant tag CI later hit Go's default aggregate 10-minute package timeout while `TestTokenMatrix`
was still progressing (six seconds into that test), without an assertion failure. Main now gives the expanded
race suite an explicit 20-minute per-package budget and 45 minutes for both complete role-mode runs.
Required PostgreSQL, race detection, all tests and authorization/vulnerability/readiness checks are unchanged.
The release tag is not moved; this is a CI-harness follow-up, not a runtime change.

## v0.4.0 (2026-10-28): MCP-only governance

Shipped and closed: scopes (#29), curation (#30), shared service connections (#26), database-role separation
(#44) and external-platform retirement (#68). Integrated on `integration/credential-policy`, fast-forwarded
to main and tagged at `d6fe895c1aa732b2cdc6c6016b63ebd59c6710d3`; the release is
[published on GitHub](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.4.0).
[Release/upgrade notes](releases/v0.4.0.md) cover migrations `00029`–`00034` and mixed-version policy limits.
The owner withdrew Pi Durable Platform/external-platform impersonation ([decision 81](decisions.md));
#62/#63 are closed as **not planned**, not completed remediation or verification. Retirement disables
issuers/marked accounts, revokes their keys and fences authority restoration while preserving marks/history.
Normal MCP clients, OAuth, keys, service accounts, personal connections and outbound identity remain.
Existing development services/data have not been changed; verification uses owned disposable fixtures.

Independent reviews and combined regressions corrected scope/OAuth serialization, curation numeric
persistence/retry records, UTC retention arithmetic, shared-connection transaction ordering and retired-account
preservation. A final narrow review approved the five shared transaction fixes and callback guidance without
confirmed findings. Local deletion/audit commits before upstream revocation HTTP; consent uses user
`KEY SHARE` → session → connection → state ordering, with final live authorization checks after waits.

**Final combined tree passed:** `make generate`, `make lint`, `go build ./...`, `make check-generated`,
required-PostgreSQL `make test` and full `go test -race -count=1 ./...` in **both** legacy and genuinely
authenticated split-role modes; web typecheck, **796 tests**, build, styling and size checks; Kubernetes
validation, actionlint, four smoke-helper lifecycle tests and clean diff checks. The full Go/deployment run
completed in 1,130 seconds after the final shared-transaction and callback corrections. Those transaction
regressions also passed three focused race repetitions per mode. Owner-only fixture DDL uses `OwnerPool`;
application writes still use authenticated runtime. Role changes were tested only in an owned disposable
PostgreSQL container, never against the development database.

**Browser/wire evidence:** literal-name scope entry preserves commas; fixed-argument `demo_echo` accepts
injected values and rejects conflicting values/old names. Shared consent through the fake OAuth server,
explicit service-account assignment and destination grants succeed. Actual legacy and modern MCP calls
receive the shared credential with verified portal identity and matching provider claim; a normal personal
caller still needs its own consent and has no personal connection. A 390px shared-connections screen has no
horizontal overflow and zero axe violations/incomplete checks. Browser checks found and corrected a shared
completion page that wrongly linked personal connections, and stale relay wording.
Rebuilt mobile completion now shows shared guidance and a safe portal link, never personal-connection
instructions. Revoking the shared connection in the UI stops the same service key's next call (`-32010`);
all temporary wire-test keys were revoked. The completion screen has zero axe violations and one gradient
contrast item: manual conservative calculation gives **6.49:1**, above the 4.5:1 normal-text minimum.
These fake-server checks are not real-provider/IDE/pilot acceptance, a full mobile/all-page audit or a
wall-clock refresh/expiry soak. No production deployment was performed.

Final [main CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40735137564), both
[kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40735137539) and the
[native image/release workflow](https://github.com/ncecere/open-mcp-portal/actions/runs/40737187805) passed.
Verified the published tag and exact amd64/arm64 index, both SPDX SBOM checksums and digest asset. Cosign
validated the tag-specific workflow identity, GitHub issuer, trusted certificate and transparency-log
inclusion. The arm64 image ran as `65532:65532`, read-only with no network, and reported
`open-mcp-portal 0.4.0 (d6fe895c1aa7)`. The verified index digest, now pinned in the example overlay, is
`sha256:7610c003c56d92e460c504b9752d91e89b75c7006630ca0e2b8d5c235d57a016`.
Owned scratch browser/app/fake-server processes and PostgreSQL were stopped/removed; private fixture
credentials, harness and binaries were removed. Existing development services/database were untouched.
GitHub reported zero open Dependabot alerts after publication.

## v0.3.3 (2026-10-28)

The [implementation order](implementation-order.md) reconciled 36 open GitHub issues with the v0.3.2
checkout. Shipped and closed: **#28 owner-set tool classification** and independent **#37 browser sessions**.
The classification [design](tool-classification.md) records the trust boundary and migration `00027`;
[session management](phase4-client-auth.md#browser-sessions-37-decision-76) uses migration `00028`.
The combined implementation is committed as `9864b75`; the release is tagged at `8a10de3` and
[published on GitHub](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.3.3). No production deployment
has been performed.

Subagent implementation and independent code reviews found and fixed three regressions before finishing:

- A capability refresh did not advance the server revision. Added/changed/gone capabilities now invalidate an
  old classification dialog; unchanged refreshes preserve its revision. Existing owner classes still
  intentionally survive changed definitions.
- Logout and session revocation deleted rows in opposite orders. Both now lock/delete the session before its
  connect states. A coordinated PostgreSQL regression fails against the old order with a deadlock and passes
  against the fix, including ten race-enabled repetitions.
- Session UI success handling could use a changed keep-current checkbox value rather than the submitted
  choice. The mutation now captures its inputs and sign-out effect; controls are disabled while pending.
  Delayed-response and credential/cache-clearing regressions cover it.

**Passed on the combined tree:** `make generate`, `make lint`, `go build ./...`, `OMP_TEST_REQUIRE_DB=1 make test`
(all Go tests with PostgreSQL required), focused session/classification tests with `-race`, `git diff --check`;
and web typecheck, **697 tests in 71 files**, production build, styling and source-size checks.

**Browser-checked on a scratch database and separate loopback ports:** classification bulk suggestions,
individual lowering and re-review, read-only admin classes; upgrade with an existing browser session intact;
Account Sessions listing/current marker, another-session revocation, keep-current sign-out, default sign-out
and admin self-revocation (the latter two returned to sign-in and `/v1/me` answered 401). Desktop screenshots
were inspected. Browser axe checks reported zero violations on the checked classification/session screens;
incomplete checks remain (the existing search-shortcut contrast and modal background focus checks), so this
is not a complete accessibility audit. Existing dev services and database were left untouched.

**Not run:** real-client/provider/pilot verification, a live Pi Durable Platform instance, a wall-clock idle
expiry soak, a full mobile/all-page browser pass or a fresh conformance-suite run. Docker and deployment
checks subsequently passed in release CI, as recorded below. Idle boundaries,
cleanup and activity throttling are covered with an injected clock. Very large session inventories have not
been load-tested; revoke-all currently deletes pending connect states per ended session.
At release preparation, the external agreement for #62 could not be verified (the linked upstream repository
returned 404). That work has since been withdrawn by the owner; see the unreleased scope change above.
The next implementation lanes were
**#29 scopes**, **#30 curation**, **#26 service connections** and **#44 database roles**, in isolated branches.

The first release-candidate CI passed the full Go race suite, Docker builds, generated-code and deployment
checks, and kindnet/Calico smoke tests, but failed dependency gates: Go 1.26.9's x509 advisory and Undici 8.12.1.
The toolchain/builder are updated to Go 1.26.10 and the web lockfile to Undici 8.12.3; patched application CI
passed. Calico smoke then exposed an orphaned port-forward into a draining pod after eviction: the wrapper
PID, not `kubectl`, had been stopped. The helper now launches/reaps the real process and waits for the evicted
pod to disappear. Four deterministic lifecycle tests reproduce the old failure and pass the fix.

Final [CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40697899296), both
[kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40697899038), and the
[native multi-architecture image/release workflow](https://github.com/ncecere/open-mcp-portal/actions/runs/40699155000)
passed at `8a10de3`. The published index contains linux/amd64 and linux/arm64, with SBOMs and checksums.
Cosign verification checked the tag-specific workflow identity, GitHub issuer, trusted certificate and
transparency-log inclusion. The arm64 image ran read-only with no network and reported
`open-mcp-portal 0.3.3 (8a10de3e34ec)`. The verified index digest is
`sha256:021672961ead3bc78de0e2383373e780ce1035b34b25d676e433199dcf8c5ed8`; the example overlay was pinned to it at publication.
GitHub reported zero open Dependabot alerts after publication.

At v0.3.3 publication, #29/#30/#26/#44 remained staged rather than shipped. See the v0.4.0
section above for their combined verification and the subsequent MCP-only retirement. No production
deployment is implied by either publication or scratch-environment checks.

## v0.3.2 (2026-10-20)

Per-person secrets, machine OAuth, mTLS and a private CA (migrations `00024` to `00026`): see the [release notes](releases/v0.3.2.md). Verified by tests on each branch and the merged tree, and a browser check of the add-server form; **not** run against a real authorization server, a real server that wants a per-person key or a client certificate, or checked in a browser beyond the form.

## v0.3.1 (2026-10-20)

Provider access lists and narrowing, credential parts, tracing (migrations `00021` to `00023`): see the [release notes](releases/v0.3.1.md). Verified by tests and a browser check of two screens; **not** run against a real provider, a real collector or a real server that wants Basic or a query key.

## v0.3.0 (2026-10-20)

Agent-platform trust (migration `00020`): see the [release notes](releases/v0.3.0.md) and [agent-platforms.md](agent-platforms.md). Verified by tests, a contract check against tokens signed by Pi Durable Platform v0.4.0's real signer (19 tokens, 5 key sets) and an independent security review (0 Critical or High). **Not** verified: a live Pi Durable Platform instance end to end.

## v0.2.2 (2026-10-20)

Hardening (migrations `00018`, `00019`): see the [release notes](releases/v0.2.2.md). Verified by tests, including a full authorization-code and PKCE flow for Claude Code's metadata-document shape with a loopback redirect; **not** yet browser-checked or run with the real Claude Code client.

## v0.2.1 (2026-10-18)

What is planned next, and what is still unverified, is the [roadmap](roadmap.md): 49 issues in five [milestones](https://github.com/ncecere/open-mcp-portal/milestones), each with its implementation plan.

The cluster deployment (mcp.bitop.dev) runs v0.2.1, rolled out one replica at a time with no failed readiness probe.

Built, see [CHANGELOG.md](../CHANGELOG.md): a manual **Test connection** sends the editor's identity token and says when the server refuses it (decision 61; the limit is stated there: a server that refuses only at tool execution still passes), and `OAUTH_MAX_REGISTERED_CLIENTS` caps Dynamic Client Registration (threat model H-4, cap done). Verified by Go tests against PostgreSQL (the Test with a fake upstream that refuses `Authorization` at the HTTP level, with the token verified against the JWKS, and the cap with concurrent registrations) and the web tests. Not tried against DeepWiki itself or in a browser.

## v0.2.0 (2026-10-18)

Built: MCP 2026-07-28 toward clients and toward upstream servers ([mcp-protocol.md](mcp-protocol.md); migration `00016`), the admin
overview and team attention, notifications (inbox, email, signed and Slack webhooks), automation tokens (migrations `00014`, `00015`;
designs: [admin-overview.md](admin-overview.md), [notifications.md](notifications.md), [automation-tokens.md](automation-tokens.md)), and the
fixes F-1 to F-4 from the [threat model](threat-model.md), F-3 with migration `00017` (decisions 59 and 60).

Verified: Go tests with PostgreSQL (the route test and an authorization and token matrix over every operation), the web tests, the
`@modelcontextprotocol/conformance` suite, and a browser walkthrough of the new screens against a real stack (an SMTP sink, a webhook receiver,
the fake MCP and OAuth servers): the overview, a test email, a webhook test with its signature checked, a publish request raising a bell
entry, an email and a webhook, a review with the digest, the decision notification, a platform token against the API, and F-3 end to end
(consent naming the server, the grant ending when the server moves to another origin, allowing it again without a provider round trip).

Verified after the release (2026-10-18): Claude Code 2.1.280 was run against a gateway (API-key authentication): it spoke 2026-07-28 natively (`server/discover`, the lists, and `tools/call` with the required `Mcp-Method` and `Mcp-Name` headers), and it showed the person the consent link from the tool error (it declares form-mode elicitation only, so it takes the tool-error answer of decision 59). v0.2.0 was also deployed to a real Talos cluster (CloudNativePG, Traefik, Pangolin, Authentik sign-in; health, `doctor` and the OAuth endpoints checked from outside), with continuous WAL archiving and a daily base backup of its database to object storage. A restore was tested the same day: a scratch cluster recovered in about 70 seconds with identical data and a row written after the base backup (WAL replay). On that deployment Claude Code also signed in over OAuth (a metadata-document client, no registration or consent page) and called tools through a gateway; that run found that a public server refusing any `Authorization` header (DeepWiki) fails on its first call with the identity token on, which led to the v0.2.1 changes. A second restore, in the live namespace under its network policies, also recovered with identical data.

Verified on kind (2026-10-18, `make k8s-smoke`, [deploy.md](deploy.md#smoke-test)): the Kustomize base applied through `overlays/smoke` to a
three-node kind cluster (Kubernetes 1.37.0) with a throwaway PostgreSQL 17 and the in-cluster fake MCP server: the migrate init container and
`doctor`, two replicas on different nodes, the PodDisruptionBudget (one eviction allowed, a second refused), `/healthz`, `/readyz`, development
sign-in, and team, server, gateway and API key through the API, then `tools/list` and `tools/call` at `/mcp/{slug}` in the legacy and the
2026-07-28 era; a rolling update and a pod deletion with no failed request through the Service, and the SIGTERM drain (`/readyz` 503, 10 s, `shutdown complete`).
With `SMOKE_CNI=calico` the NetworkPolicies are enforced and tested (an outside pod cannot reach the portal; the portal reaches PostgreSQL and the
MCP server). Not covered: NetworkPolicy under the default CNI (kindnet does not enforce it), the `egress-https` rule, ingress and TLS, OIDC,
the internal-network allowlist (development sign-in allows private upstream addresses anyway), zones, upgrades between releases and
restores. `.github/workflows/k8s-smoke.yml` ran on GitHub on 2026-10-18 and passed on both CNIs (kindnet and Calico).

Not verified: a client that declares URL elicitation, VS Code and Cursor; a real SMTP provider over TLS and a real Slack webhook; the Kubernetes egress rows on a real cluster; a real Google or
Microsoft provider. Still open from the threat model: the hardening ideas in section 9 (notably H-5, scopes per call and a per-provider
server allow-list).

## Summary

- **Phases 1 to 7 are done** (backend and web UI): foundations, registry and catalog, gateways, client sign-in and
  service accounts, delegated credentials, operations, and per-person OAuth to upstream MCP servers. Details per phase
  below and in each design's "As built" section.
- **Verified with real clients and a real upstream server:**
  - Claude Code's real client signed in to a gateway over OAuth (CIMD, a trusted client, so no consent page) and
    called tools.
  - pi signed in over OAuth (dynamic client registration, through the consent page) and called tools.
  - GitHub's hosted MCP server (`https://api.githubcopilot.com/mcp/`) was set up as an `oauth`-mode server with a
    GitHub App as a manual client, each person signed in with their own GitHub account, and six tools worked from pi:
    `get_me`, `search_repositories`, `list_issues`, `list_branches`, `get_file_contents`, `search_code`.
  - The fixes this found are in git: `4f75508` (an empty token scope from a GitHub App is no scope information),
    `9ff238e` (drop non-object `outputSchema`s; client cancellations aren't errors), `f3272d9` (the server's own
    reason in failed-exchange errors), `6fe0995` (SEP-2243 `Mcp-Param-*` headers on forwarded calls), `0182c12`
    (drop non-object `structuredContent`).
- **Not verified yet:**
  - a real Google or Microsoft delegated-credentials provider (Phase 5 auth providers were only run against the fake,
    `make fake-oauth` with `make example-mail-fake`);
  - VS Code and Cursor (only their configuration snippets; Claude Code and pi were run);
  - a smoke test on kind: now `make k8s-smoke` (see "Verified on kind" above; `.github/workflows/k8s-smoke.yml` not run on GitHub yet);
  - the release workflow (`.github/workflows/image.yml`: native amd64 and arm64 builds, scan, cosign signing, GitHub
    Release) on GitHub's runners: it runs for the first time on the `v0.1.0` tag. `scripts/github-release.sh` was
    dry-run with a stand-in SBOM; `actionlint` and `shellcheck` pass.
- **Release v0.1.0 (2026-10-17), then v0.2.0 (2026-10-18).** `v*` tags run `image.yml`: multi-arch image `ghcr.io/ncecere/open-mcp-portal`
  (tags `vX.Y.Z`, `latest` for final releases) with SBOM and provenance, cosign keyless signature, and a GitHub Release
  from `docs/releases/vX.Y.Z.md`. The Kustomize base uses the `v0.1.0` tag; overlays pin the digest. `CONTRIBUTING.md`
  has the release steps. `compose.demo.yaml` still builds locally.

## Where things stand

- **Renamed to Open MCP Portal (decision 46).** Formerly Open MCP Gateway. Module
  `github.com/ncecere/open-mcp-portal`, binary and command `open-mcp-portal`, `OMP_*` environment variables (`OMP_CONFIG_FILE`,
  `OMP_TEST_DATABASE_URL`, `OMP_TEST_REQUIRE_DB`, `OMP_TEST_LOG`, `OMP_DEMO_PORT`, `OMP_IMAGE`, `OMP_FAKEMCP_IMAGE`),
  metrics `omp_*`, Kubernetes names `open-mcp-portal*`, dev Compose project `open-mcp-portal` (database and user
  `omp`). Prefixes: personal keys `omp_`, service account keys `omp_sa_`, access tokens `ompat_`, refresh tokens
  `omprt_`, codes `ompac_`, registered client IDs `ompcl_`, exposed resources `omp://`; keys and tokens made before
  no longer authenticate, and capture redaction still recognises the old prefixes. Migration `00013_open_mcp_portal`
  (the purge settings `omp.audit_purge`/`omp.calls_purge`, old names still accepted; key prefix checks accept both).
  The `MCP-Gateway-*` headers and the Gateways feature keep their names. An existing dev database moves with
  `scripts/migrate-dev-db.sh`; an existing `.env` needs `DATABASE_URL=postgres://omp:omp-dev-only@127.0.0.1:55442/omp?sslmode=disable`.
- Requirements interview: done. Decisions in [decisions.md](decisions.md); architecture, data model and phases in
  [../SPEC.md](../SPEC.md).
- **Phase 1 (foundations): done.** Browser QA found one blocking bug (`name@localhost` rejected) and polish items; fixed
  in the Phase 2 UI pass except: unnamed command-palette listbox (in `components/ui`), admin team tabs wrapping and
  breadcrumb collapse gap on mobile.
  - Go backend: config, store, migrations (`00001_identity`, `00002_teams`), OIDC + dev sign-in, sessions,
    users, teams, members, invites, platform admin, audit, all routes in `api/openapi.yaml`.
  - Tests: unit + integration (per-test databases), route/OpenAPI contract test, authz matrix over every operation.
  - Verified: `go build`, `go vet`, `gofmt`, `go test ./...`, integration tests with `-race`, `serve` smoke test.

- **Phase 2 (registry): done.** Browser QA run end to end; its findings are fixed (URL change now re-reads
  capabilities and blocks approval until read; form error clearing; rejected → private; wording/confirmations).
  Not re-checked in a browser after the fixes: the 390px layout tweaks. See [registry.md](registry.md).
  - UI routes: `/teams/$team/servers` (+ `?form=new`), `/teams/$team/servers/$serverId` (Overview, Capabilities,
    Health, Settings), `/catalog`, `/catalog/$serverId`, `/admin/servers`, `/admin/servers/$serverId`,
    `/admin/publishing`, publishing override in admin team › Settings. Shared record code in
    `web/src/components/servers/`. 171 Vitest tests.
  - Migration `00003_registry` adds `mcp_servers`, `mcp_capabilities`, `mcp_health_checks`, a one-row `platform_settings` table and `teams.publish_policy_override`.
  - New packages: `internal/registry`, `internal/upstream` (guarded client and SSRF guard), `internal/secrets`, plus `cmd/fakemcp` (`make fake-mcp`).
  - New config: `ENCRYPTION_KEY` (required by `serve`; the example key is refused off loopback), `ENCRYPTION_KEY_PREVIOUS` and `HEALTH_CHECK_INTERVAL` (default 5m). **An existing `.env` needs the `ENCRYPTION_KEY` line from `.env.example`.**
  - Every Phase 2 route in `api/openapi.yaml` is served, with no contract changes. The authz matrix covers every new operation. The tests cover discovery against a fake server, change detection, both publishing policies, catalog visibility and header-value non-disclosure.
  - Gaps: there is no bulk `rotate-keys` command. A URL change on a published server goes back to review under approval_required.

- **Phase 3 (gateways): backend and UI done; verified end to end with curl** (team server → gateway with 2 of 5
  tools → API key → `initialize`, `tools/list` shows only the 2, `whoami` reaches the fake with a JWT it verified
  against JWKS, an unselected tool is refused as unknown and logged `denied`). Browser QA done (no security or blocking bugs); its findings are fixed. 235 Vitest tests. See
  [phase3-gateways.md](phase3-gateways.md) "As built" and [upstream-identity.md](upstream-identity.md).
  - Migration `00004_gateways` adds `gateways`, `gateway_capabilities`, `gateway_grants`, `api_keys`, `signing_keys`,
    `mcp_calls` (append-only) and `users.groups`.
  - New packages: `internal/gateways`, `internal/mcpgw` (`/mcp/{slug}`), `internal/identity` (ES256 JWT, JWKS at
    `/.well-known/jwks.json`, rotation loop), `internal/apikeys`, `internal/calls`. `internal/upstream` gained
    `CallTool`/`GetPrompt` and an identity header; `cmd/fakemcp` gained `whoami`/`echo` and `-jwks`.
  - New config: `API_KEY_PEPPER` (required by `serve`; the example value is refused off loopback) and
    `OIDC_GROUPS_CLAIM` (default `groups`). **An existing `.env` needs the `API_KEY_PEPPER` line from `.env.example`.**
    Dev personas sign in with sample groups (engineering, support, …) for group grants.
  - Every Phase 3 route in `api/openapi.yaml` is served with no contract changes; the contract test skips `/mcp/` and
    `/.well-known/`. The authz matrix covers every new operation. Integration tests cover selection rules, grants by
    team/user/group, `/v1/me/gateways` reasons, an SDK-client end-to-end run (JWT verified against the JWKS, aud =
    server URL, never the API key), nine refusals between list and call that never reach the server, key rotation, and
    a sentinel check that arguments/results are absent from `mcp_calls`, audit and logs.
  - Gaps: resource subscriptions; no rate limit on `/mcp`; no SSE relay (calls are
    buffered within 1 MiB); `server/discover` (2026-07-28 stateless protocol) answered "method not found".
  - Follow-ups done (not yet browser-checked): archived teams stop serving (their team gateways answer 404, their
    servers leave the catalog, gateway-options and health loop, other gateways show `team_archived`; unarchive
    restores); signing keys are pre-published (`next` state, `SIGNING_KEY_PREPUBLISH`, default 24h; migration
    `00005_signing_key_next`); `/v1/me` returns `groups` (Account › Profile shows them; My gateways names the granting
    group via `MyGateway.groups`); `GET /v1/admin/mcp-servers/{serverId}/health-checks` (Admin's Health tab uses it);
    policy changes leave pending servers pending (documented in [registry.md](registry.md), tested).
    Contract changes: `GatewayUnavailableReason` + `team_archived`, `Me.groups` (required), `MyGateway.groups`
    (optional), the admin health-checks operation.
  - Follow-ups done (not yet browser-checked): gateway-options paged (`GatewayOptionPage`, `cursor`/`limit`
    100–500/`q`/`kind`/`server`; the picker searches on the server, filters by kind and server, loads more);
    resources and resource templates (exposed as `omp://{serverSlug}/{uri}`, RFC 6570 `{var}`/`{+var}` templates,
    `resources/list|templates/list|read`, JWT claim `resource`); API keys limited to gateways (`gatewayIds`,
    `ApiKey.gateways`, error class `key_scope`). Migration `00006_gateway_resources_key_scopes`. See
    [phase3-gateways.md](phase3-gateways.md) "As built".

- **Internal MCP servers (decision 20): done, not browser-checked.** Platform admins allow internal networks (CIDRs)
  and host names (exact or `*.suffix`, optionally with plain http) in **Admin › Internal networks**
  (`/admin/networks`: staged edits, Save with If-Match and confirmation, read-only deployment entries, a URL checker);
  `UPSTREAM_ALLOWED_NETWORKS` adds read-only deployment entries. Loopback, link-local/metadata, unspecified, multicast
  and broadcast stay blocked. Rules in [registry.md](registry.md#security), operations in
  [deploy.md](deploy.md#internal-mcp-servers).
  - Migration `00007_network_allowlist` adds a one-row `network_settings` table (entries JSON, own revision).
  - New package `internal/netpolicy` (classification, canonical entries, matching); `upstream.Client` gained
    `Networks` (the live policy) and `Dial` (a test seam); `registry.Networks` caches the admin entries (30s; the saving
    replica applies a change at once).
  - Contract changes: `GET`/`PUT /v1/admin/settings/network`, `POST /v1/admin/settings/network/check`; schemas
    `NetworkEntry`, `NetworkSettings`, `NetworkSettingsUpdate`, `NetworkCheckRequest`, `NetworkCheckResult`; new
    `url_not_allowed` reason `blocked_address` (loopback/link-local/metadata literals and `localhost`, previously
    `private_address`); `private_address` now says a platform admin can allow the network; audit
    `settings.network_update`. `Registry.Target` takes a context.
  - UI: the add-server and settings URL fields let plain http through to the server (it decides from the allowlist);
    a `private_address` refusal links platform admins to Internal networks and tells others to ask one.

- **Phase 4 (client sign-in and service accounts): backend and UI done; QA follow-ups done.** OAuth 2.1 authorization
  server for `/mcp/{slug}` (always on; CIMD and DCR clients, PKCE S256, resource = one gateway, consent per person +
  client + gateway, trusted clients, rotating refresh tokens) and team service accounts with `omp_sa_` keys. See
  [phase4-client-auth.md](phase4-client-auth.md) "As built", [connect-clients.md](connect-clients.md) and
  [upstream-identity.md](upstream-identity.md) (`principal_type`).
  - Migration `00008_client_auth` adds `oauth_settings` (trusted clients, seeded with Claude, Claude Code, VS Code),
    `oauth_clients`, `oauth_grants`, `oauth_codes`, `oauth_tokens`, `service_accounts`, `service_account_keys`,
    `service_account_key_gateways`; `mcp_calls` gains principal kinds `oauth`/`service_account` (nullable `user_id`)
    and snapshot columns.
  - New packages: `internal/oauth`, `internal/serviceaccounts`, `internal/ratelimit`. `upstream.Client.GuardedDial`
    lets metadata documents use the MCP servers' address guard and allowlist. `auth.SessionUser`/`LoginURL`; the
    post-login `next` limit grew to 8300 characters (an authorization request).
  - Protocol endpoints `/oauth/*` and `/.well-known/oauth-*` are outside the OpenAPI contract (the contract test skips
    `/oauth/`). Every `/v1` route already in `api/openapi.yaml` is served with **no contract changes**; the authz
    matrix covers all 16 new operations.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration` (race), and a curl smoke
    test (fake MCP server, CIMD on a loopback http server under the development allowance, hand-made PKCE pair,
    consent, token, `tools/call whoami` showing `principal_type: user` and `client`, refresh rotation, then a service
    account key showing `principal_type: service_account`). Real clients: Claude Code (CIMD, trusted, no consent) and
    pi (DCR, consent page) signed in and called tools. VS Code and Cursor not tried.
  - Gaps (rate limits and pepper rotation: done in Phase 6): no rate limit on `/mcp` itself; rate counters per process; no previous-pepper support (rotating
    `API_KEY_PEPPER` signs clients out and invalidates keys); no CORS on OAuth endpoints; no private-use redirect
    schemes; DCR clean-up runs on registration; the previous release can't list call records of service accounts.
  - QA follow-ups done (not yet browser-checked): see [phase4-client-auth.md](phase4-client-auth.md) "As built: QA
    follow-ups". Contract changes: `GET /v1/teams/{team}/service-accounts/{serviceAccountId}/gateways`
    (`MyGateway` items), `GET /v1/admin/service-accounts` (`ServiceAccountPage`), team call lists also include the
    team's service accounts' calls through any gateway, `CallPrincipal.serviceAccountExists` and
    `oauthClientVerified`; identity JWT claim `client_verified`. Migration `00009_call_principals` (nullable
    `mcp_calls.oauth_client_kind`, an index). CIMD fetches logged at info level; the OAuth error page follows the
    color mode; UI fixes (rotation note, sign-in note for apps, combined notices, wording, focus).

- **Phase 5 (delegated credentials): done.** Auth providers (presets for GitHub, Google, Microsoft Entra ID,
  Atlassian, Slack, GitLab), server requirements and capability overrides (review when widened), consent links
  (JSON-RPC `-32042`), the connect flow (`POST /v1/me/connections/start`, `GET /connect/callback`), tokens sealed and
  refreshed under a row lock, revocation, and the runtime headers `MCP-Gateway-Provider`/`MCP-Gateway-Provider-Token` with
  the identity claim `provider`. See [phase5-delegated-credentials.md](phase5-delegated-credentials.md) "As built" and
  [upstream-identity.md](upstream-identity.md#provider-tokens).
  - Migration `00010_delegated_credentials` (`auth_providers`, `provider_connections`, `provider_connect_requests`,
    `provider_auth_states`; requirement columns on `mcp_servers`/`mcp_capabilities`; `mcp_calls.provider_slug` and the
    outcome `needs_authorization`).
  - New package `internal/providers`; `cmd/fakeoauth` (`make fake-oauth`, port 8092); the fake MCP server's
    `provider_token` tool. No new settings.
  - Contract: all 14 operations served. Additive changes made while building: `AuthProviderPreset.redirectUri`, `name`
    in `in_use` details' servers, provider slugs `done` and `callback` reserved (`422 invalid_slug`).
  - UI: Admin › Auth providers, Account › Connections, the connect pages (`/connect/{provider}`, `/connect/done`),
    "Needs" badges on servers and gateways.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration` (race), `make k8s-validate`;
    end to end only with the fake provider (`make fake-oauth`, `make example-mail-fake`). Not verified against a real
    Google or Microsoft provider.
  - Gaps: no background refresh (the start rate limit is shared since Phase 6); see the design's "Not in this phase".

- **Phase 6 (operations): backend and UI done; browser QA done and its findings fixed.** Rate limits shared by replicas in PostgreSQL (per person, credential,
  service account and gateway; 429 + JSON-RPC `-32029`, recorded `rate_limited`), payload capture (opt-in per gateway or
  server, redacted, 16 KiB, sealed, audited views), retention loop, hourly usage rollups and reports, Prometheus metrics
  on `METRICS_ADDR`, `API_KEY_PEPPER_PREVIOUS`, `open-mcp-portal rotate-keys`, doctor key reports, and
  `.github/workflows/ci.yml`. See [phase6-operations.md](phase6-operations.md) "As built" and [deploy.md](deploy.md)
  (Metrics, Key rotation, Scaling).
  - Migration `00011_operations`. New packages `internal/limits`, `internal/capture`, `internal/retention`,
    `internal/usage`, `internal/observability`, `internal/keyrotation`; `internal/ratelimit` has a PostgreSQL store, and
    the OAuth, connect-start, sign-in and `/v1` limiters use it. Dependency `prometheus/client_golang` v1.25.0.
  - New config: `API_KEY_PEPPER_PREVIOUS`, `METRICS_ADDR`, `METRICS_MAX_OBJECTS`, `RETENTION_INTERVAL`,
    `RETENTION_BATCH_SIZE`. New targets `make test-ci`, `make actionlint`.
  - Contract: all 19 operations and the new fields served; **no contract changes**.
  - UI: Admin › Limits, Retention, Payload capture (patterns, tester), Usage; Admin › Teams › a team › Limits &
    retention; Team › Usage and Settings › Limits & retention; gateway rate limit and "Record call contents" switches
    on gateways and servers; call pages with "View contents"; capture badges (catalog, picker, My gateways).
  - QA fixes: catalog list badge; a server PATCH that changes nothing writes no audit entry and keeps the revision;
    usage times in UTC; call page (h1 size, 403 explained, platform staff pointed to Admin for recorded contents);
    chart colours; invalid team overrides not previewed; staged gateway limit shown; retention period in the capture
    confirmations; browser-side pattern check (RE2 rules still decide); named month/day/year selects for custom usage
    dates; "Nothing deleted" in Retention's last run. Not re-checked in a browser after the fixes.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration` (race), `make k8s-validate`,
    actionlint; web typecheck, 421 Vitest tests, build, `check:styling`, `check:size`.
  - Gaps: CI never run on GitHub; the kind smoke test (`k8s-smoke`) came later (2026-10-18); provider-token redaction had unit tests only (the end-to-end
    test came in v0.2.2: `TestEchoedProviderTokenIsRedactedEverywhere`).
- **Deployment (Phase 6 slice): done, not on a cluster.** Distroless image (`make docker`; `--target fakemcp` for the
  demo), `compose.demo.yaml` (`make demo`: gateway + Postgres + fake MCP server, dev sign-in), Kustomize base and
  example overlay in `deploy/kubernetes` (one Deployment with a migrate init container, Service, PDB, NetworkPolicies,
  ServiceAccount), `make k8s-validate` (kustomize + kubeconform). Guide: [deploy.md](deploy.md). Verified: image
  `migrate` + `serve` in production mode (https APP_URL, OIDC, fresh keys) against a scratch database, `/healthz`,
  `/readyz`, `doctor`, SIGTERM drain; demo discovered the fake server's capabilities; `k8s-validate` passes.

- **Phase 7 (upstream OAuth): done; verified end to end against GitHub.** Servers in `oauth` mode
  (GitHub's hosted MCP server): detect (RFC 9728/8414/OIDC discovery through the guard), save with DCR, CIMD, a manual
  client or a linked platform provider, setup sign-in that reads capabilities, each person's own token as the bearer
  (identity in `MCP-Gateway-Identity`, or none with `sendIdentity: false`), 401 refresh-and-retry, 403 step-up, health
  "requires sign-in", review triggers. See [phase7-upstream-oauth.md](phase7-upstream-oauth.md) "As built".
  - Migration `00012_upstream_oauth`; new package `internal/upstream/oauthmeta`; `fakeoauth`/`fakemcp` protected modes.
  - Contract additions: `sendIdentity` (McpServer, create, update; decision 45), `McpServerOAuth.redirectUri`,
    `ConnectRequest.authorizationServerHost`.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration`, `make k8s-validate`; a live
    detect against `https://api.githubcopilot.com/mcp/` (oauth, github.com/login/oauth, S256, manual, ten scopes);
    then GitHub end to end: a GitHub App as the manual client, setup sign-in, each person's own sign-in, and six tools
    called from pi (`get_me`, `search_repositories`, `list_issues`, `list_branches`, `get_file_contents`,
    `search_code`). Fixes from that run: `4f75508`, `9ff238e`, `f3272d9`, `6fe0995`, `0182c12`.
  - Gaps: upstream CIMD only tested as unavailable on loopback; DCR upstream only against the fake.

## Differences from Grounded (deliberate)

- OIDC login state lives in PostgreSQL (`login_states`), not Valkey.
- Rate limits are counted in PostgreSQL (UNLOGGED table), not Valkey.
- Listen address env var is `LISTEN_ADDR` (default `:8088`); config file env var is `OMP_CONFIG_FILE`.
- Malformed emails return `400 invalid_json` (generated Email type), same as Grounded.
- OAuth for MCP clients is always on (Grounded has a setting) and binds each connection to one gateway.
- Dropped for now: notifications/email, tracing. SSO groups are back
  (`users.groups`, for grants); API keys are our own implementation (`internal/apikeys`), personal only.

## Resume checklist

1. Read `AGENTS.md`, the current release section and [implementation order](implementation-order.md).
   Check the branch, worktree changes, main CI and published tag before assuming a release is complete.
2. Preserve existing services and the real development database. Do not reseed/reset it, run migrations
   against it, overwrite a running `bin/` executable or start duplicate servers on development ports.
3. Use scratch binaries and owned disposable browser/database fixtures. Database role changes and genuine
   split-role tests require an owned PostgreSQL container, not the development cluster.
4. Run the [contribution gates](../CONTRIBUTING.md#tests) with `OMP_TEST_REQUIRE_DB=1`; exercise both
   `OMP_TEST_SPLIT_ROLES=0` and `1`. Regenerate contracts/SQL, inspect actual diffs, and record unrun checks.
5. Follow [release steps](../CONTRIBUTING.md#releasing): passing local tests is not publication. Wait for
   main CI, both deployment smoke jobs, image scans/signing and verification of the published digest.

### Resume on another machine

- Clone `git@github.com:ncecere/open-mcp-portal.git`, check out `main` and fetch tags. All required source,
  migrations and generated code for the released baseline are on the remote. The immutable shipped source is
  `v0.9.0`; main's completed evidence/pin follow-up is recorded above. The local #40/#46 v0.10.0 integration candidate and separate #36 design draft need explicit Git transfer until pushed; do not assume a clone of main contains them.
- Read this release section, `AGENTS.md`, [CONTRIBUTING.md](../CONTRIBUTING.md) and
  [implementation order](implementation-order.md). #35 shipped in v0.9.0 and is closed. Finish the integrated #40/#46 v0.10.0 candidate's complete release acceptance; #36 SCIM follows after its identity/deprovisioning draft is corrected and decided. Do not restart already shipped features.
- Install Go 1.26.10+, Node 22+, Docker, Python 3 and sqlc 1.31.1; run `npm ci` in `web/`.
  Use owned disposable PostgreSQL for integration tests and actual split-role verification.
- Git does **not** transfer `.env`, encryption/signing keys, provider credentials or the existing development
  database. They were deliberately not exported or committed. Use a fresh development instance, or securely
  transfer a consistent database backup and its required keys separately under explicit operator control.
  Do not regenerate encryption keys for an existing database or migrate/reset the old instance implicitly.
- Development resumed on 2026-10-29 under owner authorization. There are 26 open issues (18 development,
  eight real-world verification). #32/#33/#35/#43/#52 are closed. Inspect current Git/follow-up CI before
  integrating the next features. v1.0.0 requires the owner's explicit decision.

For a **new** development instance, use [development setup](../CONTRIBUTING.md#development-setup), not a
blind restart/seed of an existing one. The historical dev-database migration helper remains
`scripts/migrate-dev-db.sh`; running it is an explicit operator task, not part of resuming feature work.

## Next steps

1. v0.4.0 is published and verified; #26/#29/#30/#44/#68 are closed with acceptance evidence. Its follow-up
   documentation/image-pin CI and both smoke jobs also passed. Keep the immutable release tag/digest intact.
2. **Historical machine-transfer stop point completed:** #31 shipped in verified v0.5.0 and is closed. The
   v0.5.1 provider-refresh patch is also published and independently verified. Development has resumed;
   use [agent-handoff.md](agent-handoff.md) and current Git/CI, not an old implementation branch. Decision **82** and
   [design](tool-approvals.md) document migrations **`00035`–`00042`**, exact dispatch and private review.
   Drain older serving images before enabling rules; schema compatibility does not imply enforcement.
   Use the new binary's rotation utility for the new ciphertext columns. Keep production autovacuum enabled;
   governed transitions intentionally fail closed during conflicting writes/reads/maintenance.
3. **v0.9.0/#35 is published, verified and closed**, after #32 in v0.6.0 and #33 in v0.7.0/v0.8.0.
   The evidence/pin follow-up is complete. Finish the integrated #40 governance/#46 CLI v0.10.0 candidate's full release gates; it is not part of v0.9.0 and neither issue is closed yet. Applied migrations49/50 are immutable. #36 SCIM comes next after its linking/deprovisioning design is corrected and decided.
   Continue [implementation order](implementation-order.md), serializing migration writers. #43's upgrade,
   ingress, restore and load gates are proven and closed; Helm packaging still depends on #41's actual
   KMS handling. #52 was design-only and #70–#73 track its first implementation slice.
4. Keep #13–#20's real review/client/provider/channel/pilot evidence separate. VS Code planning and fake OAuth
   browser checks do not close compatibility or real-provider issues. Use authorized throwaway accounts and
   dedicated client profiles; do not contact external recipients or use personal profiles implicitly.
5. Record remaining browser/accessibility/load and wall-clock expiry/refresh gaps honestly. Sampling, roots,
   logging and deprecated transports are not reintroduced; external-platform impersonation stays retired.

## Phase 1 UI

- Grounded's Vite/React app, Bitop UI library unchanged, templates, shell, team switcher, admin mode, command palette.
- Routes: `/`, `/settings/profile`, `/teams/$team`, `/teams/$team/settings?tab=members|audit|general`,
  `/admin` (→ users), `/admin/users`, `/admin/users/$userId`, `/admin/teams`, `/admin/teams/$team`, `/admin/audit`.
- Navigation lives in `web/src/components/layout/nav.tsx` as typed lists; a test checks links resolve. Adding MCP
  sections = a route plus one nav item.
- Verified: typecheck, 118 Vitest tests (with axe), build, styling/size checks; embedded build serves `/` and deep
  links; auditor can read team audit and admin users.
- `npm install` crashed in npm's resolver; the lock file was derived from Grounded's and pruned (256 packages, 0
  vulnerabilities). Re-check with a clean `npm ci`.

Known UI gaps:

- No team-scoped "update team" endpoint: team settings › General saves through `PATCH /v1/admin/teams/{team}`, so
  only platform admins can rename/archive (same as Grounded).
- No admin overview endpoint; `/admin` redirects to Users.
- `web/README.md` missing; `src/components/templates/README.md` and some comments still use Grounded wording.
- `errors.tsx` and `pager.tsx` copied but unused.
- Playwright e2e suite not set up.
