# Implementation order for open issues

Reconciled against `gh issue list --state open --limit 200` and the local roadmap at the start of this batch.
The starting checkout was v0.3.2; 36 issues were open. v0.3.3 has since shipped #28 and #37. The owner has
withdrawn #62/#63 and requested safe external-platform retirement in #68. Issue proposals were drafted against older releases: their migration
numbers and file paths are suggestions, not instructions to overwrite existing code.

## Current batch

**Shipped in v0.3.3:** #28 owner-set tool classification (migration `00027`) and #37 browser sessions
(migration `00028`, idle expiry off by default). Both issues are closed. See [classification](tool-classification.md),
[browser sessions](phase4-client-auth.md#browser-sessions-37-decision-76) and [validation](status.md).

**Shipped and closed in v0.4.0:** #29 credential scopes, #30 tool curation, #26 service connections,
#44 database roles and #68 external-platform retirement. Independent reviews, final-tree normal/race suites
in both database-role modes, 796 web tests, browser checks, main CI and both deployment smoke CNIs passed.
The published multi-architecture image/signature/SBOMs were verified; see [status](status.md). No production
deployment is implied. Approvals (#31) are now in progress under decision 82 and
[their implementation design](tool-approvals.md); reserve migration `00035`.

## Ordered backlog

Items on a row may run independently unless the dependency column says otherwise. Finish and validate each
security boundary before building on it; do not start every large issue at once.

| Order | Issues | Reason / dependency |
| --- | --- | --- |
| 0, shipped v0.4.0 | **#68** retire external-platform trust | Remove active issuer/relay impersonation and fence legacy credentials without erasing history. Preserve standard MCP authentication and outbound identity. #62/#63 are closed as not planned, not implemented/verified. |
| 1, shipped v0.3.3 | **#28**, **#37** | Classification unlocks policy; sessions are independent and prepare identity lifecycle work. |
| 2, shipped v0.4.0 | **#29** credential scopes | Needs #28; intersect every credential layer and preserve existing unscoped behavior. |
| 3, shipped v0.4.0 | **#30** per-gateway curation | Keep approved definitions immutable; validate merged arguments and stale fingerprints before approval digests depend on them. |
| 4, next | **#31** sensitive-call approvals | Needs #28 and #30; bind approval to the merged arguments, definition, origin and requester, atomically single-use. |
| 2–4, independent lane | **#26** shipped v0.4.0; next **#32** access requests | Shared token delivery, lapse, grants and refresh are validated foundations for lifecycle integration. #32 is independent, but keep gateway/API edits serialized with scopes and curation. |
| 5 | **#33** upstream protection | Classification permits safe read retries. Ship quotas/concurrency/breaker before considering failover; credential-origin binding must remain intact for every current auth mode. |
| 6 | **#35** tasks extension | Confirm the extension specification before design/code; carry approvals and access checks into every task operation. |
| 2, shipped v0.4.0 | **#44** split database roles | Independent security foundation. Preserve append-only retention through narrowly privileged definer functions; test runtime-role denial and normal operations. |
| 3, operations lane | **#43** upgrade/ingress/OIDC/restore/load gates; **#41** envelope encryption | #43 builds on #44. #41 also follows #44; select/test an actual KMS target without changing existing static-key installs by default. |
| 4, operations lane | **#42** Helm packaging | Only after #43 proves upgrade/restore and #44/#41 establish credential handling. Test parity with Kustomize rather than duplicating unverified assumptions. |
| 7 | **#40**, then **#36** lifecycle | #40 needs classification/approvals. Implement accountable ownership and safe transfer first; then SCIM uses that ownership model plus sessions and service connections to deprovision. Group-mapping refinements to #40 can follow #36. |
| 7, audit lane | **#38**, then **#39** | Start #38's export/sink/cursor and retention-floor foundations after #44. Add #39 hold-aware retention after a durable audit tail exists; integrate #38's hold semantics before #39 erasure. Erasure also waits for #36. This staged split resolves the roadmap's apparent #38 ↔ #39 cycle. |
| 8, evidence-gated | **#45** subscriptions/listen | Wait for a real client that uses it. Require live access revocation and replica fan-out tests. |
| 9 | **#46**, then **#47** developer tooling | #46 follows #29 and needs a CLI sign-in decision. #47 reuses its public client; new delete scopes need explicit review, not a hidden expansion of publisher authority. |
| 9, independent DX | **#49**, **#51** | Catalog governance follows #40. Chargeback follows #38 and needs unambiguous calling-team attribution recorded before claiming historic billing accuracy. |
| 10 | **#48**, **#50** | Console follows classification and approvals; search-mode dispatch follows classification, curation and catalog search. Both must use the normal governed call path. |
| Later, design only | **#52**, **#53** | Scanning design follows #28/#31; identity research follows #36/#37 and a concrete pilot need. No content scanning or extra IdP support is implied by this batch. |

## Real-world verification lane (start coordination now)

These issues cannot be closed by fake-server tests or by changing a documentation checkbox.

- **#13:** choose and scope an independent review of the whole portal. The recorded v0.3.0 agent-platform
  review is useful evidence, not proof that this broader engagement is complete.
- **#14 / #15:** named VS Code / Cursor versions through the compatibility checklist.
- **#16:** find a shipping URL-elicitation client and exercise approval/consent retry behavior.
- **#17:** observe real Claude Code and pi refresh across access-token expiry.
- **#18:** real Google and Entra connect/call/refresh/disconnect with throwaway accounts.
- **#19:** real Slack, signed-JSON receiver and SMTP TLS delivery/rendering.
- **#20:** a real 3–5-person pilot with written success criteria and a retrospective. Pilot findings can
  reorder independent features, but do not bypass security dependencies.

Use existing authorized test environments only; do not modify the real development database, contact external
recipients, commission paid work or claim a real-provider result without the necessary setup and evidence.

## Batch gates

- Targeted regression tests during implementation, including foreign-team and token denial paths.
- Regenerate contracts and SQL; run `make generate`, `make lint`, `go build ./...`, and
  `OMP_TEST_REQUIRE_DB=1 make test` against isolated test databases on the running PostgreSQL server.
- In `web/`: typecheck, tests, build, styling and size checks.
- Run Kubernetes/action lint gates when deployment/workflow files change.
- Review actual merged diffs, not just subagent summaries; record any unrun browser or real-service checks.
