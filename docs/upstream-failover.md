# Upstream endpoint failover (#33, separate stage)

Status: **shipped and independently verified in v0.8.0; #33 closed**. See
[release notes](releases/v0.8.0.md) and [status](status.md) for CI/artifact/runtime evidence and retained caveats. Decision85. The quota/concurrency/read-retry/
breaker stage shipped in verified [v0.7.0](releases/v0.7.0.md). This document governs the separate failover
criterion; #33 closed only after implementation, tests and release evidence satisfied it in v0.8.0.

## Scope and conservative defaults

- One canonical primary remains `mcp_servers.url`, preserving existing clients, approvals and previous-image
  expand compatibility. At most **two additional ordered endpoints** may be configured. New installations
  have none; no existing server changes destination automatically.
- Additional endpoints are replicas of the **same logical server and capability definitions**, not a way to
  federate unrelated services or select different tools. A fallback must validate the offered capability's
  kind/name/fingerprint against the trusted stored definition before its operation is sent. Discovery and
  health do not silently replace the primary catalog definitions or trusted classification.
- Initial support is effective `none` or `static_header` only, **without any provider requirement or TLS
  override/client identity**. `static_header` includes the existing validated header/bearer/Basic/query parts.
  Reject extra endpoints with upstream OAuth, per-person secrets, machine OAuth, personal/shared/linked
  provider credentials, mTLS or a private CA. Auth mode alone is insufficient: provider requirements and TLS
  are independent settings. Configuration changes into an incompatible mode must first remove extras;
  corrupt/old incompatible rows also fail closed at dispatch, not inherit credentials elsewhere.
- Extra-endpoint mutations are browser-session, server-team owner/admin operations, audited and revision-
  checked. Editors/publisher/platform automation tokens gain no endpoint/credential capability. Existing
  primary URL/editing permissions are unchanged. Endpoint configuration is catalog trust, not merely an
  operational quota, so it triggers review where the server is published.
- Existing [upstream protection](upstream-protection.md), normal authorization/credential scopes, SSRF/dial
  rules, origin binding, provider-refresh isolation and committed single-use approval semantics remain.
  No external-platform impersonation is restored. No queue, load balancing or cluster-wide lease is added.

## Credentials and origin binding

Each static extra endpoint has **its own explicitly entered credential parts**. There is no implicit
inheritance/copy of the primary's credential—even a same-origin extra starts with explicit values. Reuse of
an existing extra's parts is allowed only while its canonical scheme/host/port stays unchanged. A changed
origin requires every retained part's values to be re-entered in that request; `keep`, masked hints or a
primary credential reference cannot satisfy it. Basic requires both values. No-auth endpoints accept no
credential parts. URL, effective mode, stored credential origin and primary/extra association are checked
again while building targets.

Store only sealed values and existing-style public kind/name/hints. The endpoint record uses a versioned
sealed credential-list envelope bound by AAD to the endpoint UUID and, inside the envelope, to the server UUID
and canonical origin, with a matching public credential shape. This isolates endpoints and gives rotation a
single UUID-keyed ciphertext column. Round-trip, swapped-row/server/origin, shape-consistency, malformed
format and previous/current-key tests cover the encoding; full local/CI/artifact/runtime gates passed.
Independent whole-product security/accessibility and real-world acceptance remain separate. Never put plaintext or ciphertext in audit,
review digests, error text, metric labels or exported views. Retain all existing part validation and scrubbing.

A primary URL/mode/credential edit cannot silently rebind any extra's credential. Primary and extras are
independent. Any inconsistent endpoint/envelope/shape/origin is a configuration refusal. Removal clears its
secrets through normal deletion; changing auth modes must deliberately resolve all configured endpoints.

## Approval, retries and the actual endpoint

**Governed/`NoReplay` calls remain primary-only.** This is a deliberate conservative restriction, including
failures during negotiation. Current approval binds the primary origin, and its tools hook spends before
underlying dial: a dial failure is not permission to restore authorization or send to another origin. Do not
claim a reviewed endpoint list changes an exact-call receipt's origin. A future actual-origin approval model
would need a separate decision and review; it is not implicit in failover.

For ordinary operations:

1. Admit the logical call through the existing server-local lease/breaker, then use the same original timeout
   and **at most three forwarding iterations total**, primary first and ordered enabled extras next. Extra
   endpoints do not multiply the read retry budget. Charge the same shared server quota and freshly check
   authority/deadlines for each iteration, before any discovery/negotiation/operation networking.
2. A write/destructive/unclassified tool can switch only on positively identified **pre-request dial or TLS
   handshake failure**, never a 5xx/429, ordinary timeout, partial write or ambiguous post-send failure. Track
   transport evidence rather than treating a generic network/TLS classification as proof nothing was sent.
3. Trusted read tools/prompts/resources retain v0.7.0's bounded transient-response policy and may use the next
   eligible endpoint. A valid long/malformed delay, local refusal, auth rejection, ordinary RPC/tool error,
   continuation, progress/streamed/partial result or cancellation stops retry/failover. A read-class 503 is not
   proof of no effect. If no eligible extra remains, only the existing allowed read retry behavior applies.
4. Build a fresh endpoint target with only that endpoint's entered credential. Do not copy primary provider,
   bearer, TLS, query or identity leftovers. Mint the outbound identity for the **actual full endpoint URL**,
   with header placement based on that endpoint's Authorization usage. Never reuse a primary-audience JWT.
   Era/session caches use server plus actual URL; every exchange repeats address/origin/dial checks.
5. Before using a fallback, validate its advertised offered definition against the trusted stored capability
   fingerprint; mismatch/uninspectable discovery refuses rather than calling a differently defined tool.
   This validation is network work under the same deadline/iteration/quota and transport guards, never under
   an authority lock. Health results alone are not dispatch authority.
6. Keep the cap lease over all iterations, discovery/body/stream processing and session cleanup. One logical
   call/capture remains. Local denial never clears earlier dispatch metadata or restores spent authority.
   Circuit health is for the registered logical server, not a secret-dependent endpoint metric.

There is no caller-supplied endpoint choice or privileged bypass. Scope narrowing or revocation between
iterations refuses the next endpoint. No database connection, transaction or authority lock crosses I/O.

## Review, API, health and schema

The create/update contract will gain an optional ordered extra-endpoint list, with explicit omit/clear/
replacement semantics. Stable endpoint IDs identify retained entries. Empty means clear; omission preserves.
Values are write-only; responses show URL, enabled/order, credential shape/hints and bounded health/validation
information, never secrets. The UI keeps primary clearly separate and explains primary-only governed calls,
mode refusals, independent credential entry and the shared attempt/deadline budget.

A URL/order/enabled/credential-shape change contributes to the server review digest and the
`endpoints_changed` re-review reason. Review must show actual destinations and credential placement. Audit
records use normal server ownership and safe endpoint IDs/origins/shape, not private paths/queries or values.
Actual endpoint health records identify which endpoint was checked; primary remains compatible with older
records. Discovery/catalog definitions remain primary-owned and fallback parity is verified, not inferred
from a healthy status.

Next migration is **47**, new/expand-only; do not edit applied migrations46/35/36. New endpoint/ciphertext
storage requires proper owner/runtime grants, authority-journal triggers and maintenance participation,
append-only/history retention compatibility, rotation inventory/union/CLI doctor coverage and generated SQL/
Go/TypeScript contracts. A previous immutable v0.7.0 image must be tested on the expanded schema. Older
serving/background-worker replicas must be drained before relying on endpoint policy; expanded-schema
compatibility does not mean an old image enforces endpoint review or knows how to route.

## Required acceptance evidence

- New-origin static credential re-entry for every part kind; keep/hints/primary-copy refused. Wrong-row/AAD,
  envelope/shape/origin corruption and unsupported modes/provider/TLS combinations deny without any secret
  reaching an unentered destination. Mode changes with existing extras cannot evade the checks.
- Owner/admin/editor/token/foreign-team/stale revision, omission/clear/reorder/disable, duplicate/maximum,
  validation, rollback, audit, review digest and stale reviewer negative controls.
- Real guarded HTTP requests: read503 then matching secondary succeeds; write only proven pre-request switch;
  no 503 write/unclassified, governed/NoReplay, continuation, progress/partial, auth/business-error or
  ambiguous-send fallback. Verify destination-specific credentials and exact identity audience at both
  origins, canonical origin cases and policy changes/DNS/address denials at each attempt.
- Revoked/narrowed authority and expired credential/grant between endpoints, quota charged again, unchanged
  original timeout, shared concurrency/breaker and complete cleanup; no permit restoration, pool recursion
  or authority lock during network. Retain all v0.7.0 cancellation/prior-attempt metadata regressions.
- Endpoint-aware health, mismatched capability fingerprint refusal, modern/legacy era isolation and safe
  deleted-endpoint history/metric behavior. Cipher rotation across old/current keys with swapped-row negatives.
- Full mandatory PostgreSQL normal/race suites in both actual role modes with `GOFLAGS='-p=2'`, generated
  freshness, all web/deployment/advisory gates, owned browser and actual previous/published-image verification
  for any ready pre-1.0 release. Fixtures do not close real-client/provider/pilot/independent-review issues.

This document records the conservative delegated defaults and shipped boundary. Full changed-tree/real-role
normal/race, web/deployment/advisory, actual source/published browser, previous-image compatibility and
main/tag/native publication/independent-artifact gates passed. #33's acceptance is closed; retained browser
incompletes and real-world/independent review evidence remain separate, as recorded in [status](status.md). Publication
and acceptance evidence belongs in [status](status.md); v1.0.0 remains the owner's explicit decision.
