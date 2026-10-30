# MCP task-handle relay (#35)

Status: **first stage published and independently verified in v0.9.0** (decision86). The scope below is deliberately conservative: ungoverned,
non-streamed modern `tools/call` only. Real client/server interoperability with the released extension has not been
exercised; see [releases/v0.9.0.md](releases/v0.9.0.md).
The portal relays a server's durable task; it does not run a worker, queue or workflow engine.

## Confirmed specification

Read the official [2026-07-28 specification](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks.html),
[Final SEP-2663](https://tasks.extensions.modelcontextprotocol.io/seps/2663-tasks-extension.html) and released
schema before this design. The official `ext-tasks` source is pinned at
[`b3d28aceaa6d49f5f92258e3d06b61ad6f111e84`](https://github.com/modelcontextprotocol/ext-tasks/tree/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84):
[`tasks.md`](https://github.com/modelcontextprotocol/ext-tasks/blob/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84/specification/2026-07-28/tasks.md),
[`schema.ts`](https://github.com/modelcontextprotocol/ext-tasks/blob/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84/schema/2026-07-28/schema.ts)
and [`JSON Schema`](https://github.com/modelcontextprotocol/ext-tasks/blob/b3d28aceaa6d49f5f92258e3d06b61ad6f111e84/schema/2026-07-28/schema.json).
[Specification preflight](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6500904668) records the findings.

- Identifier `io.modelcontextprotocol/tasks`, empty object under `clientCapabilities.extensions` in **each
  request's** protocol `_meta`; the same extension is advertised in `server/discover`.
- “Unsolicited” means server-directed choice after declaration, not permission to task-return to an undeclaring
  client. There is no per-call `task` opt-in or per-tool warmup. If a synchronous result cannot be provided to
  an undeclaring client, return `-32021` with `data.requiredCapabilities.extensions`. Never silently opt the
  upstream into tasks then wait behind a client that did not declare support.
- Only modern `tools/call` creates tasks. Flat `CreateTaskResult = Result & Task`, `resultType: "task"`, with
  `taskId`, status, creation/update timestamps, nullable integer-ms `ttlMs`, optional integer-ms `pollIntervalMs`.
  Creation is durably findable before the handle is exposed. It is not a nested `task` property.
- `tasks/get` uses `resultType: "complete"` and flat status-specific state: working; input_required with
  `inputRequests`; completed with original tool result; failed with JSON-RPC error; cancelled. Tool `isError`
  is a **completed** task, not a JSON-RPC execution failure.
- `tasks/update` takes `taskId`/`inputResponses`; `tasks/cancel` takes `taskId`. Success is ack-only
  `{resultType:"complete"}`, not a task. Both are eventually consistent. Cancellation is cooperative and an
  ack never proves work stopped or entered `cancelled`.
- Task input keys are unique over the entire task lifetime. Repeated polls can repeat outstanding requests;
  partial responses may be accepted and unknown/already-answered keys should be ignored. This is a distinct
  lifecycle, not a retry of the original MRTR/requestState. No deprecated sampling/roots/logging is added.
- Task HTTP methods use `Mcp-Name=params.taskId` and the exact `Mcp-Method`: portal handle inbound, actual
  sealed upstream ID outbound. Missing current declaration is `-32021`; unknown task is uniformly `-32602`.
- No `tasks/list`, `tasks/result`, legacy experimental tasks, subscriptions or task progress/log notifications
  in this scope. Poll-only is compatible; subscription notifications are optional in the extension.

Released normative text/schema override stale SEP example discriminators and draft-version table entries.
Wire parsing must be tested against the released flat types, not copied from an inconsistent example.

## Conservative first scope: no widened approval

**Do not negotiate tasks for governed/NoReplay calls.** Current exact-call approval deliberately refuses
arbitrary upstream continuation after committed spend. A long-running task with later input mutation is not
an implied extension of that authorization. Initial approval handling and synchronous calls remain unchanged;
clear task capability alongside elicitation for a governed dispatch. An unexpected task after spending is an
uncertain spent attempt, never a restored receipt or a handle to execute more work. A separately reviewed
lifecycle-approval model is needed before supporting governed async work; this stage must state that limit.

Ordinary ungoverned calls may negotiate the extension only when the downstream declares it and the current
modern primary advertises it. All current credential modes use their existing live credential-acquisition
and origin policy; nothing inherits or reuses a credential from another principal/connection/origin.

Task initiation and task operations have **one forwarding attempt, no automatic retry/failover**, even for a
read-class tool. A task handle/async job can have been created when a response is lost. Bind the task to its
actual full primary URL and never resume it at an additional endpoint or legacy-era fallback. Server quotas,
replica-local fail-fast cap/breaker and original per-exchange timeout apply; no lease is held for the task's
whole lifetime. Polling is a request, not a background worker or authorization bypass.

## Handle and authority binding

Use a cryptographically random 32-byte portal handle, distinguishable from other credentials; store only its
SHA-256 digest for lookup, with an independent row UUID for sealed-column rotation. Never expose the upstream
ID. Lookup is bound to the original principal **and starting credential root**, gateway, server, capability,
exposed tool, actual full URL, definition fingerprint and effective curation/argument binding.

A person's API key uses its key UUID; OAuth uses the stable grant UUID, allowing legitimate access-token
refresh without allowing a different grant/key to borrow the handle; service accounts bind account and key.
All keys/grants of one principal share its capacity limit. Handles do not authenticate requests themselves.
Unknown, foreign, expired, mismatched or currently unauthorized mappings return the same not-found response;
invalid/suspended authentication still uses the existing outer authentication refusal, before any lookup.

Every get/update/cancel re-resolves current principal/credential scopes, active gateway/team, effective live
grant/deadline, selected/listed/approved definition and curation, original exposed name and current provider/
service-connection dependencies. A new approval requirement refuses lifecycle access rather than creating or
consuming an approval on a poll. Compare stable dependency identity/configuration, not an old access token.
Acquire fresh permitted credentials and actual-URL identity for each operation. Do not retain a credential
for later outbound reuse. A configuration/URL/definition/curation change that no longer matches the original
binding fails closed; no task moves to a new endpoint or silently gains an updated offer.

Preserve final transport clock/authority checks, including current request credential and grant deadlines.
Only a bounded, network-free SQL reservation/transition may lock a row; release every pool lease/authority
lock before network I/O. Recheck safely before exposing protected results. The implementation must test these
boundaries under contention, revocation, narrow scopes and configuration changes, not infer them from login.

## Durable storage, bounds and lifetime

The migration48/SQL foundation passed targeted and full store/rotation/approval/task-package races in both
actual database-role modes; it is not a functional task service. Migration48 is applied/frozen; any further
DDL starts at49. No applied migration is edited. Its operational schema records:

- Task UUID, handle digest, principal/starting-credential binding and gateway/server/capability references;
  creation/deadline/status/revision, bounded poll timing and in-flight reservation facts.
- One versioned sealed payload (AAD includes row UUID; payload also verifies handle/binding) for upstream ID,
  original full destination, required original argument/curation/dependency snapshots and initial redaction-
  only secrets. Old values are for scrubbing, **never outbound credential reuse**. New column participates in
  doctor/key rotation/runtime grants and safe user/server/gateway deletion/retention.
- Bounded input-key mapping/definition hashes and single-use attempt state, sealed where it contains server
  keys/payloads. A stale poll may not resurrect consumed keys or overwrite a newer transition.

Reserve capacity **before** initial network dispatch and persist the actual mapping **before** exposing a
handle. The capacity transaction takes a principal-scoped advisory transaction lock, counts live active/reserved
rows across that principal's credential roots, and inserts before releasing the transaction. Operation
UUIDs plus monotonic row revisions fence responses; commit input-attempt state before transport, and never
restore it when releasing a failed operation. These SQL primitives do not replace live authorization or
implement the sealed input lifecycle by themselves.

Initial failed/ambiguous dispatch may have left untracked upstream work; do not claim cancellation or
restore spent authorization. Expire abandoned reservations with a bounded deadline. Concurrent replicas must
not bypass the cap by count-then-insert without serialization.

Initial delegated defaults: maximum local lifetime24h (`TASKS_MAX_TTL`, bounded1m–24h),100 active/reserved tasks
per principal (`TASKS_MAX_OPEN_PER_PRINCIPAL`,1–1000), minimum advertised poll interval1s and maximum60s
(default5s). These are bounds, not a queue or guaranteed completion time. Null/unlimited or changing upstream
TTL never extends the original portal ceiling or a previously shortened local deadline; clamp using
authoritative time and upstream creation+TTL, without overflowing a duration or using DST calendar days.
Reject malformed/non-finite/negative durations and invalid/inconsistent timestamps rather than overflow.
Current authorization is checked independently of retention; expiry denies without waiting for cleanup.

Bound IDs, input maps and messages; reuse the existing 1MiB response and bounded elicitation/input validation.
At most8 simultaneous input requests,16KiB request set,64KiB responses and128 distinct lifetime input keys.
Rebuild permitted form/URL elicitation only at the client's current capability/trust level. Stable portal
input keys map to sealed server keys and must not collide with, expose or be confused for the actual task ID.
Reject a server reusing a key for a different request. Client unknown/already-attempted keys are not forwarded.

After local quota/cap/breaker admission, an accepted input response is reserved/consumed atomically
**before** its single upstream attempt; ambiguous
send/ack loss never restores it for replay. A cancellation ack records intent, not confirmed termination.
Concurrent polls/updates/cancel must be revision-fenced, with tests proving no stale response resurrects a
consumed input or invalidated handle. Terminal result retrieval still checks current access.

## Response privacy, records and operations

Construct the public Task/DetailedTask from validated fields with the portal handle/timeline/bounded TTL;
never relay arbitrary task objects or nested credentials. Preserve the completed tool result/error semantics
and use existing result/meta/elicitation redaction, including original redaction-only secrets plus fresh
credentials and the actual upstream task ID. Rebuild portal serverInfo, never treat task metadata as trust.

Task operations use their own call method/outcome but original exposed tool/server identity, not IDs in
names/URLs/logs. Inbound quotas count once and server quota counts each task operation; the existing server
cap/breaker bounds only that network exchange. Capture must redact both handles and input IDs/secrets; no
plaintext upstream ID in response, logs, audit, captures, notices, errors, metrics or serialized request URLs.
Metrics are bounded method/result categories, never principal/handle/raw URL labels. No audit event per poll.

An expired/revoked handle does not prove upstream work stopped. Best-effort cancellation must not bypass
current credentials/authority or broaden background-worker rights; otherwise leave an explicitly orphaned
upstream operation, with no false termination claim. Normal tasks do not expose legacy retired impersonation.

## Required acceptance before release

- Published contract fixtures from the pinned released schema: flat create/all get variants, per-request
  declaration/error/header rules, ack-only update/cancel and isError/completed distinction.
- Actual guarded modern wire creation/get/input/cancel flow with independently sealed portal handles;
  zero legacy/undeclaring/governed task negotiation and no repeated or failover task dispatch.
- Principal/key/OAuth-grant/service-account/gateway isolation, current narrowed scopes/revocation/suspension/
  deadlines, changed offers/curation/URL/provider connection and rules; uniform private not-found semantics.
- Concurrent reservation caps/expiry/TTL/poll bounds, single-use input/ambiguous-send/revision fencing,
  durable mapping before exposure, no held DB/authority lease across network and no old-token reuse.
- Echoed upstream-ID/credential/initial-refreshed-secret sentinels in every result/status/input/error/capture/
  log surface; key rotation/old-key and swapped-row/binding failures, retention and protected runtime grants.
- Full mandatory PostgreSQL normal/race suites in both actual role modes, all web/deployment/advisory gates,
  actual previous immutable v0.8.0 image on expanded schema, browser and independently published artifacts/
  runtime checks. Real client/provider/channel/pilot/independent-review issues require separate evidence.

The design boundary above is implemented as described in the next section; v0.9.0 is its first release.

## As built in the gateway and upstream client (v0.9.0)

What the code does, and where the design left room:

- **Configuration.** `TASKS_MAX_TTL` (default 24h, 1m–24h) and `TASKS_MAX_OPEN_PER_PRINCIPAL` (default 100, 1–1000) are
  validated at startup (`mcptasks.ValidateLimits`); an invalid value stops the process, never "unlimited". There is no
  separate on/off switch: the feature is on when the store is built (it needs the encryption key) and a client declares
  the extension. A handler without the store (or without the approval runtime) advertises nothing, never negotiates and
  answers the task methods as unknown.
- **Discovery.** A successful read of the **canonical primary** that negotiated the modern era and advertised the extension
  (an object under `capabilities.extensions`) stores `mcp_servers.supports_tasks = true`; a legacy era or absence stores
  `false`, and a changed URL clears it. Additional endpoints never set it. `McpServer.supportsTasks` is read-only.
- **Negotiation.** A `tools/call` declares the extension upstream (empty object in that request's `_meta`) only when the
  downstream request declared it, the server supports it, the capability is a tool, the call is **ungoverned**
  (decided after the approval plan: `plan.Required` or `NoReplay` means no), it is not a streamed request (progress
  token over SSE; out of this first scope) and not the retry of an upstream input request. Anything else is the call it
  always was, with no declaration. A server that answers a task to a request that did not declare the extension is a bad
  response, never tracked.
- **One attempt.** Creation and every lifecycle operation are a single guarded exchange to the recorded primary: no retry
  (not even for a read tool), no failover endpoint, no era re-negotiation resend, no legacy fallback, and no automatic
  renew-and-resend of an upstream 401 (the token is still renewed for the *next* request, and the failure is reported).
  The transport guard treats `tasks/get|update|cancel` like `tools/call` (single dispatch, `GetBody` removed).
- **Reservation.** Capacity is reserved (sealed arguments, binding, credential values to scrub) **before** dispatch. At the
  cap the call is refused (`-32010`, `data.reason: task_capacity`) with nothing sent. Because the reservation precedes
  dispatch, a principal at the cap is also refused declared calls to task-capable servers that would have answered
  synchronously; an undeclared call is unaffected. Anything that is not a task result abandons the reservation; an
  ambiguous failure may leave untracked upstream work and is never reported as cancelled.
- **Lifecycle.** Every operation: authenticate → the request declares the extension (`-32021`, HTTP 400, with
  `data.requiredCapabilities`) → `Mcp-Name` equals `params.taskId` (`-32020` otherwise) → look up by handle **and** the
  starting credential root → re-resolve the exact offer (allowed; same capability, server, revision, full URL, definition
  fingerprint, tool class and curation) → read-only no-rule approval check (never `Begin`) → fresh credentials and
  identity token for the actual URL, with an unchanged dependency identity → claim the task for one fenced exchange →
  send once → build the public result. Every failure of the first five steps is the same `-32602` "Task not found".
  A transient dependency outage is a retryable `-32010`; a busy task is `-32010 task_busy`, except that a poll that
  cannot claim the task (another exchange holds it, or the stored interval has not elapsed) is answered from the
  stored status **only when that status is `working`**; anything else (input requests and results are never stored
  outside the sealed exchange) is the busy error.
- **Dependency identity** (`dependencyDigest`): auth mode, static credential parts' kind and name, a person secret's
  placement/name/prefix, the provider and scopes (and shared connection, resource, server-bound flag) of a delegated
  credential, a machine client's non-secret configuration, identity on/off and TLS present. Never a token, secret value,
  hint or generation. The server revision is in the binding as well, so editing the server (a rotated static value
  included) ends its in-flight tasks: they fail closed rather than silently follow a changed configuration.
- **Input.** `tasks/update` validates the client's responses with the existing elicitation-result rules against the
  task's unanswered portal keys, consumes them before the single send, and answers with an acknowledgement only; unknown
  or already-attempted keys are acknowledged but never sent, and a failed or ambiguous send never restores them.
  Input requests are rebuilt and validated at the client's **current** declared elicitation capability; a task that wants
  input the client cannot give is `-32010 task_input_unsupported` and nothing is consumed.
- **Public shape.** `CreateTaskResult` and `DetailedTask` are rebuilt from validated fields: the portal handle, the
  portal's own creation time, the local remaining lifetime as whole milliseconds (never null, never beyond the original
  ceiling) and the stored bounded poll interval. A completed task relays the tool result through the same decoding and
  `serverInfo` scrub as a synchronous result (`isError: true` is still `completed`); a failed task relays a JSON-RPC error
  object with its text scrubbed (error `data` over 16 KiB is dropped).
- **Redaction.** Every status message, input request, result and error is scrubbed on decoded JSON strings, keys and
  numbers of the actual upstream task ID, the credential values sealed with the creation, and the fresh credentials of
  that exchange (never `capture.Secrets`, which holds the downstream bearer); an encoding that still contains one is
  refused. Credential values under four characters are not treated as secrets; the task ID always is (a server that uses
  a very short ID gets mangled text in results). No handle, upstream ID or input key is logged, recorded, labelled or
  captured.
- **Capture.** The creating `tools/call` is captured like any call (its arguments, redacted); its task result is **not**,
  and task lifecycle payloads are never captured.
- **Records.** `mcp_calls` rows use `tasks/get|update|cancel` with the original exposed tool and server; the
  error class says what happened (`task_created`, `task_working`, …, `task_not_found`, `task_binding_changed`,
  `task_dependency_changed`, `task_approval_required`, `cancel_requested`, `task_input_sent`, `task_input_ignored`).
  The class is for operators; the client always sees the uniform answer. No audit event per poll.
- **Retention.** The retention loop prunes expired or abandoned rows in bounded batches (at most 10 × batch statements per
  pass); expiry already denies on its own.

Known limits of this scope: governed (approval-required) calls, streamed calls, MRTR continuations and legacy/undeclaring
clients are never tasked; no `tasks/list`, `tasks/result`, notifications or sampling/roots; a lifecycle poll may create a
provider consent request when a delegated connection lapsed (the answer is still the uniform not-found); and an expired,
revoked or abandoned handle does not stop upstream work.
