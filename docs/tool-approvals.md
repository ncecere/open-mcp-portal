# Sensitive-call approvals (#31, decision 82)

Implementation design, not a claim of completed enforcement. Applies to ordinary MCP users and service
accounts; external-platform impersonation remains retired. Classification/scopes/curation are prerequisites,
not substitutes for approval. No new dependencies or workflow engine.

## Policy

A rule targets one server or one gateway, optionally one tool capability or one or more classes. A matching
server rule wins over gateway rules; within that tier a capability-specific rule wins over a class rule.
Equal-priority overlapping rules are rejected, and corrupt/ambiguous stored policy fails closed.
Unclassified tools match destructive rules **for approval matching only**; their actual class and tool-scope
semantics do not change. Lists remain unchanged. Rules never grant access.

Reviewers are named active users/SSO groups, or the server team's active owners/admins by default. Apply
decision 52's non-requester platform-admin fallback only when there is no eligible primary reviewer.
Gateway owners have no implicit approval authority. Human requesters never approve themselves. A human
owner/admin of the requesting service account is excluded, including from fallback, unless the rule
explicitly permits that separation-of-duties exception. An account is never treated as its creator/operator.
An empty eligible reviewer set refuses the call, never silently approves it. Review, decision and consumption
all re-evaluate current eligibility and requester authority.

Pending lifetime defaults to 24 hours (5 minutes–24 hours); approved validity defaults to 15 minutes
(1–60 minutes), bounded by the pending request's absolute expiry. At most 20 pending requests per requester.
Identical pending/approved requests reuse their ID without extending deadlines or repeating notifications.
A denied binding remains denied on ordinary MCP retries. Only an explicit browser renewal creates another
attempt. A used approval never authorizes a second dispatch: a repeat asks for a new approval.

## Bindings and transitions

Bind requester kind/ID, gateway/server/capability IDs, curated exposed name, actual class, exact merged
argument digest, approved capability fingerprint, canonical server origin, selected rule/revision and a
monotonic authorization-context epoch. Normalize absent/null arguments to the `{}` actually forwarded.
Changing a policy and changing it back does not resurrect approval. Argument and binding digests use a
stable installation-specific HMAC root, sealed in its own immutable storage slot—not a public dictionary
oracle for redacted low-entropy values. Encryption-key rotation rewraps that root without changing it;
retiring the previous encryption key preserves deduplication, denial memory, renewal and consumption.
Migration `00041` invalidates the earlier derived-key implementation once. Governed arguments reject
duplicate object keys and excessive nesting. Tool arguments are merged by curation
before either retry-state or approval digests are calculated.

States: `pending → approved|denied|expired|cancelled`; `approved → used|expired|cancelled`.
Terminal states never return to approved. Decisions require the displayed digest and review revision.
All transitions and their audits commit atomically. Links and client input responses grant no authority.

## Dispatch boundary and no replay

Obtain credentials, build/validate the immutable target and request before spending approval. Recheck live
policy before every outbound MCP transport, including negotiation. Negotiation does not spend approval.
Non-spending context checks and calls with no matching rule use a consistent read-only snapshot, not the
installation-wide writer fence. Their authorization point is that snapshot: prior committed rule/authority
changes invalidate the originally captured epoch; later commits cannot retroactively revoke an admitted
check. Each following transport checks again. Governed tool dispatch still requires the exclusive consume
fence and atomic audited spend. Unrelated refreshes and concurrent calls must retain normal availability.
Immediately before the underlying transport sends `tools/call`, atomically compare the complete binding,
live authority/approver eligibility and expiry, mark approved authorization used and insert its audit. Only
a confirmed successful commit yields an in-memory single-dispatch permit. Release locks before networking.
An ambiguous commit result never dispatches or automatically retries consumption.

A guarded call cannot automatically replay through machine/provider renewal, cached-era recovery, SDK
reconnect or Go HTTP transport retry. Clear replayable request bodies/headers as appropriate and enforce a
one-tool-transport budget. Initially governed calls advertise no upstream elicitation and reject upstream
continuations before consumption; a server asking anyway gets a spent/unsupported-continuation outcome.

`used` means **authorization spent**, not confirmed execution. A crash/cancellation after spending but
before bytes leave still spends it. An upstream effect followed by a lost response is unknown; show a
warning that a repeat may duplicate effects. Never restore approval after a post-consumption failure.
Policy changes after the dispatch authorization boundary cannot recall an already authorized attempt.

## Context epoch and lock protocol

A coarse installation-wide epoch is a conservative first boundary: unrelated authority edits can require
new approval, but change-and-revert cannot recover an old grant. Database triggers cover authority-bearing
changes in users/groups, teams/memberships, MCP credentials/scopes, gateways/grants/selections, server
configuration/definitions/class/review, providers/access, personal grants/secrets and shared connections.
Usage touches, probe timestamps and unchanged-authority token refreshes do not advance it. Rule mutations
and same-scope authorization-code reconnects do advance it. Old replicas' ordinary writes pass through the
same triggers.

Migration `00035` initially used a singleton writer mutex. Independent review found writer–writer lock
inversions in existing provider/disconnect and user/team-audit sequences. Forward-only `00036` replaces it:
semantic writes append positive event IDs without a central transaction-row lock. Current context is a
protected base plus the **SUM of MVCC-visible committed events**, not MAX or sequence last-value, so an
older allocated event committing last still invalidates context. An initial epoch read before authentication
never blesses an uncommitted mutation. Atomic compaction above 1,000 events preserves the exact total.
Runtime can neither mutate/prune the journal nor advance/reset its sequence or base. Forward-only
`00042` places the context, journal, owned sequence, stable binding-root slot and their protected functions
in the owner-controlled `omp_private` schema. Runtime has schema usage, not creation; the binding-root
ciphertext alone can be rewrapped. There are no public compatibility views. This preserves unmodified
v0.4.0 strict-role startup against the new schema without granting forbidden rights.

Final approval transactions acquire an owner-definer **EXCLUSIVE NOWAIT table fence** over all authority
tables, including row-locking readers, before validation/consumption. Both legacy shared/exclusive helper
interfaces use this conservative fence. A busy/partial fence aborts with `55P03`; roll back and refuse/retry,
never wait or spend authorization. This avoids existing-writer cycles without rewriting their lock order.
It intentionally trades availability under concurrent authority writes, row-locking reads and PostgreSQL
maintenance (including `ANALYZE`) for fail-closed safety; load/latency behavior still needs measurement.
Keep production autovacuum enabled. Matrix fixtures alone quiesce maintenance in their disposable databases;
a separate deterministic lock regression verifies that real contention refuses admission without spending.
The initial context read is unfenced and committed-snapshot-only.

For browser audit attribution, take the actor user's `KEY SHARE` **before** the fence, then requester
advisory/request/rule locks. Validation under the fence uses non-locking reads. Request/rule historical
UUIDs have no foreign keys to authority tables, avoiding hidden FK inversions. Team audit attribution has
no team FK. Runtime consumption uses a system audit actor with requester/decider IDs in metadata;
browser decisions retain the protected human actor. No locks survive into network I/O. Audit failure rolls
back the transition. Test real suspension/revocation/rule races and out-of-order writer commits.

## Browser API and privacy

Session-only rule CRUD under team/admin approval-rule routes, requested/actionable lists, authorized detail,
decision/cancel/explicit renewal. No automation-token scope annotations, and services also reject tokens.
Target writes bind revisions. Requester/eligible reviewer detail is separate from metadata-only platform
oversight; being an auditor/platform admin alone never reveals a preview. Service-account owners/admins
can manage its request receipt/cancellation/renewal, but the separation-of-duties rule still controls review.

Redact previews independently of capture enablement: built-ins, platform patterns and known credential
values, including short values and member names. Conservatively mask JSON-looking strings in full so
nested decoding cannot materialize escaped credentials after redaction. Then UTF-8-safe truncate to at most 16 KiB and seal with request-specific AAD. Redaction/sealing
failure refuses creation. Display escaped text with redaction/truncation warnings. No raw arguments,
previews or free-text notes in audit/notifications. Register the ciphertext for key rotation. Terminal
previews become inaccessible immediately and are physically cleared within 24 hours; metadata is retained
90 days independently of audit retention. Retained terminal ciphertext can be rewrapped, but a cleared
terminal preview cannot be restored and terminal projections never disclose it. Expiry is enforced
synchronously, including after commit acknowledgement, not dependent on cleanup.

The authoritative queue survives notification failure; the current notification outbox is best effort.
Requested events go to currently eligible reviewers, decisions to the user requester or service account's
owning-team authorized humans. Notification bodies contain metadata, never previews. Attention and list
queries apply the same visibility rules. Metadata queues use read-only snapshot transactions, real keyset
cursors, a five-second deadline and at most 200 SQL-filtered candidates per page. They never hold the
authority writer fence; empty pages may carry a cursor when further candidates remain. URL-capable modern clients receive `input_required`; other modern
tool callers receive `isError` with a link; legacy callers receive `-32042` with a link. Browserless service
accounts can create requests and notify humans; no retired impersonation behavior is reintroduced.

## Implementation/verification sequence

1. Add forward-only migrations `00035`–`00042`, context journal/fence, preview/identity safeguards and stable
   binding-root storage, with focused real split-role/lock-order and previous-release compatibility tests.
2. Add transactional rules/requests/review/preview services and OpenAPI-first browser contracts.
3. Integrate transport-boundary consume/no-replay, live bindings and all three MCP response shapes.
4. Add notification/attention/retention/rotation integration and browser UI.
5. Independent review, full legacy/split-role Go/race suites, web gates, browser checks and release gates.

Required regressions include dedup/quota/decision/consume races, audit rollback, stale review, exact numeric
argument binding, policy change-and-revert, reviewer revocation, connector lapse, no automatic replay,
post-consume/no-send and effect-before-lost-response cases, secret sentinels, key rotation and retention.
Do not enable rules with old serving replicas; an image rollback with active rules must block governed
execution. Schema compatibility is not enforcement compatibility. Use the new binary's key-rotation
utility after applying these migrations; older utilities do not know the new ciphertext columns.
