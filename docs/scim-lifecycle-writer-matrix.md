# SCIM lifecycle: current-source writer and reader matrix

> **Design history.** Supported SCIM provisioning is implemented as [decision 92](decisions.md); see [SCIM provisioning](scim.md) for current behavior. This page records the preflight analysis and is not current instruction.

**Working inventory, not a total-lock proof, provisioning schema allocation or SCIM support.** This accompanies [the preflight](scim-provisioning-preflight.md) for #36. Baseline is independently verified v0.11.0 plus evidence follow-up `cc44f0433c372785dd151f2425a222d812b364c6`. The owner resumed SCIM as the primary task; catalog-search review is the independent side lane. [Decision90/migrations51–52](request-authority-epochs.md) separately cover only the user request-epoch prerequisite and first personal-key writer. No SCIM router, token or provisioning-resource schema exists.

## Evidence terminology

- **Current read:** the actual baseline implementation was reread during this batch.
- **Independent current-source review:** a read-only reviewer traced exact draft checkpoint432017d and left its source clean. Source-derived counterexample schedules are not executed races; that review ran no tests.
- **Carried observation:** the earlier direct service review is still applicable because the relevant implementation is byte-unchanged in the inspected baseline4100-to-cc44 diff. It is not a new executable proof.
- **Required:** a future integration/proof target, not behavior the current product already provides.
- A source comparison, SQL model or successful primitive test is never called an application-wide lifecycle proof.

## Authentication/admission boundaries

At reviewedcc44, `auth.Identity.Actor` copied user UUID/platform role and `authz.Actor` had no captured epoch. The current decision90 prerequisite adds a dedicated request epoch to authenticated actors and the first personal-key writer; its four-adjacent-package normal/race/both-role proofs, six extra queued-cycle races and bounded actual previous-image compatibility passed. Other OAuth/personal/approval/task writers still need explicit admission/lifetime propagation. A profile revision is not this authority epoch.

Reusable credentials and individual requests need different bindings. A new request using an existing otherwise-valid unrevoked key/connection may succeed after reversible reactivation. A pre-cycle request, taken code, deleted session, old callback or spent input cannot inherit the new request epoch. Irreversible deletion additionally needs a distinct cleanup/lifetime identity so old work cannot target a newly enrolled lifetime.

## Personal authority writers

| Entry | Current ordering/behavior | Required lifecycle integration | Evidence |
| --- | --- | --- | --- |
| `auth.completeLogin` / bootstrap | Identity upsert, email bookkeeping, status check, optional bootstrap, sorted invite-team locks, session insert/audit | Verified-selector eligibility and new/pending/adopted/tombstone decision before upsert/bootstrap/invites/session; serialize issuer/subject allocation; all bootstrap promotions participate | Current read |
| `platform.UpdateUser` | Active-admin row set before target USER FOR UPDATE; revision check; status/role update; suspension deletes sessions | Separate manual/directory provenance, epoch advancement and a placement that does not invert admin-set/user/resource locks | Current read |
| `apikeys.Create` | USER FOR UPDATE, fresh active-status and captured request-epoch checks, current gateway eligibility, cap, insert/audit | First epoch consumer implemented; global-G/lifecycle integration still pending; preserve existing-key use by fresh requests after reactivation | Current branch scoped proofs passed; historical released-source negative below |
| `providers.Callback` / personal `store` | Network exchange outside final transaction; existing CONNECTION wait, USER KEY SHARE NOWAIT, original SESSION UPDATE NOWAIT, sealed store/request/grant/audit | Preserve original browser/state and no-replay guarantees; no authority guard before connection wait; decided epoch/lifetime checks before insertion/publication | Current read; shipped v0.11.0 regressions |
| Existing personal connection refresh | CONNECTION retained across bounded provider I/O; existing-row rotated-material persistence | Pre/post-I/O standing capture; nonblocking post-I/O guards; no credential publication on conflict; narrowly proven existing-row dormant completion only, never late insertion/upsert | Carried service observation; sealed/cache/transport tests still required |
| `oauth.Approve` / `grantFor` | USER NO KEY UPDATE; existing GRANT lock/renew/revoke or new grant; code insert. The helper query selects the user without an active predicate, and its returned row is not itself checked here | Place the common lifecycle gate before existing resource locks, validate admitted user standing/epoch and durable code/lifetime binding; retain compatible FK lock mode | Current read; no newly reproduced released-policy defect claimed |
| OAuth authorization-code exchange | `TakeOAuthCode` commits deletion first; transaction locks GRANT, reads current active user, inserts tokens/audit | Capture the original owner/lifetime safely before canonical locks; do not restore a consumed code on any fence failure | Current read |
| OAuth refresh, first rotation | Digest lookup, GRANT lock/current user read, TOKEN lock, expiry/reuse checks, rotate and insert successor pair/audit | Capture request epoch independently of reusable grant lifetime; validate after waits without grant/user inversion; preserve rotation/single-use policy | Current read |
| OAuth refresh, grace repeat | Same grant/token checks; reconstructs the previously issued pair after looking up both successor rows | A repeat returns authority even without a new token row; fence it too. Never reissue missing/revoked successors or restore committed spend | Current read |
| `personsecrets.Set` | Reads active user/reachability before transaction; SERVER then PERSON_SECRET; sealed create/replace, used-link updates, optional setup attribution. Setup discovery is after commit | Guard/current epoch before resource locks; final current eligibility; preserve origin/AAD/request-consumption and team-owned configuration boundaries | Current read |
| Person-secret request/reuse | Transaction finds open link or inserts a sealed user/server/origin/capability-bound request, trims count | Treat links as future-authority material, capture lifetime/epoch; no request reuse after deletion/re-enrollment | Current read |
| Personal gateway access-request create | Requester advisory, UUID-sorted USER FOR SHARE actor checks, optional subject TEAM, GATEWAY, pending/cooldown/live-access checks, insert/audit/outbox | Common lifecycle gates before requester/resource locks; current requester/subject standing and admission binding | Current read |
| Access-request decide / withdraw | Decide privately prediscovers immutable requester; then sorted actor+requester USER SHARE, optional TEAM, GATEWAY, REQUEST and grant/decision/audit. Withdraw takes actor then REQUEST and checks exact owner | Declare actor/requester before gates and compare original association under the resource transaction; retain reviewer/privacy/self-decision/expiry rules. Team grants are not the departing requester's personal property | Current read |
| Sensitive-call approval requests/decisions | Human ACTOR KEY SHARE precedes approval CONTEXT; nil-actor paths take CONTEXT before requester advisory/request. Migration47 CONTEXT takes EXCLUSIVE authority-table locks NOWAIT, not a singleton row mutex | Participant-aware entry before actor/context; no late blocking lifecycle acquisition under context. Retain current physical actor-FK protection, private discovery, exact bindings/deadlines and no retry of spent/unknown commits | Independent current-source review; parent current entry reads |
| Task `Reserve` | Seals arguments, root ASSOCIATION query, principal-capacity guard, reservation insert/prepare/commit | Root association is not current standing; place lifecycle checks before capacity/resource locks for personal roots; preserve no-handle-before-activation and no retry | Current read |
| Task `Activate` | TASK FOR UPDATE, immutable binding/revision checks, root ASSOCIATION query, clock/deadline, sealed actual ID, commit then handle | No late blocking USER lock in association lookup; original root/lifetime must remain unchanged. Serving-layer final authority remains mandatory | Current read |
| Task `Begin` / `CommitInput` | Claim is a revision/deadline-bound UPDATE; input attempt is committed before a single upstream send | Capture each exchange's request epoch and original root/lifetime before TASK/capacity locks; final transport check; never restore input on conflict/lost acknowledgement | Independent current-source review; current store reads |
| Task `Finish` / release / lookup | Finish can map `input_required` into NEW input-ledger entries; release clears the operation without restoring input; lookup checks association/seal/expiry, not standing | Gate every Finish conservatively; a result-only exception must explicitly exclude new input/root/lifetime authority and publication. Version durable bindings/envelopes; do not reinterpret v1 ciphertext or reattach old work | Independent current-source review; current store reads |

### Current request-cycle probe

The private `TestSCIMFutureEpochFenceQueuedCreateAcrossSuspensionCycle` runs only in an exact baseline archive, not in the root test suite. A dedicated authenticated runtime pool's explicit `BeforeAcquire` barrier holds a pre-cycle `Identity.Actor` create. Actual `platform.UpdateUser` transactions on a separate authenticated pool suspend/reactivate the person; both audits are checked. Releasing the request currently creates a key, so the future epoch-refusal assertion fails as intended.

Three race-enabled repetitions in each actual PostgreSQL role mode reproduced that expected negative in31s. Every repetition passed the positive controls: suspension rejects the existing key, reversible reactivation preserves it, and a fresh request after reactivation can create a key. Original v0.11.0 status/session regressions remain unmodified. This demonstrates the missing future-contract distinction; it is **not** a passed SCIM-invariant suite or a newly alleged defect in current reversible-suspension policy. OAuth/callback/task/delete cleanup proofs are not inferred from it.

## Protected-principal writers

Initial managed-population exclusion covers every platform admin and team owner, not only the last one. A bind-time check is insufficient; all writers below must serialize against adoption and obey explicit unlink/re-enrollment policy:

- `platform.UpdateUser` and `auth.applyBootstrapRole`;
- `teams.Create` and `AddMember` through `addOrInvite`;
- `teams.UpdateMember`;
- `teams.AssignOwner` through `promoteMember`/`addOrInvite`;
- `teams.AcceptInvites`, including an owner invite created before the identity existed.

These observations are carried from byte-unchanged implementations. Fresh multi-user discovery/revalidation, email changes, FK locks and all actual promotion traces remain proof targets. A user guard inserted after a TEAM lock is not a total order. A database backstop that waits in that inverse order can introduce a deadlock rather than prevent one.

## Objects not owned merely by their creator

Current `automation` contract and authentication were reread: **team publisher tokens outlive their creator**. Platform-admin tokens are different: their use requires the creator to remain an active platform admin. Team-owned service accounts/keys and shared service connections are not personal cleanup targets; preserve their current independent scope/standing rules.

A former admin can have an unrevoked but presently creator-blocked platform token. Excluding *current* admins from adoption does not remove that stored artifact. The irreversible cleanup inventory must explicitly address creator-bound platform-admin tokens so a future re-enrollment/unlink/promotion cannot silently revive old-lifetime authority. Do not generalize this into revoking team publisher tokens. The new directory-machine token's creator-attribution/standing policy is still a separate unallocated decision, not another automation-token kind.

## Effective membership and group readers

Initial current SQL inventory finds raw `team_members` references in:

- `access_requests.sql`, `approval_attention.sql`, `approval_notifications.sql`, `approval_queue.sql`, `approvals_service.sql`;
- `gateways.sql`, `governance.sql`, `notifications.sql`, `overview.sql`;
- `personsecrets.sql`, `serviceconnections.sql`, `teams.sql`, `users.sql`.

Current direct group consumers include `gateways.groupsOf`, gateway-grant queries, overview queries and `identity.sql` login snapshots. Registry authorization also calls team-role helpers outside the catalog SQL. This is a starting inventory, not proof that grep found every service/helper/cache consumer.

A manual row plus multiple directory/claim sources requires effective provenance, not a destructive one-column source switch. Every authority reader must resolve current enabled mappings, link/lifetime and group generations, with no stale-positive materialized row. Existing automation scope-derived roles stay independent of the human creator's derived role. Group reductions and mapping previews must cover absent rows/phantoms as well as the rows returned in a preview.

## Concrete review blockers and additional source facts

The independent exact432017d read-only review returned no implementation or tests. It identifies remaining integration blockers, not newly reproduced released-policy defects:

- A declared actor/target pair is not automatically the complete physical USER lock set: platform administration locks every active admin, and invite acceptance writes `added_by = invited_by`. An explicit admin-set serializer and pre-discovery/revalidation are needed before sorted guards. New identity allocation must accept a preallocated UUID; adding a guard after the current upsert is too late. Unknown late participants must refuse/rollback, not append an out-of-order blocking guard or replay a consumed login code.
- Approval context is an **EXCLUSIVE TABLES NOWAIT** fence from migration47. Preserve human ACTOR KEY SHARE before it and avoid any newly blocking user guard inside it. Request-ID methods need private immutable-requester pre-discovery; nil-actor bindings already carry the requester. A bare pool-derived queries object is not proof that the correct transaction holds a lifecycle gate.
- Personal refresh publication includes already-fresh shortcuts, retry/setup paths, narrow-cache hits, post-commit cache puts and actual return/transport, not only `storeRefreshed`. A typed dormant/nonpublishable outcome must stop all of them. A callback cannot use an existing-row dormant-refresh exception.
- Shared-service callback/start also waits on a connection held across refresh I/O. Merely prepending directory/user gates to its current USER/SESSION/CONNECTION order would make a directory fence wait for that network operation. Authorizer changes need a checked PRELOCK/TRY classification too; ownership remains team/service-owned.
- A parent SKIP LOCKED does not skip a locked cascading child: deleting a grant can wait on TASK, and deleting a personal connection can wait on a server-grant child. Cleanup must inventory/try children and report incomplete, not mistake a bounded row count or `affected=0` for bounded lock wait or stable zero.

### Browser-session invalidation is separate from reusable credentials

The parent reread `auth.session`, `RevokeSessions`, logout and `identity.sql`. Sessions are individually persisted, with strict idle/absolute expiry; login has no per-user session-count cap here. Manual suspension currently physically deletes sessions; service-state deletion also has a session trigger. A future minimal directory fence that only changes effective status and later reactivates it would allow an undeleted old session to become usable again unless session revocation is independently represented and checked. A request epoch alone does not solve this if authentication simply stamps a fresh epoch onto that old cookie.

The contract must choose irreversible session invalidation (for example, a separately captured session-revocation generation) and apply it to authentication, touch/list and both personal/shared original-session callback checks. Physical cleanup can then be bounded without reviving an old session after reversible reactivation. Existing unrevoked reusable keys/grants/connections have different resume semantics. This requirement and example mechanism are not implemented or allocated schema.

## Proposed transaction classification to prove next

1. **New authority:** capture authenticated request epoch; determine actor/target identities; take the canonical non-network lifecycle gates before resource locks; revalidate discovery/standing after waits; insert/update/audit.
2. **Connection completion:** wait on an existing network-held connection before trying any lifecycle gate. Post-I/O acquisition must not block in the inverse order. Busy/stale completion cannot publish or create authority. Any dormant existing-row preservation needs exact original lifetime/owner binding and must remain counted by cleanup.
3. **First irreversible fence:** one short local adopted-user state/epoch/deletion-identity/audit commit, no artifact enumeration, no network-held connection locks and no remote revocation I/O.
4. **Cleanup:** bounded batches with nonblocking acquisition of busy targets; release lifecycle guards when work remains; recount all relevant artifacts under the exact deletion identity. `affected=0` is not completion. Re-enrollment cannot precede a stable final zero barrier, and old jobs cannot address a new lifetime.
5. **Selected global authority protocol:** one shared/exclusive G rather than additional identity/email/admin-set/per-user logical locks. Short login/standing/role/membership/group/policy changes are exclusive; ordinary authority mutations are shared; network-held resource prefixes precede TRY; bounded bulk closure uses TRY exclusive. The [selected contract](scim-authority-transaction-contract.md) requires a separate physically compatible first fence, same-transaction helpers and full child/phantom closure. Its canonical primitive is unwired; no application-wide proof, persistent lifecycle fields or supported SCIM is implied.

The deliverable is one concrete common order with explicit try-lock exceptions and executable actual-service barrier tests, not another claim that a primitive or SQL toy proves the whole application. Router/credential/schema work remains gated on that contract.
