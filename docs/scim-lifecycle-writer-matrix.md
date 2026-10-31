# SCIM lifecycle: current-source writer and reader matrix

**Working inventory, not accepted decision90, a total-lock proof, schema allocation or SCIM support.** This accompanies [the preflight](scim-provisioning-preflight.md) for #36. Baseline is independently verified v0.11.0 plus evidence follow-up `cc44f0433c372785dd151f2425a222d812b364c6`. The owner resumed SCIM as the primary task; catalog-search review is the independent side lane. No SCIM router, token or migration51 exists in this change.

## Evidence terminology

- **Current read:** the actual baseline implementation was reread during this batch.
- **Carried observation:** the earlier direct service review is still applicable because the relevant implementation is byte-unchanged in the inspected baseline4100-to-cc44 diff. It is not a new executable proof.
- **Required:** a future integration/proof target, not behavior the current product already provides.
- A source comparison, SQL model or successful primitive test is never called an application-wide lifecycle proof.

## Authentication/admission boundaries

`auth.Identity` contains the user/session/CSRF state. `Identity.Actor` copies user UUID and platform role; `authz.Actor` has no captured lifecycle epoch. API-key and OAuth authentication read current user standing, but a future queued writer needs to distinguish that admission from a later suspend/reactivate cycle. A profile revision is not automatically this authority epoch.

Reusable credentials and individual requests need different bindings. A new request using an existing otherwise-valid unrevoked key/connection may succeed after reversible reactivation. A pre-cycle request, taken code, deleted session, old callback or spent input cannot inherit the new request epoch. Irreversible deletion additionally needs a distinct cleanup/lifetime identity so old work cannot target a newly enrolled lifetime.

## Personal authority writers

| Entry | Current ordering/behavior | Required lifecycle integration | Evidence |
| --- | --- | --- | --- |
| `auth.completeLogin` / bootstrap | Identity upsert, email bookkeeping, status check, optional bootstrap, sorted invite-team locks, session insert/audit | Verified-selector eligibility and new/pending/adopted/tombstone decision before upsert/bootstrap/invites/session; serialize issuer/subject allocation; all bootstrap promotions participate | Current read |
| `platform.UpdateUser` | Active-admin row set before target USER FOR UPDATE; revision check; status/role update; suspension deletes sessions | Separate manual/directory provenance, epoch advancement and a placement that does not invert admin-set/user/resource locks | Current read |
| `apikeys.Create` | USER FOR UPDATE, fresh active-status check, current gateway eligibility, cap, insert/audit | Validate captured request epoch after waits; preserve existing-key use by fresh requests after reactivation | Current read; shipped v0.11.0 regressions; new private future-contract probe below |
| `providers.Callback` / personal `store` | Network exchange outside final transaction; existing CONNECTION wait, USER KEY SHARE NOWAIT, original SESSION UPDATE NOWAIT, sealed store/request/grant/audit | Preserve original browser/state and no-replay guarantees; no authority guard before connection wait; decided epoch/lifetime checks before insertion/publication | Current read; shipped v0.11.0 regressions |
| Existing personal connection refresh | CONNECTION retained across bounded provider I/O; existing-row rotated-material persistence | Pre/post-I/O standing capture; nonblocking post-I/O guards; no credential publication on conflict; narrowly proven existing-row dormant completion only, never late insertion/upsert | Carried service observation; sealed/cache/transport tests still required |
| `oauth.Approve` / `grantFor` | USER NO KEY UPDATE; existing GRANT lock/renew/revoke or new grant; code insert. The helper query selects the user without an active predicate, and its returned row is not itself checked here | Place the common lifecycle gate before existing resource locks, validate admitted user standing/epoch and durable code/lifetime binding; retain compatible FK lock mode | Current read; no newly reproduced released-policy defect claimed |
| OAuth authorization-code exchange | `TakeOAuthCode` commits deletion first; transaction locks GRANT, reads current active user, inserts tokens/audit | Capture the original owner/lifetime safely before canonical locks; do not restore a consumed code on any fence failure | Current read |
| OAuth refresh, first rotation | Digest lookup, GRANT lock/current user read, TOKEN lock, expiry/reuse checks, rotate and insert successor pair/audit | Capture request epoch independently of reusable grant lifetime; validate after waits without grant/user inversion; preserve rotation/single-use policy | Current read |
| OAuth refresh, grace repeat | Same grant/token checks; reconstructs the previously issued pair after looking up both successor rows | A repeat returns authority even without a new token row; fence it too. Never reissue missing/revoked successors or restore committed spend | Current read |
| `personsecrets.Set` | Reads active user/reachability before transaction; SERVER then PERSON_SECRET; sealed create/replace, used-link updates, optional setup attribution. Setup discovery is after commit | Guard/current epoch before resource locks; final current eligibility; preserve origin/AAD/request-consumption and team-owned configuration boundaries | Current read |
| Person-secret request/reuse | Transaction finds open link or inserts a sealed user/server/origin/capability-bound request, trims count | Treat links as future-authority material, capture lifetime/epoch; no request reuse after deletion/re-enrollment | Current read |
| Personal gateway access requests | Requester guard, current actor checks, optional TEAM then GATEWAY and request/audit | Common lifecycle placement must cover create/decision/cancel and actor/requester targets without discarding current privacy/role checks | Carried observation; fresh complete trace pending |
| Sensitive-call approval requests/decisions | Requester/context paths and human ACTOR-before-CONTEXT paths have distinct entry orders | Discover actor/requester targets before guards, or use a specifically justified fail-fast class; retain exact argument/context/deadline checks and spent/unknown state | Carried observation; fresh complete trace pending |
| Task `Reserve` | Seals arguments, root ASSOCIATION query, principal-capacity guard, reservation insert/prepare/commit | Root association is not current standing; place lifecycle checks before capacity/resource locks for personal roots; preserve no-handle-before-activation and no retry | Current read |
| Task `Activate` | TASK FOR UPDATE, immutable binding/revision checks, root ASSOCIATION query, clock/deadline, sealed actual ID, commit then handle | No late blocking USER lock in association lookup; original root/lifetime must remain unchanged. Serving-layer final authority remains mandatory | Current read |
| Task input/finish/release/lookup | Operation revision and sealed input ledger; current live policy belongs to serving layer | Distinguish result-only persistence from new root/input authority; never restore committed input, imply upstream cancellation or turn an old handle into authentication | Fresh complete trace pending |

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

## Proposed transaction classification to prove next

1. **New authority:** capture authenticated request epoch; determine actor/target identities; take the canonical non-network lifecycle gates before resource locks; revalidate discovery/standing after waits; insert/update/audit.
2. **Connection completion:** wait on an existing network-held connection before trying any lifecycle gate. Post-I/O acquisition must not block in the inverse order. Busy/stale completion cannot publish or create authority. Any dormant existing-row preservation needs exact original lifetime/owner binding and must remain counted by cleanup.
3. **First irreversible fence:** one short local adopted-user state/epoch/deletion-identity/audit commit, no artifact enumeration, no network-held connection locks and no remote revocation I/O.
4. **Cleanup:** bounded batches with nonblocking acquisition of busy targets; release lifecycle guards when work remains; recount all relevant artifacts under the exact deletion identity. `affected=0` is not completion. Re-enrollment cannot precede a stable final zero barrier, and old jobs cannot address a new lifetime.
5. **Directory/group policy:** investigate a shared directory-policy gate before personal authority writers and an exclusive gate for authority-changing directory/mapping operations. This may close group-preview/adoption phantoms, but its placement against identity/admin/user/approval/task/FK locks has **not** been proved and must not be coded as an established invariant.

The deliverable is one concrete common order with explicit try-lock exceptions and executable actual-service barrier tests, not another claim that a primitive or SQL toy proves the whole application. Router/credential/schema work remains gated on that contract.
