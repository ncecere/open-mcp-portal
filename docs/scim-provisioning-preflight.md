# SCIM provisioning: main-thread implementation preflight

**Status: draft review, not accepted policy or implementation.** This document advances [#36](https://github.com/ncecere/open-mcp-portal/issues/36); it does not close its acceptance criteria, allocate decision90 or reserve migration51. There is no SCIM endpoint, token, schema change or supported IdP integration in this change.

Reviewed baseline: `4100cdc4c05cf26e9b6d6199ec85789504645ba6`, the evidence follow-up to verified v0.10.1. Work is handled directly in the main thread. Earlier isolated drafts are background research, not accepted specifications. The invite-acceptance/revocation lock inversion found during review was independently fixed and released in [v0.10.1](releases/v0.10.1.md); that fix is not SCIM support.

## Provider-neutral scope

The implementation target is **SCIM 2.0 and standards-based OIDC**, not an Authentik-specific integration. Authentik is the owner's available interoperability test environment, not an architectural dependency or a source of vendor-specific authorization semantics. Identity/group correlation must use an explicit, issuer-bound verified-claim contract rather than guessed vendor defaults. Provider-specific configuration examples and observed deviations must stay separate from the protocol implementation; testing one provider does not establish interoperability with others. An Authentik management API integration is not required for the portal's SCIM server.

## 1. What must remain true

1. A directory resource is not an authenticated identity. Existing users remain keyed by verified `(issuer, subject)`. Neither email, a local UUID, SCIM `userName`, nor an arbitrary stored claim is sufficient to link an account.
2. Directory authority over an existing unmanaged person requires explicit, audited adoption. An unadopted resource or tombstone must not suspend an unrelated existing account.
3. Enrollment rules for **new** identities are distinct from protection of existing unmanaged accounts. A required-provisioning policy must refuse missing/inactive enrollment before user upsert, bootstrap, invite acceptance or session creation.
4. Manual and directory restrictions retain separate provenance. Directory reactivation cannot lift a manual suspension, undo manual grants or restore consumed authorization.
5. DELETE must fence authority promptly without waiting for a provider network exchange. Cleanup must not miss artifacts created by requests authenticated before the fence.
6. Team-owned service identities, service connections and automation tokens do not become personal property merely because the departing person created them.
7. A pending task, approval, access request or consent link cannot recreate old authority after irreversible deprovisioning and later enrollment.
8. No authority lock spans provider I/O. No consumed code, approval, task input or uncertain committed spend is restored after a conflict.
9. Applied migrations through50 remain immutable. Schema compatibility with older binaries is not proof that older serving/background replicas enforce a new lifecycle policy.

The issue's historical suggestion of verified-email linking is **not accepted**: verified email is still not the portal's authenticated issuer/subject identity.

## 2. Identity binding: a concrete boundary, not a guessed equality

### Observed implementation

`internal/auth/oidc.go:verifyCode` verifies the ID token and nonce, decodes the full verified claim map, extracts profile/groups, then constructs `loginIdentity`. Its `Claims` field is produced by `boundedClaims`; oversized persisted claim documents may omit individual values. `internal/auth/login.go:completeLogin` currently upserts a user before checking suspension, applying bootstrap, accepting invites and creating a session.

### Recommended direction, pending acceptance

- Introduce an explicit directory/issuer binding profile, rather than assuming `externalId == sub`. The configured claim and its canonicalization rules must be validated, immutable for existing links, and scoped to the exact trusted issuer/tenant.
- Extract a bounded scalar provisioning selector from the **just-verified ID token**, before `boundedClaims`, into a dedicated ephemeral login value. Never recover identity proof from an earlier stored claim document.
- Keep the verified OIDC subject as the user's authentication key even when a different verified claim is used to correlate provisioning. Changing a selector must not relink or move an existing authenticated identity.
- Refuse missing, malformed, multi-valued, ambiguous or conflicting selectors. No fallback to email, userName or a client-supplied local UUID.
- Keep adopted links, unadopted directory resources, pending enrollment and tombstones separate. User and directory-resource identifiers need not be equal and are not credentials.
- Make requiring active provisioning for new identities an explicit enablement operation, after unmanaged break-glass administration is established. Enabling it needs a preview and a clear failure mode for a missing resource; it must not be inferred from the presence of a bearer token.

### Observed live OIDC baseline (not SCIM interoperability)

A separate schema50 portal instance built from `e63bf0a211096e2de7685a568c6f8d0cdbb105cf` was exercised against live Authentik **2025.10.3**, with six dedicated synthetic identities, three unprivileged groups and a group-restricted OIDC client. Development sign-in was disabled; the instance used fresh matching keys and separate restricted PostgreSQL owner/runtime roles. No existing production identity, infrastructure access group, global mapping, flow or signing key was modified. Only public signing-key metadata was referenced, not private-key material. Authentik is an interoperability fixture, not a product dependency.

The first real browser sign-in completed the production authorization-code/PKCE/state/nonce/signed-ID-token path and explicit exact-subject administrator bootstrap. The initial browser helper failed before sign-in because it selected a nonexistent Chromium path; that attempt was retained and the corrected installed-Playwright-browser rerun passed in8s without weakening TLS or authentication checks.

The subsequent baseline passed **53 checks in38s**: exact reader/editor/no-grant gateway access and group-grant provenance; no inferred platform/team role; non-admin write denial; signed-unverified-email refusal; IdP application-policy denial; and real group removal/restoration. Changing membership at the IdP alone did not update an existing portal snapshot. A fresh verified login updated the shared user row and therefore access for both fresh and original sessions, without changing user identity. These are direct gateway grants, **not** group-to-team-role reconciliation.

A further **21 checks in13s** confirmed the existing lifecycle boundary: IdP-only deactivation did not notify an already authenticated portal session without a provisioning integration. Manual portal suspension revoked its sessions and remained effective despite a valid new IdP sign-in. Manual reactivation did not resurrect the revoked session; a new verified sign-in succeeded for the same identity. This is not proof of SCIM lifecycle enforcement or of key, callback, approval or task final-writer fencing.

The live built-in email mapping explicitly emitted `email_verified:false`. A separate mapping attached only to the synthetic client used explicit per-fixture true/false assertions for synthetic addresses; the portal's verified-email requirement stayed enabled. This tests signed-claim acceptance/refusal, **not real mailbox verification**. The client used an explicit UUID subject mode; no assumption was made that a SCIM client's default `externalId` matches that subject.

Final owned-database checks found exactly four expected verified issuer/subject identities, one bootstrap marker/administrator, zero teams, two group-granted empty gateways and one manual suspend/reactivate audit pair. A scoped24-file scan found none of the known setup/client/user/database/key/session credentials in the selected logs/reports; intentional private credential/session files were excluded. Generated credentials and exact fixture ownership references remain private. The synthetic reader was returned to active status and its group membership restored; the old revoked session remains revoked. No SCIM endpoint, bearer token, provisioning push, remote ingress or tunnel was created. These synthetic checks do not close real-client, Entra/Google or human-pilot acceptance.

### Proposed binding contract

The recommended first contract is an explicit directory-bound profile with **no default correlation claim**. It may select the verified OIDC `sub`, or an explicitly configured top-level scalar ID-token claim whose stability/non-reassignment contract the operator has confirmed. The profile is tied to the exact verified issuer and expected audience/client; provider-specific defaults are not guessed. Email, userName and display-name selectors are not supported identity fallbacks. Missing, array/object-valued, over-limit or ambiguous values refuse managed enrollment. Comparison is exact: no trimming, case folding or Unicode normalization may merge identifiers.

This contract must keep three different things separate:

- **OIDC authentication identity:** the verified `(issuer, subject)` remains the local user's authentication key. OIDC defines `sub` as case-sensitive, locally unique and never reassigned within its issuer.
- **SCIM resource identity:** the server-issued resource `id` is stable, non-reassignable and not a local login credential.
- **Client correlation data:** RFC7643 defines `externalId` as optional, case-exact, client-issued, provisioning-domain scoped and read/write. It must not silently become an immutable authentication key or a globally unique database identity column.

Use `externalId` only as a candidate correlation value under the explicitly selected profile. Ambiguous candidates refuse enrollment/adoption rather than selecting the first record. Enforce uniqueness on the **adopted binding**, not by pretending the core `externalId` attribute has different RFC characteristics. Once bound, store the immutable authenticated issuer/subject, directory-resource identity and profile-version/selector association separately. Later `externalId` edits must never relink an authenticated account or transfer that binding to another principal. An enrollment selector already bound or tombstoned for another identity must not be recycled implicitly.

Existing-user adoption requires a recent dedicated observation from a verified login under the current profile version, plus an explicit revision-bound administrative approval and protected-principal checks. Persisted arbitrary `users.claims`, a matching email or a user UUID alone is insufficient evidence. Profile edits invalidate unaccepted observation/preview state; migrating an adopted binding requires a separate audited operation, not an in-place configuration side effect. The exact observation lifetime and migration/re-enrollment procedure still need tests and acceptance.

### Proposed login eligibility matrix

The following recommendation resolves the ordering ambiguity in the older drafts; it still needs review and deterministic tests before acceptance:

- **SCIM disabled:** retain current issuer/subject login behavior. Merely storing a directory token or draft mapping does not enable enforcement.
- **Existing unmanaged issuer/subject:** retain normal login and manual status checks. A matching unadopted resource/tombstone does not seize authority over the account. Adoption remains an explicit operation, not a side effect of email or claim matching.
- **Existing adopted identity, matching immutable link:** require both manual and directory eligibility. Directory inactivity or a DELETE/cleanup marker refuses sign-in. An active directory resource cannot override manual suspension.
- **Existing adopted identity, changed/missing/ambiguous verified selector:** refuse managed sign-in before updating profile, bootstrap, invitations or sessions. Do not relink the account or fall back to an unmanaged login.
- **New issuer/subject, active matching pending resource:** allow enrollment only after uniqueness/collision checks and protected-principal checks. Record the exact issuer/subject association atomically with enrollment; it remains the authentication key.
- **New issuer/subject, inactive matching pending resource:** refuse before `UpsertLoginUser`, even when optional unmanaged JIT enrollment is enabled. An inactive pending record must not become an unmanaged owner/admin through bootstrap or an invitation.
- **New issuer/subject, matching tombstone or incomplete DELETE cleanup:** refuse before upsert. Neither `active:true` nor re-POST silently restores the deleted principal's authority. An explicit separately defined re-enrollment operation is required after stable cleanup.
- **New issuer/subject, no matching resource and required provisioning enabled:** refuse before upsert. This policy must be deliberately enabled, not inferred from a missing record.
- **New issuer/subject, no matching resource and optional unmanaged JIT enabled:** retain unmanaged JIT, visibly outside SCIM control. Document the race boundary: if login creates an unmanaged account before a later directory push, that push cannot retroactively adopt it without approval. Optional JIT is not complete directory enforcement.
- **New enrollment would become a platform admin or team owner:** refuse the managed transition; never silently unlink or grant a protected role. Bootstrap must not bypass an inactive/missing enrollment gate. Before enabling required provisioning, establish an existing unmanaged break-glass administrator. Any later recovery exception must be explicit, not an accidental fallback.
- **Concurrent provisioning change:** eligibility and link creation must use one serialized directory/identity snapshot. A stale pre-check is not permission to create a user or session after a reducing update commits.

A denied new enrollment must leave no user, bootstrap marker, membership, session or new credential behind. Existing-user denial auditing is distinct from granting authority. Protected accounts and optional unmanaged JIT must be displayed as outside the managed population rather than reported as successfully offboarded.

This is a proposed provider-neutral binding contract, not a claim that a provider's default `externalId` already matches its OIDC subject. The exact explicit re-enrollment and profile-migration protocol remains to be specified and tested. No Entra/authentik interoperability is established by this matrix.

## 3. Supported managed population

### Recommended bounded first scope, pending acceptance

Initially exclude **all platform admins and all team owners** from adoption, not just the last active ones. A managed person cannot become either without an explicit audited unlink from directory control. Unlinking must not automatically reactivate the person or restore old credentials.

This avoids claiming automated offboarding of protected principals while leaving the existing global owner-counting and administrator-recovery policy unchanged. Protected/unadopted accounts must be visibly outside SCIM control; a successful directory write must not be presented as successful local offboarding for such an account.

Adoption-time checks alone are insufficient. All promotion writers must participate:

- `platform.UpdateUser` for platform roles;
- `auth.applyBootstrapRole`, including a bootstrap subject configured after the account already exists;
- team creation and `AddMember` through `addOrInvite`;
- `UpdateMember`;
- platform `AssignOwner` through `promoteMember` or `addOrInvite`;
- sign-in `AcceptInvites`, including owner invitations.

`AssignOwner` currently locks the team before resolving an email to users. A user-first guard cannot simply be added after that lock. Target discovery must be followed by identity/email revalidation before mutation. Unknown-user owner invitations need their own guarded treatment at eventual acceptance.

A database backstop and deterministic adopt-versus-promote races are required. A trigger that blocks acquiring a user guard after a team lock can itself create the inverse order it is intended to prevent. Nonblocking backstops are a possible direction, not a proved implementation.

## 4. Current final-writer inventory

The following are direct code observations. They identify requirements for a future lifecycle fence, **not reproduced new vulnerabilities** in the released policy.

### Browser sessions and bootstrap

`completeLogin` performs identity upsert, verified-email bookkeeping, status check, one-time bootstrap, invite acceptance, session creation and audit in one transaction. The new enrollment check must precede persistent provisioning side effects. Existing unmanaged identities must not acquire directory restrictions merely because their email resembles a directory record.

### API keys

`internal/apikeys/apikeys.go:Create` locks the user with `GetUserForUpdate`, checks the key cap and inserts a key. The returned user's status is not revalidated there. Merely waiting for this lock is not a generation fence for a previously authenticated request. Future lifecycle eligibility must be checked at the final write, after any wait.

### OAuth grants, codes and tokens

`internal/oauth/authorize.go:Approve` deliberately locks the user **FOR NO KEY UPDATE** before creating/replacing a grant. The query comment explains why: grant-first token/revocation audits need the user foreign key's compatible KEY SHARE lock.

`internal/oauth/token.go` locks GRANT, reads the user's status, and for refresh locks TOKEN. Both fresh issuance and grace-repeat can return token authority. A lifecycle integration must cover both without introducing a grant/user inverse or changing refresh single-use/grace semantics.

`TakeOAuthCode` consumes a code whether the exchange succeeds or fails. A lifecycle conflict must not restore that code. OAuth client metadata is shared/client state, not automatically a departing user's personal erasure target.

### Personal upstream connections

Personal provider callbacks exchange outside the final store transaction. The final store locks a connection but does not have the shared-service callback's final user/session lock equivalent. A status check at initial authorization is not sufficient to fence a late callback store.

Refresh paths hold the connection transaction across a bounded network exchange and persist rotated refresh material before returning it. `storeRefreshed` updates an existing connection. A first user fence cannot wait for this connection lock. Adding a blocking user guard after the exchange can invert cleanup's USER→CONNECTION order. Dropping a rotated token on a try-lock failure has an availability consequence and is not silently accepted here.

Separate new-connection creation from existing-row refresh. The design still needs to prove which dormant refresh state may be persisted during reversible suspension, how DELETE/generation changes prevent publication or recreation, and how final cleanup accounts for every in-flight writer.

### Team-owned service connections

The shared callback already revalidates USER KEY SHARE→SESSION→CONNECTION→STATE around an exchange performed outside its transactions. Its creator's departure does not make the team-owned connection a personal cleanup target. Current authorizer standing and original consent/session validation still matter for an in-flight change.

### Per-person secrets and one-use request links

`internal/personsecrets/personsecrets.go:Set` checks active user/reachability before its transaction, then locks SERVER→PERSON_SECRET, creates/replaces sealed values, consumes request links and optionally updates the server's setup-person attribution. Setup discovery follows outside the transaction. A final lifecycle guard must precede the resource locks, not be added after them.

Secret-request creation/reuse has its own bounded transactional path. Personal secret values and links are cleanup targets; team-owned server configuration and another person's setup authority are not interchangeable with them. No consumed link is restored after a lifecycle conflict.

### Gateway access requests

`CreateAccessRequest` takes its per-requester advisory guard, locks/revalidates current actors, then the subject TEAM, if any, and GATEWAY before insert/audit. These existing live actor/role/privacy checks must remain. A common lifecycle guard needs a consistent position relative to the requester guard across create/decision/cancel paths.

### Sensitive-call approvals

Approval creation enters the approval-context transaction, checks deadline/current requester/rule/review audience, then requester advisory guard and request state. Human-decision transactions lock an active actor before the context and reread status/role. Nil-actor requester paths and human-decision paths are different lock entries; both must be accounted for.

Cleanup cannot erase spent history, restore consumed approval availability or turn an uncertain commit into a dispatch permit. The existing context/revision/deadline/live-authority machinery remains in force.

### MCP Tasks

Task reservation checks principal/credential association, takes the principal capacity guard, then inserts. Activation locks TASK before checking the root association and updating sealed state. The store deliberately delegates live authorization to the serving layer.

`MCPTaskRootBelongsToPrincipal` explicitly checks association only, not current status, expiry or authorization. A new lifecycle guard inserted into that later lookup can invert USER→TASK cleanup. It must be placed consistently across reserve/activate/input/finish/lookup paths, with original root/generation binding. Service-account tasks are not the creator's personal tasks. Removing a local mapping is not proof of upstream cancellation.

## 5. Lifecycle state and cleanup requirements

The first irreversible fence should be a short, user-local commit containing adopted-link state, a new authority generation, tombstone/cleanup marker and audit. It must not lock all keys, grants, secrets, tasks or provider connections, and must not wait for provider I/O.

### Proposed lifetime and request-fence distinction

Use an explicit lifecycle state machine, not one overloaded suspension flag. Effective eligibility is the intersection of manual standing, directory standing and absence of an irreversible deletion fence. Directory `active:true` cannot write away the manual restriction. An unlinked protected/unmanaged person is not a successful directory offboarding target.

A proposed monotonic **request-authority epoch** advances on adoption/unlink, reducing lifecycle transitions and re-enablement. Capture it at authentication/admission and validate it under the final writer barrier after waits. This prevents an old authenticated request from becoming valid again merely because a suspend/reactivate cycle finished before its final store. The exact actor/session propagation is an implementation requirement; current actor UUIDs and stored claims do not already provide it.

Do not permanently bind preserved reusable credentials to a pre-suspension request epoch: reversible suspension is intended to permit a **new request** using an otherwise valid, unrevoked key/connection after reactivation. Conversely, old callback/consent/approval/task request state must not inherit that new epoch or regain consumed availability. Their session/root/lifetime binding must be validated separately, and the supported resume/invalidation semantics need explicit tests.

Irreversible DELETE additionally needs an immutable deletion/cleanup identity. Workers must compare that identity, not a wall-clock cutoff, and re-enrollment must be a distinct post-cleanup transition with newly issued authority. Updating an unrelated status revision cannot redirect an old cleanup job onto a newly enrolled lifetime. This is still a proposed state protocol, not implemented generation fencing.

### Cleanup target set

Cleanup then needs an explicit complete target set and a stable final barrier:

- sessions and personal API keys;
- personal OAuth grants, codes and tokens;
- personal provider connections, grants, auth states and connect requests;
- per-person secrets and their one-use request links;
- supported personal memberships and user grants;
- pending approvals/access requests/task state whose later use could recreate authority;
- relevant private notice state, without destroying audit/call history or team-owned objects.

**Never filter cleanup only by `created_at <= deprovisioned_at`.** A request authenticated before the fence can create an artifact later. Final writers must serialize current state/generation, and the completion barrier must recount **all** target-owned artifacts. Re-enrollment cannot become usable before cleanup reaches a stable zero-artifact state. Audit/history and irreversibly consumed records are not counted as usable credentials to be erased.

Reversible directory inactivity is different: it blocks use but preserves eligible dormant credentials; reactivation lifts only the directory restriction. Manual suspension, provider revocation and committed spend are not undone. A provider may no longer honor a dormant credential, so local reactivation is not a promise of upstream validity.

Remote revocation is deferred in the recommended initial design. A mutable provider URL read at cleanup is not original issuance provenance. Future delivery would require sealed issuance/refresh endpoint, client and permitted-origin bindings; unknown legacy provenance sends nothing. No authority/connection lock may span delivery.

## 6. Group roles and independent gateway group access

A single `team_members.source` value cannot represent a manual grant and one or more directory grants simultaneously. Removing one source must not erase or silently recreate another. Recommended direction: explicit provenance layers with a defined effective role; every authorization/list/catalog/count reader must use the intended layer.

There is a separate boundary beyond team roles: `internal/gateways/access.go:groupsOf` returns stored `users.groups` directly, and gateway group grants/list/catalog queries consume that slice. `UpsertLoginUser` overwrites it from OIDC at each sign-in.

The baseline is now covered by `TestOIDCGroupSnapshotChangesOnLoginForAllSessions` in `internal/httpapi/oidc_group_snapshot_integration_test.go`: changing an owned fake IdP's claims alone leaves the stored snapshot/access unchanged; a fresh interactive login updates group-based gateway access for both new and older sessions of the same user. A missing groups claim clears the snapshot. The identity remains the same, and no platform role/team membership is manufactured. This test and existing group/login/grant tests passed three race-enabled repetitions in both actual database-role modes (48s), using owned disposable PostgreSQL. This is **not** live Authentik or SCIM interoperability evidence.

Therefore removing a SCIM-derived team membership does **not** automatically remove access independently granted through a cached OIDC group. The design must explicitly choose whether managed-user direct group grants remain an independent OIDC authority or become SCIM-authoritative. If the latter, it needs a trusted group identifier namespace and a live fence that stale sign-in claims cannot overwrite. Do not claim complete group revocation while updating only team-role rows.

### Recommended managed-group authority model

The safer initial recommendation is an explicit authority transition at adoption, not a silent union of stale OIDC claims and directory groups:

- Unmanaged people retain the current verified-login snapshot behavior, covered by the baseline test above.
- For adopted managed people, directory group membership is the source of directory-derived team roles. New OIDC sign-ins may refresh profile/raw claim observations but cannot overwrite that effective directory membership.
- A SCIM group must not acquire portal privileges because its mutable display name or client-supplied `externalId` happens to equal a privileged SSO-group string. Any bridge to an existing gateway group-grant key must be an explicitly reviewed administrative binding to the stable SCIM group resource ID and directory.
- Default managed-user group bridges to legacy direct SSO-group grants are empty/fail-closed. Adoption/mapping preview must show resulting access losses and any newly proposed positive bridge. No automatic alias/backfill from an old claim snapshot is permitted.
- Preserve independently authorized manual team memberships and explicit user/team grants. Removing one directory-derived source does not revoke another legitimate manual source; the UI and test evidence must identify the access provenance rather than call every group reduction complete offboarding.
- Effective role/grant readers must join current directory/link/group/membership generations and enabled mappings. A stale materialized role row, cached claim, group rename or old mapping preview is not authority.
- Adding/removing group-bridge authority is itself an audited, revision-bound administrative policy change, not something the SCIM bearer token can request by creating an arbitrary matching group name.

RFC7643 leaves group authorization semantics to the service provider; it does not prescribe this model. This recommendation deliberately avoids silently widening or preserving stale group authority, but requires an explicit adoption preview and complete reader/epoch integration. It remains unimplemented and unaccepted until those proofs are complete.

Large group reductions also need an immediate authority boundary. A size error is not successful offboarding, and asynchronous cleanup without a group generation/fence leaves stale derived authority. A complete bounded synchronous representation or an immediate logical group fence must be chosen and proven before acceptance. Additions can be bounded/refused before mutation; reductions cannot be reported as complete while stale access remains effective.

Mapping previews must bind the whole mapping set, link set, manual provenance and relevant revisions, including absence. Hashing only currently returned rows or a maximum revision does not prevent phantoms.

## 7. Lock-order proof required before implementation

There is not yet one proved total order. Known entries include:

- platform administration: active-admin set before target USER;
- login: identity upsert/user before bootstrap and all sorted invitation TEAM locks;
- manual membership/owner recovery: TEAM before resolving/promoting target;
- OAuth approval: USER NO KEY UPDATE before GRANT; issuance/revocation: GRANT before audit user-FK KEY SHARE;
- personal secrets: SERVER before SECRET;
- refresh: CONNECTION across bounded network work;
- service callback: USER KEY SHARE before SESSION/CONNECTION/STATE;
- approval decisions: active ACTOR before CONTEXT; requester paths: CONTEXT before requester guard;
- access requests: requester guard before current USER actors, TEAM/GATEWAY;
- task activation: TASK before association lookup.

A per-user advisory barrier before resource locks is a candidate, not an established invariant. Every actor and target identity, multi-user ordering, identity lookup race, database trigger/FK edge and mixed-version writer must be included. An independent cleanup transaction does not remove an inverse order if it still holds the same logical user guard while waiting on a resource.

### Isolated refresh/cleanup lock-model experiment

A standalone PostgreSQL design experiment used a newly created disposable database, dummy person/connection rows, the race detector and a deterministic `pg_blocking_pids` barrier. It did not use the application schema, migrations, credentials or provider network I/O. The owned experiment database was destroyed afterwards.

- The minimal user-local first fence committed while a simulated refresh still held its connection row.
- **Negative control:** cleanup held the logical user guard and waited on the connection; refresh then tried to acquire the same user guard with a blocking call. PostgreSQL reported `40P01`. This is a deliberately constructed **proposed-order** deadlock, not a newly reproduced defect in the released application.
- **Candidate:** refresh instead tried the user guard without waiting. On contention it updated only its already-locked existing dummy row as dormant state and published no credential. Cleanup then unblocked, deleted that late write and reached a zero-row barrier. No rotated-material restoration or new connection insertion was simulated.

Both controls completed in4s. This supports investigating a distinct **existing-row-only, no-publication refresh completion class**, rather than forcing every network-held connection transaction through a blocking user guard. It does **not** prove correct application cache behavior, callback creation, split-role permissions, all final writers, provider interoperability or a total application lock order. Integrating the candidate requires a real service-level test with sealed rotating material and current lifecycle/generation checks; the model's `credentialPublished=false` was a property of the model, not a measurement of production transport.

The common user-first protocol remains appropriate to investigate for **new artifact creation**, where the guard can be acquired before resource locks and outside network work. The refresh exception must not be generalized into permission for late inserts, an ignored lifecycle conflict or a retry of already-spent authorization.

## 8. Protocol and credential boundary to specify next

The future protocol profile must enumerate supported Users/Groups verbs, PATCH paths, filters, pagination, uniqueness, tombstone/re-POST behavior and discovery capabilities against RFC7643/7644. No usable router or discovery advertising resource support should ship merely because token storage exists.

The recommended token domain is directory/issuer-bound, separate from automation and MCP credentials, with finite expiry, digest/pepper handling, revocation, redaction and first-class SCIM audit identity. Session-only administration, creator-standing policy, rotation and cross-surface401 matrices still need specification. No new token class or management route exists in this draft.

## 9. Required proofs and next concrete work

Before accepting a design or allocating DDL:

1. Finish the new/existing identity and group-binding state matrices, including unadopted collisions, protected principals, required enrollment and manual restrictions.
2. Inventory all remaining final writers and choose a single auditable lock/generation protocol. Trace the actual calls, not only SQL names.
3. Write deterministic real-PostgreSQL barrier tests for adopt/promote, login/bootstrap/invite, late API-key/code/token/callback/secret/task writes, refresh/fence/cleanup and final-zero/re-enrollment races in both actual DB-role modes.
4. Prove manual-plus-directory role preservation and immediate group reductions, including direct gateway group grants and stale OIDC login claims.
5. Specify the RFC capability/error profile and token/audit/storage boundary; keep the router absent until its advertised resources actually work.
6. Inspect integrated schema before separately allocating migration51 or later. Test the actual prior release against the expanded schema and drain older writers before relying on new enforcement.
7. Keep owned fixtures distinct from real authentik/Entra, client/pilot and independent security acceptance. Preserve failed proof attempts instead of weakening gates.

No implementation slice is authorized by this draft's existence. A token-only foundation is not complete SCIM support and does not need an independent release.

## References

- [Issue36](https://github.com/ncecere/open-mcp-portal/issues/36), originally drafted against v0.2.1; its proposed paths/numbers are not current implementation instructions.
- [RFC7643: SCIM core schema](https://www.rfc-editor.org/rfc/rfc7643).
- [RFC7644: SCIM protocol](https://www.rfc-editor.org/rfc/rfc7644).
- [OpenID Connect Core: subject identifier](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes).
- [RFC7009: OAuth token revocation](https://www.rfc-editor.org/rfc/rfc7009).
- [Verified prerequisite release and scoped evidence](releases/v0.10.1.md).
