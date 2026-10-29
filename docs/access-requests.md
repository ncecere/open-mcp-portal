# Gateway access requests (#32)

Status: **shipped and verified in v0.6.0; #32 closed**. Publication/acceptance evidence is in [status](status.md). Decision 83. This is separate from exact-call
[sensitive-call approvals](tool-approvals.md): an access decision grants eligibility to use a
gateway, never permission to bypass tool scopes, credentials, curation or call approval.

## Authority and visibility

Only **platform** gateways can opt into `accessRequestsEnabled` (default false). Any active
signed-in person can discover the opted-in, enabled gateway's name and description. The
requestable projection exposes no selections, upstream information or credentials. Hidden
and disabled gateways keep their existing not-found behavior, including on `/mcp/{slug}`.
A requestable gateway still requires an effective grant before MCP access is allowed.

Platform admins manage discoverability and at most 50 named, active human **stewards** per
gateway. Stewards can review/decide requests for that gateway only; stewardship grants no
MCP access, ability to edit the gateway, manage grants directly, change stewards or gain
platform roles. Review is available outside the admin-only navigation. A requester can
never decide their own request, even as a platform admin or steward.

A person requests for themselves, or for an active team they currently own/administer.
Team grants intentionally include the team's people and service accounts (decision 23).
Requester and reviewer authority, team status, gateway state and request state are checked
live when deciding. No synthetic platform-admin actor is used for steward decisions.
Automation tokens cannot discover, submit, review, withdraw or decide requests or manage
stewards; every new operation is browser-session-only.

## Request lifecycle

Requests require a trimmed reason of 1–1000 characters; optional decision notes are at most
1000 characters. Pending requests are unique per gateway/requester/subject. There are at
most 10 pending per person and a 24-hour cooldown after a denial for the same subject and
gateway. Existing effective access refuses a new request. A pending requester can withdraw;
only an eligible, different human can approve/deny. Concurrent decisions serialize and a
terminal request cannot be decided again.

Approval inserts a user or team grant and records the decision and audit in one transaction,
reusing the normal grant insertion validation/audit path. An existing grant is never silently
widened or extended by a stale request. A grant expiring before approval must be handled
explicitly rather than treated as current access. Denial/withdrawal creates no grant. A
request records the grant ID and the expiry that was actually committed.

## Expiring grants

An approver may choose 1–365 days; omitted expiry is permanent. Existing grants stay
permanent. All effective-grant SQL filters on database time, including user/group/team
matching, service-account access, OAuth authorization, key creation, reachability and
approval rechecks. Expiry ends access without any sweeper. A bounded leader-elected cleanup
removes expired rows and audits `gateway.grant_expire`; cleanup is not enforcement.

Grant expiry is authority: changing it must invalidate outstanding exact-call approval
bindings, and natural expiry must be checked at the actual outbound transport boundary.
Temporary-grant transport hooks check both local and authoritative database time before and after
prior admission/approval consumption, including its commit. A clock-read failure refuses dispatch;
a slow application clock cannot override SQL expiry. Each clock read releases its pool connection
before the next guard/network step. A post-spend refusal never restores or replays an approval.
A grant's tool scope remains a narrowing layer. Alternative valid grants may still provide
access, but an expired grant cannot contribute a scope. An approval cannot survive lost
access simply because no authority row was updated at the wall-clock deadline.

Migrations are expand-only, beginning at `00043`; never reuse the historical migration
number in the issue. Previous code can read the expanded schema but **does not enforce
expiry or deliver access-request events**. Drain pre-feature serving and background-worker replicas
before enabling access requests or expiring grants. Rollback is
not permission to keep serving with unenforced deadlines. Runtime privileges and the
private approval authority journal/fence must remain least-privilege.

## Privacy, notifications and evidence

Request reasons and decision notes are private to the requester and live eligible reviewers,
not general catalog/team metadata. New request/decision notices use inbox and verified email
only, resolved from live roles; no webhook subscription/delivery or free-text reason/note in
notification payloads, logs, traces or audit. Audit records the ordinary gateway label, IDs, subject, decision and expiry.
Failed notification delivery does not roll back the authoritative decision. Queues remain
available and display exact pending counts to the authorized person.

Validation includes route and authorization/token matrices, foreign-team/steward/self-decision
denials, concurrent duplicate/limit/decision races, grant rollback, expiry with no cleanup,
all grant subject kinds, credentials and scoped alternative grants, and expiry between
approval/list and actual call transport. Run full mandatory-PostgreSQL normal/race suites in
actual legacy and split-role modes with `GOFLAGS='-p=2'`, generated-code freshness, frontend
typecheck/tests/accessibility/build/styling/size and deployment gates as applicable. Fake
SMTP/MCP fixtures do not establish real-provider/client or pilot acceptance.
