# Team service connections (#26)

## Design

A service connection is a team's explicitly shared upstream OAuth account, not a
person's connection and not a server's machine credential. Owners and admins may
connect their own account, but the account label must clearly say it is shared.
Personal secrets are not shared. Both platform providers and server-bound OAuth
providers are supported. No implicit first/newest connection or personal fallback
is permitted.

Migration 00031 is additive. `service_connections` stores the encrypted tokens,
status, revision and consent generation. A tokenless `needs_reconsent` row exists
before the first redirect. Assignments uniquely bind (service account, provider)
to one connection; composite foreign keys enforce matching team and provider.
Server grants record the exact server, normalized origin and scopes approved by
the team's administrator. Published cross-team servers need the same explicit
grant. Provider access rules apply to the destination server's team, never the
connection's team. Origin changes invalidate grants; path changes do not.

A connection is derived `lapsed` while its connecting person is missing,
suspended, or no longer an owner/admin of its owning team. Every credential use
checks live roles, active account/team, provider and linked client, assignment,
connection status, scopes and destination grant before decrypting or consulting
any cache. Completed connections do not depend on browser session lifetime.

## OAuth safety and rolling deployment

Service OAuth state is stored in a **separate** `service_connection_auth_states`
table. Previous-release replicas cannot find that state in `provider_auth_states`
and consequently cannot write a personal connection. The callback dispatches by
state ownership; the personal flow remains unchanged. States are single-use,
10 minutes, bound to the initiating person and SHA-256 digest of the browser
session row UUID, connection ID/revision/generation, provider configuration,
scopes and exact resource. Consent locks the initiating user (`KEY SHARE`) before
session, connection and state, agreeing with administrative suspension's user-first
session deletion. Live suspension and session status are checked after waiting.
The callback checks live session, membership and configuration both before code
exchange and before committing tokens. Revoke/reconnect/configuration races must
never resurrect or overwrite newer consent. Logout and session revocation remove
both types of pending state transactionally.

Tokens use AAD `service_connection:<id>:access` and `:refresh`. Refresh is serialized
by the connection's PostgreSQL row lock across replicas. Rotated refresh tokens
are committed atomically. Transient failures preserve tokens; fatal failures erase
both ciphers, mark `needs_reconsent`, audit, and notify the live owning-team admins
and owners. A fresh browser authorization never retains an old refresh token when
the provider returns none: the admin may have selected a different upstream
account. Ordinary refresh rotation retains the same grant's refresh token when
no replacement is returned. The personal reconnect compatibility rule is unchanged.
No background refresh is introduced. Narrowing reuses the provider's
scope separator, refuses `invalid_scope` without full-token fallback and uses a
bounded owner-namespaced generation/scope cache, populated only after commit.
Live authorization precedes every cache hit and is repeated after waiting/refresh.

An ordinary service-account principal uses `ServiceCredential`; a person uses only
their own credentials. External-platform impersonation is [retired](platform-retirement.md).
Missing/not-allowed/reconsent/lapsed answers are `-32010` without URL, elicitation
or pending request. OAuth 401 retries once with the original connection and
consent generation pinned; a second rejection invalidates only that credential.
A 403 scope challenge refuses without automatically widening grants or consent.
Tokens are redacted from answers, progress, logs, spans and captures.

## Management contract

Browser-session-only endpoints list/start/update/revoke/reconnect team connections
and list paginated metadata for platform admins/auditors. No automation-token
scopes are assigned. Team mutations require genuine team owner/admin membership,
without platform bypass. Updates use `If-Match`, replace bounded account/grant
lists atomically, revalidate reachable/visible destinations and the origin/scopes
the admin saw, return 404 for foreign IDs and 409/412 for conflicts/staleness.
All mutations and grants are audited in the same transaction, without secrets.
Grant updates first reject ineligible destinations using metadata only, before
locking any destination; authoritative live authority, provider, origin and scope
checks run again after lock/write waits. Revocation commits local deletion and its
audit before attempting upstream revocation, with no database row locks held during
HTTP. Upstream revocation is best effort: failure never restores the connection or
changes a committed local success to forbidden. A separate bounded system audit
records only the remote outcome; if that audit fails, a safe connection-ID-only
error is logged. No credential is persisted for remote retries.
A team may have at most 200 connections; account and destination lists each have a
500-entry bound. `GET /v1/auth-providers?serviceTeam={team}` supplies the shared
picker with platform providers and reachable server-bound providers. Session
logout/deletion has an additive database trigger as well as the new query cleanup,
so previous-release session handlers also cancel pending service consent.

Team Service accounts has a Connections tab for account assignments, destination
grants, shared account label and connect/reconnect/revoke actions. Permission gates
explain, rather than replace, server authorization. Capability labels explain that
a team service connection is required instead of claiming all service accounts
can or cannot use the capability.

## Verification plan

Cover both provider kinds, browser/token/team authz matrix, assignment conflicts,
foreign IDs, callback session/configuration/resource/revision/revoke races, live
admin lapse/reactivation, destination access lists, origin/path edits, concurrent
refresh on two handlers, narrowed/reduced scopes, 401/403 and personal
no-fallback. Verify live notification recipients, encryption rotation, sentinel
redaction and accessible web workflows. Integration tests use only throwaway
databases on localhost:55442/postgres; never the development `omp` database.

## Implementation and verification map

- `internal/providers/service_*`: separate owner-specific consent/store adapters,
  strict assignments and grants, metadata views and row-locked runtime refresh.
- `internal/mcpgw/service_connections.go`, `delegated.go`, `upstreamoauth.go`:
  genuine-service branching, link-free refusals, pinned retries and shared-token
  response/progress redaction. Personal provider-header live-result behavior is
  deliberately unchanged.
- `internal/httpapi/service_connections*.go`: management contract, authorization
  matrix, first-consent and reconnect flows, callback commit races, live lapse,
  cross-team destination policy, refresh/narrowing across two handlers, 401/403,
  no personal fallback, metadata pagination, FK/uniqueness enforcement,
  atomic audit rollback and response/progress/span/capture sentinels.
- `internal/notify/service_connections*`: team-owned re-consent delivery to live
  active owners/admins, deduplication, shared wording and a link to the team's
  Connections tab. Personal delivery and webhook policy are unchanged.
- `internal/keyrotation/columns.go` and rotation tests: both token ciphers and the
  service state's PKCE verifier, all with owner-specific AAD.
- `web/src/pages/team/service-accounts/`: Connections on the team list and account
  record, shared labels, explicit account/destination checkboxes, optimistic
  updates, safe connect/reconnect redirects and confirmed revocation. Vitest/axe
  cover permission gates, metadata, exact grant payloads, revision headers,
  consent starts and navigation.

No real OAuth provider, physical browser workflow or deployment has been used to
verify this feature. The automated provider is the repository's guarded fake;
its optional scope-honouring mode is not evidence that every real provider
supports narrowing. No background refresh or personal-secret sharing is added.
