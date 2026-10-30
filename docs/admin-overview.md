# Admin overview and attention (design)

Status: **built in v0.2 (roadmap B)** (backend; the web screens follow). Decision 57. See "As built" at the end. The contract is in [`../api/openapi.yaml`](../api/openapi.yaml):
`GET /v1/admin/overview` (`adminGetOverview`) and `GET /v1/teams/{team}/attention` (`getTeamAttention`); schemas `AdminOverview`, `TeamAttention`, `AttentionItem`, `LinkTarget`.
No migration: everything is read from existing tables (and, for notification failures, the tables of [notifications.md](notifications.md)).

## Goal

`/admin` redirects to Users today, and a team's page doesn't say that its server has been down since Tuesday. The overview answers one question for each audience: **what needs me?**
It is a read-only view over data the portal already has; it never changes state and adds no new background work. The pilot's first week depends on people noticing.

## Shape

`AdminOverview`: `generatedAt`, `counts` (users, teams, servers, publishedServers, gateways, serviceAccounts, automationTokens), `last24h`
(`calls`, `errors`, `errorRate` 0-1 or null, `rateLimited`, `rolledUpTo`), `attention` (`AttentionItem[]`), `totals` (exact number per kind), `truncated`.
`TeamAttention`: `generatedAt`, `attention`, `totals`, `truncated`. An `AttentionItem` has `kind`, `severity` (`critical`, `warning`, `info`), a one-line English `summary` (for scripts; the UI builds its own wording),
`count`, `at`, `subject {id, name, slug}`, `team {id, slug, name}` and `link` (a `LinkTarget`, null only for personal keys). At most **20 items per kind**, ordered by severity, then `at` (oldest first), then name; `totals` stays exact and `truncated` says a kind was cut.
Computed per request, `Cache-Control: no-store`; each kind is one indexed query with `LIMIT 20` plus one count; the UI refetches on focus and every 60 s while visible.

## What counts, kind by kind

"Active team" means not archived; archived teams' servers are unavailable everywhere (registry.md), so nothing about them is listed. `at` is the time that matters for the kind.

| Kind | Platform overview | Team card | `at` | Severity | Link |
|---|---|---|---|---|---|
| `server_failing` | one per **published**, enabled server of an active team whose latest health check failed | one per enabled server of the team, any publish state | `status_since` (failing since) | warning; critical after 24 h | `server` |
| `upstream_signin_lapsed` | one per published, enabled `oauth`-mode server whose setup sign-in needs re-consent (Phase 7: refresh answers `409 setup_reconsent_required`) | same, any publish state | when it lapsed | warning | `server` |
| `review_pending` | one item: `count` = servers `pending` review in active teams | one item: the team's pending servers | the oldest `publish_requested_at` | info; warning when the oldest is over 3 days | `review_queue` / `servers` |
| `capabilities_changed` | one per published, enabled server with `pendingChanges > 0` (changed **or** new unapproved capabilities, held back from the catalog); `count` = how many | same for the team's published servers | none | warning | `server` |
| `personal_keys_expiring` | one item: personal API keys of active people expiring within **14 days** (unrevoked, unexpired) | none (personal) | the earliest expiry | info; warning when within 3 days | none: keys belong to individuals and staff can't open them |
| `service_account_keys_expiring` | one per team (at most 20 teams), `count` = its service account keys expiring within 14 days | one item, owners and admins only | the earliest expiry | as above | `service_accounts` + `teamSlug` |
| `automation_tokens_expiring` | one for platform tokens (team null) and one per team for publisher tokens, within 14 days | the team's, owners and admins only | the earliest expiry | as above | `automation_tokens` / `team_automation_tokens` |
| `connections_reconsent` | one item: people's connections with status `needs_reconsent` (active people; server setup sign-ins are `upstream_signin_lapsed`, not counted twice) | none: personal, and service accounts can't use them | none | info | `auth_providers` |
| `gateways_disabled` | one item: switched-off gateways (platform gateways, and team gateways of active teams) | none | none | info | `gateways` |
| `rate_limited` | one item when the last 24 h had calls refused by a rate limit (from the usage rollups) | none | none | info | `usage` |
| `server_certificate_expiring` | one per published, enabled server of an active team whose mTLS client certificate has expired or expires within **14 days** (decision 74) | one per enabled server of the team, any publish state | the certificate's expiry | info; warning within 3 days; critical once expired | `server` |
| `review_due` | one per **published** server of an active team whose `review_due_at` has passed (decision 88) | same for the team's published servers | the due date | warning | `server` |
| `server_unlabelled` | one per **published** server of an active team whose sensitivity label nobody has confirmed (`internal` is only the default until a team owner or admin sends a label; a confirmed `internal` is not listed). Informational: nothing is blocked or unpublished | same for the team | none | info | `server` |
| `server_ownerless` | one per **published** server of an active team with no accountable owner: none named, or the owner left the team, lost the editor role, was suspended or deleted | same for the team | none | warning | `server` |
| `server_transfer_pending` | none | one item, `count` = servers other teams offered this team that wait for its owners to accept; **owners only** | the oldest request | info | `servers` |
| `notification_failures` | one item: failing webhook destinations (stopped automatically, or 3+ failures in a row; platform and team) plus 1 if email had a failed delivery in the last 24 h | one item: the team's failing destinations; owners and admins only | the latest failure | warning | `notification_settings` / `team_notification_settings` |

`last24h` sums the hourly rollups (`usage_hourly`) of the 24 buckets ending with the current hour, so it lags the call log by the rollup's few minutes (`rolledUpTo`).
`errors` is every outcome but `ok`, **the same definition as Admin › Usage** (`denied`, `rate_limited` and `needs_authorization` included), so the two pages agree; `errorRate` is null without calls. No thresholds invent alerts on it: it is shown, not judged.
`counts.users` is active people; `teams` active teams; `gateways` platform gateways plus those of active teams; `automationTokens` active tokens of both kinds.

## Roles and errors

| Operation | Who | Errors |
|---|---|---|
| `adminGetOverview` | platform admins and auditors (a `platform:read` token too: it is an admin `GET`, see [automation-tokens.md](automation-tokens.md)) | `403 forbidden` for everyone else |
| `getTeamAttention` | team members and above, and platform admins and auditors for any team | `404 team_not_found` for people outside the team |

Visibility follows what each role can already open: every member sees the team's server items, review state and capability changes (members read servers); **only owners, admins and platform staff** see key and token expiries and notification failures
(they can list those). An archived team answers `200` with no items. A suspended person is refused by authentication as everywhere. Nothing in a response is secret: counts, names, times, error classes.

## Link targets

The UI routes on `type` (+ `id`, `teamSlug`); the same `LinkTarget` is used by inbox notifications, so one function resolves both. A Vitest test fails when a type has no route.

| `type` | `id` | `teamSlug` | Route |
|---|---|---|---|
| `server` | server ID | the server's team | `/teams/$team/servers/$id` for members; `/admin/servers/$id` for platform staff who aren't members |
| `servers` | none | yes | `/teams/$team/servers?publishState=pending` |
| `review_queue` | none | none | `/admin/publishing` |
| `gateways` | none | none | `/admin/gateways` |
| `service_account` / `service_accounts` | account ID / none | yes | `/teams/$team/service-accounts[/$id]` |
| `automation_tokens` | none | none | `/admin/automation-tokens` |
| `team_automation_tokens` | none | yes | `/teams/$team/settings?tab=automation-tokens` |
| `auth_providers` | none | none | `/admin/auth-providers` |
| `usage` | none | none | `/admin/usage` |
| `notification_settings` | none | none | `/admin/notifications` |
| `team_notification_settings` | none | yes | `/teams/$team/settings?tab=notifications` |
| `account_connections` | none | none | `/settings/connections` |
| `account_api_keys` | none | none | `/settings/api-keys` |

## UI

- **Admin › Overview** (`/admin`, first item of the admin sidebar; replaces the redirect to Users): stat cards (people, teams, servers, published, gateways), the last-24 h strip (calls, error rate, rate-limited calls, "as of" time from `rolledUpTo`), then **Needs attention**: items grouped by severity, each with its wording, team, "since 3 d" and a button that follows `link`; an empty state "Nothing needs attention"; per-kind totals when truncated ("and 12 more servers: see Admin › Servers").
- **Team overview, Attention card** (`/teams/$team`, above the existing content): the team's items with the same rows; hidden when empty for members, "All clear" for owners and admins; archived teams show the existing archived notice only.
- Auditors see the same pages (buttons lead to read-only screens). Both fetches show an inline error with Retry; the rest of the page keeps working.

## Tests that must exist

- **Matrix:** `adminGetOverview` own=platform (token scope `platform:read`); `getTeamAttention` team own=members, foreign=platform.
- Per kind, seeded data: failing since the right time, recovered servers disappear, private/pending servers excluded from the platform view and included in the team's, disabled servers and archived teams excluded, 20-item cut with exact `totals` and `truncated`, pending age and `at` = oldest request, changed vs new capabilities counted once, keys at 13/14/15 days and expired or revoked ones, setup sign-in vs person connection not double counted, gateways disabled (platform and team), severity thresholds (24 h, 3 days).
- `last24h` equals a direct aggregate of `usage_hourly` and `Admin › Usage`'s totals for the same range; zero calls gives `errorRate` null; `rolledUpTo` null before the first rollup.
- Roles: members don't get key, token or notification items; owners and admins do; auditors get the platform view; `404` for outsiders; archived team empty.
- A sentinel test that no header value, token prefix or URL appears in either response; each `link` resolves through the UI's route table (Vitest) and to an object the caller may open.
- Vitest: both screens (grouping, empty and all-clear states, truncation line, error with Retry).

## Access-request attention (v0.6.0, #32)

Human platform overview requests may include `access_requests_pending`: one aggregate with the exact count
of pending gateway access requests the current human can decide, excluding their own. It links to the
session-only `/access-requests` review queues. Named stewards without platform roles get their count in the
review-queue response, not general admin access. Automation tokens receive no private access-request count.
The count respects active requester/reviewer status, gateway opt-in/enabled state and current team-request
authority; reasons/notes never appear here. See [access requests](access-requests.md).

## As built

`internal/overview` (`Service.Admin`, `Service.Team`) and `internal/httpapi/v02.go`; queries in `internal/store/queries/overview.sql`. No migration.

- Every kind is one query with `LIMIT 20` and a window count for the exact total (`totals`); `truncated` is true when any kind was cut. Kinds counting groups (`service_account_keys_expiring`, `automation_tokens_expiring`) cut at 20 teams.
  Order: severity, then `at` (oldest first, items without `at` last), then name.
- `review_pending` is one item for the platform (`count`, oldest `at`: warning past 3 days) and one for the team card (link `servers`).
  A failing server is critical past 24 h. Expiry items are a warning within 3 days. `personal_keys_expiring` has no link.
- Aggregates over no rows return the epoch internally; `at` is null then. `upstream_signin_lapsed` takes `at` from the latest `provider_connection.refresh_failed` audit entry of the setup connection (null when none was recorded).
- `last24h` sums `usage_hourly` for the 24 hourly buckets ending with the current hour; `errors` is every outcome but `ok`. `rolledUpTo` is the rollup watermark.
- Authz: platform staff for the overview (a `platform:read` token too, which acts as an auditor); the team card for members and platform staff; key, token and notification-failure items only for owners, admins and platform staff. An archived team answers `200` with no items.
- Tests: `internal/overview/overview_integration_test.go` (every kind on seeded data, thresholds, the 20-item cut with exact totals, roles, archived teams, `last24h` against a direct aggregate) and `TestOverviewAPI`.
