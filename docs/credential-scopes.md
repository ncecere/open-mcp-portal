# Credential tool scopes (#29, decision 77)

Status: backend implementation, generated contract and Go regression tests. Product UI work is separate.
Do not rely on enforcement while an older binary remains in the serving pool (see rollout below).

A nullable `tool_scope` on personal keys, service accounts, their keys, OAuth grants and platform gateway grants is a ceiling, never a grant of access. Null is unrestricted at that layer, including unclassified tools. `{}` denies every tool. Prompts and resources are unchanged.

A scope matches a trusted owner-set class (`read`, `write`, `destructive`) **or** an exact exposed tool name. Unclassified tools match only names, except under null. Matching team, user and group gateway grants are alternatives (OR); every independent credential, account and gateway layer must match (AND). Relayed person calls retain both the person's gateway-grant union and the relay's gateway-grant union, account ceiling and key ceiling. No absent personal credential or external platform claim supplies a scope. Mixed class/name intersections remain predicates, not intersected arrays.

Inputs are validated, deduplicated and canonicalized; at most 3 class entries and 500 exact exposed names
(each 1–1100 UTF-8 bytes) are accepted. Names are exact and case-sensitive, including Unicode, and do not
need the current server/tool `__` separator (future exposed-name aliases are valid). Control characters,
glob operators (`*`, `?`, `[`, `]`, `{`, `}`, backslash) are refused with `400 invalid_tool_scope`.
Unknown properties are rejected by strict JSON decoding or the scope validator. Names may refer to
tools not yet registered; they are never normalized. Invalid stored JSON fails closed. Keys may have null ceilings under restricted accounts: runtime intersection inherits the account's live limit. Account edits apply on the next request; PATCH omission keeps, null clears, and objects replace the ceiling. Scope checks precede provider/person-secret lookup and consent creation; refused calls retain normal unknown-tool responses and `denied` / `tool_scope` metadata.

OAuth accepts `omp:read`, `omp:write`, `omp:destructive` after safe redirect validation. Missing authorization scope is null (not the explicit three-class set). Consent can narrow, never widen, the requested class ceiling. Omission defaults to the requested ceiling; `{}` denies all. Remembered or trusted clients must reconfirm expansions, including after human narrowing. Scope is immutable within a grant: changing it atomically revokes the old grant, its tokens and pending codes and creates a replacement. Concurrent authorization is serialized. Refresh accepts omitted or equal scope only. Restricted token responses carry canonical scope strings (empty string for deny-all); unrestricted responses omit scope. DCR metadata's scope is not an authorization request.

## Management API shapes

No routes or automation-token permissions change. Optional nullable `toolScope: ToolScope` is added to
`ApiKey`, `ApiKeyCreate`, `ServiceAccount`, `ServiceAccountCreate`, `ServiceAccountUpdate`,
`ServiceAccountKey`, `ServiceAccountKeyCreate`, `GatewayGrant`, `GatewayGrantCreate`, `OAuthGrant`
and `OAuthConsentDecision`. `OAuthConsent` gains optional nullable `requestedToolScope: ToolScope`.

`ToolScope` has optional `classes: ("read" | "write" | "destructive")[]` and `tools: string[]`.
On create, absent/null is unrestricted; on account PATCH absent retains and null clears. All returned
scope objects are canonicalized. OAuth consent allows only classes: tools must be absent/empty.
`400 oauth_invalid_scope` refuses widening or named tools on consent. A token response has optional
`scope: string`; an unrestricted response omits it, deny-all sends `""`. Protocol scope strings use
read, write, destructive order. Protected-resource and authorization-server metadata advertise all three.
The requested ceiling remains bound to the authorization query and is checked again on consent POST.

SQL adds nullable JSONB columns to the five tables, includes them in insert/update and embedded
read models, and adds `GatewayGrantsForUser` / `GatewayGrantsForTeam` for matching scoped rows.
Legacy grant-kind/existence queries are retained for compatibility with the initial contract checkpoint;
the enforcing runtime reads matching scoped rows. `McpCall.errorClass` documents `tool_scope`; no new enum or route is added.

## Upgrade and rollback

Migration `00029` adds nullable columns and widens the OAuth revocation-reason check to accept
`scope_changed`; existing rows and existing credentials retain their behavior. The previous binary can use the expanded schema **but ignores these ceilings**. Drain all old replicas before relying on scopes. Rolling back enforcement requires draining traffic or revoking scoped credentials/grants first; otherwise a rollback widens access. Do not deploy mixed enforcement versions once restricted scopes are in use.
