# Owner-set tool classification (#28)

## Boundary

A tool's server-supplied annotations are untrusted suggestions. Only the server team's owners and admins set
`read`, `write` or `destructive`; null means **unclassified**, not read. Platform staff may review the class but
cannot set it without a qualifying team role. Archived teams are read-only. Classification alone does not
restrict existing credentials: scopes (#29), approvals (#31) and retries (#33) will consume it. Those consumers
must fail closed for unclassified tools where a class is required.

## Storage and refresh

Migration `00027_tool_classification` adds nullable `tool_class`, `class_set_by` and `class_set_at` to
`mcp_capabilities`, with a tools-only constraint, and a nullable class snapshot on `mcp_calls`. Existing tools
remain unclassified. Applied migrations are not edited.

Refresh preserves owner classification even when the definition changes. Disappearance clears classification
and setter metadata, so a returning tool must be classified again. Definition JSON and fingerprints remain
exactly what the upstream supplied; classification is a separate layer.

Suggestions follow MCP defaults: `readOnlyHint: true` suggests read; otherwise only explicit
`destructiveHint: false` suggests write; everything else suggests destructive. Read-only wins if hints conflict.
Non-tools have no suggestion. `classDrift` means a classified tool's current suggestion differs from its class;
it is a review prompt, not a diagnosis that either value is correct.

## Editing and review

Two session-only operations use the server's `If-Match` revision:

- `PUT /v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/class`, body
  `{ "toolClass": "read", "viaSuggestion": true }` (null clears).
- `PUT /v1/teams/{team}/mcp-servers/{serverId}/capabilities/classes`, body
  `{ "items": [{ "capabilityId": "…", "toolClass": "read" }] }`.

Bulk changes are atomic, bounded to 500 unique tools, and bump the server revision together. A refresh that
adds, changes or removes capabilities also bumps that revision, so an old classification dialog cannot assign
a class to a changed or returning tool. An unchanged refresh does not invalidate the edit. A foreign, gone
or non-tool capability is not silently skipped. `viaSuggestion` records an explicit acceptance of the current
suggestion; it is not permission to classify automatically on refresh. Both operations audit
`mcp_capability.class_set` in the same transaction. Automation tokens cannot classify.

The review digest covers every listed tool's class and uses `omp-review-v4`; an open approval from an older
version needs one reload. Lowering destructive → write/read or write → read returns a published server to
review under `approval_required` (`classification_changed`). Assigning read/write to an unclassified tool is
also treated conservatively as lowering. Raising, clearing or assigning destructive does not resubmit.
Self-publishing teams keep publishing under their existing policy.

## Output and UI

Management views show the owner class, suggestion and drift separately from upstream hints. The team's
Capabilities tab provides individual and bulk classification, including explicit acceptance of suggestions.
Only team owners/admins see editing controls. Admin reviewers see classes read-only.

For a classified tool, gateway `tools/list` overlays only `readOnlyHint` and `destructiveHint` on a copy:
read = true/false, write = false/false, destructive = false/true. Other annotations and the stored definition
are unchanged. Unclassified tools keep their upstream hints; clients must not mistake those hints for an
owner assertion. Forwarded tool identity JWTs optionally carry `tool_class`; call records snapshot the class
at execution, so a later reclassification cannot rewrite history. Prompts, resources and unclassified calls
carry no class claim.

## Validation

Tests cover annotation defaults and conflicting/malformed hints, authorization and automation-token denial,
atomic updates and stale revisions, refresh/disappearance, review transitions and digest binding, gateway
annotations and class snapshots, and the classification UI including stale-edit errors and accessibility.
Real-client behavior and browser checks must be reported separately from automated test results.
