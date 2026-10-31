# The omp command line

`omp` is the portal's command line for people and pipelines: print the snippet that connects an MCP client, register,
test, refresh and publish a team's servers from CI, and keep configuration in a file (`omp export`, `omp import --plan`).
It is built on [`pkg/ompclient`](../pkg/ompclient), a Go client generated from [`api/openapi.yaml`](../api/openapi.yaml),
and it authenticates with [automation tokens](automation-tokens.md) only (decision 89).

Status: **new in the first release after v0.9.0** (issue #46). `pkg/ompclient` is versioned `v0`: it follows the API
contract, which may still change before 1.0.

## Install

Download `omp-<tag>-<os>-<arch>` (`.exe` on Windows) from the GitHub Release, for linux, darwin or windows on amd64 or
arm64. Each file has a cosign bundle (`.sigstore.json`, keyless, signed by the same workflow as the image) and is listed in
`checksums.txt`:

```sh
cosign verify-blob omp-v1.2.3-linux-amd64 \
  --bundle omp-v1.2.3-linux-amd64.sigstore.json \
  --certificate-identity https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/v1.2.3 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
chmod +x omp-v1.2.3-linux-amd64 && mv omp-v1.2.3-linux-amd64 /usr/local/bin/omp
```

From a checkout: `make build-omp` (writes `bin/omp`), or as a container: `make docker-omp`
(`docker build --target omp .`; distroless, non-root, entrypoint `/omp`):

```sh
docker run --rm -e OMP_URL -e OMP_TOKEN omp-cli servers list --json
```

## Configuration

| Setting | Where | Notes |
|---|---|---|
| Portal URL | `--portal URL`, else `OMP_URL`, else `url:` in the config file | `https://` only; plain `http://` is accepted for `localhost` and loopback addresses (development) |
| Token | `OMP_TOKEN`, else `token:` in the config file | There is no `--token` flag: a flag shows up in shell history and `ps`. It must look like `ompadm_…` or `omppub_…`; anything else (a personal key, an OAuth token) is refused before any request |

The config file is `~/.config/omp/config.yaml` (`$XDG_CONFIG_HOME/omp/config.yaml` when set; `OMP_CONFIG` names another
file). `omp configure` writes it with mode `0600` in a directory of mode `0700`:

```sh
omp configure --portal https://portal.example.com --token-stdin < token.txt
omp configure --portal https://portal.example.com --token-env OMP_TOKEN
```

**A config file that group or others can read is refused** (like ssh does for a private key): the error says
`chmod 600`. The file is read only when the URL or token is not already given by a flag or variable. On Windows the mode
bits do not describe access, so the check is skipped there.

`OMP_URL` and `OMP_TOKEN` share the `OMP_` prefix with the server's own settings (`OMP_*` in `.env`); in a shell that
also runs the portal, set them only for the `omp` process. Decision 89 keeps these two names.

Safety rules that have no switch: **TLS certificates are always verified** (there is no `--insecure`; add a private CA to
the system's trust store, or `SSL_CERT_FILE`); redirects are never followed (a redirect cannot carry the token to
another host); the token is sent only to the configured URL; and **no command prints a token or any secret it read**:
every line of output passes a filter that replaces them with `[redacted]`, and a test runs every command against a portal
that repeats the `Authorization` header in its errors.

## Output and exit codes

Without `--json`, output is text for people. With `--json`, success is one JSON document on stdout. **Errors always go to
stderr**: text (`omp: error: <code>: <message>`), or with `--json` an object
`{"error": {"code", "message", "exitCode", "status", "details"}}`. `code` is the API's `error.code`
(`token_not_allowed`, `slug_taken`, `changed_since_review`, …) or the CLI's own (`usage`, `config`, `network`,
`unexpected_redirect`, `test_failed`, `changes_found`, …). A 403 names the missing scope (`details.requiredScopes`).

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected internal error |
| 2 | Usage: bad flags or arguments, a declarative file that is not valid `omp/v1`, a token that cannot do what the file says, or a change `omp` refuses (`refused`: curation or a grant deadline it cannot keep) |
| 3 | Configuration: no URL or token, an `http://` URL that is not loopback, an unsafe config file, a token of the wrong shape |
| 4 | Authentication: `401` (`invalid_token`: unknown, expired or revoked) |
| 5 | Forbidden: `403` (`token_not_allowed`, `session_required`) |
| 6 | Not found: `404` |
| 7 | Conflict: `409`, `412`, `428` (`slug_taken`, `already_published`, `revision_conflict`, …) |
| 8 | Rejected: `400`, `422` and other `4xx` (`url_not_allowed`, `auth_value_required`, …) |
| 9 | Unavailable: `5xx`, `429`, or the portal could not be reached (including a certificate that is not trusted) |
| 10 | Changes found: `omp import --plan` found drift; `servers refresh --fail-on-changes` saw changed capabilities |
| 11 | A check failed: `servers test` answered `ok: false`; discovery failed (`servers register`, `servers refresh`) |

These numbers are part of the interface and do not change within a release line.

Global flags (before or after the command): `--json`, `--portal URL`, `--timeout 60s`.

## Commands

### `omp whoami`

Shows the token in use (`getToken`): kind, name, scopes, team, expiry, status. Use it first when something answers `401`
or `403`.

### `omp connect <gateway> --client claude|vscode|cursor|curl`

Prints the snippet that connects a client to a gateway, without any request: `<gateway>` is a slug (the endpoint is
`<portal URL>/mcp/<slug>`) or the full `https://…/mcp/<slug>` URL. `--auth oauth` (default) prints the browser sign-in
variant (just the URL); `--auth key` prints the API-key variant with the placeholder `<YOUR_API_KEY>` (curl always uses a
key). `--name` sets the name the client shows. It never writes a key into a snippet, and an automation token does not
work on `/mcp`.

The templates are a port of the web UI's (`web/src/components/gateways/connect-snippets.ts`). Both are tested against
[`api/connect-snippet-vectors.json`](../api/connect-snippet-vectors.json) (`internal/ompcli/snippets_test.go`,
`web/src/test/gateway-helpers.test.ts`): the output is byte for byte what the UI shows, and a change to one side without
the other fails a test. To change a snippet, change both implementations and regenerate the vectors.

### `omp servers list|get|register|test|refresh|publish|unpublish`

A **team publisher token** (`omppub_`, scopes `servers:read` and `servers:write`) manages its own team's servers. The
team defaults to the token's team (`--team` to name it). `<server>` is the slug (the natural key) or the ID. Only
operations with `x-omp-token-scopes` are used: `listTeamMcpServers`, `getTeamMcpServer`, `createTeamMcpServer`,
`testTeamMcpServer`, `refreshTeamMcpServer`, `publishTeamMcpServer`, `unpublishTeamMcpServer`. A platform token never
reaches team routes (`403 token_not_allowed`).

```sh
export OMP_URL=https://portal.example.com OMP_TOKEN=omppub_…
omp servers register --slug status --name "Service status" --url https://status.example.com/mcp
omp servers refresh status --fail-on-changes     # exit 10 if tool definitions changed
omp servers publish status --note "deployed by CI"
```

- `register` reads the capabilities at once. If discovery fails the server **is** created, and the command exits 11 with
  `discovery_failed`. A static header credential is `--auth static_header --auth-header X-API-Key --auth-value-env VAR`;
  the value is read from the environment variable `VAR`, never from a flag. Other auth modes (`oauth`, `machine_oauth`,
  `person_secret`, TLS settings) need a browser session.
- `test` connects and lists capabilities without saving them; exit 11 when `ok` is false.
- `refresh` reads the capabilities again. A changed definition on a published server stays out of the catalog until
  someone approves it, so `--fail-on-changes` makes a deploy that changed a tool fail loudly (exit 10) instead of looking
  green. Approving is never possible with a token.
- `publish` requests publication (published at once under `self_publish`, pending review under `approval_required`;
  `--expected-digest` guards against a server that changed since you looked). `unpublish` withdraws it.

Deleting servers is not possible with a token (`servers:delete` is proposed in #47).

## Declarative files: `omp export` and `omp import`

`omp export` writes the portal's configuration as an `omp/v1` document; `omp import -f FILE` applies one;
`omp import --plan` prints what would change and **exits 10 when anything would** (0 when the portal already matches). The
format is YAML (JSON is valid YAML) with a published JSON Schema, [`api/omp-v1.schema.json`](../api/omp-v1.schema.json),
used by the [GitHub Action integration](../integrations/github-action/README.md) and the Terraform provider planned in #47.

```yaml
schema: omp/v1
servers:                          # needs a team publisher token for that team
  - team: bravo
    slug: status                  # the natural key: unique on the portal, immutable
    name: Service status
    url: https://status.example.com/mcp
    enabled: true
    authMode: static_header       # none or static_header
    authHeaderName: X-API-Key
    authValueEnv: STATUS_API_KEY  # the NAME of an environment variable; never the secret
    publish: request              # none = private; request = published or pending review
teams:                            # platform objects need a platform-admin token (platform:write to apply)
  - slug: bravo
    name: Bravo
    ownerEmail: boss@example.com  # only to create the team; not compared, not exported
    limits: { gateway_per_minute: 600 }
gateways:                         # platform gateways
  - slug: support
    name: Support tools
    capabilities:                 # the whole selection; absent means "leave alone"
      - server: status
        kind: tool
        name: check
        curation:                 # a tool's policy, as the portal has it (see "Curation"); absent leaves it alone
          nameOverride: check_team
          constraints: { region: { fixed: us } }
    grants:                       # the whole list of grants; absent means "leave alone"
      - { team: bravo }           # a new grant is unrestricted and permanent; an existing one keeps its ceiling and deadline
      - { userEmail: ann@example.com, toolScope: { classes: [read] }, expiresAt: "2026-12-31T00:00:00Z" }
limits:                           # platform rate limits
  person_per_minute: { default: 600, ceiling: null }
```

**What is in v1**: servers (with a publisher token), and teams, team limit overrides, platform gateways (settings,
capability selection, grants) and platform rate limits (with a platform token). **Not in v1**, because tokens cannot reach
them: team gateways, members, invitations, service accounts, auth providers, approvals, and every setting that widens
trust (decision 58, [automation-tokens.md](automation-tokens.md)). A server's `oauth`, `machine_oauth`, `person_secret`,
credential lists, TLS settings, failover endpoints, quotas and capture switch are browser-session settings: export skips a
server that uses them (with a warning on stderr), and import refuses to touch one.

**Semantics**

- *Natural keys*: server, team and gateway `slug`. Import creates what is missing and updates what differs. **It never
  deletes** (a token cannot). An object the file does not mention is left alone.
- *Optional fields mean "leave it alone"*. Lists (`capabilities`, `grants`) are authoritative only when present; `[]` means
  none. This includes what an object already has: a listed capability's `curation`, a listed grant's `toolScope` and
  `expiresAt` are kept when the file does not say them. See [Curation](#curation) and [Grant expiry](#grant-expiry).
- *Refusals*. A declaration omp cannot make true without losing or widening authority is refused **while planning, before
  the first write**: exit 2, error code `refused`, and the message ends "Nothing was changed." `--plan` refuses too, so a
  pull-request check fails rather than reporting a change that cannot be applied.
- *Two token kinds, two parts of a file*. A file with servers needs a publisher token; one with teams, gateways or limits
  needs a platform token. A file that has both fails with exit 2 and a hint: split it, or select a part with
  `--only servers|platform`. Applying platform objects checks for `platform:write` before the first change; planning
  needs only the read scope.
- *Secrets are never exported*, never printed, and never compared. `omp export` writes `authValueEnv` as a suggested
  variable name (`OMP_<SLUG>_AUTH_VALUE`). `import` reads the value from that variable when it **creates** the server, when
  it switches the server to `static_header` or changes its header name, or with `--replace-secrets` (rotation). The
  portal never returns a stored value, so a changed variable is **not drift**; the plan shows `authValue … (read from
  $NAME)` where it would send one. A missing variable fails the import before the first change (exit 2); a plan only
  warns.
- *Plans are exact about what they read*: the revision (`If-Match`) of each object as read; a concurrent change is a `412`
  with the hint to run again. Side effects the portal applies (a URL change sending a published server back to review
  under `approval_required`) are reported by `apply`, not predicted by `plan`.
- `--refresh` (apply only) refreshes every declared server afterwards, changed or not; with `--fail-on-changes` it exits
  10 when a refresh found changed capabilities. This is the deploy-time use: apply the file, refresh, fail if tool
  definitions moved.
- `publish: request` publishes a private server (or requests it under `approval_required`); `publish: none` withdraws it.
  Absent leaves publication alone.

### Governance and sensitivity ceilings

Export carries `servers[].governance` and `gateways[].maxSensitivity` when the portal exposes them. These are **comparison-only declarations**: automation tokens cannot write governance or ceilings. The optional `sensitivityConfirmed` assertion compares the read-only marker; it never confirms a label, and a declared marker that an older portal does not expose is refused. Missing fields preserve existing policy; a declared mismatch or unreadable policy refuses the **entire plan before any mutation**, in both plan and apply mode. These comparisons are configuration checks, not authentication or a whole-import transaction; the concurrency limits below still apply.

- A server governance declaration contains `sensitivity`, the effective `lifecycle`, and `sunsetAt` (an exact RFC 3339 instant, or `""` to declare no cutoff). Optional `ownerUserId` and `oncallContact` compare the stored metadata; `""` explicitly declares none. `replacementServerId` is exported only for a visible replacement. An omitted replacement may be hidden and never asserts that none is configured. UUIDs are portal-local references, not portable identity mappings or authorization.
- **Any new server with a governance declaration is refused.** Prepare its governance through the browser first, then import against that existing object. CLI-created servers without a declaration receive the portal's defaults; omission never confirms a sensitivity label. Existing servers keep all undeclared governance, including hidden replacement data. Historical review timestamps are not exported as configurable policy. An effective lifecycle can change when a cutoff passes: re-export rather than treating the old snapshot as current authority.
- A declared gateway ceiling must match the current ceiling. A new gateway can match only the documented `restricted` default (no ceiling); a more restrictive declaration requires browser preparation. CLI requests never send the session-only `maxSensitivity` field.
- `null` is not an omission or a request to clear these declarations, including through YAML aliases/merges. Invalid or unreadable labels fail closed; policy values are not printed in refusal messages.

Exports may include private contacts and sensitive fixed curation values, even though authentication secrets are not exported. `-o FILE` atomically writes owner-only mode `0600` where supported, including when replacing a previously broader-permission file. It requires a writable parent directory (creating missing parents with mode `0700`) and rejects symlinks, directories and special files; it does not follow a symlink or write through `/dev/stdout`. Omit `-o`, or use `-o -`, for stdout. Atomic replacement guarantees visibility, not durability through a machine crash. Protect stdout redirects yourself and review exports before sharing them.

### Curation

A gateway's selected tools can be *curated* in the web UI ([gateway-curation.md](gateway-curation.md)): a renamed exposed
name, a rewritten description, and per-argument constraints (a `fixed` value, or an `allowed` list) that the portal
enforces on every call. `omp` treats that policy as authority it must never lose or widen:

- **Export writes it.** A selected tool's `curation` is exported as the portal stores it, under the tool's own
  `server`/`name` (not its exposed name). A policy the portal reports but does not return, or returns in a form this version
  cannot read, **fails the export** (`curation_unreadable`) instead of writing a file that would widen the gateway when
  imported. A policy that went stale (the tool's definition changed after it was saved, so the tool is not served until an
  owner saves it again) is exported as stored, with a warning.
- **Changing the selection keeps it.** Adding or removing *other* capabilities rewrites the gateway's selection, and the
  portal keeps the policy of every selection that stays when the request names no `curation` (docs/gateway-curation.md:
  "Omission preserves policy"). `omp` never sends `curation` or `expectedFingerprint`, and after the write it checks that
  every kept selection reports the same policy as before (`curation_changed` otherwise). Removing a curated selection
  deletes its policy, as the portal does for any removal; the plan and a warning say so, and selecting the tool again later
  is uncurated until someone curates it in the web UI.
- **The file can declare it, and `omp` can only compare.** Writing curation needs a browser session: an automation token
  gets `403 session_required`, including for `curation: null`. So a declared `curation` is compared with the portal's
  (normalized as the portal stores it: allowed lists are narrowed to the tool's schema, numbers keep their exact value) and
  is *no change* when equal. A declaration that **differs** from the portal's, a `curation` on a tool that is not selected
  yet, or a policy that is invalid for the tool's current definition is refused. Edit the policy in the web UI, or remove the
  key from the file to leave it alone.
- **Absent, `null` and `{}` are three different statements.** Absent: leave it alone. `null`: the tool has no policy (the
  portal's "clear"). `{}`: an empty policy, which the portal stores as a policy; it is not the same as none.
- *Validation is the portal's own.* The file's policy is checked offline by the same code that checks it on the server
  (shape, 64 KiB, 50 constraints, `fixed` null is a value, exactly one of `fixed`/`allowed`, numbers that round-trip through
  binary64, safe integers). YAML spellings with no JSON form (a timestamp, `0x10`, `1_000`, `.5`, aliases) are refused; quote
  a value to make it a string. Only tools can be curated.
- *Values are never printed by a refusal or a plan* (only argument names, counts and a short digest), because a fixed value
  can be a secret. **An export contains them**: it is a configuration file, not a vault. Review it before committing it.

### Grant expiry

A platform gateway grant can expire ([access-requests.md](access-requests.md)). The portal sets a deadline when the grant is
created (`expiresInDays`, 1 to 365 whole 24-hour days) and **has no operation to change a grant**: only add and remove.
An elapsed deadline never contributes access, whether or not the row is still listed (the portal removes such rows later, and
replaces one when the same subject is granted again; `omp` does not claim to clean them up). Given that:

- `expiresAt` (RFC 3339) is exported for every grant that has one, expired ones included (with a warning), and an unrestricted
  grant is exported as `toolScope: null`, so the file states what the portal has.
- *Absent `expiresAt`*: a new grant is permanent; an existing grant **keeps its deadline**. Likewise an absent `toolScope`
  keeps an existing ceiling (and is unrestricted for a new grant); `toolScope: null` declares it unrestricted. `expiresAt: null`
  is refused when the file is read.
- *Absolute deadlines are comparison-only in v1.* An unchanged exported `expiresAt` must match the portal's timestamp
  exactly. Creating, shortening, extending or renewing an expiring grant, or changing its scope, is refused before any
  import write. The API accepts only a relative day count against the portal's clock, not an absolute deadline; guessing a
  clock-skew allowance cannot guarantee the existing deadline. Use the web UI for temporary-grant changes. This limitation
  preserves the existing row, scope and deadline byte-for-byte instead of silently making it permanent or approximating it.
- *An expired grant is never recreated permanently.* A file that lists it with no `expiresAt`, a different deadline or a
  changed ceiling is refused. A file that records it as exported is no drift. Renewal needs a browser operation; leaving it
  out of the authoritative `grants` list removes its row.
- *Permanent grant scope changes are not atomic.* The API has no update or grant revision: the CLI removes the existing
  permanent grant and creates its replacement. If creation fails, **no automatic rollback or replay restores the old grant**:
  another actor may have revoked it. The error identifies the partial operation and asks the operator to inspect current
  grants before retrying. A request may also have succeeded when its response was lost.
- *Partial writes.* All predictable refusals are checked while planning, before any write. Within a gateway step the CLI
  writes the selection (at the planned revision), new permanent grants, permanent-grant replacements, then removals.
  Earlier successful steps remain applied on a later runtime failure (the error says how many). There is no transaction
  across HTTP requests and no automatic restoration of removed authority.

### Concurrent edits

A gateway's settings and selection are read at one revision; if the gateway changes while the plan is read, the import stops
with `revision_conflict` before any write. Every write is conditional (`If-Match`) on that revision, advanced only by this
import's own successful writes: **a selection that was planned from an older state is never applied over somebody else's
change**, it fails with `412 revision_conflict` and "run the command again". Grants have no revision: a creation for a
subject that was granted meanwhile is `409 grant_exists`, and a removal of a grant that was replaced meanwhile is `404`.

```sh
omp export --only servers -o omp.yaml          # a publisher token: its team's servers
omp import -f omp.yaml --plan                  # exit 10 when the portal differs from the file; never prints a secret
STATUS_API_KEY=… omp import -f omp.yaml --refresh --fail-on-changes
```

## Why there is no `omp keys` and no sign-in

Decision 89: **v1 ships no `omp keys` and no sign-in flow.** `/v1` accepts browser sessions and automation tokens only
(`RequireSession` refuses `Authorization`, BR-3), and decision 55 closed the token kinds at two. Personal API keys are
MCP credentials (`omp_…`): they never authorize `/v1`, so a CLI that created them would still need a human session to
do it. Options were (a) a CLI for CI only, people use the browser for keys, or (b) a third, short-lived *personal* token
kind minted by a device-authorization flow (RFC 8628). (b) widens what a stolen laptop can do and needs its own
decision and threat-model entry, so v1 takes (a): no new server endpoints, no token-scope widening.

A later sign-in flow would need, at least: a decision and a threat-model entry for the new token kind; its prefix, expiry
(minutes), scopes (bound to the person's own roles, never more) and revocation; the device-authorization endpoints with
their rate limits and consent page; a standing rule (valid only while the person is active); audit as the person and
the CLI; GitHub secret-scanning registration for the prefix; matrix tests like `TestTokenMatrix` for the new kind; and
`omp keys` (list, create, revoke) on top, with the operations annotated for it.

## Development

`make generate` regenerates `pkg/ompclient` (an overlay in `pkg/ompclient/overlay.yaml` keeps only the operations that
carry `x-omp-token-scopes`; a test pins the client to the same table the server enforces), and `make check-generated`
fails when it is stale. The CLI's code is `internal/ompcli`; `cmd/omp` only starts it. Unit tests run against an in-memory
portal built from the generated types (`fake_portal_test.go`); `internal/httpapi/omp_cli_integration_test.go` runs the CLI
against the real handler and PostgreSQL (`OMP_TEST_REQUIRE_DB=1`, in both `OMP_TEST_SPLIT_ROLES` modes). Golden files are
in `internal/ompcli/testdata` (`go test ./internal/ompcli -update` rewrites them).
