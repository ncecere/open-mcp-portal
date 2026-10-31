# Open MCP Portal server Action

Linux (amd64/arm64) composite Action over the real token-only `omp` CLI.
This directory is distributable as an Action; it has not been published as a separate
repository. Pin the containing repository to a reviewed commit. Requires Python 3.9+,
Bash, network access to GitHub releases and Sigstore, and HTTPS access to the portal.
No Node dependencies, container image, login or GitHub OIDC authority are needed.

## Example

After checking out the repository containing this Action:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@<reviewed-commit>
  - uses: ./integrations/github-action
    id: portal
    with:
      url: https://portal.example.com
      token: ${{ secrets.OMP_PUBLISHER_TOKEN }}
      team: bravo
      slug: status
      config-file: deploy/status.json
      refresh: 'true'
      publish: request
      fail-on-changes: 'true'
    env:
      OMP_SECRET_STATUS_KEY: ${{ secrets.STATUS_API_KEY }}
```

`deploy/status.json`:

```json
{
  "schema": "omp/v1",
  "servers": [{
    "team": "bravo",
    "slug": "status",
    "name": "Service status",
    "url": "https://status.example.com/mcp",
    "authMode": "static_header",
    "authHeaderName": "X-API-Key",
    "authValueEnv": "OMP_SECRET_STATUS_KEY"
  }]
}
```

Use an **already issued, unexpired team publisher token** with `servers:read`
and `servers:write`, for this exact team. Platform tokens are not accepted.
Secrets belong only in environment variables or the private token input, never in
committed JSON, command-line values, artifacts or outputs. `authValueEnv` is limited
to `OMP_SECRET_*` to prevent a declaration from forwarding the portal/GitHub token.
Do not run a secret-bearing deployment on untrusted pull request code/configuration.
Mask upstream secrets in the caller as usual; this wrapper never emits CLI bodies.

## Contract and safety

Required inputs: `url`, `token`, `team`, `slug`, `config-file`.
Optional inputs: `refresh` (default true), `publish` (`none|request`, default none),
`fail-on-changes` (default true). Booleans are literal true/false.

The configuration is the **JSON subset** of `omp/v1` YAML: exactly one server,
matching team/slug, with no platform sections or `publish` key. JSON duplicates,
unsafe paths, YAML tags/aliases and oversize files are refused. Required
name/url are the CLI's required desired state; optional fields retain the CLI's
omission semantics. Governance declarations are comparison-only: a new server
with governance, a mismatch or unreadable governance refuses before mutations.
Unsupported fields also refuse through the CLI parser before mutation. There is
no curation, gateway, grant, expiry or ceiling writer in this Action.

1. Install **v0.10.1**, never latest/main. Check the exact binary SHA-256 entry in
   `checksums.txt`, then verify its `.sigstore.json` bundle using cosign v3.0.2,
   pinned installer commit, exact `image.yml@refs/tags/v0.10.1` certificate identity
   and GitHub's OIDC issuer. Signature failure never falls back to unsigned execution.
2. `omp import -f <private snapshot>` creates missing servers or conditionally
   updates changed fields. Identical config does not bump revisions. Existing
   TLS/SSRF/auth restrictions remain enforced. The child has a private empty HOME,
   no ambient CLI config, and only the one `authValueEnv` secret explicitly referenced
   by this declaration (unrelated `OMP_SECRET_*` values are not forwarded).
3. `omp servers test` verifies connectivity/discovery, then optional
   `omp servers refresh` persists capability discovery. Test failure fails the job.
   This is a synchronous check, not an asynchronous health-polling guarantee.
4. Read live state. `publish: none` **leaves publication unchanged**, including an
   existing publication (it does not unpublish). `request` requests publication
   only for private/rejected servers, guarded by the observed review digest.
   Pending/published servers are not republished.
5. Fail by default on changed definitions, already pending definitions or pending
   publication. Explicit `fail-on-changes: 'false'` warns with a portal server
   review link instead. A request is **not approval**. Tokens cannot approve.
   The portal continues withholding unapproved changed definitions.

Outputs are strictly validated fixed single lines:
- `server-id`: server UUID;
- `changed-capabilities`: integer count changed by **this refresh**, excluding added/
  gone; zero if refresh is off. Check `needs-approval` for preexisting pending work;
- `needs-approval`: boolean for observed pending publication/capabilities or changes.

Outputs are written before an approval-related failure, but GitHub may not expose
composite outputs after failed steps; do not depend on them for recovery. Earlier
successful HTTP writes remain on subsequent failure; no cross-request transaction,
rollback, automatic retry or publication/health/approval wait is claimed. Concurrent
writers may still act after the final read. Re-run only after inspecting live state.

403 errors name the required server scopes without echoing portal messages. Live
409/412/428 conflicts and stale review require a fresh read and human review.
400/422 errors direct the operator to origin/auth-value replacement: **old secrets
are never replayed to a new origin**. Protected credential changes require the
browser; there is deliberately no force/replace-secrets option. Expired tokens or
authority are never renewed/recreated. No delete, token minting, key, governance,
owner/label confirmation, policy, member or administration writes exist.

## Validation

```sh
make test-action
go test -p=2 ./internal/ompcli ./pkg/ompclient
```

CI runs `make test-action` with a scratch CLI binary; it never overwrites `bin/omp`.
Installer tests cover independent repeated invocations in the same runner job and
no executable permissions on checksum/signature failure. Unknown publication state
is a refusal, not an inferred absence of approval work.

The tests use the actual CLI against an in-memory HTTP mock, including conditional
updates/no-op revisions, pending reviews, errors, injection and secret sentinels.
The adapter's production HTTPS restriction is replaced only inside those tests so
the CLI can talk to loopback. There is no production insecure option.

For real-handler/PostgreSQL acceptance, run `tests/real-portal.sh` **only with a
NEW disposable local PostgreSQL**. It requires the supplied database URL and runs
both the existing CLI acceptance tests and `TestOmpActionWorkflowAgainstThePortal`
in both actual role modes. The latter runs this production Python adapter and a
scratch CLI through a certificate-verified HTTPS test front to the real portal
handler, with synthetic identities and upstream credentials. It checks creation,
no-op revisions, updates, read-only refusal, pending publication, changed-definition
failure/warning and secret-free outputs without substituting the adapter's HTTPS
checks. It does not contact a production portal, mint external credentials, or
execute the composite step itself inside a hosted GitHub runner.

Remaining #47 work: Terraform provider/resources and acceptance/state tests,
any separately decided delete scope, vendor secret-scanning registration, separate
Action repository/publication and a hosted-runner acceptance run. This slice does
not close #47.
