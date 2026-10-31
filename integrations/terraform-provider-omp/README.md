# Open MCP Portal Terraform provider — read-only development slice

Standalone terraform-plugin-framework module for issue #47, built on this checkout's
generated public pkg/ompclient. **Unreleased** work on the v0.11.0 integration
candidate, not a registry release or complete #47 acceptance.

## Build and test

Requires Go **1.26.10**. From this directory:

~~~sh
GOTOOLCHAIN=go1.26.10 GOFLAGS=-p=2 go build -o /tmp/terraform-provider-omp .
GOTOOLCHAIN=go1.26.10 GOFLAGS=-p=2 go test -race -count=1 -timeout=20m ./...
# Optional genuine Terraform CLI fixture test (not real-portal TF_ACC):
OMP_TERRAFORM_CLI=/absolute/path/to/verified/terraform   GOTOOLCHAIN=go1.26.10 GOFLAGS=-p=2 go test -race -v -count=1 -timeout=20m ./...
~~~

The CLI test builds this provider, uses temporary development overrides and a loopback
HTTP fixture, validates HCL, plans, saves data-only state, observes an external edit
with a refresh-only plan, tests failed reads, and scans saved plans/state/TRACE logs for
auth and upstream-secret sentinels. Every request must be GET. To retain fixture-only
JSON evidence, set OMP_TERRAFORM_EVIDENCE_DIR to an owned directory. No real token is
needed. Without OMP_TERRAFORM_CLI the CLI test explicitly skips.

Use a pinned official Terraform release. Verify the archive against its published
SHA256SUMS and verify the SUMS signature with HashiCorp's public release key before
running it. Tested version: **1.13.5**, from
https://releases.hashicorp.com/terraform/1.13.5/ (ZIP, SHA256SUMS and SHA256SUMS.sig).
No automatic download or unverified executable is part of these tests.

For local use, put this in a dedicated CLI config selected by TF_CLI_CONFIG_FILE:

~~~hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/ncecere/omp" = "/absolute/binary/directory"
  }
  direct {}
}
~~~

Development overrides skip registry installation; **do not run terraform init to
install this unpublished provider**. Use terraform validate / terraform plan with
the override and [examples](examples/read-only/main.tf). Never reuse production state.

## Configuration and contracts

- **url** (optional) defaults to OMP_URL. HTTPS certificates are always verified.
  HTTP is permitted only for localhost or loopback IPs, like the existing CLI.
  URL credentials, query strings and fragments are rejected.
- **token_env** (optional, default OMP_TOKEN) is an environment variable **name**,
  restricted to OMP_TOKEN or OMP_TOKEN_[A-Z0-9_]+. Use aliases for separate
  publisher/platform tokens. No token-valued HCL, plan or state attribute exists.
  Never interpolate tokens into any HCL field.
- Supply an **existing** token in that environment variable. No login, session,
  minting, credential-file loading or arbitrary environment variable access.
- Each lookup has a 30-second total deadline (including pagination), honors caller
  cancellation and caps a response at 4 MiB and a list at 100 pages.
  Redirects (same or cross-origin) are never followed. Only GET requests to the
  configured origin receive Authorization. No insecure toggle, request/response
  logging or error-body forwarding exists.
- A 401 means invalid/expired/revoked; a 403 explains required kind/scope without
  echoing upstream bodies. A 404 fails the read (no silent state removal).
  Retry unavailable/rate-limited reads later; reads do not automatically retry.

### omp_team_mcp_server

Inputs: **team**, **lookup**, both required exact slugs or canonical UUIDs.
Publisher tokens (omppub_, servers:read) are bound to **one exact team**. Platform
tokens are not accepted. Slugs resolve using paginated listTeamMcpServers, then
getTeamMcpServer reads the selected UUID. UUID lookup uses only get.
Response identity/team and required metadata are validated.

Deliberately **not** omp_catalog_server: this is team-owned metadata, not the global
catalog. It does not prove capabilities are published, approved, healthy,
appropriately labelled or available to any gateway.

State allowlist: inputs plus **id, slug, name, revision, team_id, team_slug, enabled,
tools, prompts, resources, resource_templates, supports_tasks**.
Counts must be present non-negative integers, IDs nonzero canonical UUIDs and revision
positive. Zero counts/false enablement are preserved. Missing/null optional supportsTasks
becomes Terraform null, never inferred true or proof of safety; required absent/null/
wrong-type metadata fails closed. External edits update outputs on the next plan/refresh.

### omp_team

Input: **lookup**, required slug/UUID. Only a platform token (ompadm_,
platform:read) through annotated **adminGetTeam** is supported. Publishers cannot use
session-only getTeam; that route is never called.
State allowlist: input plus **id, slug, name, revision, status**.

Both sources omit credential values/ciphers/hints, URLs, descriptions, contacts,
owner invitations, OAuth/claims, raw server JSON and governance/curation data. Names
are intentional metadata: don't put secrets in display names or input slugs.
Unknown upstream fields are ignored, not copied into state. Prefixes are checked
locally but the portal remains authority for exact team, scopes, expiry and revocation
on **every** request; no authority is cached or widened.

## Unsupported and extraction plan

**No resources**: no create/update/delete, apply convergence or destroy semantics.
Data-only apply saves observed metadata; it does not mutate the portal. No discovery,
test, refresh API operation, publication, policy write, new scopes or token kinds.
Terraform refresh means re-reading GET routes, not invoking the portal's mutating
refresh operation. This does **not** close #47 or satisfy resource CRUD, real-portal
TF_ACC or secret-write-only resource acceptance.

go.mod/go.sum pin dependencies. The sole development replace resolves the parent
module to ../..; run from this checkout at base
368007db292424fae10db6cc3041e9cbb4201712 plus this provider commit.
Extraction (parent-owned, not performed):
1. Copy this directory and parent MIT license into an approved new repository.
2. Identify an owner-approved published public v0 client containing these operations,
   replace the placeholder parent requirement with that immutable version, remove
   replace, run go mod tidy and review the module diff.
3. Add independent race/schema/verified-CLI CI and required disposable PostgreSQL
   portal acceptance. Preserve this allowlist and scope matrix.
4. Decide versioning, registry identity, signing/releases and upgrade tests before
   publication. Resource/delete proposals require separate decisions; never map
   destroy to unpublish/disable.
