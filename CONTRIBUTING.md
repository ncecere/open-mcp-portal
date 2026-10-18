# Contributing

Thanks for helping. This file covers how to set up, test and submit changes. Report security problems privately, as described in [`SECURITY.md`](SECURITY.md), not in issues.

## Before you start

- For anything larger than a small fix, open an issue first and describe the problem and the change you have in mind.
- Read [`SPEC.md`](SPEC.md), [`docs/decisions.md`](docs/decisions.md) and the phase design in [`docs/`](docs/) for the part you're changing. A change to a product decision gets a new numbered row in `docs/decisions.md`.

## Where to help

The [roadmap](docs/roadmap.md) lists everything planned, and each item is an [issue](https://github.com/ncecere/open-mcp-portal/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap)
with a proposed implementation and acceptance criteria. Good places to start:

- [`good first issue`](https://github.com/ncecere/open-mcp-portal/labels/good%20first%20issue): small, self-contained changes.
- [`help wanted`](https://github.com/ncecere/open-mcp-portal/labels/help%20wanted) and [`needs real-world testing`](https://github.com/ncecere/open-mcp-portal/labels/needs%20real-world%20testing): things only a person with a
  particular client, account or environment can do, such as trying VS Code or Cursor against a gateway. Open a
  [client compatibility report](https://github.com/ncecere/open-mcp-portal/issues/new?template=client_compatibility.yml) with what you saw.
- [`decision needed`](https://github.com/ncecere/open-mcp-portal/labels/decision%20needed): open product questions with options and a recommendation. A comment with your use case helps.

Please comment on an issue before starting a large one, so the design is agreed first.

## Issue triage and support

Open MCP Portal is a one-maintainer project. Issue triage and support are best-effort, with a goal of a first response
within five business days; this is a target, not a guarantee. Use the issue forms for bugs, feature requests and client
compatibility reports. Use [Discussions](https://github.com/ncecere/open-mcp-portal/discussions) for questions and
early ideas. Report security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), never in a public
issue or pull request.

### Issue labels

Labels describe the issue's status or scope; they are not commitments to a delivery date.

| Label | Meaning |
|---|---|
| `bug` | Something isn't working as expected. |
| `enhancement` | A feature request or other proposed improvement. |
| `compatibility` | A report about how an MCP client works with a gateway. |
| `decision needed` | Work is waiting for an owner decision; the issue should give the options and a recommendation. |
| `needs real-world testing` | Verification needs a person, account or real client that CI cannot provide. |
| `help wanted` | Extra contributor attention is useful. |
| `good first issue` | A small, self-contained contribution suitable for a first change. |
| `security` | Security hardening or other security-relevant work. Vulnerabilities must still be reported privately. |
| `size: S` | A few days of work. |
| `size: M` | A week or two of work. |
| `size: L` | Several weeks of work. |

Milestones follow release lines: `v0.2.x` groups patch follow-ups, while `v0.3`, `v0.4` and later milestones track
minor releases. They order planned work; they are not release dates. Patch releases are made when a fix or small
improvement is ready, and minor releases follow the [roadmap](docs/roadmap.md). Each release has notes in
[`docs/releases/`](docs/releases/), with notable changes summarized in [`CHANGELOG.md`](CHANGELOG.md).

Before 1.0, only `main` and the latest minor release are supported; older minor releases do not receive fixes. Fixes
land on `main` and are released as patches of the latest minor version. Security fixes follow the same policy in
[`SECURITY.md`](SECURITY.md).

Product questions that need an owner decision are recorded in [`docs/decisions.md`](docs/decisions.md) and should use
the `decision needed` label. A good pull request focuses on one change, links the issue or decision, explains what
changed and why, and describes how it was checked. Behavior changes need a regression test; update documentation when
it changes, and add a line under `Unreleased` in [`CHANGELOG.md`](CHANGELOG.md) for user-visible behavior. Internal
changes and documentation-only changes do not need a changelog entry. CI must pass before merge: it runs `make lint`,
`make actionlint`, `make check-generated`, `make test-ci` against PostgreSQL, the web type-check, tests, build, styling
and size checks, `make k8s-validate`, and both Docker targets. The local commands and optional Kubernetes smoke test
are listed above.

## Development setup

Requires Go 1.26+, Node 22+, Docker and Python 3. `make generate` also needs [sqlc](https://sqlc.dev) (CI uses 1.31.1) on your `PATH` or in `~/go/bin`.

```sh
make deps-up      # PostgreSQL 17 on 127.0.0.1:55442 (docker compose project open-mcp-portal)
make web          # build the UI into web/dist (embedded by the binary)
make run          # creates .env from .env.example if needed, runs `open-mcp-portal serve` on :8088
make fake-mcp     # optional: a fake MCP server on http://127.0.0.1:8091/mcp
make fake-oauth   # optional: a fake OAuth provider on http://127.0.0.1:8092 (delegated credentials)
make dev-seed     # optional, after run and fake-mcp: team demo, a published server and two gateways
make web-dev      # optional: Vite with hot reload on :5175, proxying the API to :8088
make demo         # optional, instead of all of the above: everything in Docker on :8090
```

- Open http://localhost:8088 and choose a development persona (`admin@localhost` is a platform admin). Development sign-in is refused unless `APP_URL` is a loopback address. Never expose it.
- `make deps-down` stops Postgres and keeps its data. `make help` lists every target.
- Settings come from environment variables (optionally layered over a YAML file named by `OMP_CONFIG_FILE`); [`.env.example`](.env.example) describes each one.
- Never commit `.env` or anything else that holds a secret.

## Tests

| Command | What it runs |
|---|---|
| `make test` | All Go tests; integration tests skip when Postgres is unreachable |
| `make test-integration` | `make deps-up`, then all Go tests with `-race`, failing instead of skipping without Postgres |
| `make lint` | `go vet` and the gofmt check |
| `make web-test` | UI type-check and Vitest tests, with axe accessibility checks |
| `make k8s-validate` | Renders the Kustomize base and overlays and validates them with kubeconform |
| `make actionlint` | Checks the GitHub Actions workflows |
| `make k8s-smoke` | Applies the Kubernetes base to a throwaway kind cluster and checks it (about 2 minutes; needs docker, kind, kubectl and jq; `SMOKE_CNI=calico` also tests the NetworkPolicies). See [deploy.md](docs/deploy.md#smoke-test) |

- Integration tests create one database per test on the server in `OMP_TEST_DATABASE_URL` (default: the compose Postgres, `postgres://omp:omp-dev-only@127.0.0.1:55442/postgres`); `OMP_TEST_REQUIRE_DB=1` makes them fail instead of skip, and `OMP_TEST_LOG=1` shows the server's logs.
- In `web/`: `npm run typecheck`, `npm test`, `npm run build`, and the policies `npm run check:styling` (Base UI components, CSS Modules and design tokens only) and `npm run check:size` (source files ≤ 400 lines, tests ≤ 700).
- Add or update tests with every behaviour change. Bug fixes come with a test that fails without the fix.

CI (`.github/workflows/ci.yml`) runs `make lint` and `make actionlint`, `make check-generated`, `make test-ci` against a Postgres service, the web checks above, `make k8s-validate` and both Docker targets. Run the same before opening a pull request. `make k8s-smoke` is not part of it: `.github/workflows/k8s-smoke.yml` runs it on demand, weekly and when `deploy/**`, the `Dockerfile` or the script change on `main`; run it yourself when you change `deploy/`.

## Generated code

`make generate` regenerates:
- sqlc queries: `internal/store/queries/*.sql` → `internal/store/dbgen`
- Go API types: `api/openapi.yaml` → `internal/httpapi/apitypes` (oapi-codegen)
- TypeScript API types: `api/openapi.yaml` → `web/src/api/schema.gen.ts` (openapi-typescript)

Commit generated files with the change that caused them, and never edit them by hand. CI fails if they are stale (`make check-generated`).

## API changes: OpenAPI first

1. Change [`api/openapi.yaml`](api/openapi.yaml) first: paths, schemas, error codes and examples.
2. Run `make generate`.
3. Implement the handler and the UI against the generated types.

- A test fails if the routes the server serves and the spec differ, and the authorization matrix covers every operation.
- Success responses are `{"data": …}`; errors are `{"error": {"code", "message"}}`.
- The MCP endpoint, the OAuth protocol endpoints and `/.well-known/*` are documented in `docs/`, not in the contract.

## Database

- Queries live in `internal/store/queries/*.sql`; sqlc generates the Go.
- Migrations live in `migrations/`. They are forward-only and **expand/contract**: each release's schema must work with both the previous and the new code. Never edit a migration that has been applied anywhere; add a new one.
- Changes are audited in the same transaction as the change itself. `audit_log` and `mcp_calls` are append-only.

## UI components

UI components come from the bitop-ui registry and live in `web/src/components/ui`. Don't edit them by hand; fix or extend the component in bitop-ui, then re-install it. Product components live in `web/src/components/` or next to their page in `web/src/pages/`. Every page has a Vitest test with axe; new pages need one.

## Names

The product is **Open MCP Portal** (short form OMP, only after the full name has been written). A **gateway** is the feature: a curated set of capabilities served at `/mcp/{slug}`. Write "the portal" for the product and "gateway" only for the feature. The `MCP-Gateway-*` headers MCP servers receive keep their names (a contract with server authors).

## Commits and pull requests

- Keep pull requests focused on one change. Separate refactors from behaviour changes.
- Commit subjects are short and say what changed, optionally prefixed by the area (`web: …`, `docs: …`, `mcpgw: …`).
- The pull request description says what changed and why, how you tested it, and which issue or decision it relates to.
- CI must pass, generated code must be current, and docs (`SPEC.md`, `docs/`, `.env.example`) must match the change.

## Releasing

1. Write `docs/releases/vX.Y.Z.md`, turn the changelog's unreleased entry into `X.Y.Z - <date>`, and make `Version` in
   `internal/buildinfo/buildinfo.go` the release version. The release workflow refuses a tag that doesn't match it, or one
   without notes.
2. Push `main` and wait for CI to pass.
3. Tag `vX.Y.Z` (or `vX.Y.Z-rc.1`, which becomes a pre-release with the base version's notes) and push the tag.
   `.github/workflows/image.yml` builds, scans, signs and publishes the image and creates the GitHub Release
   (`scripts/github-release.sh`; `RELEASE_DRY_RUN=1` with `RELEASE_SBOM_FILE` tries it without publishing).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE), the project's licence.
