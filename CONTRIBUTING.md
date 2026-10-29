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

## How issues are handled

Open MCP Portal has one maintainer, so everything here is best effort.

**Replies.** The goal is a first reply within about a week. It can be a question, a label or "not now", and it may take longer around a release. Security reports follow [`SECURITY.md`](SECURITY.md) (private report, reply within 5 business days), never an issue.

**Labels**

| Label | Meaning |
|---|---|
| `bug` | Something doesn't work as documented |
| `enhancement` | A new feature or an improvement |
| `compatibility` | A report on how an MCP client works with a gateway (use the compatibility template) |
| `decision needed` | Waiting for an owner decision; the issue lists options and a recommendation |
| `needs real-world testing` | Needs a person, account or real client that CI can't provide |
| `help wanted` | Welcome from contributors; comment first |
| `good first issue` | Small and self-contained |
| `security` | Hardening or a security-relevant change. Vulnerabilities go to a private advisory |
| `size: S`, `size: M`, `size: L` | A few days, a week or two, several weeks |
| `area: …` | The part of the product: `registry`, `gateway`, `oauth`, `providers`, `web`, `auth`, `ops` |
| `roadmap` | Planned work listed in [`docs/roadmap.md`](docs/roadmap.md) |

**Milestones** name the release that should carry the work: `v0.2.x` for patch releases of the current minor (the milestone is named for what they hold, such as "v0.2.x: pilot follow-ups"), `v0.3`, `v0.4` and so on for minor releases, and `Later` for anything not scheduled. A milestone is a plan, not a promise.

**Supported versions.** The latest minor release gets fixes, security or otherwise. Before 1.0, older minors are not supported: upgrade to the latest. This matches the table in [`SECURITY.md`](SECURITY.md).

**Releases.** A patch release (`v0.2.2`) ships when a fix or a small improvement is ready. A minor release (`v0.3.0`) follows the [roadmap](docs/roadmap.md) and may include breaking changes, which its notes say how to handle. Every release has notes in [`docs/releases/`](docs/releases/) and a changelog entry.

**How decisions are made.** A product choice is a numbered row in [`docs/decisions.md`](docs/decisions.md), and a row that changes an earlier one says so. An open question is an issue with the `decision needed` label, with options and a recommendation. A comment with your use case helps; the owner decides and the row records it.

**Contributing a fix.** Open an issue first for anything beyond a small fix (see above). A good pull request:

- is focused on one change, linked to its issue;
- has tests: a bug fix comes with a test that fails without it;
- updates the docs it changes (`docs/`, `SPEC.md`, `.env.example`) and adds a line under `## Unreleased` in [`CHANGELOG.md`](CHANGELOG.md);
- commits regenerated code when it changes `api/openapi.yaml` or the SQL queries (`make generate`);
- passes what CI runs: `make lint`, `make actionlint`, `make check-generated`, the Go tests against PostgreSQL, the web checks (`npm run typecheck`, `npm test`, `npm run build`, `check:styling`, `check:size`), `make k8s-validate` and the Docker builds. [Tests](#tests) lists the commands.

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
| `make k8s-smoke` | Applies the Kubernetes base to a throwaway kind cluster and checks it (about 2 minutes; needs docker, kind, kubectl and jq; `SMOKE_CNI=calico` also tests the NetworkPolicies). `SMOKE_SCENARIO=upgrade`, `ingress`, `restore` or `load` run the other scenarios (the previous release to this tree and back; ingress, TLS and OIDC; a `pg_dump` restore; three replicas under k6). See [deploy.md](docs/deploy.md#smoke-test) |
| `make smoke-selftest` | The smoke scripts' assertion helpers against stubs, and the Python script tests in `scripts/tests`: no cluster, no Docker |
| `make shellcheck` | ShellCheck on the deployment and smoke scripts (installs the pinned release into `bin/k8s-tools/bin` when it is not on the PATH) |

- Integration tests create one database per test on the server in `OMP_TEST_DATABASE_URL` (default: the compose Postgres, `postgres://omp:omp-dev-only@127.0.0.1:55442/postgres`); `OMP_TEST_REQUIRE_DB=1` makes them fail instead of skip, and `OMP_TEST_LOG=1` shows the server's logs.
- In `web/`: `npm run typecheck`, `npm test`, `npm run build`, and the policies `npm run check:styling` (Base UI components, CSS Modules and design tokens only) and `npm run check:size` (source files ≤ 400 lines, tests ≤ 700).
- Add or update tests with every behaviour change. Bug fixes come with a test that fails without the fix.

`make test` and `make test-ci` both keep every test with an explicit 20-minute per-package budget. The growing
HTTP integration package can exceed Go's default cumulative 10 minutes even in normal mode; a package
watchdog is not an individual-test deadline. CI still requires PostgreSQL and the race detector in both roles.

CI (`.github/workflows/ci.yml`) runs `make lint` and `make actionlint`, `make check-generated`, `make test-ci` against a Postgres service, the web checks above, `make k8s-validate`, `make shellcheck`, the smoke self-test (`SMOKE_SELFTEST=1 scripts/k8s-smoke.sh`) with the script tests, and both Docker targets. `make test-ci` retains every test, required PostgreSQL and the race detector with an explicit 20-minute per-package timeout; the CI job allows 45 minutes for both complete database-role modes. Run the same before opening a pull request. The kind scenarios are not part of it: `.github/workflows/k8s-smoke.yml` runs `base`, `ingress` and `restore` on demand, weekly and when `deploy/**`, the `Dockerfile` or the scripts change on `main`; `k8s-upgrade.yml` runs the upgrade from the previous release on every `v*` tag, weekly and on demand (and, weekly or on request, the canary that proves a breaking migration fails it); `k8s-load.yml` runs the load test weekly and on demand. Run the scenario yourself when you change `deploy/` or the scripts.

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

1. Write `docs/releases/vX.Y.Z.md`, then run `scripts/bump-version.py X.Y.Z` (add `--check` to see what it would change
   first). It sets the version in `internal/buildinfo/buildinfo.go`, `api/openapi.yaml`, `web/package.json` and its lock, the
   Kustomize base and example overlay (the overlay's digest goes back to the all-zeros placeholder until the image exists),
   `docs/deploy.md`, `README.md`, `SECURITY.md` and the issue-form placeholders, turns `## Unreleased` in the changelog into
   `## [X.Y.Z] - <date>`, and lists the other mentions of the old version for you to judge (history and older release pages
   stay). The release workflow refuses a tag that doesn't match `Version`, or one without notes.
2. Push `main` and wait for CI to pass.
3. Tag `vX.Y.Z` (or `vX.Y.Z-rc.1`, which becomes a pre-release with the base version's notes) and push the tag.
   `.github/workflows/image.yml` builds, scans, signs and publishes the image and creates the GitHub Release
   (`scripts/github-release.sh`; `RELEASE_DRY_RUN=1` with `RELEASE_SBOM_FILE` tries it without publishing).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE), the project's licence.
