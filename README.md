# Open MCP Portal

A self-hosted portal for a company's [Model Context Protocol](https://modelcontextprotocol.io) servers. Teams register
the MCP servers they run, publish them to a company catalog, and curate **gateways**: sets of tools, prompts and
resources served at one MCP endpoint, `/mcp/{slug}`. People and agents connect Claude Code, VS Code, Cursor or their
own scripts to a gateway and see only what they may use, with every call checked, limited and recorded.

Go + PostgreSQL 17, with a React/Vite web UI embedded in one binary. Documentation: <https://docs.omp.bitop.dev>.
Website: <https://omp.bitop.dev>.

**Development software (v0.2.1).** Phases 1 to 7 and the v0.2 pilot work (MCP 2026-07-28, an admin overview, notifications, automation tokens) are done. Claude Code and pi have signed in over OAuth and called
tools (Claude Code also speaks the 2026-07-28 revision natively), and GitHub's hosted MCP server works with each person's own GitHub sign-in. It runs on one Talos cluster. Not tried yet: a real Google or
Microsoft provider for delegated credentials (only a fake), VS Code and Cursor; it hasn't run
in production. See the [v0.2.0 release notes](docs/releases/v0.2.0.md) and [status](docs/status.md) for what has been
checked and what hasn't.

## What it does

- **Registry and catalog.** A team registers a remote MCP server; Open MCP Portal reads its tools, resources and
  prompts, checks its health, and notices when a definition changes. Platform admins approve servers into the company
  catalog, or trusted teams publish their own. Internal servers are reached only on networks a platform admin allows
  ([registry](docs/registry.md)).
- **Gateways.** Teams and platform admins build gateways from the capabilities they may use and grant them to teams,
  people or SSO groups. Each gateway is one MCP endpoint, re-checked on every request ([gateways](docs/phase3-gateways.md)).
- **Sign-in for MCP clients.** Interactive clients sign in with OAuth 2.1 (PKCE, CIMD and dynamic registration,
  per-person consent); scripts use personal API keys, and pipelines and agents use team service accounts
  ([connecting clients](docs/connect-clients.md)).
- **Signed identity.** Every call to an MCP server carries a short-lived ES256 JWT that says who is calling, through
  which gateway and for which tool. Client credentials never reach the server
  ([verifying the identity token](docs/upstream-identity.md)).
- **Delegated credentials.** Tools that act as the caller on GitHub, Google, Microsoft, Atlassian, Slack or GitLab get
  that person's own token, which the portal obtains with their consent, stores encrypted and refreshes
  ([delegated credentials](docs/phase5-delegated-credentials.md)).
- **Per-person OAuth to upstream servers.** MCP servers that are OAuth resource servers themselves (such as GitHub's
  hosted MCP server) get each caller's own sign-in ([upstream OAuth](docs/phase7-upstream-oauth.md)).
- **Audit, limits and operations.** An append-only audit log and call log, rate limits shared by every replica,
  opt-in payload capture with redaction, retention, usage reports, Prometheus metrics, key rotation and a `doctor`
  command ([operations](docs/phase6-operations.md), [deploying](docs/deploy.md)).

Not in scope: hosting or running agents or MCP servers, and LLM routing.

## Quick start (development)

Requires Go 1.26+, Node 22+, Docker and Python 3 (for the seed script).

```sh
make deps-up      # PostgreSQL 17 on 127.0.0.1:55442 (docker compose)
make web          # build the web UI (embedded by the Go binary)
make fake-mcp     # a fake MCP server on http://127.0.0.1:8091/mcp (separate terminal)
make run          # creates .env from .env.example, serves http://localhost:8088 (separate terminal)
make dev-seed     # team "demo", a published server and two gateways
```

Open <http://localhost:8088> and pick a development persona (`admin@localhost` is a platform admin). Development
sign-in and the example keys in `.env.example` only work with a loopback `APP_URL`. Then create an API key under
Account › API keys and connect a client to `http://localhost:8088/mcp/demo`, or follow the snippets under My gateways.

`make fake-oauth` adds a fake OAuth provider for delegated credentials, and `make demo` runs everything in Docker
instead. `make help` lists every target; [CONTRIBUTING.md](CONTRIBUTING.md) has the tests and checks.

## Deploying

One stateless binary in a distroless image, PostgreSQL 17, and a Kustomize base in
[`deploy/kubernetes`](deploy/kubernetes). Configuration is environment variables (or a YAML file named by
`OMP_CONFIG_FILE`), described in [`.env.example`](.env.example). See [deploying](docs/deploy.md).

## Install

Releases publish a multi-arch image (linux/amd64 and linux/arm64) with SBOM and provenance attestations and a
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) keyless signature:

```sh
docker pull ghcr.io/ncecere/open-mcp-portal:v0.2.1
```

Tags are `vX.Y.Z` and, for final releases, `latest`. **Pin the image by digest** in a real deployment: the digest is in
each GitHub Release (and its `open-mcp-portal-<tag>.digest.txt` asset). Verify the signature with cosign v3 or newer
before you use it:

```sh
cosign verify ghcr.io/ncecere/open-mcp-portal@sha256:<digest> \
  --certificate-identity https://github.com/ncecere/open-mcp-portal/.github/workflows/image.yml@refs/tags/v0.2.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The Kubernetes base uses `ghcr.io/ncecere/open-mcp-portal:v0.2.1`; the example overlay shows pinning the digest. You
generate your own `ENCRYPTION_KEY` and `API_KEY_PEPPER` (`openssl rand -base64 32` each); see
[deploying](docs/deploy.md#required-settings-and-secrets). To try it locally without installing anything, run
`make demo` (Docker builds the image itself).

## Documentation

- [Specification](SPEC.md) and [product decisions](docs/decisions.md)
- [Status and handoff](docs/status.md)
- [Roadmap](docs/roadmap.md): what comes after v0.2.1, in order, with an [issue and implementation plan](https://github.com/ncecere/open-mcp-portal/milestones) for each item
- Phase designs: [registry](docs/registry.md), [gateways](docs/phase3-gateways.md),
  [client sign-in](docs/phase4-client-auth.md), [delegated credentials](docs/phase5-delegated-credentials.md),
  [operations](docs/phase6-operations.md), [upstream OAuth](docs/phase7-upstream-oauth.md)
- For MCP server authors: [verifying the identity token](docs/upstream-identity.md) and the Gmail example in
  [`examples/mail-mcp`](examples/mail-mcp)
- Management API: [`api/openapi.yaml`](api/openapi.yaml)
- [Threat model](docs/threat-model.md): assets, actors, trust boundaries, threats with the code and tests that address them, and code review findings

## Releases and security

- **Releases:** [changelog](CHANGELOG.md) and per-release notes in [`docs/releases/`](docs/releases/) (what is in each release, how to install it, known limitations).
- **Security:** report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes.

## Questions, feedback and compatibility reports

- **Questions and ideas:** [GitHub Discussions](https://github.com/ncecere/open-mcp-portal/discussions).
- **Bugs and feature requests:** [issues](https://github.com/ncecere/open-mcp-portal/issues/new/choose), with a form for each.
- **Issue triage and support:** see [CONTRIBUTING.md](CONTRIBUTING.md#issue-triage-and-support) for labels, response expectations,
  supported versions and pull request guidance.
- **Does your MCP client work?** Claude Code and pi have been run against the portal; VS Code, Cursor and others haven't yet. The
  [client compatibility page](https://docs.omp.bitop.dev/docs/use/client-compatibility) has a ten-minute checklist and a report form.

## License

[MIT](LICENSE). Copyright (c) 2026 Nicholas Cecere.
