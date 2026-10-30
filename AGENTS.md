# Agent notes

Conventions for building and testing are in [CONTRIBUTING.md](CONTRIBUTING.md), and where the work stands is in
[docs/status.md](docs/status.md) (its "Resume checklist" and "Next steps"). This file covers what is specific to working
with an AI agent on this repository. For a fresh machine/session, start with
[docs/agent-handoff.md](docs/agent-handoff.md); confirm its release stop point against `docs/status.md` and GitHub.

- **Execution mode.** The owner now wants work handled directly in the main thread. Do not start subagents unless
  explicitly asked again; this supersedes earlier delegation authorization in historical handoff notes.
- **Names.** The product is Open MCP Portal (OMP only after the full name). "Gateway" is the feature (a curated set
  of capabilities at `/mcp/{slug}`): write "the portal" for the product. Keep the `MCP-Gateway-*` header names.
- **A dev instance may be running.** `make run` (or `bin/open-mcp-portal serve`) on :8088, `make fake-mcp` on :8091,
  `make fake-oauth` on :8092 and `make example-mail-fake` on :8093. Don't stop it, don't start servers on those
  ports, and build to a scratch path (`go build -o /tmp/... ./cmd/open-mcp-portal`) instead of `make build`, which
  overwrites `bin/`.
- **The dev database holds real setup** (auth providers with encrypted secrets, users, teams, gateways). Never stop or
  remove the compose Postgres or its volume, and never run migrations or tests against database `omp` itself:
  integration tests create their own databases on the server in `OMP_TEST_DATABASE_URL`.
- **Migrations.** Never edit an applied migration; add the next number. Expand/contract: the previous release must
  keep working with the new schema.
- **Before reporting done:** `make generate`, `make lint`, `go build ./...`, `make test` (with Postgres up), and in
  `web/`: `npm run typecheck`, `npm test`, `npm run build`, `npm run check:styling`, `npm run check:size`; plus
  `make k8s-validate` and `make actionlint` when `deploy/` or `.github/` changed. Say what was not run or not
  browser-checked.
