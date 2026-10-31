# Agent notes

Conventions for building and testing are in [CONTRIBUTING.md](CONTRIBUTING.md), and where the work stands is in
[docs/status.md](docs/status.md) (its "Resume checklist" and "Next steps"). This file covers what is specific to working
with an AI agent on this repository. For a fresh machine/session, start with
[docs/agent-handoff.md](docs/agent-handoff.md); confirm its release stop point against `docs/status.md` and GitHub.

- **Owner pause (latest instruction).** Finish v0.11.0 publication/verification and its release bookkeeping, then pause.
  Do not resume backlog work, integrate returned worker branches or start new assignments without the owner's request.
  Preserve partial evidence and keep all four reusable Boat VMs up; pausing an agent is not stopping its sandbox.
- **Execution mode.** When the owner resumes work, the main thread owns coordination, review, integration and releases. The owner has explicitly
  re-authorized parallel Boat/Codex coding agents for bounded development issues. Give each writer an isolated
  sandbox/checkout, only the required model credentials, and a narrow task; never forward production or infrastructure
  credentials. Agents must not spawn further agents, push, merge or publish unless separately authorized. Review actual
  diffs and completed test evidence before integrating, then validate the merged tree. This supersedes older
  main-thread-only handoff notes; it does not authorize arbitrary providers or unbounded fan-out.
- **Reusable Boat workers.** Keep newly created coding sandboxes up after assignments and artifact export; the owner
  wants to reuse them for future issues. Do not automatically stop or delete them. Record and share their names when
  created, then use clean per-issue branches and fresh conversations with one writer per sandbox. Make provider expiry,
  idle-stop and plan limits explicit rather than silently losing a reusable worker; stop only on the owner's request
  or a genuine safety incident, with an explanation.
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
