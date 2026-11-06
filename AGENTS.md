# Agent notes

Conventions for building and testing are in [CONTRIBUTING.md](CONTRIBUTING.md), and where the work stands is in
[docs/status.md](docs/status.md) (its "Resume checklist" and "Next steps"). This file covers what is specific to working
with an AI agent on this repository. For a fresh machine/session, start with
[docs/agent-handoff.md](docs/agent-handoff.md); confirm its release stop point against `docs/status.md` and GitHub.

- **v0.15.1 released 2026-11-06; batch complete.** v0.15.1 ships signed audit checkpoints and audit webhook sinks
  (#38 slice 2, decision 94, docs/audit-sinks.md; off until `enable-checkpoints`/`enable-sinks` after rollout),
  migrations 63–64. v0.15.0 was tagged but never published (image CVE gate); it is listed as unpublished in
  scripts/previous-release.sh. Nothing is in progress; follow-ups are in [docs/status.md](docs/status.md). Decisions
  95+ and migrations 65+ are unallocated; allocate them from the main thread only. Parked on GitHub:
  `parked/terraform-provider` and `parked/keyprovider-transit` (#41, deferred). Do not infer v1.0.0 approval.
- **Release lessons (v0.14.0, v0.15.x).** Run frozen-candidate validation in a dedicated worktree (never switch
  branches in a checkout a run is using), set `GOTMPDIR` on disk (`/tmp` is a small shared tmpfs), run the Kubernetes
  smoke/upgrade/load gates before tagging (they caught a multi-replica migration deadlock), and Trivy-scan a locally
  built image before tagging (a new upstream CVE failed v0.15.0's publication after the tag). Tags are immutable: a
  failed publication becomes an unpublished tag listed in scripts/previous-release.sh and a new patch version.
- **Execution mode.** The main thread owns coordination, review, integration and releases. The owner has explicitly
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
