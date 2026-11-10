/* Automation tokens: Team settings and Admin (roles, create, the secret once, the "can never do" list, revoke, limits). */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { team } from "./fixtures";
import { automationToken, platformToken, tokenSecret } from "./fixtures-v02";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const teamPath = `/v1/teams/${team.slug}/automation-tokens`;
// Noon, n calendar days from today: "now + n * 24h" reads as n-1 days when the test runs just after midnight
// or across a daylight-saving change.
const inDays = (n: number) => {
  const d = new Date();
  d.setHours(12, 0, 0, 0);
  d.setDate(d.getDate() + n);
  return d.toISOString();
};

const teamRoutes = (extra: Record<string, Handler> = {}, role: Schemas["TeamRole"] | null = "owner", platform: Schemas["PlatformRole"] = "none"): Record<string, Handler> => ({
  ...shellRoutes(platform, role),
  [`GET ${teamPath}`]: () => [automationToken({ expiresAt: inDays(60) })],
  ...extra,
});
const adminRoutes = (extra: Record<string, Handler> = {}, role: Schemas["PlatformRole"] = "platform_admin"): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/automation-tokens": () => [platformToken({ expiresAt: inDays(30) })],
  ...extra,
});
const openTeam = () => renderApp(`/teams/${team.slug}/settings?tab=automation-tokens`);

describe("Team settings › Automation tokens", () => {
  it("lists tokens with kind, what they may do, who made them, expiry in days with the date as its title, last use and status", async () => {
    mockApi(
      teamRoutes({
        [`GET ${teamPath}`]: () => [
          automationToken({ expiresAt: inDays(60) }),
          automationToken({ id: "t2", name: "Old pipeline", prefix: "omppub_Zz9yXx8w", scopes: ["servers:read"], status: "revoked", revokedAt: "2026-10-10T10:00:00Z", lastUsedAt: null }),
          automationToken({ id: "t3", name: "Expired one", status: "expired", expiresAt: "2026-10-01T10:00:00Z" }),
        ],
      }),
    );
    const { container } = openTeam();
    const table = await screen.findByRole("table", { name: "Publisher tokens" });
    const active = (await within(table).findByText("CI publisher")).closest("tr")!;
    expect(active).toHaveTextContent("omppub_Ab3dEf9h…");
    expect(within(active).getByText("Team publisher")).toBeInTheDocument();
    // Write includes read: only the highest scope is listed.
    expect(within(active).getByText("servers:write")).toBeInTheDocument();
    expect(within(active).queryByText("servers:read")).toBeNull();
    expect(active).toHaveTextContent("Una User");
    expect(within(active).getByText("in 60 days")).toHaveAttribute("title", expect.stringMatching(/\d{4}/));
    expect(active).toHaveTextContent("Active");
    const revoked = within(table).getByText("Old pipeline").closest("tr")!;
    expect(revoked).toHaveTextContent("Revoked");
    expect(revoked).toHaveTextContent("Never");
    expect(within(revoked).queryByRole("button", { name: /Actions for/ })).toBeNull();
    expect(within(table).getByText("Expired one").closest("tr")).toHaveTextContent("Expired");
    // Never a secret after creation.
    expect(document.body.textContent).not.toMatch(/omppub_[A-Za-z0-9_-]{20,}/);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("tells editors and members who can see tokens, without asking for the list", async () => {
    for (const role of ["editor", "member"] as const) {
      const calls = mockApi(teamRoutes({}, role));
      const { unmount } = openTeam();
      expect(await screen.findByText("Only the team's owners and admins see automation tokens.")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
      expect(calls.some((c) => c.url === teamPath)).toBe(false);
      unmount();
    }
  });

  it("is read-only for platform staff who aren't on the team", async () => {
    mockApi(teamRoutes({}, null, "platform_auditor"));
    openTeam();
    expect(await screen.findByText("CI publisher")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();
    expect(screen.getByText(/tokens can be read, not changed/)).toBeInTheDocument();
  });

  it("can revoke but not create in an archived team", async () => {
    mockApi({ ...teamRoutes(), [`GET /v1/teams/${team.slug}`]: () => ({ team: { ...team, status: "archived" }, role: "owner" }) });
    openTeam();
    expect(await screen.findByText("CI publisher")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
    expect(screen.getByRole("button", { name: "Actions for CI publisher" })).toBeInTheDocument();
    expect(screen.getByText("The team is archived: tokens can be revoked, not created.")).toBeInTheDocument();
  });

  it("creates a token with read by default, lists what it can never do, and shows the secret once", async () => {
    const u = userEvent.setup();
    const secret = tokenSecret();
    const created: Schemas["AutomationTokenCreated"] = { token: automationToken({ id: "new", name: "Release", scopes: ["servers:read", "servers:write"] }), secret };
    const calls = mockApi(teamRoutes({ [`POST ${teamPath}`]: () => new Reply(201, { data: created }) }));
    openTeam();
    await u.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a publisher token" });
    expect(within(dialog).getByRole("textbox", { name: /Expires after/ })).toHaveValue("90");
    // Read is the default; each scope says what it can do.
    expect(within(dialog).getByRole("radio", { name: /Read servers/ })).toBeChecked();
    expect(within(dialog).getByText(/register servers, change their settings, test and refresh them/)).toBeInTheDocument();
    // The explicit list of what no token can do.
    const cannot = within(dialog).getByText("What this token can never do, whatever you choose").closest("[role=status]") as HTMLElement;
    for (const line of ["Delete a server", "Approve capabilities or review a server", "Create or revoke tokens", "Reach another team"]) expect(cannot).toHaveTextContent(line);
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    expect(await within(dialog).findByText("Enter a name.")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Release");
    await u.click(within(dialog).getByRole("radio", { name: /Read and manage servers/ }));
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Release", scopes: ["servers:write"], expiresInDays: 90 }));

    const shown = await screen.findByRole("dialog", { name: "Token created" });
    expect(within(shown).getByText("Copy this token now.")).toBeInTheDocument();
    expect(within(shown).getByText(/It won't be shown again/)).toBeInTheDocument();
    expect(within(shown).getByText(secret)).toBeInTheDocument();
    expect(within(shown).getByRole("button", { name: /Copy automation token/ })).toBeInTheDocument();
    // A usage hint that is never filled with the secret.
    const hint = within(shown).getByText(/curl -H "Authorization: Bearer \$OMP_TOKEN"/);
    expect(hint).toHaveTextContent(`/v1/teams/${team.slug}/mcp-servers`);
    expect(hint.textContent).not.toContain(secret);
    await u.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // Gone: not on the page, and not in what the list returns.
    expect(document.body.textContent).not.toContain(secret);
    expect(screen.queryByText(secret)).toBeNull();
  });

  it("checks the expiry and sends a chosen number of days", async () => {
    const u = userEvent.setup();
    const calls = mockApi(teamRoutes({ [`POST ${teamPath}`]: () => new Reply(201, { data: { token: automationToken(), secret: tokenSecret() } }) }));
    openTeam();
    await u.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a publisher token" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "CI");
    const days = within(dialog).getByRole("textbox", { name: /Expires after/ });
    await u.clear(days);
    await u.type(days, "400");
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    expect(await within(dialog).findByText("Enter a whole number of days from 1 to 365.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await u.clear(days);
    await u.type(days, "30");
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ expiresInDays: 30 }));
  });

  it("says why when there are too many tokens, or the request needs a session", async () => {
    const u = userEvent.setup();
    let error = Reply.error(409, "too_many_tokens", "too many");
    mockApi(teamRoutes({ [`POST ${teamPath}`]: () => error }));
    openTeam();
    await u.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a publisher token" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "CI");
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    expect(await within(dialog).findByText("Too many active tokens")).toBeInTheDocument();
    expect(within(dialog).getByText(/At most 20 tokens can be active at once/)).toBeInTheDocument();
    error = Reply.error(403, "session_required", "x");
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    expect(await within(dialog).findByText("Sign in to do this")).toBeInTheDocument();
  });

  it("stops at 20 active tokens: Create is off and the page says why", async () => {
    const many = Array.from({ length: 20 }, (_, i) => automationToken({ id: `t${i}`, name: `Token ${i}`, expiresAt: inDays(30) }));
    mockApi(teamRoutes({ [`GET ${teamPath}`]: () => many }));
    openTeam();
    expect(await screen.findByText("20 active tokens: the most there can be")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create token" })).toBeDisabled();
    expect(screen.getByText(/at most 20 can be active at once/i)).toBeInTheDocument();
  });

  it("revokes only after asking", async () => {
    const u = userEvent.setup();
    const calls = mockApi(teamRoutes({ [`DELETE ${teamPath}/${automationToken().id}`]: () => ({ ok: true }) }));
    openTeam();
    await u.click(await screen.findByRole("button", { name: "Actions for CI publisher" }));
    await u.click(await screen.findByRole("menuitem", { name: "Revoke…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Revoke CI publisher?" });
    expect(ask).toHaveTextContent("stops working on its next request");
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Revoke token" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
  });

  it("says that tokens are session-only and never work on /mcp", async () => {
    mockApi(teamRoutes());
    openTeam();
    expect(await screen.findByText(/never on an MCP gateway \(\/mcp\)/)).toBeInTheDocument();
    expect(screen.getByText(/a token can't create or revoke tokens/)).toBeInTheDocument();
  });
});

describe("Admin › Automation tokens", () => {
  it("lists platform tokens, notes where team tokens live, and shows a blocked one", async () => {
    mockApi(
      adminRoutes({
        "GET /v1/admin/automation-tokens": () => [platformToken({ expiresAt: inDays(30) }), platformToken({ id: "b", name: "Reporting", blockedReason: "creator_not_platform_admin", expiresAt: inDays(10) })],
      }),
    );
    const { container } = renderApp("/admin/automation-tokens");
    expect(await screen.findByRole("heading", { level: 1, name: "Automation tokens" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Platform-admin tokens" });
    const row = (await within(table).findByText("Monitoring")).closest("tr")!;
    expect(row).toHaveTextContent("Platform admin");
    expect(row).toHaveTextContent("platform:read");
    const blocked = within(table).getByText("Reporting").closest("tr")!;
    expect(blocked).toHaveTextContent("Blocked");
    expect(blocked).toHaveTextContent("its creator is no longer a platform admin");
    expect(screen.getByText("Team publisher tokens")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Automation tokens · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("creates a platform token with the explicit list of what write can not do", async () => {
    const u = userEvent.setup();
    const secret = tokenSecret("ompadm_");
    const calls = mockApi(adminRoutes({ "POST /v1/admin/automation-tokens": () => new Reply(201, { data: { token: platformToken({ scopes: ["platform:read", "platform:write"] }), secret } }) }));
    renderApp("/admin/automation-tokens");
    await u.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a platform-admin token" });
    expect(within(dialog).getByRole("radio", { name: /Read the platform/ })).toBeChecked();
    await u.click(within(dialog).getByRole("radio", { name: /Read and provision/ }));
    const cannot = within(dialog).getByText("What this token can never do, whatever you choose").closest("[role=status]") as HTMLElement;
    for (const line of [
      "Create or revoke tokens",
      "Change anyone's role, suspend people or assign team owners",
      "Review or approve servers and capabilities",
      "Change the publishing policy, internal networks, trusted clients, payload capture, retention or auth providers",
      "Delete anything",
      "Read recorded call contents",
    ])
      expect(cannot).toHaveTextContent(line);
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Terraform");
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Terraform", scopes: ["platform:write"], expiresInDays: 90 }));
    const shown = await screen.findByRole("dialog", { name: "Token created" });
    expect(within(shown).getByText(secret)).toBeInTheDocument();
    expect(within(shown).getByText(/curl -H "Authorization: Bearer \$OMP_TOKEN".*\/v1\/admin\/overview/)).toBeInTheDocument();
    await u.click(within(shown).getByRole("button", { name: "Done" }));
    expect(document.body.textContent).not.toContain(secret);
  });

  it("is read-only for auditors", async () => {
    mockApi(adminRoutes({}, "platform_auditor"));
    renderApp("/admin/automation-tokens");
    expect(await screen.findByText("Monitoring")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create token" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();
    expect(screen.getAllByText(/Only platform admins can change them/).length).toBeGreaterThan(0);
  });

  it("is in the admin sidebar and the command palette", async () => {
    const u = userEvent.setup();
    mockApi(adminRoutes());
    renderApp("/admin/automation-tokens");
    await screen.findByText("Monitoring");
    expect(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: "Automation tokens" })).toHaveAttribute("aria-current", "page");
    await u.click(screen.getByRole("button", { name: /Search or jump to/ }));
    await u.type(await screen.findByRole("combobox"), "ompadm");
    expect(await screen.findByRole("option", { name: /Automation tokens/ })).toBeInTheDocument();
  });
});
