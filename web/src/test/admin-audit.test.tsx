/* Admin → Audit log: server filters in the URL, sign-ins hidden by default, entries in a record page, and the audit helpers. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { auditChange, changeSummary, plainKey, valueText } from "../components/audit/changes";
import { actionLabel, actorName, areaOptions, personFilter } from "../components/audit/labels";
import { toCSV } from "../pages/admin/audit/common";
import { auditEntry, page, team, user } from "./fixtures";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const signIn = auditEntry({
  id: 102,
  action: "auth.login",
  teamId: null,
  teamName: null,
  teamSlug: null,
  targetType: "user",
  targetId: user().id,
  targetLabel: "Una User",
  before: null,
  after: null,
  clientIp: "192.0.2.10",
});
const suspend = auditEntry({
  id: 103,
  action: "platform.user_suspend",
  teamId: null,
  teamName: null,
  teamSlug: null,
  targetType: "user",
  targetId: "77777777-7777-4777-8777-777777777777",
  targetLabel: "Pat Admin",
  before: { status: "active" },
  after: { status: "suspended" },
});

describe("Admin → Audit log", () => {
  it("hides sign-ins by default, shows changes in one line and the team, and opens an entry", async () => {
    const u = userEvent.setup();
    const calls = mockApi({ ...shellRoutes("platform_auditor"), "GET /v1/admin/users": () => page([user()]), "GET /v1/admin/audit": () => page([auditEntry(), suspend]) });
    const { container } = renderApp("/admin/audit");
    const table = await screen.findByRole("table", { name: "Audit log" });
    const row = (await within(table).findByText("Changed member role")).closest("tr")!;
    expect(row).toHaveTextContent("Role Member → Editor");
    expect(within(row).getByRole("link", { name: team.name })).toHaveAttribute("href", `/admin/teams/${team.slug}`);
    const suspended = within(table).getByText("Suspended user").closest("tr")!;
    expect(within(suspended).getByRole("link", { name: "Pat Admin" })).toHaveAttribute("href", "/admin/users/77777777-7777-4777-8777-777777777777");
    expect(calls.find((c) => c.url === "/v1/admin/audit")?.search.get("excludeAction")).toBe("auth.");
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("switch", { name: "Hide sign-ins" }));
    await waitFor(() => expect(calls.filter((c) => c.url === "/v1/admin/audit").at(-1)?.search.get("excludeAction")).toBeNull());

    // The list reloads without the filter: open the entry from the new rows.
    await u.click(await within(await screen.findByRole("table", { name: "Audit log" })).findByText("Suspended user"));
    expect(await screen.findByRole("heading", { level: 1, name: "Suspended user" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "What changed: Suspended user" })).toHaveTextContent("StatusActiveSuspended");
  });

  it("sends the URL's filters to the server", async () => {
    const calls = mockApi({ ...shellRoutes("platform_admin"), "GET /v1/admin/users": () => page([]), "GET /v1/admin/audit": () => page([signIn]) });
    renderApp("/admin/audit?action=auth.&person=system&target=user");
    const table = await screen.findByRole("table", { name: "Audit log" });
    expect(await within(table).findByText("Signed in")).toBeInTheDocument();
    const call = calls.filter((c) => c.url === "/v1/admin/audit").at(-1)!;
    expect(call.search.get("action")).toBe("auth.");
    expect(call.search.get("actorKind")).toBe("system");
    expect(call.search.get("targetType")).toBe("user");
    // An explicit Sign-in filter isn't fought by "Hide sign-ins".
    expect(call.search.get("excludeAction")).toBeNull();
  });

  it("opens a linked entry by id, with the address it came from", async () => {
    mockApi({ ...shellRoutes("platform_admin"), "GET /v1/admin/users": () => page([]), "GET /v1/admin/audit": () => page([]), "GET /v1/admin/audit/102": () => signIn });
    renderApp("/admin/audit?record=102");
    expect(await screen.findByRole("heading", { level: 1, name: "Signed in" })).toBeInTheDocument();
    expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
  });
});

describe("audit helpers", () => {
  it("labels actions, spelling out unknown ones", () => {
    expect(actionLabel("team.member_add")).toBe("Added member");
    expect(actionLabel("gateway.tool_select")).toBe("Gateway: tool select");
    expect(actorName({ kind: "system" })).toBe("System");
    expect(actorName({ kind: "user", email: "a@example.com" })).toBe("a@example.com");
  });

  it("offers platform areas only in the platform log, and maps the System person", () => {
    expect(areaOptions(false).map((o) => o.value)).not.toContain("auth.");
    expect(areaOptions(true).map((o) => o.value)).toEqual(expect.arrayContaining(["team.", "platform.", "auth.", "team.invite_create"]));
    expect(personFilter("system")).toEqual({ actorKind: "system" });
    expect(personFilter("abc")).toEqual({ actorUserId: "abc" });
    expect(personFilter(undefined)).toEqual({});
  });

  it("puts a change in words", () => {
    expect(auditChange(suspend)).toEqual({ before: { Status: "Active" }, after: { Status: "Suspended" } });
    expect(changeSummary(auditEntry())).toBe("Role Member → Editor");
    expect(changeSummary(signIn)).toBeNull();
    expect(plainKey("ownerEmail")).toBe("Owner email");
    expect(plainKey("mcp_server_ids")).toBe("MCP server IDs");
    expect(valueText(undefined)).toBe("Not set");
    expect(valueText(["a", "b"])).toBe("a, b");
  });

  it("writes CSV with quoted fields", () => {
    expect(toCSV(["a", "b"], [["x,y", { k: 1 }]])).toBe('a,b\r\n"x,y","{""k"":1}"\r\n');
  });
});
