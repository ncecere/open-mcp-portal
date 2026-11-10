/* v0.2 in the audit logs: labels and areas for notification and token actions, and the actor of an automation token. */
import { screen, within } from "@testing-library/react";
import { axe } from "vitest-axe";
import { auditChange, changedRows, changeSummary } from "../components/audit/changes";
import { actedHow, actionLabel, actorName, areaOf, areaOptions, personFilter, targetTypeLabel, tokenKindLabel } from "../components/audit/labels";
import { auditEntry, page, team } from "./fixtures";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const tokenActor = { kind: "automation_token", automationTokenId: "99999999-0000-4000-8000-000000000001", automationTokenName: "CI publisher", automationTokenKind: "team_publisher" } as const;
const byToken = auditEntry({
  id: 301,
  actorKind: "automation_token",
  actorUserId: null,
  actor: tokenActor,
  via: null,
  action: "mcp_server.update",
  targetType: "mcp_server",
  targetLabel: "Service status",
  before: null,
  after: null,
});

describe("audit labels for v0.2", () => {
  it("names the notification and token actions and their areas", () => {
    expect(actionLabel("notification_destination.create")).toBe("Added webhook destination");
    expect(actionLabel("notification_destination.rotate_secret")).toBe("Rotated webhook signing secret");
    expect(actionLabel("notification_destination.disable")).toBe("Webhook destination stopped after repeated failures");
    expect(actionLabel("settings.notifications_test_email")).toBe("Sent a test email");
    expect(actionLabel("automation_token.create")).toBe("Created automation token");
    expect(actionLabel("automation_token.revoke")).toBe("Revoked automation token");
    expect(actionLabel("automation_token.pepper_rehash")).toBe("Re-secured automation token after key rotation");
    expect(areaOf("notification_destination.test")).toBe("Webhook destinations");
    expect(areaOf("automation_token.create")).toBe("Automation tokens");
    expect(areaOf("settings.notifications_test_email")).toBe("Platform settings");
    expect(targetTypeLabel("notification_destination")).toBe("Webhook destination");
    expect(targetTypeLabel("automation_token")).toBe("Automation token");
    // Both areas are offered in a team's log too: team destinations and tokens are audited there.
    const teamAreas = areaOptions(false).map((o) => o.label);
    expect(teamAreas).toContain("Webhook destinations (all)");
    expect(teamAreas).toContain("Automation tokens (all)");
    expect(areaOptions(false).map((o) => o.value)).toContain("automation_token.revoke");
  });

  it("shows what changed in words, and never a URL", () => {
    const e = {
      action: "notification_destination.update",
      before: { name: "Pager", events: ["server.unhealthy"], enabled: true, urlDisplay: "https://hooks.example.com/..." },
      after: { name: "Pager", events: ["server.unhealthy", "key.expiring"], enabled: false, urlDisplay: "https://hooks.example.com/..." },
    };
    expect(changedRows(auditChange(e))).toEqual([
      { field: "Events", before: ["A server is failing"], after: ["A server is failing", "A key or token expires soon"] },
      { field: "Enabled", before: "On", after: "Off" },
    ]);
    expect(changeSummary({ action: "notification_destination.update", before: { enabled: true }, after: { enabled: false } })).toBe("Enabled On → Off");
    const t = auditChange({ action: "automation_token.create", before: null, after: { kind: "platform_admin", scopes: ["platform:read"], expiresAt: "2027-01-01T00:00:00Z" } });
    expect(t.after).toEqual({ Kind: "Platform admin token", Can: ["platform:read"], Expires: "2027-01-01T00:00:00Z" });
  });

  it("names an automation token's actor by its recorded name, with its kind", () => {
    expect(actorName(tokenActor)).toBe("CI publisher");
    expect(actorName({ kind: "automation_token" })).toBe("Automation token");
    expect(tokenKindLabel(tokenActor)).toBe("Team publisher token");
    expect(tokenKindLabel({ ...tokenActor, automationTokenKind: "platform_admin" })).toBe("Platform admin token");
    expect(tokenKindLabel({ kind: "user" })).toBeUndefined();
    expect(actedHow({ actor: tokenActor, metadata: {} })).toBe("Automation token (team publisher)");
  });

  it("filters by automation tokens through actorKind", () => {
    expect(personFilter("automation_token")).toEqual({ actorKind: "automation_token" });
    expect(personFilter("system")).toEqual({ actorKind: "system" });
    expect(personFilter("abc")).toEqual({ actorUserId: "abc" });
  });
});

describe("audit logs show automation tokens", () => {
  it("lists a token's action in the platform log with its name and kind", async () => {
    mockApi({ ...shellRoutes("platform_auditor"), "GET /v1/admin/users": () => page([]), "GET /v1/admin/audit": () => page([byToken]) });
    const { container } = renderApp("/admin/audit");
    const table = await screen.findByRole("table", { name: "Audit log" });
    const row = (await within(table).findByText("Changed MCP server")).closest("tr")!;
    expect(within(row).getByText("CI publisher")).toBeInTheDocument();
    expect(within(row).getByText("Team publisher token")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("filters the platform log to automation tokens (Person: Automation tokens)", async () => {
    const calls = mockApi({ ...shellRoutes("platform_auditor"), "GET /v1/admin/users": () => page([]), "GET /v1/admin/audit": () => page([byToken]) });
    renderApp("/admin/audit?person=automation_token");
    expect(await screen.findByText("Changed MCP server")).toBeInTheDocument();
    expect(calls.filter((c) => c.url === "/v1/admin/audit").at(-1)?.search.get("actorKind")).toBe("automation_token");
    expect(screen.getAllByText("Automation tokens").length).toBeGreaterThan(0);
  });

  it("shows the token as the actor in a team's log, with the same filter", async () => {
    const calls = mockApi({
      ...shellRoutes("none", "admin"),
      [`GET /v1/teams/${team.slug}/audit`]: () => page([byToken]),
      [`GET /v1/teams/${team.slug}/audit/${byToken.id}`]: () => byToken,
    });
    renderApp(`/teams/${team.slug}/settings?tab=audit`);
    const row = (await screen.findByText("Changed MCP server")).closest("tr")!;
    expect(within(row).getByText("CI publisher")).toBeInTheDocument();
    expect(within(row).getByText("Team publisher token")).toBeInTheDocument();
    expect(calls.some((c) => c.url === `/v1/teams/${team.slug}/audit`)).toBe(true);
  });
});
