/* Call records: rows link to a call's page; recorded contents load only on request, as text; rate-limited calls; the new audit words. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { auditChange, changedRows } from "../components/audit/changes";
import { actionLabel, areaOf, targetTypeLabel } from "../components/audit/labels";
import { AuditTarget } from "../components/audit/target";
import { partText } from "../components/gateways/call-payload";
import { auditEntry, gateway, gatewayCapabilities, gatewayId, mcpCall, myGateway, page, team } from "./fixtures";
import { callPayload } from "./fixtures-operations";
import { type Call, type Handler, Reply, mockApi, renderApp, renderBare, shellRoutes } from "./harness";

const teamApi = `/v1/teams/${team.slug}`;
const payloadUrl = `${teamApi}/calls/501/payload`;
const payloads = (calls: Call[], url = payloadUrl) => calls.filter((c) => c.url === url);

const teamRoutes = (role: "owner" | "admin" | null, platformRole: "none" | "platform_auditor" = "none", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(platformRole, role),
  [`GET ${teamApi}/gateways/${gatewayId}`]: () => gateway(),
  [`GET ${teamApi}/gateways/${gatewayId}/capabilities`]: () => gatewayCapabilities(),
  [`GET ${teamApi}/calls`]: () =>
    page([
      mcpCall({ captured: true }),
      mcpCall({ id: 502, outcome: "rate_limited", errorClass: "person_per_minute", latencyMs: 0, responseBytes: 0, requestId: "req-call-2" }),
    ]),
  [`GET ${teamApi}/calls/501`]: () => mcpCall({ captured: true }),
  [`GET ${payloadUrl}`]: () => callPayload(),
  "GET /v1/me/gateways": () => [myGateway()],
  ...extra,
});

describe("Call lists", () => {
  it("link each call to its page, mark recorded ones and name rate-limited calls", async () => {
    mockApi(teamRoutes("owner"));
    renderApp(`/teams/${team.slug}/gateways/${gatewayId}?tab=activity`);
    const table = await screen.findByRole("table", { name: "Calls" });
    const links = await within(table).findAllByRole("link", { name: "service-status__get_status" });
    expect(links[0]).toHaveAttribute("href", `/teams/${team.slug}/calls/501`);
    expect(links[0]!.closest("tr")).toHaveTextContent("Recorded");
    const limited = within(table).getAllByRole("link", { name: "service-status__get_status" })[1]!.closest("tr")!;
    expect(limited).toHaveTextContent("Rate limited");
    expect(limited).toHaveTextContent("Over the per-person limit");
    expect(limited).not.toHaveTextContent("Recorded");
  });
});

describe("A call's page", () => {
  it("shows the class recorded at call time, not a live server classification", async () => {
    mockApi(teamRoutes("owner", "none", { [`GET ${teamApi}/calls/501`]: () => mcpCall({ toolClass: "write" }) }));
    renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByText("Tool class at call time")).toBeInTheDocument();
    expect(screen.getByText("write")).toBeInTheDocument();
  });

  it("loads the contents only when asked, after saying viewing is recorded, and shows them as text", async () => {
    const u = userEvent.setup();
    const live = mockApi(teamRoutes("owner"));
    const { container } = renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByRole("heading", { level: 1, name: "service-status__get_status" })).toBeInTheDocument();
    expect(screen.getByText("Contents recorded")).toBeInTheDocument();
    expect(screen.getByText(/Viewing the contents is recorded in the audit log/)).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe(`Call 501 · ${team.name} · Open MCP Portal`));
    expect(await axe(container)).toHaveNoViolations();
    // Nothing is fetched (or audited) until the person asks.
    expect(payloads(live)).toHaveLength(0);

    await u.click(screen.getByRole("button", { name: "View contents" }));
    expect(await screen.findByText(/"service": "<img src=x onerror=alert\(1\)>"/)).toBeInTheDocument();
    expect(payloads(live)).toHaveLength(1);
    // The recorded markup is text, never HTML.
    const card = screen.getByRole("heading", { name: "Contents" }).closest("section")!;
    expect(card.querySelector("img")).toBeNull();
    expect(card.querySelector("b")).toBeNull();
    expect(card).toHaveTextContent('"text":"<b>up</b>');
    expect(screen.getByText("Cut to 16 KiB")).toBeInTheDocument();
    expect(screen.getAllByText("1 value redacted").length).toBeGreaterThan(0);
    expect(screen.getByText("Result (40,000 bytes)")).toBeInTheDocument();
    expect(screen.getByText("the gateway")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says when the contents are gone (404 payload_not_found)", async () => {
    const u = userEvent.setup();
    mockApi({ ...teamRoutes("admin"), [`GET ${payloadUrl}`]: () => Reply.error(404, "payload_not_found", "gone") });
    renderApp(`/teams/${team.slug}/calls/501`);
    await u.click(await screen.findByRole("button", { name: "View contents" }));
    expect(await screen.findByText("The contents are gone")).toBeInTheDocument();
  });

  it("sends platform staff on a team's page to Admin for the contents", async () => {
    // The team route never says "captured" to platform staff; the Admin record (metadata, not audited) does.
    const staffRoutes = (captured: boolean) =>
      teamRoutes(null, "platform_auditor", { [`GET ${teamApi}/calls/501`]: () => mcpCall({ captured: false }), "GET /v1/admin/calls/501": () => mcpCall({ captured }) });
    const calls = mockApi(staffRoutes(true));
    const { unmount } = renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByRole("link", { name: "open this call in Admin" })).toHaveAttribute("href", "/admin/calls/501");
    expect(screen.queryByRole("button", { name: "View contents" })).toBeNull();
    expect(payloads(calls)).toHaveLength(0);
    expect(payloads(calls, "/v1/admin/calls/501/payload")).toHaveLength(0);
    unmount();

    // Not recorded: no pointer.
    const quiet = mockApi(staffRoutes(false));
    renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByRole("heading", { level: 1, name: "service-status__get_status" })).toBeInTheDocument();
    await waitFor(() => expect(quiet.some((c) => c.url === "/v1/admin/calls/501")).toBe(true));
    expect(screen.queryByRole("link", { name: "open this call in Admin" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Contents" })).toBeNull();
  });

  it("team owners don't look the call up in Admin", async () => {
    const calls = mockApi(teamRoutes("owner"));
    renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByRole("button", { name: "View contents" })).toBeInTheDocument();
    expect(calls.some((c) => c.url.startsWith("/v1/admin/"))).toBe(false);
  });

  it("explains a refusal (403) without offering to try again", async () => {
    mockApi(teamRoutes("owner", "none", { [`GET ${teamApi}/calls/501`]: () => Reply.error(403, "forbidden", "Forbidden") }));
    renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByRole("heading", { level: 1, name: "No access to this call" })).toBeInTheDocument();
    expect(screen.getByText("Call records are for the team's owners and admins.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /try again/i })).toBeNull();
  });

  it("in Admin reads the contents through the admin route", async () => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes("platform_auditor", null),
      "GET /v1/admin/calls/501": () => mcpCall({ captured: true }),
      "GET /v1/admin/calls/501/payload": () => callPayload({ capturedBy: ["gateway", "server"], result: null }),
    });
    renderApp("/admin/calls/501");
    expect(await screen.findByRole("link", { name: "Support tools" })).toHaveAttribute("href", `/admin/gateways/${gatewayId}`);
    await waitFor(() => expect(document.title).toBe("Call 501 · Calls · Open MCP Portal"));
    await u.click(screen.getByRole("button", { name: "View contents" }));
    expect(await screen.findByText("the gateway and the server")).toBeInTheDocument();
    expect(screen.getByText(/Nothing was received/)).toBeInTheDocument();
    expect(payloads(calls, "/v1/admin/calls/501/payload")).toHaveLength(1);
  });

  it("shows the trace of a sampled call, as a link when the deployment has a trace viewer", async () => {
    const traceId = "0af7651916cd43dd8448eb211c80319c";
    const url = `https://traces.example.com/trace/${traceId}`;
    mockApi(teamRoutes("owner", "none", { [`GET ${teamApi}/calls/501`]: () => mcpCall({ traceId, traceUrl: url }) }));
    renderApp(`/teams/${team.slug}/calls/501`);
    const link = await screen.findByRole("link", { name: traceId });
    expect(link).toHaveAttribute("href", url);
    expect(link).toHaveAttribute("rel", expect.stringContaining("noreferrer"));
  });

  it("shows only the trace ID without a link template, and nothing for an untraced call", async () => {
    const traceId = "0af7651916cd43dd8448eb211c80319c";
    mockApi(teamRoutes("owner", "none", { [`GET ${teamApi}/calls/501`]: () => mcpCall({ traceId }) }));
    renderApp(`/teams/${team.slug}/calls/501`);
    expect(await screen.findByText(traceId)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: traceId })).toBeNull();
  });

  it("has no Trace row for a call without a trace", async () => {
    mockApi(teamRoutes("owner"));
    renderApp(`/teams/${team.slug}/calls/501`);
    await screen.findByText("req-call-1");
    expect(screen.queryByText("Trace")).toBeNull();
  });

  it("isn't found for an unknown call", async () => {
    mockApi({ ...shellRoutes("platform_admin", null), "GET /v1/admin/calls/9": () => Reply.error(404, "call_not_found") });
    renderApp("/admin/calls/9");
    expect(await screen.findByRole("heading", { level: 1, name: "Not found" })).toBeInTheDocument();
  });

  it("pretty-prints JSON parts and leaves cut ones as recorded", () => {
    expect(partText({ content: '{"a":1}', bytes: 7, truncated: false, redactions: 0 })).toBe('{\n  "a": 1\n}');
    expect(partText({ content: '{"a":', bytes: 90000, truncated: true, redactions: 0 })).toBe('{"a":');
  });
});

describe("Phase 6 audit words", () => {
  it("names the new actions, areas and targets", () => {
    expect(actionLabel("settings.limits_update")).toBe("Changed rate limits");
    expect(actionLabel("team.retention_update")).toBe("Changed team retention");
    expect(actionLabel("settings.capture_update")).toBe("Changed redaction patterns");
    expect(actionLabel("mcp_call.payload_view", { metadata: { via: "admin" } })).toBe("Viewed call contents in Admin");
    expect(actionLabel("mcp_call.payload_view", { metadata: { via: "team" } })).toBe("Viewed call contents on the team's page");
    expect(areaOf("mcp_call.payload_view")).toBe("Call contents");
    expect(areaOf("retention.purge")).toBe("Retention");
    expect(targetTypeLabel("mcp_call")).toBe("Call");
  });

  it("shows limit, retention, pattern and switch changes in words", () => {
    const limits = { action: "settings.limits_update", before: { items: [{ key: "person_per_minute", default: 600, ceiling: null }] }, after: { items: [{ key: "person_per_minute", default: 500, ceiling: null }] } };
    expect(changedRows(auditChange(limits))).toEqual([{ field: "Rate limits", before: ["Per person: 600/min"], after: ["Per person: 500/min"] }]);
    const team = { action: "team.limits_update", before: { items: [{ key: "gateway_per_minute", value: null }] }, after: { items: [{ key: "gateway_per_minute", value: 2000 }] } };
    expect(changedRows(auditChange(team))).toEqual([{ field: "Rate limits", before: ["Per gateway: inherit"], after: ["Per gateway: 2,000/min"] }]);
    const periods = { action: "settings.retention_update", before: { periods: [{ kind: "captured_payloads", days: 14 }] }, after: { periods: [{ kind: "captured_payloads", days: 7 }] } };
    expect(changedRows(auditChange(periods))[0]?.after).toEqual(["Recorded call contents: 7 days"]);
    const patterns = { action: "settings.capture_update", before: { patterns: [] }, after: { patterns: [{ pattern: "EMP-[0-9]{6}", note: "Employees" }] } };
    expect(changedRows(auditChange(patterns))[0]?.after).toEqual(["EMP-[0-9]{6} · Employees"]);
    const gw = { action: "gateway.update", before: { capturePayloads: false }, after: { capturePayloads: true } };
    expect(changedRows(auditChange(gw))).toEqual([{ field: "Record call contents", before: "Off", after: "On" }]);
  });

  it("links a viewed call to its page", () => {
    const e = auditEntry({ action: "mcp_call.payload_view", targetType: "mcp_call", targetId: "501", targetLabel: "service-status__get_status", before: null, after: null, metadata: { via: "admin" } });
    const { unmount } = renderBare(<AuditTarget entry={e} scope={{ kind: "platform" }} />);
    return screen.findByRole("link", { name: "service-status__get_status" }).then((link) => {
      expect(link).toHaveAttribute("href", "/admin/calls/501");
      unmount();
      renderBare(<AuditTarget entry={e} scope={{ kind: "team", team: team.slug }} />);
      return screen.findByRole("link", { name: "service-status__get_status" }).then((l) => expect(l).toHaveAttribute("href", `/teams/${team.slug}/calls/501`));
    });
  });
});
