/* Contract/UI evidence with mocked responses, not functional backend acceptance. */
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { rulesKey } from "../api/approvals";
import { approvalRule, capabilityId, deferred, requesterId, ruleId } from "./fixtures-approvals";
import { gateway, gatewayId, mcpServer, serverId, team } from "./fixtures";
import { mockApi, renderApp, Reply, shellRoutes, type Handler } from "./harness";

const base = `/v1/teams/${team.slug}/approval-rules`;
const path = `/teams/${team.slug}/approval-rules`;
const adminBase = "/v1/admin/approval-rules";
const routes = (role: Schemas["TeamRole"] | null = "owner", platform: Schemas["PlatformRole"] = "none", extra: Record<string, Handler> = {}) => ({
  ...shellRoutes(platform, role),
  [`GET ${base}`]: () => ({ items: [approvalRule()], nextCursor: null }),
  [`GET ${adminBase}`]: () => ({ items: [approvalRule(), approvalRule({ id: "platform-rule", teamId: null, name: "Platform review", targetKind: "gateway", targetId: gatewayId })], nextCursor: null }),
  [`GET /v1/teams/${team.slug}/mcp-servers`]: () => ({ items: [mcpServer()], nextCursor: null }),
  [`GET /v1/teams/${team.slug}/gateways`]: () => ({ items: [gateway()], nextCursor: null }),
  "GET /v1/admin/gateways": () => ({ items: [gateway({ ownerKind: "platform", teamId: undefined })], nextCursor: null }),
  ...extra,
});

describe("Approval rules access and metadata", () => {
  it.each(["member", "editor"] as const)("does not request or expose rules for team %s", async (role) => {
    const calls = mockApi(routes(role));
    const { container } = renderApp(path);
    await screen.findByRole("heading", { level: 1, name: "No access" });
    expect(calls.some((c) => c.url === base)).toBe(false);
    expect(screen.queryByRole("link", { name: "Approval rules" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it.each(["platform_admin", "platform_auditor"] as const)("lets nonmember %s read team rules but not write", async (platform) => {
    mockApi(routes(null, platform));
    const { container } = renderApp(path);
    await screen.findByRole("heading", { name: "Review destructive calls" });
    expect(screen.queryByRole("button", { name: "Create approval rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Edit Review/ })).toBeNull();
    expect(screen.getByText(/Read-only. Team rule writes require active owner\/admin membership/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows platform admins both scopes but only platform-owned rule write controls in Admin", async () => {
    mockApi(routes(null, "platform_admin"));
    const { container } = renderApp("/admin/approval-rules");
    await screen.findByRole("heading", { name: "Platform review" });
    expect(screen.getByRole("button", { name: "Create approval rule" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Edit Platform review" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit Review destructive calls" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("keeps auditors' platform rules read-only", async () => {
    mockApi(routes(null, "platform_auditor"));
    renderApp("/admin/approval-rules");
    await screen.findByRole("heading", { name: "Platform review" });
    expect(screen.queryByRole("button", { name: "Create approval rule" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Edit Platform/ })).toBeNull();
  });

  it("rejects ordinary users at the root admin gate without loading rules", async () => {
    const calls = mockApi(routes("owner"));
    renderApp("/admin/approval-rules");
    await screen.findByRole("heading", { level: 1, name: "No access" });
    expect(calls.some((c) => c.url === adminBase)).toBe(false);
  });

  it("paginates rules and shows backend load errors", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", "none", { [`GET ${base}`]: (_body, c) => c.search.has("cursor") ? Reply.error(403, "forbidden", "Rules unavailable") : { items: [approvalRule()], nextCursor: "rule-next" } }));
    renderApp(path);
    await screen.findByRole("heading", { name: "Review destructive calls" });
    await u.click(screen.getByRole("button", { name: /next page/i }));
    await screen.findByText("Rules unavailable");
    expect(calls.filter((c) => c.url === base).at(-1)?.search.get("cursor")).toBe("rule-next");
  });
});

describe("Approval rule editor", () => {
  it("creates a class rule with documented defaults, exact group names, no metadata, and accessible fields", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("admin", "none", { [`POST ${base}`]: () => approvalRule() }));
    const { container } = renderApp(path);
    await u.click(await screen.findByRole("button", { name: "Create approval rule" }));
    await u.type(await screen.findByRole("textbox", { name: "Rule name" }), "Critical review");
    const target = await screen.findByRole("combobox", { name: "Target" });
    await waitFor(() => expect(within(target).getByRole("option", { name: new RegExp(serverId) })).toBeInTheDocument());
    await u.selectOptions(target, serverId);
    expect(screen.getByRole("spinbutton", { name: "Pending lifetime (minutes)" })).toHaveValue(1440);
    expect(screen.getByRole("spinbutton", { name: "Approved validity (minutes)" })).toHaveValue(15);
    expect(screen.getByRole("checkbox", { name: "Allow requesting service account's owners/admins to review" })).not.toBeChecked();
    await u.type(screen.getByRole("textbox", { name: "Approver user IDs" }), requesterId);
    await u.type(screen.getByRole("textbox", { name: "Approver SSO groups" }), "Risk, Security\nProduction Owners");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Create rule" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      name: "Critical review", targetKind: "server", targetId: serverId, capabilityId: null, classes: ["destructive"], enabled: true, pendingMinutes: 1440, validMinutes: 15, allowServiceAccountAdmins: false,
      approvers: [{ kind: "user", userId: requesterId, groupName: null }, { kind: "group", userId: null, groupName: "Risk, Security" }, { kind: "group", userId: null, groupName: "Production Owners" }],
    });
  });

  it("binds If-Match and the immutable target; capability selection excludes classes and pending fields stay frozen", async () => {
    const u = userEvent.setup();
    const response = deferred<ReturnType<typeof approvalRule>>();
    const calls = mockApi(routes("owner", "none", { [`PUT ${base}/${ruleId}`]: () => response.promise }));
    renderApp(path);
    await u.click(await screen.findByRole("button", { name: "Edit Review destructive calls" }));
    expect(await screen.findByText(/This target cannot be changed/)).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Target kind" })).toBeNull();
    await u.selectOptions(screen.getByRole("combobox", { name: "Match by" }), "capability");
    await u.type(screen.getByRole("textbox", { name: "Tool capability ID" }), capabilityId);
    await u.click(screen.getByRole("checkbox", { name: "Allow requesting service account's owners/admins to review" }));
    await u.click(screen.getByRole("button", { name: "Save rule" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    expect(screen.getByRole("textbox", { name: "Rule name" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Match by" })).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Enabled" })).toHaveAttribute("aria-disabled", "true");
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.headers.get("If-Match")).toBe('"5"');
    expect(put.body).toEqual({ name: "Review destructive calls", targetKind: "server", targetId: serverId, capabilityId, classes: [], enabled: true, pendingMinutes: 1440, validMinutes: 15, allowServiceAccountAdmins: true, approvers: [] });
    await act(async () => response.resolve(approvalRule({ revision: 6 })));
    await waitFor(() => expect(screen.queryByRole("textbox", { name: "Rule name" })).toBeNull());
  });

  it("explains invalid reviewer IDs and exclusive selectors without sending a request", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(path);
    await u.click(await screen.findByRole("button", { name: "Edit Review destructive calls" }));
    await u.type(await screen.findByRole("textbox", { name: "Approver user IDs" }), "not-a-user-uuid");
    await u.click(screen.getByRole("button", { name: "Save rule" }));
    await screen.findByText(/Each approver user must be an active user's UUID/);
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(0);
    await u.clear(screen.getByRole("textbox", { name: "Approver user IDs" }));
    await u.click(screen.getByRole("checkbox", { name: "Destructive" }));
    await u.click(screen.getByRole("button", { name: "Save rule" }));
    expect(await screen.findByText(/Choose at least one tool class/)).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(0);
  });

  it("shows ambiguity 409 and stale 412 errors without automatically retrying or replacing the edited revision", async () => {
    const u = userEvent.setup();
    let stale = false;
    const calls = mockApi(routes("owner", "none", { [`PUT ${base}/${ruleId}`]: () => stale ? Reply.error(412, "revision_mismatch") : Reply.error(409, "ambiguous_rule", "Equal-priority overlap") }));
    renderApp(path);
    await u.click(await screen.findByRole("button", { name: "Edit Review destructive calls" }));
    await u.click(await screen.findByRole("button", { name: "Save rule" }));
    await screen.findByText("Equal-priority overlap");
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
    stale = true;
    await u.click(screen.getByRole("button", { name: "Save rule" }));
    await screen.findByText(/This revision changed. Close this editor/);
    expect(screen.getByRole("button", { name: "Save rule" })).toBeDisabled();
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(2);
  });

  it("uses only platform gateway targets for platform creation", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(null, "platform_admin"));
    const { container } = renderApp("/admin/approval-rules");
    await u.click(await screen.findByRole("button", { name: "Create approval rule" }));
    const kind = await screen.findByRole("combobox", { name: "Target kind" });
    expect(kind).toBeDisabled();
    expect(within(kind).queryByRole("option", { name: "Server" })).toBeNull();
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Target" })).toBeEnabled());
    expect(calls.find((c) => c.url === "/v1/admin/gateways")?.search.get("ownerKind")).toBe("platform");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("ignores late save closure after cancelling and reopening an editor", async () => {
    const u = userEvent.setup();
    const response = deferred<ReturnType<typeof approvalRule>>();
    mockApi(routes("owner", "none", { [`PUT ${base}/${ruleId}`]: () => response.promise }));
    const { qc } = renderApp(path);
    await u.click(await screen.findByRole("button", { name: "Edit Review destructive calls" }));
    await u.click(await screen.findByRole("button", { name: "Save rule" }));
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Rule name" })).toBeDisabled());
    await u.click(screen.getByRole("button", { name: "Cancel" }));
    await u.click(await screen.findByRole("button", { name: "Create approval rule" }));
    await screen.findByRole("textbox", { name: "Rule name" });
    await act(async () => { response.resolve(approvalRule({ revision: 6 })); await qc.invalidateQueries({ queryKey: rulesKey(team.slug) }); });
    expect(screen.getByRole("heading", { name: "Create approval rule", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Rule name" })).toBeEnabled();
  });

  it("deletes with the displayed If-Match revision and refuses a stale delete retry until reviewed again", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", "none", { [`DELETE ${base}/${ruleId}`]: () => Reply.error(412, "revision_mismatch") }));
    renderApp(path);
    await u.click(await screen.findByRole("button", { name: "Delete Review destructive calls" }));
    const dialog = await screen.findByRole("alertdialog");
    await u.click(within(dialog).getByRole("button", { name: "Delete rule" }));
    await screen.findByText(/This revision changed. Close this dialog/);
    expect(calls.find((c) => c.method === "DELETE")?.headers.get("If-Match")).toBe('"5"');
    await u.click(within(dialog).getByRole("button", { name: "Reload rules" }));
    expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(1);
  });
});
