import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { teamServerQuery } from "../api/queries";
import { lowersClass } from "../components/servers/classification";
import { capabilities, capability, healthCheck, mcpServer, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, mockApi, renderApp, Reply, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers/${serverId}`;
const record = `/teams/${team.slug}/servers/${serverId}?tab=capabilities`;
const server = mcpServer({ publishState: "published" });
const routes = (role: Schemas["TeamRole"] = "owner", caps = capabilities, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => server,
  [`GET ${base}/capabilities`]: () => caps,
  [`GET ${base}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  ...extra,
});

describe("Owner-set tool classification", () => {
  it("shows suggestions separately without saving them; owners can accept them in an atomic batch", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", capabilities, {
      [`PUT ${base}/capabilities/classes`]: (body) => (body as Schemas["CapabilityClassesInput"]).items.map((item) => capability({ id: item.capabilityId, toolClass: item.toolClass })),
    }));
    const { container } = renderApp(record);
    const tool = await screen.findByRole("listitem", { name: "tool: get_status" });
    expect(within(tool).getByText("Unclassified")).toBeInTheDocument();
    expect(within(tool).getByText("Suggested: read")).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(0);
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Classify tools…" }));
    const dialog = await screen.findByRole("dialog", { name: "Classify tools" });
    expect(within(dialog).getAllByRole("combobox")).toHaveLength(2);
    expect(within(dialog).getByRole("button", { name: "Save classes" })).toBeDisabled();
    await u.click(within(dialog).getByRole("button", { name: "Use suggestions" }));
    expect(within(dialog).getByRole("combobox", { name: "Class for get_status" })).toHaveValue("read");
    expect(within(dialog).getByRole("combobox", { name: "Class for restart" })).toHaveValue("destructive");
    expect(within(dialog).getByText("The server will leave the catalog")).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await u.click(within(dialog).getByRole("button", { name: "Save classes" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.headers.get("If-Match")).toBe('"4"');
    expect(put.body).toEqual({ items: [
      { capabilityId: capabilities[0]!.id, toolClass: "read", viaSuggestion: true },
      { capabilityId: capabilities[1]!.id, toolClass: "destructive", viaSuggestion: true },
    ] });
  });

  it("saves an individual explicit class and warns only when lowering", async () => {
    const u = userEvent.setup();
    const cap = capability({ toolClass: "write", classDrift: true });
    const calls = mockApi(routes("admin", [cap], {
      [`PUT ${base}/capabilities/${cap.id}/class`]: (body) => capability({ toolClass: (body as Schemas["CapabilityClassInput"]).toolClass }),
    }));
    renderApp(record);
    expect(await screen.findByText("Class: write")).toBeInTheDocument();
    expect(screen.getByText("Class differs from suggestion")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Classify get_status" }));
    const dialog = await screen.findByRole("dialog", { name: "Classify get_status" });
    const select = within(dialog).getByRole("combobox", { name: "Class for get_status" });
    await u.selectOptions(select, "destructive");
    expect(within(dialog).queryByText("The server will leave the catalog")).toBeNull();
    await u.selectOptions(select, "read");
    expect(within(dialog).getByText("The server will leave the catalog")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Save classes" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ toolClass: "read", viaSuggestion: false }));
  });

  it("clears a class explicitly without treating it as read", async () => {
    const u = userEvent.setup();
    const cap = capability({ toolClass: "read" });
    const calls = mockApi(routes("owner", [cap], {
      [`PUT ${base}/capabilities/${cap.id}/class`]: () => capability(),
    }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Classify get_status" }));
    const dialog = await screen.findByRole("dialog");
    await u.selectOptions(within(dialog).getByRole("combobox"), "");
    expect(within(dialog).queryByText("The server will leave the catalog")).toBeNull();
    await u.click(within(dialog).getByRole("button", { name: "Save classes" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ toolClass: null, viaSuggestion: false }));
  });

  it("never retries stale edits with a newer revision without another review", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", [capability()], {
      [`PUT ${base}/capabilities/${capabilities[0]!.id}/class`]: () => Reply.error(412, "stale_revision", "The server changed"),
    }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Classify get_status" }));
    const dialog = await screen.findByRole("dialog");
    await u.selectOptions(within(dialog).getByRole("combobox"), "read");
    await u.click(within(dialog).getByRole("button", { name: "Save classes" }));
    expect(await within(dialog).findByText(/Close this dialog and review the refreshed tools/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Save classes" })).toBeDisabled();
    expect(within(dialog).getByRole("combobox")).toBeDisabled();
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
  });

  it("keeps the reviewed revision when the server refetches while the dialog is open", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", [capability()], {
      [`PUT ${base}/capabilities/${capabilities[0]!.id}/class`]: () => capability({ toolClass: "read" }),
    }));
    const { qc } = renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Classify get_status" }));
    const dialog = await screen.findByRole("dialog");
    await u.selectOptions(within(dialog).getByRole("combobox"), "read");
    act(() => { qc.setQueryData(teamServerQuery(team.slug, serverId).queryKey, { ...server, revision: 9 }); });
    await u.click(within(dialog).getByRole("button", { name: "Save classes" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.headers.get("If-Match")).toBe('"4"'));
  });

  it("requires another review after a changed suggestion is refused", async () => {
    const u = userEvent.setup();
    mockApi(routes("owner", [capability()], {
      [`PUT ${base}/capabilities/${capabilities[0]!.id}/class`]: () => Reply.error(409, "suggestion_changed", "The suggestion changed"),
    }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Classify get_status" }));
    const dialog = await screen.findByRole("dialog");
    await u.click(within(dialog).getByRole("button", { name: "Use suggestions" }));
    await u.click(within(dialog).getByRole("button", { name: "Save classes" }));
    expect(await within(dialog).findByText(/Close this dialog and review the refreshed tools/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Save classes" })).toBeDisabled();
  });

  it("keeps archived teams read-only even for an owner", async () => {
    mockApi(routes("owner", [capability()], {
      [`GET /v1/teams/${team.slug}`]: () => ({ team: { ...team, status: "archived" }, role: "owner" }),
    }));
    renderApp(record);
    await screen.findByRole("listitem", { name: "tool: get_status" });
    expect(screen.queryByRole("button", { name: /Classify/ })).toBeNull();
  });

  it.each(["editor", "member"] as const)("allows %s to read but not classify", async (role) => {
    mockApi(routes(role, [capability({ toolClass: "destructive" })]));
    renderApp(record);
    expect(await screen.findByText("Class: destructive")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Classify/ })).toBeNull();
  });

  it("keeps gone tools out of the classification dialog", async () => {
    mockApi(routes("owner", [capability({ goneAt: "2026-10-20T12:00:00Z" })]));
    renderApp(record);
    await screen.findByRole("listitem", { name: "tool: get_status" });
    expect(screen.queryByRole("button", { name: /Classify/ })).toBeNull();
  });

  it("shows platform reviewers the class without classification controls", async () => {
    mockApi({
      ...shellRoutes("platform_admin", null),
      [`GET /v1/admin/mcp-servers/${serverId}`]: () => server,
      [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => [capability({ toolClass: "write" })],
      [`GET /v1/admin/mcp-servers/${serverId}/health-checks`]: () => [],
    });
    renderApp(`/admin/servers/${serverId}?tab=capabilities`);
    expect(await screen.findByText("Class: write")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Classify/ })).toBeNull();
  });
});

describe("Class lowering", () => {
  it("is conservative for unclassified tools but not clearing or raising", () => {
    expect(lowersClass(null, "read")).toBe(true);
    expect(lowersClass(null, "write")).toBe(true);
    expect(lowersClass(null, "destructive")).toBe(false);
    expect(lowersClass("destructive", "write")).toBe(true);
    expect(lowersClass("write", "read")).toBe(true);
    expect(lowersClass("read", "write")).toBe(false);
    expect(lowersClass("destructive", null)).toBe(false);
    expect(lowersClass("read", "read")).toBe(false);
  });
});
