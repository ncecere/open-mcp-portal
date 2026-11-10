/* A gateway's Capabilities tab and the picker: grouping, availability, minimum roles, If-Match, conflicts and refused selections (422). */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import g from "../components/gateways/gateways.module.css";
import type { Schemas } from "../api/client";
import { catalogServerId, gateway, gatewayCapabilities, gatewayCapability, gatewayId, gatewayOption, gatewayOptions, optionsPage, page, team } from "./fixtures";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

type Role = Schemas["TeamRole"];
const base = `/v1/teams/${team.slug}/gateways`;
const tab = `/teams/${team.slug}/gateways/${gatewayId}?tab=capabilities`;
const wiki = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const restart = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const routes = (role: Role = "owner", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}/${gatewayId}`]: () => gateway(),
  [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities(),
  [`GET /v1/teams/${team.slug}/gateway-options`]: (_b, call) => optionsPage(gatewayOptions, call.search),
  ...extra,
});

async function openPicker(u: ReturnType<typeof userEvent.setup>) {
  await u.click(await screen.findByRole("button", { name: "Edit selection" }));
  return screen.findByRole("checkbox", { name: "wiki__search" });
}

describe("Gateway › Capabilities", () => {
  it("groups the selection by server with availability and minimum roles; members can't edit", async () => {
    const off = gatewayCapability({ capabilityId: restart, name: "restart", exposedName: "service-status__restart", minRole: "admin", available: false, unavailableReason: "changed" });
    mockApi(routes("member", { [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities([gatewayCapability(), off]) }));
    const { container } = renderApp(tab);
    expect(await screen.findByRole("heading", { level: 3, name: /Service status/ })).toBeInTheDocument();
    const ok = screen.getByRole("listitem", { name: "tool: service-status__get_status" });
    expect(within(ok).getByText("Available")).toBeInTheDocument();
    const changed = screen.getByRole("listitem", { name: "tool: service-status__restart" });
    expect(within(changed).getByText("Changed, waiting for approval")).toBeInTheDocument();
    expect(within(changed).getByText("Admins and owners")).toBeInTheDocument();
    expect(screen.getByText("1 capability isn't available right now")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit selection" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("lets owners pick from their team and the catalog, with search, a kind filter and a minimum role, and saves with If-Match", async () => {
    const u = userEvent.setup();
    const saved = gatewayCapabilities([gatewayCapability()], 8);
    const calls = mockApi(routes("owner", { [`PUT ${base}/${gatewayId}/capabilities`]: () => saved }));
    const { container } = renderApp(tab);
    const wikiBox = await openPicker(u);
    expect(screen.getByRole("checkbox", { name: "service-status__get_status" })).toBeChecked();
    expect(wikiBox).not.toBeChecked();
    // Where each server comes from.
    expect(within(screen.getByRole("heading", { level: 3, name: /Company wiki/ })).getByText("Catalog")).toBeInTheDocument();
    expect(within(screen.getByRole("heading", { level: 3, name: /^Service status/ })).getByText("Team")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    // Search and the kind filter run on the server.
    await u.type(screen.getByRole("searchbox", { name: "Search capabilities" }), "wiki");
    await waitFor(() => expect(screen.queryByRole("checkbox", { name: "service-status__restart" })).toBeNull());
    expect(calls.some((c) => c.url.endsWith("/gateway-options") && c.search.get("q") === "wiki")).toBe(true);
    await u.clear(screen.getByRole("searchbox", { name: "Search capabilities" }));
    await u.click(screen.getByRole("button", { name: "Prompts" }));
    expect(await screen.findByRole("checkbox", { name: "service-status__incident_summary" })).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("checkbox", { name: "wiki__search" })).toBeNull());
    expect(calls.some((c) => c.url.endsWith("/gateway-options") && c.search.get("kind") === "prompt")).toBe(true);
    await u.click(screen.getByRole("button", { name: "All" }));
    await screen.findByRole("checkbox", { name: "wiki__search" });

    await u.click(screen.getByRole("checkbox", { name: "wiki__search" }));
    await u.click(screen.getByRole("checkbox", { name: "service-status__restart" }));
    await u.selectOptions(screen.getByRole("combobox", { name: "Who may use service-status__restart" }), "admin");
    // The fixed width is on a box around the select and its chevron (NativeSelect's wrapper), not on the
    // select alone, which left the chevron at the far edge of the row.
    const roleSelect = screen.getByRole("combobox", { name: "Who may use service-status__restart" });
    const box = roleSelect.parentElement!.parentElement!;
    expect(g.roleSelect).toBeTruthy();
    expect(box).toHaveClass(g.roleSelect!);
    expect(roleSelect).not.toHaveClass(g.roleSelect!);
    expect(box.querySelector("svg")).not.toBeNull();
    expect(screen.getByText("3 of at most 200 selected")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save selection" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")).toBeDefined());
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.headers.get("If-Match")).toBe('"7"');
    expect(put.body).toEqual({ items: [{ capabilityId: gatewayCapability().capabilityId }, { capabilityId: wiki }, { capabilityId: restart, minRole: "admin" }] });
    // Back to the selection as saved.
    expect(await screen.findByRole("button", { name: "Edit selection" })).toBeInTheDocument();
  });

  it("marks capabilities that can't be selected (422) and removes them on request", async () => {
    const u = userEvent.setup();
    let refuse = true;
    const calls = mockApi(
      routes("owner", {
        [`PUT ${base}/${gatewayId}/capabilities`]: () =>
          refuse ? Reply.error(422, "capability_not_selectable", "Not selectable", { capabilityIds: [wiki] }) : gatewayCapabilities([gatewayCapability()], 8),
      }),
    );
    renderApp(tab);
    await u.click(await openPicker(u));
    await u.click(screen.getByRole("button", { name: "Save selection" }));
    expect(await screen.findByText(/1 selected capability can't be selected any more/)).toBeInTheDocument();
    expect(screen.getByText("Can't be selected now. Remove it to save.")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Remove them" }));
    expect(screen.getByRole("checkbox", { name: "wiki__search" })).not.toBeChecked();
    expect(screen.queryByText(/can't be selected any more/)).toBeNull();
    refuse = false;
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
  });

  it("says which name clashes, and when there are too many", async () => {
    const u = userEvent.setup();
    let reply = Reply.error(422, "name_clash", "Clash", { exposedName: "wiki__search" });
    mockApi(routes("owner", { [`PUT ${base}/${gatewayId}/capabilities`]: () => reply }));
    renderApp(tab);
    await u.click(await openPicker(u));
    await u.click(screen.getByRole("button", { name: "Save selection" }));
    expect(await screen.findByText("Two selected capabilities are both exposed as wiki__search. Keep only one of them and save again.")).toBeInTheDocument();
    expect(screen.getByText("Clients would see two capabilities with this name. Keep one.")).toBeInTheDocument();

    reply = Reply.error(422, "too_many", "Too many");
    await u.click(screen.getByRole("checkbox", { name: "service-status__restart" }));
    // too_many shows while over the limit only; the server's word is the one that counts here.
    await u.click(screen.getByRole("button", { name: "Save selection" }));
    await waitFor(() => expect(screen.queryByText(/both exposed as/)).toBeNull());
  });

  it("keeps the selection through a save conflict (412) and overwrites on the latest revision", async () => {
    const u = userEvent.setup();
    let current = gatewayCapabilities();
    let conflict = true;
    const calls = mockApi(
      routes("owner", {
        [`GET ${base}/${gatewayId}/capabilities`]: () => current,
        [`PUT ${base}/${gatewayId}/capabilities`]: () => {
          if (!conflict) return gatewayCapabilities([gatewayCapability()], 10);
          conflict = false;
          // Someone else saved meanwhile: their selection is empty, at revision 9.
          current = gatewayCapabilities([], 9);
          return Reply.error(412, "revision_conflict", "Changed");
        },
      }),
    );
    renderApp(tab);
    await u.click(await openPicker(u));
    await u.click(screen.getByRole("button", { name: "Save selection" }));
    expect(await screen.findByText("Someone else changed this gateway while you were editing")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "wiki__search" })).toBeChecked();
    await u.click(await screen.findByRole("button", { name: "Overwrite with mine" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "PUT").at(-1)?.headers.get("If-Match")).toBe('"9"');
  });

  it("lists selected capabilities that can't be selected now, with Remove", async () => {
    const u = userEvent.setup();
    const gone = gatewayCapability({ capabilityId: "99999999-0000-4000-8000-000000000000", name: "old", exposedName: "service-status__old", available: false, unavailableReason: "gone" });
    mockApi(routes("owner", { [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities([gatewayCapability(), gone]) }));
    renderApp(tab);
    await openPicker(u);
    expect(screen.getByText("Selected, but can't be selected now")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Remove service-status__old" }));
    expect(screen.queryByText("Selected, but can't be selected now")).toBeNull();
    expect(screen.getByText("1 of at most 200 selected")).toBeInTheDocument();
  });
});

describe("the picker with many options", () => {
  // 150 tools on the team's server (two pages of 100), then the catalog's wiki and its resources.
  const many = Array.from({ length: 150 }, (_, i) =>
    gatewayOption({ capabilityId: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, name: `tool_${String(i).padStart(3, "0")}`, exposedName: `service-status__tool_${String(i).padStart(3, "0")}`, title: "" }),
  );
  const resource = gatewayOption({
    capabilityId: "f1f1f1f1-f1f1-4f1f-8f1f-f1f1f1f1f1f1",
    serverId: catalogServerId,
    serverSlug: "wiki",
    serverName: "Company wiki",
    source: "catalog",
    kind: "resource",
    name: "wiki://pages",
    exposedName: "omp://wiki/wiki://pages",
    title: "Pages",
    description: "Every page.",
  });
  const template = gatewayOption({ ...resource, capabilityId: "f2f2f2f2-f2f2-4f2f-8f2f-f2f2f2f2f2f2", kind: "resource_template", name: "wiki://pages/{id}", exposedName: "omp://wiki/wiki://pages/{id}", title: "Page" });
  const all = [...many, gatewayOptions[3]!, resource, template];

  it("loads more by cursor, filters by server and kind, and keeps the selection through paging and search", async () => {
    const u = userEvent.setup();
    const saved = gatewayCapabilities([gatewayCapability()], 8);
    const calls = mockApi(routes("owner", { [`GET /v1/teams/${team.slug}/gateway-options`]: (_b, call) => optionsPage(all, call.search), [`PUT ${base}/${gatewayId}/capabilities`]: () => saved }));
    renderApp(tab);
    await u.click(await screen.findByRole("button", { name: "Edit selection" }));
    expect(await screen.findByRole("checkbox", { name: "service-status__tool_099" })).toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: "service-status__tool_100" })).toBeNull();
    expect(screen.getByText("100 shown")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Load more" }));
    await u.click(await screen.findByRole("checkbox", { name: "service-status__tool_120" }));
    expect(calls.some((c) => c.url.endsWith("/gateway-options") && c.search.get("cursor") === "100")).toBe(true);
    // Resources show with their exposed URIs; the template filter asks the server.
    expect(await screen.findByRole("checkbox", { name: "omp://wiki/wiki://pages" })).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Templates" }));
    await u.click(await screen.findByRole("checkbox", { name: "omp://wiki/wiki://pages/{id}" }));
    await waitFor(() => expect(screen.queryByRole("checkbox", { name: "service-status__tool_000" })).toBeNull());
    await u.click(screen.getByRole("button", { name: "All" }));

    // Filter by server: only the wiki; the tool chosen on page 2 is still selected.
    await u.selectOptions(screen.getByRole("combobox", { name: "Server" }), "Company wiki");
    await waitFor(() => expect(screen.queryByRole("checkbox", { name: "service-status__tool_000" })).toBeNull());
    expect(calls.some((c) => c.url.endsWith("/gateway-options") && c.search.get("server") === catalogServerId)).toBe(true);
    await u.selectOptions(screen.getByRole("combobox", { name: "Server" }), "All servers");
    await u.type(screen.getByRole("searchbox", { name: "Search capabilities" }), "tool_00");
    await waitFor(() => expect(screen.queryByRole("checkbox", { name: "wiki__search" })).toBeNull());
    await u.click(screen.getByRole("checkbox", { name: "Selected only" }));
    await u.clear(screen.getByRole("searchbox", { name: "Search capabilities" }));
    expect(await screen.findByRole("checkbox", { name: "service-status__tool_120" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "omp://wiki/wiki://pages/{id}" })).toBeChecked();
    expect(screen.getByText("3 of at most 200 selected")).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Save selection" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")).toBeDefined());
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({
      items: [{ capabilityId: gatewayCapability().capabilityId }, { capabilityId: many[120]!.capabilityId }, { capabilityId: template.capabilityId }],
    });
  });
});

describe("an empty gateway", () => {
  it("asks owners to choose capabilities", async () => {
    mockApi(routes("admin", { [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities([]), [`GET ${base}`]: () => page([]) }));
    renderApp(tab);
    expect(await screen.findByText("No capabilities selected yet.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Choose capabilities" })).toBeInTheDocument();
  });
});
