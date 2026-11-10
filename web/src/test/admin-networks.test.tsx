/* Admin → Internal networks (the allowlist, its save with If-Match and confirmation, the deployment's entries, the URL checker) and the private_address refusal on a server's URL. */
import { readFileSync } from "node:fs";
import path from "node:path";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { entryWarnings, parseCidr, valueProblem } from "../pages/admin/networks/entries";
import { page, team } from "./fixtures";
import { type Call, type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

type Settings = Schemas["NetworkSettings"];

const settings = (over: Partial<Settings> = {}): Settings => ({
  entries: [{ kind: "cidr", value: "10.20.0.0/16", allowHttp: false, note: "Build farm" }],
  deploymentEntries: [{ kind: "host", value: "*.svc.cluster.local", allowHttp: true }],
  revision: 3,
  updatedAt: "2026-10-15T10:00:00Z",
  ...over,
});

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/settings/network": () => settings(),
  ...extra,
});

const puts = (calls: Call[]) => calls.filter((c) => c.method === "PUT" && c.url === "/v1/admin/settings/network");

describe("Admin → Internal networks", () => {
  it("shows the admin entries and the deployment's read-only, and adds a host with http after confirming (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        "PUT /v1/admin/settings/network": (body) => settings({ entries: (body as Settings).entries, revision: 4 }),
      }),
    );
    const { container } = renderApp("/admin/networks");
    const table = await screen.findByRole("table", { name: "Allowed networks and hosts" });
    expect(within(table).getByText("10.20.0.0/16")).toBeInTheDocument();
    expect(within(table).getByText("Build farm")).toBeInTheDocument();
    const deployment = screen.getByRole("table", { name: "From deployment config" });
    expect(within(deployment).getByText("*.svc.cluster.local")).toBeInTheDocument();
    expect(within(deployment).getByText("Subdomains of svc.cluster.local, not svc.cluster.local itself")).toBeInTheDocument();
    expect(within(deployment).queryByRole("button", { name: /Actions for/ })).toBeNull();
    await waitFor(() => expect(document.title).toBe("Internal networks · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("button", { name: "Add network or host" }));
    const dialog = await screen.findByRole("dialog", { name: "Add network or host" });
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Kind" }), "host");
    await u.type(within(dialog).getByRole("textbox", { name: "Host name" }), "MCP.Corp.Example.com.");
    await u.click(within(dialog).getByRole("checkbox", { name: /Allow plain http/ }));
    expect(within(dialog).getByText(/Plain http sends requests/)).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await u.click(within(dialog).getByRole("button", { name: "Add entry" }));
    expect(within(table).getByText("mcp.corp.example.com")).toBeInTheDocument();
    expect(puts(calls)).toHaveLength(0);

    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Save the internal networks?" });
    expect(ask).toHaveTextContent("Servers are never changed");
    expect(ask).toHaveTextContent("mcp.corp.example.com: Plain http sends requests");
    await u.click(within(ask).getByRole("button", { name: "Save networks" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect(puts(calls)[0]?.body).toEqual({
      entries: [
        { allowHttp: false, kind: "cidr", note: "Build farm", value: "10.20.0.0/16" },
        { allowHttp: true, kind: "host", value: "mcp.corp.example.com" },
      ],
    });
    expect(puts(calls)[0]?.headers.get("If-Match")).toBe('"3"');
    expect(await screen.findByText("Internal networks saved")).toBeInTheDocument();
  });

  it("warns about a very broad network, edits and removes entries, and shows a refused entry on its row", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", { "PUT /v1/admin/settings/network": () => Reply.error(422, "invalid_entry", "entry 1: bad", { index: 0, reason: "always_blocked" }) }),
    );
    renderApp("/admin/networks");
    const table = await screen.findByRole("table", { name: "Allowed networks and hosts" });
    await u.click(within(table).getByRole("button", { name: "Actions for 10.20.0.0/16" }));
    await u.click(await screen.findByRole("menuitem", { name: "Edit…" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit entry" });
    const value = within(dialog).getByRole("textbox", { name: "Network" });
    await u.clear(value);
    await u.type(value, "nope");
    await u.click(within(dialog).getByRole("button", { name: "Update entry" }));
    expect(within(dialog).getByText(/Enter a network such as 10.20.0.0\/16/)).toBeInTheDocument();
    await u.clear(value);
    await u.type(value, "0.0.0.0/4");
    expect(within(dialog).getByText(/Very broad: \/4 covers more than 16 million/)).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Update entry" }));
    expect(within(table).getByText("0.0.0.0/4")).toBeInTheDocument();
    expect(within(table).getByText("Very broad")).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save networks" }));
    expect(await within(table).findByText(/always blocked/)).toBeInTheDocument();
    expect(puts(calls)).toHaveLength(1);

    await u.click(within(table).getByRole("button", { name: "Actions for 0.0.0.0/4" }));
    await u.click(await screen.findByRole("menuitem", { name: "Remove" }));
    expect(within(table).getByText(/Nothing yet/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByRole("alertdialog")).toHaveTextContent("1 entry is removed.");
  });

  it("keeps the edits through a save conflict (412) and overwrites on the latest revision", async () => {
    const u = userEvent.setup();
    let current = settings();
    let conflict = true;
    const calls = mockApi(
      routes("platform_admin", {
        "GET /v1/admin/settings/network": () => current,
        "PUT /v1/admin/settings/network": (body) => {
          if (!conflict) return settings({ entries: (body as Settings).entries, revision: 6 });
          conflict = false;
          current = settings({ entries: [], revision: 5 });
          return Reply.error(412, "revision_conflict", "Changed");
        },
      }),
    );
    renderApp("/admin/networks");
    await u.click(await screen.findByRole("button", { name: "Add network or host" }));
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByRole("textbox", { name: "Network" }), "fd00:1234::/32");
    await u.click(within(dialog).getByRole("button", { name: "Add entry" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save networks" }));
    await u.click(await screen.findByRole("button", { name: "Overwrite with mine" }));
    // Overwriting asks again, like any save.
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save networks" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(2));
    expect(puts(calls)[1]?.headers.get("If-Match")).toBe('"5"');
    expect((puts(calls)[1]?.body as Settings).entries.map((e) => e.value)).toEqual(["10.20.0.0/16", "fd00:1234::/32"]);
  });

  it("is read-only for auditors, who can still check a URL", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_auditor", {
        "POST /v1/admin/settings/network/check": (): Schemas["NetworkCheckResult"] => ({
          allowed: false,
          reason: "blocked_address",
          message: "Not every address the host resolves to is allowed.",
          resolvedAddresses: [
            { address: "10.20.0.5", allowed: true, reason: "host_entry" },
            { address: "169.254.169.254", allowed: false, reason: "blocked_address" },
          ],
        }),
      }),
    );
    const { container } = renderApp("/admin/networks");
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add network or host" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();

    await u.type(screen.getByRole("textbox", { name: "MCP server URL" }), "https://rebind.corp.example.com/mcp");
    await u.click(screen.getByRole("button", { name: "Check URL" }));
    expect(await screen.findByText("Not allowed: always blocked")).toBeInTheDocument();
    const addresses = screen.getByRole("table", { name: "Addresses checked" });
    expect(within(addresses).getByText("169.254.169.254").closest("tr")).toHaveTextContent("Always blocked");
    expect(within(addresses).getByText("10.20.0.5").closest("tr")).toHaveTextContent("Allowed host");
    expect(calls.find((c) => c.url.endsWith("/check"))?.body).toEqual({ url: "https://rebind.corp.example.com/mcp" });
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("URL checker layout", () => {
  // Form stacks its children in a column; the checker's form must override that, or the URL field
  // grows to its 20rem flex basis in height and the button drops below an empty area (jsdom has no
  // layout, so the stylesheet itself is checked).
  it("lays the field and the button out in a row", () => {
    const css = readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), "../pages/admin/networks/networks.module.css"), "utf8");
    const rule = /\.checkForm\s*\{([^}]*)\}/.exec(css)?.[1] ?? "";
    expect(rule).toMatch(/flex-direction:\s*row/);
  });
});

describe("internal network helpers", () => {
  it("reads CIDRs and flags broad ones and plain http", () => {
    expect(parseCidr("10.0.0.0/8")).toEqual({ v4: true, bits: 8 });
    expect(parseCidr("10.0.0.5")).toEqual({ v4: true, bits: 32 });
    expect(parseCidr("fd00::/8")).toEqual({ v4: false, bits: 8 });
    expect(parseCidr("10.0.0.0/33")).toBeNull();
    expect(parseCidr("corp.example.com")).toBeNull();
    expect(entryWarnings({ kind: "cidr", value: "10.0.0.0/8", allowHttp: false })).toEqual([]);
    expect(entryWarnings({ kind: "cidr", value: "10.0.0.0/7", allowHttp: false })[0]).toMatch(/Very broad/);
    expect(entryWarnings({ kind: "cidr", value: "fd00::/31", allowHttp: false })[0]).toMatch(/Very broad/);
    expect(entryWarnings({ kind: "cidr", value: "fd00::/32", allowHttp: false })).toEqual([]);
    expect(entryWarnings({ kind: "host", value: "a.example.com", allowHttp: true })[0]).toMatch(/Plain http/);
  });

  it("catches typos in host names before the server does", () => {
    expect(valueProblem("host", "*.corp.example.com")).toBeUndefined();
    expect(valueProblem("host", "MCP.corp.example.com.")).toBeUndefined();
    expect(valueProblem("host", "https://mcp.example.com")).toMatch(/no scheme, port or path/);
    expect(valueProblem("host", "mcp.example.com:8443")).toMatch(/no scheme, port or path/);
    expect(valueProblem("host", "bücher.example")).toMatch(/punycode/);
    expect(valueProblem("host", "10.0.0.1")).toMatch(/network \(CIDR\)/);
    expect(valueProblem("host", "localhost")).toMatch(/loopback/);
    expect(valueProblem("host", "a.*.example.com")).toMatch(/host name such as/);
  });
});

describe("A server URL at an internal address", () => {
  const base = `/v1/teams/${team.slug}/mcp-servers`;
  const refuse = { [`GET ${base}`]: () => page([]), [`POST ${base}`]: () => Reply.error(422, "url_not_allowed", "Internal", { reason: "private_address" }) };

  async function addServer(u: ReturnType<typeof userEvent.setup>) {
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Internal tools");
    await u.type(screen.getByRole("textbox", { name: "URL" }), "http://mcp.corp.example.com/mcp");
    await u.click(screen.getByRole("button", { name: "Add server" }));
  }

  it("links platform admins to Internal networks", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("platform_admin", "editor"), ...refuse });
    await addServer(u);
    const link = await screen.findByRole("link", { name: "Internal networks" });
    expect(link).toHaveAttribute("href", "/admin/networks");
    expect(screen.getByText(/won't connect to this internal \(private\) address until it's allowed/)).toBeInTheDocument();
  });

  it("tells everyone else to ask a platform admin", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("none", "editor"), ...refuse });
    await addServer(u);
    expect(await screen.findByText(/Ask a platform admin to allow its network/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Internal networks" })).toBeNull();
  });
});
