/* A server's own credential as parts (decision 70): the pure rules, the editor in Add and in Settings. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { credentialsBody, newPart, partProblems, type PartForm, partsOf, partSummary } from "../components/servers/credentials";
import { sameOrigin } from "../components/servers/origin";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers`;
const record = `/teams/${team.slug}/servers/${serverId}`;
const multi = (extra: Partial<Schemas["McpServer"]> = {}) =>
  mcpServer({
    authHeaderName: undefined,
    authValueHint: "",
    credentials: [
      { kind: "header", name: "X-Tenant", hint: "0001" },
      { kind: "query", name: "sig", hint: "" },
      { kind: "basic", hint: "5678" },
    ],
    ...extra,
  });

const routes = (server = mcpServer(), extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "editor"),
  [`GET ${base}`]: () => page([server]),
  [`GET ${base}/${serverId}`]: () => server,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing({ effective: server.effectivePublishPolicy }),
  ...extra,
});

const part = (extra: Partial<PartForm>): PartForm => ({ ...newPart(), ...extra });

describe("credential parts (rules)", () => {
  it("reads a server's parts, the single legacy header included, without values", () => {
    expect(partsOf(mcpServer()).map(partSummary)).toEqual(["Authorization: ••••x9Kz"]);
    expect(partsOf(multi()).map(partSummary)).toEqual(["X-Tenant: ••••0001", "?sig=••••", "Authorization: Basic (user and password ••••5678)"]);
    const old = mcpServer({ credentials: undefined });
    expect(partsOf(old)).toHaveLength(1);
    expect(partsOf(mcpServer({ hasAuth: false, authHeaderName: undefined, credentials: [] }))).toEqual([]);
  });

  it("sends nothing when nothing changed, keeps stored parts without values and sends new ones whole", () => {
    const server = multi();
    expect(credentialsBody(partsOf(server), server)).toBeUndefined();
    const parts = partsOf(server);
    expect(credentialsBody(parts.slice(0, 2), server)).toEqual([
      { kind: "header", name: "X-Tenant", keep: true },
      { kind: "query", name: "sig", keep: true },
    ]);
    const replaced = parts.map((p, i) => (i === 1 ? { ...p, value: "s3cret key" } : p));
    expect(credentialsBody(replaced, server)).toEqual([
      { kind: "header", name: "X-Tenant", keep: true },
      { kind: "query", name: "sig", value: "s3cret key" },
      { kind: "basic", keep: true },
    ]);
    expect(credentialsBody([...parts, part({ kind: "bearer", value: "tok-1" })], server)?.at(-1)).toEqual({ kind: "bearer", value: "tok-1" });
    expect(credentialsBody([part({ kind: "basic", value: "alice", secondary: "pw" })])).toEqual([{ kind: "basic", value: "alice", secondary: "pw" }]);
    expect(credentialsBody([], server)).toEqual([]);
  });

  it("checks names, values, duplicates and a second Authorization", () => {
    const keys = (parts: PartForm[], o?: { originMoved?: boolean }) => Object.keys(partProblems(parts, o)).length;
    expect(keys([part({ kind: "header", name: "X-Tenant", value: "a" }), part({ kind: "query", name: "sig", value: "b" }), part({ kind: "basic", value: "u", secondary: "p" })])).toBe(0);
    expect(partProblems([part({ key: "a", kind: "header", name: "bad name", value: "v" })]).a?.name).toMatch(/header name/);
    expect(partProblems([part({ key: "a", kind: "header", name: "MCP-Gateway-Identity", value: "v" })]).a?.name).toMatch(/belong to the portal/);
    expect(partProblems([part({ key: "a", kind: "query", name: "mcp-session", value: "v" })]).a?.name).toMatch(/mcp-/);
    expect(partProblems([part({ key: "a", kind: "query", name: "a b", value: "v" })]).a?.name).toBeDefined();
    expect(partProblems([part({ key: "a", kind: "header", name: "X-A" })]).a?.value).toBe("Enter the value.");
    expect(partProblems([part({ key: "a", kind: "basic", value: "u" })]).a?.secondary).toBe("Enter the password.");
    expect(partProblems([part({ key: "a", kind: "basic", value: "u:v", secondary: "p" })]).a?.value).toMatch(/colon/);
    const dup = partProblems([part({ key: "a", kind: "header", name: "X-A", value: "1" }), part({ key: "b", kind: "header", name: "x-a", value: "2" })]);
    expect(dup.a).toBeUndefined();
    expect(dup.b?.name).toBe("Another part has this name.");
    // Authorization once: a header named so, a bearer or Basic.
    expect(partProblems([part({ key: "a", kind: "bearer", value: "t" }), part({ key: "b", kind: "header", name: "authorization", value: "x" })]).b?.name).toMatch(/Only one part/);
    expect(partProblems([part({ key: "a", kind: "bearer", value: "t" }), part({ key: "b", kind: "basic", value: "u", secondary: "p" })]).b?.name).toMatch(/Only one part/);
    // A stored part keeps its value unless the URL moves to another origin (F-1).
    const stored = partsOf(multi());
    expect(keys(stored)).toBe(0);
    expect(keys(stored, { originMoved: true })).toBe(3);
    expect(partProblems(stored, { originMoved: true })[stored[0]!.key]?.value).toMatch(/moves to another host/);
    const entered = stored.map((p) => ({ ...p, value: "new", secondary: p.kind === "basic" ? "pw" : "" }));
    expect(keys(entered, { originMoved: true })).toBe(0);
  });

  it("compares origins the way the server does", () => {
    expect(sameOrigin("https://a.example/mcp", "https://A.example:443/other/")).toBe(true);
    expect(sameOrigin("https://a.example/mcp", "https://a.example:8443/mcp")).toBe(false);
    expect(sameOrigin("https://a.example/mcp", "http://a.example/mcp")).toBe(false);
    expect(sameOrigin("https://a.example/mcp", "https://b.example/mcp")).toBe(false);
  });
});

describe("Add MCP server: credential parts", () => {
  it("adds a header, a Basic login and a query key, warns about the query, and sends them as parts", async () => {
    const u = userEvent.setup();
    const created: Schemas["McpServerCreated"] = { server: multi(), refresh: null, refreshError: null };
    const calls = mockApi(routes(mcpServer(), { [`POST ${base}`]: () => new Reply(201, { data: created }) }));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Tenant API");
    await u.type(screen.getByRole("textbox", { name: "URL" }), "https://tenant.example.com/mcp");
    await u.click(screen.getByRole("radio", { name: /^Static credential/ }));

    const first = screen.getByRole("group", { name: "Credential part 1" });
    await u.type(within(first).getByRole("textbox", { name: /Header name/ }), "X-Tenant");
    await u.type(within(first).getByLabelText("Value"), "acme-0001");
    expect(screen.queryByText("A query value is part of the address")).toBeNull();

    await u.click(screen.getByRole("button", { name: "Add part" }));
    const second = screen.getByRole("group", { name: "Credential part 2" });
    await u.selectOptions(within(second).getByRole("combobox", { name: "Kind" }), "query");
    await u.type(within(second).getByRole("textbox", { name: "Parameter name" }), "sig");
    await u.type(within(second).getByLabelText("Value"), "k&1 2");
    expect(screen.getByText("A query value is part of the address")).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Add part" }));
    const third = screen.getByRole("group", { name: "Credential part 3" });
    await u.selectOptions(within(third).getByRole("combobox", { name: "Kind" }), "basic");
    await u.type(within(third).getByRole("textbox", { name: "User name" }), "alice");
    await u.click(screen.getByRole("button", { name: "Add server" }));
    // The password is missing.
    expect(await screen.findByText("Enter the password.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await u.type(within(third).getByLabelText("Password"), "p:w");
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({
        authMode: "static_header",
        credentials: [
          { kind: "header", name: "X-Tenant", value: "acme-0001" },
          { kind: "query", name: "sig", value: "k&1 2" },
          { kind: "basic", value: "alice", secondary: "p:w" },
        ],
      }),
    );
    expect(JSON.stringify(calls.find((c) => c.method === "POST")?.body)).not.toContain("authHeaderName");
  });

  it("needs a part in static mode, and stops at eight", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Parts");
    await u.type(screen.getByRole("textbox", { name: "URL" }), "https://tenant.example.com/mcp");
    await u.click(screen.getByRole("radio", { name: /^Static credential/ }));
    await u.click(within(screen.getByRole("group", { name: "Credential part 1" })).getByRole("button", { name: "Remove part 1" }));
    await u.click(screen.getByRole("button", { name: "Add server" }));
    expect(await screen.findByText("Add at least one part, or choose None.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    for (let i = 0; i < 8; i++) await u.click(screen.getByRole("button", { name: "Add part" }));
    expect(screen.getByRole("button", { name: "Add part" })).toBeDisabled();
    expect(screen.getByText(/At most 8 parts/)).toBeInTheDocument();
  });
});

describe("Settings: credential parts", () => {
  it("shows each stored part without its value, keeps what isn't touched and replaces one value", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(multi(), { [`PATCH ${base}/${serverId}`]: () => multi({ revision: 5 }) }));
    const { container } = renderApp(`${record}?tab=settings`);
    await screen.findByRole("textbox", { name: "Name" });
    expect(screen.getByText(/Header: X-Tenant \(value ends in 0001\)/)).toBeInTheDocument();
    expect(screen.getByText(/Query parameter: sig/)).toBeInTheDocument();
    expect(screen.getByText(/Basic \(user and password\) \(value ends in 5678\)/)).toBeInTheDocument();
    expect(screen.getByText("A query value is part of the address")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    // Nothing touched: the credential isn't sent at all.
    const name = screen.getByRole("textbox", { name: "Name" });
    await u.type(name, "!");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    expect(calls.find((c) => c.method === "PATCH")?.body).not.toHaveProperty("credentials");

    // Replace the query key's value and drop the Basic part.
    await u.type(within(screen.getByRole("group", { name: "Credential part 2" })).getByLabelText("Replace value"), "n3w key");
    await u.click(screen.getByRole("button", { name: "Remove part 3" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "PATCH")[1]!.body).toMatchObject({
      credentials: [
        { kind: "header", name: "X-Tenant", keep: true },
        { kind: "query", name: "sig", value: "n3w key" },
      ],
    });
    expect(JSON.stringify(calls.filter((c) => c.method === "PATCH")[1]!.body)).not.toContain("authValue");
  });

  it("asks for every value again when the URL moves to another host, and for none when only the path changes", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(multi(), { [`PATCH ${base}/${serverId}`]: () => multi({ revision: 5 }) }));
    renderApp(`${record}?tab=settings`);
    const url = await screen.findByRole("textbox", { name: "URL" });
    await u.clear(url);
    await u.type(url, "https://status.example.com/v2/mcp");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    expect(calls.find((c) => c.method === "PATCH")?.body).not.toHaveProperty("credentials");

    await u.clear(url);
    await u.type(url, "https://other.example.com/mcp");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect((await screen.findAllByText(/The URL moves to another host, so enter this value again/)).length).toBeGreaterThanOrEqual(3);
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
    for (const n of [1, 2, 3]) {
      const group = screen.getByRole("group", { name: `Credential part ${n}` });
      await u.type(within(group).getByLabelText(/^Replace (value|user name)$/), `v-${n}`);
      if (n === 3) await u.type(within(group).getByLabelText("Replace password"), "pw");
    }
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "PATCH")[1]!.body).toMatchObject({
      url: "https://other.example.com/mcp",
      credentials: [
        { kind: "header", name: "X-Tenant", value: "v-1" },
        { kind: "query", name: "sig", value: "v-2" },
        { kind: "basic", value: "v-3", secondary: "pw" },
      ],
    });
  });

  it("shows the server's refusal of two Authorization parts in words", async () => {
    const u = userEvent.setup();
    mockApi(routes(multi(), { [`PATCH ${base}/${serverId}`]: () => Reply.error(422, "auth_conflict", "two", { reason: "authorization_twice" }) }));
    renderApp(`${record}?tab=settings`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "!");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/Only one part of the credential can set the Authorization header/)).toBeInTheDocument();
  });
});
