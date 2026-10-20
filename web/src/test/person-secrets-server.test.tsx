/*
 * Choosing how each person's own key is sent (decision 72) in Add and Settings: the mode's fields, what the
 * request holds (never a key), the warnings (a query value is in the address; a new address or placement
 * deletes everyone's keys; a published server goes back to review), and the Overview card that counts who
 * entered one.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers`;
const ownKeys = (extra: Partial<Schemas["McpServer"]> = {}, settings: Partial<NonNullable<Schemas["McpServer"]["personSecret"]>> = {}): Schemas["McpServer"] => ({
  ...mcpServer(),
  authMode: "person_secret",
  hasAuth: false,
  credentials: [],
  personSecret: { placement: "header", name: "X-API-Key", prefix: "", label: "Acme API key", help: "", people: 3, rejected: 1, setup: { status: "missing" }, ...settings },
  ...extra,
});

const routes = (current: Schemas["McpServer"], extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "owner"),
  [`GET ${base}`]: () => page([current]),
  [`GET ${base}/${serverId}`]: () => current,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  "GET /v1/auth-providers": () => [],
  ...extra,
});

afterEach(() => vi.restoreAllMocks());

describe("Add server › each person's own key", () => {
  it("sends the mode and how the key travels, with no key, and says where the keys are entered", async () => {
    const u = userEvent.setup();
    const created: Schemas["McpServerCreated"] = { server: ownKeys({ refreshedAt: null }), refresh: null, refreshError: null, setupRequired: true };
    const calls = mockApi({ ...routes(ownKeys()), [`POST ${base}`]: () => new Reply(201, { data: created }) });
    const { container } = renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Acme");
    await u.type(screen.getByRole("textbox", { name: "URL" }), "https://mcp.acme.example/mcp");
    await u.click(screen.getByRole("radio", { name: "Each person's own key" }));
    expect(await screen.findByRole("radio", { name: "A header" })).toBeChecked();
    expect(await axe(container)).toHaveNoViolations();
    // The name is required for a header.
    await u.click(screen.getByRole("button", { name: "Add server" }));
    expect(await screen.findByText(/Use a header name such as X-API-Key/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST" && c.url === base)).toBe(false);
    await u.type(screen.getByRole("textbox", { name: "Header name" }), "X-API-Key");
    await u.type(screen.getByRole("textbox", { name: /Prefix/ }), "Token ");
    await u.type(screen.getByRole("textbox", { name: /What the key is called/ }), "Acme API key");
    await u.click(screen.getByRole("radio", { name: /A query parameter/ }));
    expect(screen.getByText("A query value is part of the address")).toBeInTheDocument();
    await u.click(screen.getByRole("radio", { name: "A header" }));
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === base)).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.url === base)?.body as Record<string, unknown>;
    expect(body.authMode).toBe("person_secret");
    expect(body.personSecret).toEqual({ placement: "header", name: "X-API-Key", prefix: "Token ", label: "Acme API key", help: "" });
    expect(body.credentials).toBeUndefined();
    expect(body.requirement).toBeUndefined();
  });
});

describe("Server settings › each person's own key", () => {
  it("warns that a new placement deletes everyone's keys, and sends only the settings that changed", async () => {
    const u = userEvent.setup();
    const current = ownKeys();
    const calls = mockApi(routes(current, { [`PATCH ${base}/${serverId}`]: () => ({ ...current, revision: current.revision + 1 }) }));
    renderApp(`/teams/${team.slug}/servers/${serverId}?tab=settings`);
    expect(await screen.findByRole("radio", { name: "Each person's own key" })).toBeChecked();
    expect(screen.queryByText("Everyone's keys are deleted")).toBeNull();
    // A new label alone keeps the keys.
    await u.type(screen.getByRole("textbox", { name: /What the key is called/ }), "!");
    expect(screen.queryByText("Everyone's keys are deleted")).toBeNull();
    await u.click(screen.getByRole("radio", { name: "A bearer token (Authorization: Bearer)" }));
    const warning = await screen.findByText("Everyone's keys are deleted");
    expect(warning.closest("[role]")).toHaveTextContent(/3 people have entered a key for/);
    await u.click(screen.getByRole("button", { name: /Save/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const body = calls.find((c) => c.method === "PATCH")?.body as Record<string, unknown>;
    expect(body.personSecret).toEqual({ placement: "bearer", label: "Acme API key!", help: "" });
    expect(body.authMode).toBeUndefined();
    expect(body.credentials).toBeUndefined();
  });

  it("shows the Overview card with the counts and sends an editor to enter their key; no User authorization next to it", async () => {
    mockApi(routes(ownKeys({ refreshedAt: null })));
    renderApp(`/teams/${team.slug}/servers/${serverId}`);
    expect(await screen.findByRole("heading", { name: "People's own keys" })).toBeInTheDocument();
    expect(await screen.findByText("Nobody's key reads its capabilities yet")).toBeInTheDocument();
    expect(screen.getByText("3 people, 1 refused by the server")).toBeInTheDocument();
    expect(screen.getAllByText("Header X-API-Key").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: /Enter my key/ })).toHaveAttribute("href", "/settings/connections");
    expect(screen.queryByRole("heading", { name: "User authorization" })).toBeNull();
    expect(within(document.body).getByText("Own key per person")).toBeInTheDocument();
  });
});
