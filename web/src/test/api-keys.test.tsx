/* Account › API keys: the list, Create (the secret once, never again), the choice to fill snippets, and Revoke. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { apiKey, myGateway } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const secret = "omp_ab12cd34_0123456789abcdefghijklmnopqrstuv";
const created: Schemas["ApiKeyCreated"] = { key: apiKey({ id: "new-key", name: "CI runner", lastUsedAt: null }), secret };

const routes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "member"),
  "GET /v1/me/api-keys": () => [apiKey({ expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString() }), apiKey({ id: "old", name: "Old laptop", status: "revoked", revokedAt: "2026-10-10T10:00:00Z", lastUsedAt: null })],
  "GET /v1/me/gateways": () => [myGateway()],
  ...extra,
});

describe("API keys", () => {
  // Freeze Date, not timers: the seven-day fixture must not cross a local DST
  // transition merely because the suite ran on a different day.
  beforeEach(() => vi.setSystemTime(new Date("2026-10-15T12:00:00Z")));
  afterEach(() => vi.useRealTimers());

  it("lists the person's keys with status, last use and expiry, from the account menu", async () => {
    mockApi(routes());
    const { container } = renderApp("/settings/api-keys");
    expect(await screen.findByRole("heading", { level: 1, name: "API keys" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "API keys" });
    const active = (await within(table).findByText("Claude Code on my laptop")).closest("tr")!;
    expect(active).toHaveTextContent("omp_ab12cd34…");
    expect(active).toHaveTextContent("Active");
    // Expiry in days with the exact date as its tooltip, never "next week".
    expect(within(active).getByText("in 7 days")).toHaveAttribute("title", expect.stringMatching(/\d{4}/));
    const revoked = within(table).getByText("Old laptop").closest("tr")!;
    expect(revoked).toHaveTextContent("Revoked");
    expect(revoked).toHaveTextContent("Never");
    // The status says it's revoked; Expires doesn't repeat it.
    expect(revoked.textContent?.match(/Revoked/g)).toHaveLength(1);
    expect(revoked).toHaveTextContent("—");
    // Revoked keys can't be revoked again: no row menu.
    expect(within(revoked).queryByRole("button", { name: /Actions for/ })).toBeNull();
    await waitFor(() => expect(document.title).toBe("API keys · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows the secret once after creating a key, and never again", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/me/api-keys": () => new Reply(201, { data: created }) }));
    const { container } = renderApp("/settings/api-keys");
    await u.click(await screen.findByRole("button", { name: "Create API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Create API key" });
    expect(within(dialog).getByRole("textbox", { name: /Expires after/ })).toHaveValue("90");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    expect(await within(dialog).findByText("Enter a name.")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "CI runner");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "CI runner", expiresInDays: 90, toolScope: null }));

    const shown = await screen.findByRole("dialog", { name: "API key created" });
    // The dialog says it was created; no toast covers its buttons.
    expect(screen.queryByText("CI runner was created")).toBeNull();
    expect(within(shown).getByText("Copy this key now.")).toBeInTheDocument();
    expect(within(shown).getByText(/It won't be shown again/)).toBeInTheDocument();
    expect(within(shown).getByText(secret)).toBeInTheDocument();
    expect(within(shown).getByRole("button", { name: /Copy API key secret/ })).toBeInTheDocument();
    // The snippets keep the placeholder unless the person asks for the key in them.
    expect(within(shown).getByText(/claude mcp add/).textContent).toContain("<YOUR_API_KEY>");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(shown).getByRole("checkbox", { name: "Put this key into the snippets" }));
    expect(within(shown).getByText(/claude mcp add/).textContent).toContain(`Bearer ${secret}`);
    expect(within(shown).getByText(/These snippets contain your API key/)).toBeInTheDocument();

    await u.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "API key created" })).toBeNull());
    expect(document.body.textContent).not.toContain(secret);
    // Opening Create again starts over: the old secret is gone.
    await u.click(screen.getByRole("button", { name: "Create API key" }));
    expect(await screen.findByRole("dialog", { name: "Create API key" })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(secret);
  });

  it("limits a new key to chosen gateways, and offers only those to connect", async () => {
    const u = userEvent.setup();
    const other = myGateway({ id: "g-other", slug: "company-tools", name: "Company tools", ownerKind: "platform", url: "https://mcp.example.com/mcp/company-tools" });
    const scoped: Schemas["ApiKeyCreated"] = { key: apiKey({ id: "new-key", name: "CI runner", gateways: [{ id: "g-other", slug: "company-tools", name: "Company tools", exists: true }] }), secret };
    const calls = mockApi(routes({ "GET /v1/me/gateways": () => [myGateway(), other], "POST /v1/me/api-keys": () => new Reply(201, { data: scoped }) }));
    renderApp("/settings/api-keys");
    await u.click(await screen.findByRole("button", { name: "Create API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Create API key" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "CI runner");
    await u.click(within(dialog).getByRole("combobox", { name: /Limit to gateways/ }));
    await u.click(await screen.findByRole("option", { name: /Company tools/ }));
    // Closing the list leaves the dialog open.
    await u.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("option", { name: /Company tools/ })).toBeNull());
    expect(within(dialog).getByText("The key works only on these gateways, and only while you can use them.")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "CI runner", expiresInDays: 90, gatewayIds: ["g-other"], toolScope: null }));
    const shown = await screen.findByRole("dialog", { name: "API key created" });
    const choice = within(shown).getByRole("combobox", { name: "Connect a gateway" });
    expect(within(choice).getAllByRole("option").map((o) => o.textContent)).toEqual(["Company tools"]);
    expect(within(shown).getByText(/claude mcp add/).textContent).toContain("https://mcp.example.com/mcp/company-tools");
  });

  it("shows where each key works, and warns about a key whose gateways are all gone", async () => {
    const limited = apiKey({ id: "k2", name: "Scoped", gateways: [{ id: "g1", slug: "support-tools", name: "Support tools", exists: true }] });
    const stranded = apiKey({ id: "k3", name: "Stranded", gateways: [{ id: "g2", slug: "old", name: "Old gateway", exists: false }] });
    mockApi(routes({ "GET /v1/me/api-keys": () => [apiKey(), limited, stranded] }));
    renderApp("/settings/api-keys");
    const table = await screen.findByRole("table", { name: "API keys" });
    expect((await within(table).findByText("Claude Code on my laptop")).closest("tr")).toHaveTextContent("All my gateways");
    expect(within(table).getByText("Scoped").closest("tr")).toHaveTextContent("Support tools");
    const row = within(table).getByText("Stranded").closest("tr")!;
    expect(row).toHaveTextContent("Old gateway (deleted)");
    expect(row).toHaveTextContent("Works nowhere");
    expect(screen.getByText("Stranded works nowhere")).toBeInTheDocument();
  });

  it("checks the expiry and shows a refusal", async () => {
    const u = userEvent.setup();
    mockApi(routes({ "POST /v1/me/api-keys": () => Reply.error(409, "too_many_keys", "You have 20 active keys. Revoke one first.") }));
    renderApp("/settings/api-keys");
    await u.click(await screen.findByRole("button", { name: "Create API key" }));
    const dialog = await screen.findByRole("dialog", { name: "Create API key" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "One more");
    const days = within(dialog).getByRole("textbox", { name: /Expires after/ });
    await u.clear(days);
    await u.type(days, "400");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    expect(await within(dialog).findByText("Enter a whole number of days from 1 to 365.")).toBeInTheDocument();
    await u.clear(days);
    await u.type(days, "30");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    expect(await within(dialog).findByText("You have 20 active keys. Revoke one first.")).toBeInTheDocument();
  });

  it("revokes a key after confirming", async () => {
    const u = userEvent.setup();
    const key = apiKey();
    const calls = mockApi(routes({ [`DELETE /v1/me/api-keys/${key.id}`]: () => ({ ok: true }) }));
    renderApp("/settings/api-keys");
    await u.click(await screen.findByRole("button", { name: `Actions for ${key.name}` }));
    await u.click(await screen.findByRole("menuitem", { name: "Revoke…" }));
    const ask = await screen.findByRole("alertdialog", { name: `Revoke ${key.name}?` });
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Revoke key" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/me/api-keys/${key.id}`)).toBe(true));
  });

  it("is in the account menu next to Profile", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    renderApp("/");
    await u.click(await screen.findByRole("button", { name: /Una User/ }));
    const items = (await screen.findAllByRole("menuitem")).map((i) => i.textContent);
    expect(items.indexOf("API keys")).toBe(items.indexOf("Profile") + 1);
  });
});
