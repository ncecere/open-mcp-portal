/*
 * Admin → Trusted agent platforms: the list with each platform's last key fetch and key IDs, adding and editing
 * (server refusals on their fields), turning off, Test (the keys, or why not), the relay accounts (mark and remove,
 * platform admins only), deleting after a confirmation, and auditors reading.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { fetchErrorLabel, issuerProblem } from "../pages/admin/agent-platforms/api";
import { page, serviceAccount, serviceAccountId } from "./fixtures";
import { agentPlatform, otherPlatformId, platformId, relayAccount } from "./fixtures-agents";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = "/v1/admin/agent-platforms";
const one = `${base}/${platformId}`;
const sent = (calls: Call[], method: string, url: string) => calls.filter((c) => c.method === method && c.url === url);

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  [`GET ${base}`]: () => [agentPlatform(), agentPlatform({ id: otherPlatformId, name: "Staging platform", issuer: "https://staging.example.com", enabled: false, relayCount: 0, lastFetch: { at: "2026-10-20T09:00:00Z", ok: false, error: "not_allowed" }, keyIds: [] })],
  [`GET ${one}/relays`]: () => [relayAccount()],
  ...extra,
});

describe("Admin → Trusted agent platforms", () => {
  it("lists each platform with its audience, relays and last key fetch", async () => {
    mockApi(routes());
    const { container } = renderApp("/admin/agent-platforms");
    expect(await screen.findByRole("heading", { level: 1, name: "Trusted agent platforms" })).toBeInTheDocument();
    expect(screen.getByText(/The person's own connections are used; an agent never gets a sign-in link/)).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Trusted agent platforms" });
    const row = within(table).getByText("Pi Durable Platform").closest("tr")!;
    expect(row).toHaveTextContent("https://agents.example.com");
    expect(row).toHaveTextContent("https://mcp.example.com");
    expect(row).toHaveTextContent("Enabled");
    expect(row).toHaveTextContent("1 account");
    expect(row).toHaveTextContent("Keys fetched");
    expect(row).toHaveTextContent("Key IDs: Z3k1aXQ, B9fR2sA");
    const off = within(table).getByText("Staging platform").closest("tr")!;
    expect(off).toHaveTextContent("Disabled");
    expect(off).toHaveTextContent("None yet");
    expect(off).toHaveTextContent("Fetch failed");
    expect(off).toHaveTextContent("The portal may not connect to the JWKS address");
    await waitFor(() => expect(document.title).toBe("Trusted agent platforms · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("adds a platform: checks the issuer, shows the server's refusals on their fields, sends the defaults as absent", async () => {
    const u = userEvent.setup();
    let refuse: Reply | undefined = Reply.error(409, "issuer_taken", "That issuer is already trusted");
    const calls = mockApi(
      routes("platform_admin", {
        [`POST ${base}`]: (body) => refuse ?? agentPlatform({ ...(body as object), id: otherPlatformId, name: (body as { name: string }).name }),
      }),
    );
    renderApp("/admin/agent-platforms");
    await u.click(await screen.findByRole("button", { name: "Trust a platform" }));
    const dialog = await screen.findByRole("dialog", { name: "Trust an agent platform" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Corp agents");
    await u.type(within(dialog).getByRole("textbox", { name: "Issuer" }), "http://agents.corp.example");
    await u.click(within(dialog).getByRole("button", { name: "Trust platform" }));
    expect(within(dialog).getByText("The issuer must be an https address.")).toBeInTheDocument();
    expect(sent(calls, "POST", base)).toHaveLength(0);
    const issuer = within(dialog).getByRole("textbox", { name: "Issuer" });
    await u.clear(issuer);
    await u.type(issuer, "https://agents.corp.example");
    await u.click(within(dialog).getByRole("button", { name: "Trust platform" }));
    expect(await within(dialog).findByText("This issuer is already trusted.")).toBeInTheDocument();
    refuse = undefined;
    // Editing the issuer takes the refusal away; the corrected one is sent.
    await u.clear(issuer);
    await u.type(issuer, "https://agents-2.corp.example");
    expect(within(dialog).queryByText("This issuer is already trusted.")).toBeNull();
    await u.click(within(dialog).getByRole("button", { name: "Trust platform" }));
    await waitFor(() => expect(sent(calls, "POST", base)).toHaveLength(2));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Trust an agent platform" })).toBeNull());
    const last = sent(calls, "POST", base).at(-1)!;
    expect(last.body).toEqual({ name: "Corp agents", issuer: "https://agents-2.corp.example", enabled: true });
  });

  it("edits a platform with its revision, turns it off, and refuses a name another platform has", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        [`PATCH ${one}`]: (body) => {
          if ((body as { name?: string }).name === "Staging platform") return Reply.error(409, "name_taken", "Another trusted agent platform has that name");
          return agentPlatform({ ...(body as object), revision: 4 });
        },
      }),
    );
    renderApp("/admin/agent-platforms");
    const table = await screen.findByRole("table", { name: "Trusted agent platforms" });
    await u.click(within(within(table).getByText("Pi Durable Platform").closest("tr")!).getByRole("button", { name: "Actions for Pi Durable Platform" }));
    await u.click(await screen.findByRole("menuitem", { name: "Edit…" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit Pi Durable Platform" });
    const name = within(dialog).getByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Staging platform");
    await u.click(within(dialog).getByRole("button", { name: "Save" }));
    expect(await within(dialog).findByText("Another platform has this name.")).toBeInTheDocument();
    await u.clear(name);
    await u.type(name, "PDP production");
    await u.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(sent(calls, "PATCH", one)).toHaveLength(2));
    expect(sent(calls, "PATCH", one)[1]!.headers.get("If-Match")).toBe('"3"');
    expect(sent(calls, "PATCH", one)[1]!.body).toMatchObject({ name: "PDP production", issuer: "https://agents.example.com" });

    await u.click(within(within(table).getByText("Pi Durable Platform").closest("tr")!).getByRole("button", { name: "Actions for Pi Durable Platform" }));
    await u.click(await screen.findByRole("menuitem", { name: "Turn off" }));
    await waitFor(() => expect(sent(calls, "PATCH", one)).toHaveLength(3));
    expect(sent(calls, "PATCH", one)[2]!.body).toEqual({ enabled: false });
  });

  it("tests the keys: the key IDs and cache time, or why it failed", async () => {
    const u = userEvent.setup();
    let result: Reply | object = { ok: true, keyIds: ["Z3k1aXQ", "B9fR2sA"], checkedAt: "2026-10-20T10:05:00Z", latencyMs: 41, cacheSeconds: 300 };
    const calls = mockApi(routes("platform_admin", { [`POST ${one}/test`]: () => result }));
    renderApp("/admin/agent-platforms");
    const table = await screen.findByRole("table", { name: "Trusted agent platforms" });
    const open = async () => {
      await u.click(within(within(table).getByText("Pi Durable Platform").closest("tr")!).getByRole("button", { name: "Actions for Pi Durable Platform" }));
      await u.click(await screen.findByRole("menuitem", { name: "Test the keys" }));
      return screen.findByRole("dialog", { name: "Test the keys of Pi Durable Platform" });
    };
    let dialog = await open();
    expect(await within(dialog).findByText("The keys were fetched")).toBeInTheDocument();
    expect(within(dialog).getByText(/Z3k1aXQ, B9fR2sA/)).toBeInTheDocument();
    expect(within(dialog).getByText(/for 300 seconds/)).toBeInTheDocument();
    expect(sent(calls, "POST", `${one}/test`)).toHaveLength(1);
    result = { ok: false, error: "http_status", httpStatus: 503, keyIds: [], checkedAt: "2026-10-20T10:06:00Z", latencyMs: 12 };
    await u.click(within(dialog).getByRole("button", { name: "Test again" }));
    expect(await within(dialog).findByText("The keys couldn't be fetched")).toBeInTheDocument();
    expect(within(dialog).getByText(/The platform answered with an error status\. \(HTTP 503\)/)).toBeInTheDocument();
    await u.click(within(dialog).getAllByRole("button", { name: "Close" })[0]!);
    result = { ok: false, error: "not_allowed", keyIds: [], checkedAt: "2026-10-20T10:07:00Z", latencyMs: 1 };
    dialog = await open();
    expect(await within(dialog).findByText(/Internal addresses need an entry in Admin › Internal networks/)).toBeInTheDocument();
  });

  it("lists the relay accounts, marks one found by search, removes a mark", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        "GET /v1/admin/service-accounts": (_, call) => page(call.search.get("q") ? [serviceAccount({ id: "18181818-1818-4181-8181-181818181818", name: "deploy-bot" }), serviceAccount()] : []),
        [`PUT ${one}/relays/18181818-1818-4181-8181-181818181818`]: () => relayAccount({ serviceAccountId: "18181818-1818-4181-8181-181818181818", name: "deploy-bot" }),
        [`DELETE ${one}/relays/${serviceAccountId}`]: () => ({ ok: true }),
      }),
    );
    renderApp("/admin/agent-platforms");
    const table = await screen.findByRole("table", { name: "Trusted agent platforms" });
    await u.click(within(within(table).getByText("Pi Durable Platform").closest("tr")!).getByRole("button", { name: "Actions for Pi Durable Platform" }));
    await u.click(await screen.findByRole("menuitem", { name: "Relay accounts…" }));
    const dialog = await screen.findByRole("dialog", { name: "Relay accounts of Pi Durable Platform" });
    const relays = await within(dialog).findByRole("table", { name: "Relay accounts of Pi Durable Platform" });
    expect(within(relays).getByText("pdp-relay")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Add a relay account" }), "bot");
    const found = await within(dialog).findByRole("table", { name: "Matching service accounts" });
    // The account that already relays isn't offered again.
    expect(within(found).queryByText("ci-release-bot")).toBeNull();
    await u.click(within(found).getByRole("button", { name: "Mark deploy-bot as a relay" }));
    await waitFor(() => expect(sent(calls, "PUT", `${one}/relays/18181818-1818-4181-8181-181818181818`)).toHaveLength(1));
    await u.click(within(relays).getByRole("button", { name: "Remove the relay mark from pdp-relay" }));
    await waitFor(() => expect(sent(calls, "DELETE", `${one}/relays/${serviceAccountId}`)).toHaveLength(1));
  });

  it("deletes after a confirmation that says what happens to the relay accounts", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`DELETE ${one}`]: () => ({ ok: true }) }));
    renderApp("/admin/agent-platforms");
    const table = await screen.findByRole("table", { name: "Trusted agent platforms" });
    await u.click(within(within(table).getByText("Pi Durable Platform").closest("tr")!).getByRole("button", { name: "Actions for Pi Durable Platform" }));
    await u.click(await screen.findByRole("menuitem", { name: "Stop trusting…" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Stop trusting Pi Durable Platform?" });
    expect(within(dialog).getByText(/Its relay accounts become ordinary service accounts again/)).toBeInTheDocument();
    expect(sent(calls, "DELETE", one)).toHaveLength(0);
    await u.click(within(dialog).getByRole("button", { name: "Stop trusting" }));
    await waitFor(() => expect(sent(calls, "DELETE", one)).toHaveLength(1));
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    renderApp("/admin/agent-platforms");
    const table = await screen.findByRole("table", { name: "Trusted agent platforms" });
    expect(within(table).getByText("Pi Durable Platform")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Trust a platform" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();
    expect(screen.getByText(/Only platform admins can change them/)).toBeInTheDocument();
  });

  it("words the key fetch problems and checks issuers", () => {
    expect(fetchErrorLabel("redirect")).toMatch(/never follows redirects/);
    expect(fetchErrorLabel("http_status", 404)).toMatch(/HTTP 404/);
    expect(fetchErrorLabel("something_new")).toBe("The key fetch failed.");
    expect(issuerProblem("")).toMatch(/Enter the issuer/);
    expect(issuerProblem("agents.example.com")).toMatch(/full https address/);
    expect(issuerProblem("https://u:p@agents.example.com")).toMatch(/user name/);
    expect(issuerProblem("https://agents.example.com/?a=b")).toMatch(/query and fragment/);
    expect(issuerProblem("https://agents.example.com")).toBeUndefined();
  });
});
