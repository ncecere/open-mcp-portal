/* Admin → Trusted clients: the list, its client-ID checks, the open-registration switch, the save with If-Match and confirmation, a refused entry, a save conflict, and auditors reading. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { clientIdProblem } from "../pages/admin/oauth/clients";
import { trustedClients } from "./fixtures";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type Clients = Schemas["TrustedClients"];
const path = "/v1/admin/settings/oauth-clients";
const puts = (calls: Call[]) => calls.filter((c) => c.method === "PUT" && c.url === path);

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  [`GET ${path}`]: () => trustedClients(),
  ...extra,
});

describe("Admin → Trusted clients", () => {
  it("explains what trusting does, and adds a client after confirming (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PUT ${path}`]: (body) => trustedClients({ clients: (body as Clients).clients, revision: 3 }) }));
    const { container } = renderApp("/admin/trusted-clients");
    expect(await screen.findByRole("heading", { level: 1, name: "Trusted clients" })).toBeInTheDocument();
    expect(screen.getByText(/Everyone still signs in with their company account/)).toBeInTheDocument();
    expect(screen.getByText(/Clients that registered themselves can't be trusted/)).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Trusted clients" });
    expect(within(table).getByText("https://claude.ai/oauth/claude-code-client-metadata")).toBeInTheDocument();
    expect(within(table).getByText("Vouched for by vscode.dev")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Trusted clients · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("button", { name: "Add client" }));
    const dialog = await screen.findByRole("dialog", { name: "Add trusted client" });
    const id = within(dialog).getByRole("textbox", { name: "Client ID" });
    // A registered client's ID can't be trusted.
    await u.type(id, "ompcl_3f9a1c");
    await u.click(within(dialog).getByRole("button", { name: "Add client" }));
    expect(within(dialog).getByText(/Clients that registered themselves can't be trusted/)).toBeInTheDocument();
    await u.clear(id);
    await u.type(id, "https://claude.ai/oauth/claude-code-client-metadata");
    expect(within(dialog).getByText("This client is already on the list.")).toBeInTheDocument();
    await u.clear(id);
    await u.type(id, "https://cursor.com/oauth/client-metadata.json");
    await u.type(within(dialog).getByRole("textbox", { name: /Label/ }), "Cursor");
    expect(await axe(dialog)).toHaveNoViolations();
    await u.click(within(dialog).getByRole("button", { name: "Add client" }));
    expect(within(table).getByText("https://cursor.com/oauth/client-metadata.json")).toBeInTheDocument();
    expect(puts(calls)).toHaveLength(0);

    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Save the trusted clients?" });
    expect(ask).toHaveTextContent("Trusted from now on: Cursor.");
    expect(ask).toHaveTextContent("they only sign in");
    await u.click(within(ask).getByRole("button", { name: "Save trusted clients" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect(puts(calls)[0]?.headers.get("If-Match")).toBe('"2"');
    expect((puts(calls)[0]?.body as Clients).clients).toEqual([
      { clientId: "https://claude.ai/oauth/claude-code-client-metadata", label: "Claude Code" },
      { clientId: "https://vscode.dev/oauth/client-metadata.json", label: "VS Code" },
      { clientId: "https://cursor.com/oauth/client-metadata.json", label: "Cursor" },
    ]);
    expect(await screen.findByText("Client settings saved")).toBeInTheDocument();
  });

  it("turns open client registration off after confirming, saving it with the list (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PUT ${path}`]: (body) => trustedClients({ ...(body as Clients), revision: 3 }) }));
    const { container } = renderApp("/admin/trusted-clients");
    const section = await screen.findByRole("region", { name: "Client registration" });
    const toggle = within(section).getByRole("switch", { name: "Allow open client registration" });
    expect(toggle).toBeChecked();
    expect(section).toHaveTextContent("registered apps are always marked Unverified");
    expect(section).toHaveTextContent("Apps that already registered keep working");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(toggle);
    expect(toggle).not.toBeChecked();
    expect(puts(calls)).toHaveLength(0);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Save the trusted clients?" });
    expect(ask).toHaveTextContent("Apps can no longer register themselves.");
    await u.click(within(ask).getByRole("button", { name: "Save trusted clients" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect(puts(calls)[0]?.headers.get("If-Match")).toBe('"2"');
    expect(puts(calls)[0]?.body).toEqual({ clients: trustedClients().clients, openRegistration: false });
    expect(await screen.findByText("Apps can no longer register themselves.")).toBeInTheDocument();
    expect(within(await screen.findByRole("region", { name: "Client registration" })).getByRole("switch")).not.toBeChecked();
  });

  it("shows registration that is already off, turns it on again, and discards a change", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`GET ${path}`]: () => trustedClients({ openRegistration: false }), [`PUT ${path}`]: (body) => trustedClients({ ...(body as Clients), revision: 3 }) }));
    renderApp("/admin/trusted-clients");
    const toggle = await screen.findByRole("switch", { name: "Allow open client registration" });
    expect(toggle).not.toBeChecked();
    await u.click(toggle);
    await u.click(screen.getByRole("button", { name: "Discard" }));
    expect(toggle).not.toBeChecked();
    await u.click(toggle);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog");
    expect(ask).toHaveTextContent("Apps can register themselves again.");
    await u.click(within(ask).getByRole("button", { name: "Save trusted clients" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect((puts(calls)[0]?.body as Clients).openRegistration).toBe(true);
  });

  it("names removed clients in the confirmation, and shows a refused client on its row", async () => {
    const u = userEvent.setup();
    mockApi(routes("platform_admin", { [`PUT ${path}`]: () => Reply.error(422, "invalid_client_id", "entry 0", { index: 0, reason: "not_metadata_url" }) }));
    renderApp("/admin/trusted-clients");
    const table = await screen.findByRole("table", { name: "Trusted clients" });
    await u.click(within(table).getByRole("button", { name: "Actions for VS Code" }));
    await u.click(await screen.findByRole("menuitem", { name: "Remove" }));
    expect(within(table).queryByText("VS Code")).toBeNull();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog");
    expect(ask).toHaveTextContent("Asks for consent again: VS Code.");
    await u.click(within(ask).getByRole("button", { name: "Save trusted clients" }));
    expect(await within(table).findByText(/The portal doesn't accept this ID/)).toBeInTheDocument();
  });

  it("keeps the edits through a save conflict (412) and overwrites on the latest revision", async () => {
    const u = userEvent.setup();
    let current = trustedClients();
    let conflict = true;
    const calls = mockApi(
      routes("platform_admin", {
        [`GET ${path}`]: () => current,
        [`PUT ${path}`]: (body) => {
          if (!conflict) return trustedClients({ clients: (body as Clients).clients, revision: 9 });
          conflict = false;
          current = trustedClients({ clients: [current.clients[0]!], revision: 8 });
          return Reply.error(412, "revision_conflict", "Changed");
        },
      }),
    );
    renderApp("/admin/trusted-clients");
    await u.click(await screen.findByRole("button", { name: "Add client" }));
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByRole("textbox", { name: "Client ID" }), "https://cursor.com/oauth/client-metadata.json");
    await u.click(within(dialog).getByRole("button", { name: "Add client" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save trusted clients" }));
    await u.click(await screen.findByRole("button", { name: "Overwrite with mine" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save trusted clients" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(2));
    expect(puts(calls)[1]?.headers.get("If-Match")).toBe('"8"');
    expect((puts(calls)[1]?.body as Clients).clients.map((c) => c.clientId)).toContain("https://cursor.com/oauth/client-metadata.json");
  });

  it("moves the focus to the first invalid field after a refused Add", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    renderApp("/admin/trusted-clients");
    await u.click(await screen.findByRole("button", { name: "Add client" }));
    const dialog = await screen.findByRole("dialog", { name: "Add trusted client" });
    const label = within(dialog).getByRole("textbox", { name: /Label/ });
    await u.type(label, "Cursor");
    expect(label).toHaveFocus();
    await u.click(within(dialog).getByRole("button", { name: "Add client" }));
    const id = within(dialog).getByRole("textbox", { name: "Client ID" });
    await waitFor(() => expect(id).toHaveFocus());
    expect(id).toHaveAttribute("aria-invalid", "true");
    expect(within(dialog).getByText(/Enter the client's ID/)).toBeInTheDocument();
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    const { container } = renderApp("/admin/trusted-clients");
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(await screen.findByText("https://vscode.dev/oauth/client-metadata.json")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add client" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();
    // The switch shows the setting and can't be changed.
    expect(screen.getByRole("switch", { name: "Allow open client registration" })).toHaveAttribute("aria-disabled", "true");
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("client ID checks", () => {
  it("accept only metadata documents: https addresses with a path", () => {
    expect(clientIdProblem("https://claude.ai/oauth/claude-code-client-metadata")).toBeUndefined();
    expect(clientIdProblem("  https://vscode.dev/oauth/client-metadata.json ")).toBeUndefined();
    expect(clientIdProblem("")).toMatch(/Enter the client's ID/);
    expect(clientIdProblem("ompcl_3f9a1c")).toMatch(/registered themselves can't be trusted/);
    expect(clientIdProblem("http://claude.ai/oauth/x")).toMatch(/Only https/);
    expect(clientIdProblem("https://claude.ai")).toMatch(/Add the document's path/);
    expect(clientIdProblem("https://claude.ai/")).toMatch(/Add the document's path/);
    expect(clientIdProblem("https://me:pw@claude.ai/x")).toMatch(/user name and password/);
    expect(clientIdProblem("https://claude.ai/x#frag")).toMatch(/fragment/);
    expect(clientIdProblem(`https://claude.ai/${"a".repeat(500)}`)).toMatch(/at most 500/);
  });
});
