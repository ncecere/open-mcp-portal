/* Team › Service accounts: the list, Create, the record (role and access, keys shown once, at most two active, revoke, settings with If-Match, disable and delete) and role-gated actions. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { gatewayId, myGateway, serviceAccount, serviceAccountId, serviceAccountKey, team } from "./fixtures";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type Role = Schemas["TeamRole"];
const base = `/v1/teams/${team.slug}/service-accounts`;
const list = `/teams/${team.slug}/service-accounts`;
const record = `${list}/${serviceAccountId}`;
const secret = "omp_sa_ab12cd34_0123456789abcdefghijklmnopqrstuv";
const platformGatewayId = "78787878-7878-4787-8787-787878787878";
/** What the account can use: its team's gateway (one capability with its role) and a platform gateway granted to the team. */
const accountGateways = [
  myGateway({ capabilityCount: 1 }),
  myGateway({ id: platformGatewayId, slug: "company-search", name: "Company search", ownerKind: "platform", teamSlug: undefined, teamName: undefined, access: ["team_grant"], capabilityCount: 3, url: "https://mcp.example.com/mcp/company-search" }),
];

const routes = (role: Role | null = "owner", sa = serviceAccount(), keys = [serviceAccountKey()], extra: Record<string, Handler> = {}, platformRole: Schemas["PlatformRole"] = "none"): Record<string, Handler> => ({
  ...shellRoutes(platformRole, role),
  [`GET ${base}`]: () => [sa],
  [`GET ${base}/${serviceAccountId}`]: () => sa,
  [`GET ${base}/${serviceAccountId}/keys`]: () => keys,
  [`GET ${base}/${serviceAccountId}/gateways`]: () => accountGateways,
  ...extra,
});

const made = (calls: Call[], method: string, url: string) => calls.filter((c) => c.method === method && c.url === url);

describe("Team › Service accounts list", () => {
  it("shows members each account's role, switch, active keys and last use, read-only", async () => {
    mockApi(routes("member"));
    const { container } = renderApp(list);
    expect(await screen.findByRole("heading", { level: 1, name: "Service accounts" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Service accounts" });
    const row = (await within(table).findByText("ci-release-bot")).closest("tr")!;
    expect(row).toHaveTextContent("Member");
    expect(row).toHaveTextContent("Enabled");
    expect(row).toHaveTextContent("1 of 2 active");
    expect(within(row).getByRole("link", { name: "ci-release-bot" })).toHaveAttribute("href", record);
    expect(screen.queryByRole("button", { name: "Create service account" })).toBeNull();
    expect(screen.getByText("Members can view the team's service accounts. Admins and owners can create and manage them and their keys.")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Service accounts · Platform Tools · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("explains service accounts when there are none, and offers Create to owners", async () => {
    mockApi(routes("owner", serviceAccount(), [], { [`GET ${base}`]: () => [] }));
    renderApp(list);
    expect(await screen.findByText("No service accounts yet.")).toBeInTheDocument();
    expect(screen.getByText(/Its keys don't depend on anyone staying on the team/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Create service account" }).length).toBeGreaterThan(0);
  });

  it("is open to platform staff who aren't members, read-only", async () => {
    mockApi(routes(null, serviceAccount(), [], {}, "platform_auditor"));
    renderApp(list);
    expect(await within(await screen.findByRole("table", { name: "Service accounts" })).findByText("ci-release-bot")).toBeInTheDocument();
    expect(screen.queryByText("Only team members can see this.")).toBeNull();
    expect(screen.queryByRole("button", { name: "Create service account" })).toBeNull();
  });
});

describe("Create service account", () => {
  it("checks the name, shows a taken one on its field, and opens the new account's keys", async () => {
    const u = userEvent.setup();
    let taken = true;
    const calls = mockApi(routes("admin", serviceAccount(), [], { [`POST ${base}`]: () => (taken ? Reply.error(409, "name_taken", "Taken") : new Reply(201, { data: serviceAccount() })) }));
    const { router, container } = renderApp(`${list}?form=new`);
    const name = await screen.findByRole("textbox", { name: "Name" });
    expect(screen.getByRole("radiogroup", { name: "Role" })).toBeInTheDocument();
    expect(screen.getByText(/The role only counts for capabilities' minimum roles/)).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Member/ })).toBeChecked();
    expect(await axe(container)).toHaveNoViolations();
    await u.type(name, "CI Bot");
    await u.click(screen.getByRole("button", { name: "Create service account" }));
    expect(await screen.findByText(/Use 1 to 64 lower-case letters, digits and dashes/)).toBeInTheDocument();
    expect(made(calls, "POST", base)).toHaveLength(0);
    await u.clear(name);
    await u.type(name, "ci-release-bot");
    await u.click(screen.getByRole("radio", { name: /Editor/ }));
    await u.click(screen.getByRole("button", { name: "Create service account" }));
    expect(await screen.findByText("Another service account in this team has this name. Choose another.")).toBeInTheDocument();
    taken = false;
    await u.type(name, "-2");
    await u.click(screen.getByRole("button", { name: "Create service account" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(record));
    expect(router.state.location.search).toMatchObject({ tab: "keys" });
    expect(made(calls, "POST", base).at(-1)?.body).toEqual({ name: "ci-release-bot-2", role: "editor", enabled: true, toolScope: null });
  });
});

describe("Service account › Overview", () => {
  it("lists the gateways it can use now, with what it reaches with its role, including platform gateways granted to the team", async () => {
    const calls = mockApi(routes("member"));
    const { container } = renderApp(record);
    expect(await screen.findByRole("heading", { level: 1, name: "ci-release-bot" })).toBeInTheDocument();
    expect(screen.getByRole("tablist", { name: "Service account sections" })).toBeInTheDocument();
    expect(screen.getByText(/Reaches the capabilities open to every member of the team/)).toBeInTheDocument();
    expect(screen.getByText(/The owners and admins of Platform Tools/)).toBeInTheDocument();
    const access = await screen.findByRole("table", { name: "Gateways ci-release-bot can use" });
    const own = within(access).getByRole("link", { name: "Support tools" }).closest("tr")!;
    expect(within(own).getByRole("link", { name: "Support tools" })).toHaveAttribute("href", `/teams/${team.slug}/gateways/${gatewayId}`);
    // The count is the account's (its role applied), not the gateway's.
    expect(own).toHaveTextContent("Platform Tools's gateway");
    expect(own).toHaveTextContent("1 capability");
    // A platform gateway granted to the team: listed, not linked for members.
    const granted = within(access).getByText("Company search").closest("tr")!;
    expect(granted).toHaveTextContent("Platform gateway granted to Platform Tools");
    expect(granted).toHaveTextContent("3 capabilities");
    expect(within(granted).queryByRole("link")).toBeNull();
    expect(screen.getByText(/A grant of a platform gateway to Platform Tools covers its service accounts/)).toBeInTheDocument();
    // Its own endpoint, not the team's gateway list.
    expect(calls.some((c) => c.url === `/v1/teams/${team.slug}/gateways`)).toBe(false);
    await waitFor(() => expect(document.title).toBe("ci-release-bot · Service accounts · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("links platform gateways to Admin for platform staff, and says when it can use none", async () => {
    mockApi(routes(null, serviceAccount(), [], {}, "platform_auditor"));
    renderApp(record);
    const access = await screen.findByRole("table", { name: "Gateways ci-release-bot can use" });
    expect(within(access).getByRole("link", { name: "Company search" })).toHaveAttribute("href", `/admin/gateways/${platformGatewayId}`);
  });

  it("says how many capabilities need a person's account, which service accounts can't use", async () => {
    mockApi(
      routes("member", serviceAccount(), [], {
        [`GET ${base}/${serviceAccountId}/gateways`]: () => [myGateway({ capabilityCount: 1, needsPersonCount: 2 }), { ...accountGateways[1]!, needsPersonCount: 0 }],
      }),
    );
    const { container } = renderApp(record);
    const access = await screen.findByRole("table", { name: "Gateways ci-release-bot can use" });
    const own = within(access).getByRole("link", { name: "Support tools" }).closest("tr")!;
    expect(own).toHaveTextContent("1 capability");
    expect(own).toHaveTextContent("2 more need a person's account");
    expect(within(access).getByText("Company search").closest("tr")).not.toHaveTextContent(/person's account/);
    expect(screen.getByText(/2 capabilities on these gateways need a person's account/)).toHaveTextContent("Service accounts can't use capabilities that need a person's account.");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("has no such note when nothing needs a person's account", async () => {
    mockApi(routes("member"));
    renderApp(record);
    await screen.findByRole("table", { name: "Gateways ci-release-bot can use" });
    expect(screen.queryByText(/need a person's account/)).toBeNull();
  });

  it("says when it can't use any gateway yet", async () => {
    mockApi(routes("owner", serviceAccount(), [], { [`GET ${base}/${serviceAccountId}/gateways`]: () => [] }));
    renderApp(record);
    expect(await screen.findByText(/It can't use any gateway yet/)).toBeInTheDocument();
  });

  it("says when it's turned off, and that it was never used", async () => {
    mockApi(routes("member", serviceAccount({ enabled: false, lastUsedAt: null })));
    renderApp(record);
    expect(await screen.findByText(/Its keys are refused until it's turned on again/)).toHaveTextContent("The team's owners and admins can turn it on again.");
    expect(screen.getByText("Never used")).toBeInTheDocument();
  });

  it("says turned off and archived in one notice, not a stack of warnings", async () => {
    mockApi({
      ...routes("owner", serviceAccount({ enabled: false })),
      [`GET /v1/teams/${team.slug}`]: () => ({ team: { ...team, status: "archived" }, role: "owner" }),
    });
    renderApp(`${record}?tab=keys`);
    const notice = await screen.findByText("Turned off, and the team is archived");
    expect(notice).toBeInTheDocument();
    await screen.findByRole("table", { name: "Keys of ci-release-bot" });
    expect(screen.queryByText("This team is archived")).toBeNull();
    expect(screen.queryByText(/Its keys are refused until it's turned on again/)).toBeNull();
    expect(screen.queryByText(/The account is turned off. Turn it on in Settings to create a key/)).toBeNull();
  });

  it("shows the not-found page for an unknown account", async () => {
    mockApi(routes("owner", serviceAccount(), [], { [`GET ${base}/${serviceAccountId}`]: () => Reply.error(404, "not_found") }));
    renderApp(record);
    expect(await screen.findByRole("heading", { level: 1, name: "Not found" })).toBeInTheDocument();
  });
});

describe("Service account › Keys", () => {
  it("creates a key and shows its secret once, with the rotation steps", async () => {
    const u = userEvent.setup();
    const created: Schemas["ServiceAccountKeyCreated"] = { key: serviceAccountKey({ id: "new", name: "Release workflow", lastUsedAt: null }), secret };
    const calls = mockApi(routes("owner", serviceAccount(), [serviceAccountKey()], { [`POST ${base}/${serviceAccountId}/keys`]: () => new Reply(201, { data: created }) }));
    const { container } = renderApp(`${record}?tab=keys`);
    const table = await screen.findByRole("table", { name: "Keys of ci-release-bot" });
    expect((await within(table).findByText("GitHub Actions")).closest("tr")).toHaveTextContent("omp_sa_ab12cd34…");
    expect(screen.getByText(/at most 2 active keys/)).toHaveTextContent("create a new key, deploy it where the old one is used, then revoke the old one");
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("button", { name: "Create key" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a key for ci-release-bot" });
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    expect(await within(dialog).findByText("Enter a name.")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Release workflow");
    // The gateways it can use, platform ones granted to the team too.
    await u.click(within(dialog).getByRole("combobox", { name: /Limit to gateways/ }));
    expect(await screen.findByRole("option", { name: /Support tools/ })).toBeInTheDocument();
    await u.click(await screen.findByRole("option", { name: /Company search/ }));
    await u.keyboard("{Escape}");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    await waitFor(() =>
      expect(made(calls, "POST", `${base}/${serviceAccountId}/keys`)[0]?.body).toEqual({ name: "Release workflow", expiresInDays: 90, gatewayIds: [platformGatewayId], toolScope: null }),
    );

    const shown = await screen.findByRole("dialog", { name: "Key created" });
    expect(within(shown).getByText("Copy this key now.")).toBeInTheDocument();
    expect(within(shown).getByText(/It won't be shown again/)).toBeInTheDocument();
    expect(within(shown).getByText(secret)).toBeInTheDocument();
    expect(within(shown).getByRole("button", { name: /Copy service account key secret/ })).toBeInTheDocument();
    // Another key was active before this one: the next step of the rotation, said once.
    expect(within(shown).getByText("Next: finish the rotation")).toBeInTheDocument();
    expect(shown).toHaveTextContent("Deploy this key where the older one is used, then revoke the older key on the Keys tab.");
    expect(shown.textContent).not.toContain("To rotate a key without downtime");
    expect(await axe(shown)).toHaveNoViolations();
    await u.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Key created" })).toBeNull());
    expect(document.body.textContent).not.toContain(secret);
  });

  it("doesn't call a first key a rotation, even once the list counts it", async () => {
    const u = userEvent.setup();
    const created: Schemas["ServiceAccountKeyCreated"] = { key: serviceAccountKey({ id: "new", name: "First", lastUsedAt: null }), secret };
    let keys: Schemas["ServiceAccountKey"][] = [];
    mockApi(
      routes("owner", serviceAccount({ activeKeyCount: 0 }), [], {
        [`GET ${base}/${serviceAccountId}/keys`]: () => keys,
        [`POST ${base}/${serviceAccountId}/keys`]: () => {
          keys = [created.key];
          return new Reply(201, { data: created });
        },
      }),
    );
    renderApp(`${record}?tab=keys`);
    await screen.findByText("No keys yet.");
    await u.click(screen.getAllByRole("button", { name: "Create key" })[0]!);
    const dialog = await screen.findByRole("dialog", { name: "Create a key for ci-release-bot" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "First");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    const shown = await screen.findByRole("dialog", { name: "Key created" });
    // The list reloads with the new key (one active now) while the secret is still shown.
    await within(await screen.findByRole("table", { name: "Keys of ci-release-bot", hidden: true })).findByText("First");
    expect(within(shown).queryByText("Next: finish the rotation")).toBeNull();
  });

  it("allows at most two active keys: Create is off and the rotation is explained", async () => {
    const two = [serviceAccountKey(), serviceAccountKey({ id: "k2", name: "New runner", prefix: "omp_sa_zz99yy88" })];
    mockApi(routes("owner", serviceAccount({ activeKeyCount: 2 }), two));
    renderApp(`${record}?tab=keys`);
    expect(await screen.findByText("2 active keys: the most it can have")).toBeInTheDocument();
    await within(await screen.findByRole("table", { name: "Keys of ci-release-bot" })).findByText("New runner");
    expect(screen.getByRole("button", { name: "Create key" })).toBeDisabled();
  });

  it("shows the server's refusal of a third key", async () => {
    const u = userEvent.setup();
    mockApi(routes("owner", serviceAccount(), [serviceAccountKey()], { [`POST ${base}/${serviceAccountId}/keys`]: () => Reply.error(409, "too_many_keys", "Too many") }));
    renderApp(`${record}?tab=keys`);
    await u.click(await screen.findByRole("button", { name: "Create key" }));
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Third");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    expect(await within(dialog).findByText("It already has 2 active keys. Revoke the older one first.")).toBeInTheDocument();
  });

  it("revokes a key after confirming, warning when it's the only active one", async () => {
    const u = userEvent.setup();
    const key = serviceAccountKey();
    const calls = mockApi(routes("owner", serviceAccount(), [key], { [`DELETE ${base}/${serviceAccountId}/keys/${key.id}`]: () => ({ ok: true }) }));
    renderApp(`${record}?tab=keys`);
    await u.click(await screen.findByRole("button", { name: `Actions for ${key.name}` }));
    await u.click(await screen.findByRole("menuitem", { name: "Revoke…" }));
    const ask = await screen.findByRole("alertdialog", { name: `Revoke ${key.name}?` });
    expect(ask).toHaveTextContent("It's the only active key of ci-release-bot");
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Revoke key" }));
    await waitFor(() => expect(made(calls, "DELETE", `${base}/${serviceAccountId}/keys/${key.id}`)).toHaveLength(1));
  });

  it("tells members who can see the keys, without asking for them", async () => {
    const calls = mockApi(routes("member"));
    renderApp(`${record}?tab=keys`);
    expect(await screen.findByText("Only the team's owners and admins see this account's keys.")).toBeInTheDocument();
    expect(calls.some((c) => c.url.endsWith("/keys"))).toBe(false);
  });

  it("lets platform staff read the keys, but not create or revoke them", async () => {
    mockApi(routes(null, serviceAccount(), [serviceAccountKey()], {}, "platform_admin"));
    renderApp(`${record}?tab=keys`);
    expect(await within(await screen.findByRole("table", { name: "Keys of ci-release-bot" })).findByText("GitHub Actions")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create key" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Actions for/ })).toBeNull();
  });
});

describe("Service account › Settings", () => {
  it("saves with If-Match, asks before turning it off, and deletes after confirming", async () => {
    const u = userEvent.setup();
    let current = serviceAccount();
    const calls = mockApi(
      routes("owner", current, [], {
        [`GET ${base}/${serviceAccountId}`]: () => current,
        [`PATCH ${base}/${serviceAccountId}`]: (body) => (current = serviceAccount({ ...(body as object), revision: 6 })),
        [`DELETE ${base}/${serviceAccountId}`]: () => ({ ok: true }),
      }),
    );
    const { router, container } = renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("radio", { name: /Editor/ }));
    await u.click(screen.getByRole("switch", { name: /Enabled/ }));
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disable ci-release-bot?" });
    expect(made(calls, "PATCH", `${base}/${serviceAccountId}`)).toHaveLength(0);
    await u.click(within(ask).getByRole("button", { name: "Disable service account" }));
    await waitFor(() => expect(made(calls, "PATCH", `${base}/${serviceAccountId}`)).toHaveLength(1));
    const patch = made(calls, "PATCH", `${base}/${serviceAccountId}`)[0]!;
    expect(patch.headers.get("If-Match")).toBe('"5"');
    expect(patch.body).toMatchObject({ role: "editor", enabled: false, name: "ci-release-bot" });

    await u.click(screen.getByRole("button", { name: "Delete service account" }));
    const del = await screen.findByRole("alertdialog", { name: "Delete ci-release-bot?" });
    await u.click(within(del).getByRole("button", { name: "Delete service account" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(list));
    expect(made(calls, "DELETE", `${base}/${serviceAccountId}`)).toHaveLength(1);
  });

  it("checks the name before saving", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("admin"));
    renderApp(`${record}?tab=settings`);
    const name = await screen.findByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Bad Name");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/Use 1 to 64 lower-case letters/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
  });

  it("is read-only for members, who can't delete", async () => {
    mockApi(routes("member"));
    renderApp(`${record}?tab=settings`);
    expect(await screen.findByText("Members can view the service account's settings. Owners and admins can change them.")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Name" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Delete service account" })).toBeNull();
  });
});

describe("the command palette", () => {
  it("offers owners Create service account, which opens the form", async () => {
    const u = userEvent.setup();
    mockApi(routes("owner"));
    const { router } = renderApp(`/teams/${team.slug}`);
    await screen.findByRole("heading", { level: 1, name: team.name });
    await u.click(screen.getByRole("button", { name: /Search or jump to/ }));
    await u.type(await screen.findByRole("combobox"), "service account");
    await u.click(await screen.findByRole("option", { name: /Create service account/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe(list));
    expect(router.state.location.search).toMatchObject({ form: "new" });
  });
});
