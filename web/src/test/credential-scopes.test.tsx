import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { callErrorLabel } from "../components/gateways/labels";
import { apiKey, gatewayId, grant, myGateway, oauthGrant, platformGateway, serviceAccount, serviceAccountId, serviceAccountKey, team, teamSummary, page } from "./fixtures";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const saBase = `/v1/teams/${team.slug}/service-accounts`;
const saOne = `${saBase}/${serviceAccountId}`;
const saPage = `/teams/${team.slug}/service-accounts/${serviceAccountId}`;
function accountRoutes(role: Schemas["TeamRole"] = "owner", account = serviceAccount(), extra: Record<string, Handler> = {}) {
  return {
    ...shellRoutes("none", role),
    [`GET ${saOne}`]: () => account,
    [`GET ${saBase}`]: () => [account],
    [`GET ${saOne}/keys`]: () => [serviceAccountKey({ toolScope: { classes: ["write"] } })],
    [`GET ${saOne}/gateways`]: () => [myGateway()],
    ...extra,
  };
}

describe("Credential scope payloads and views", () => {
  it.each([
    { preset: "Read only", scope: { classes: ["read"], tools: [] } satisfies Schemas["ToolScope"] },
    { preset: "Custom", scope: { classes: [], tools: [] } },
  ])("creates a personal key with $preset rather than unrestricted null", async ({ preset, scope }) => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes(),
      "GET /v1/me/api-keys": () => [apiKey()],
      "GET /v1/me/gateways": () => [myGateway()],
      "POST /v1/me/api-keys": () => ({ key: apiKey({ toolScope: scope }), secret: "one-time" }),
    });
    renderApp("/settings/api-keys");
    await u.click(await screen.findByRole("button", { name: "Create API key" }));
    await u.type(screen.getByRole("textbox", { name: "Name" }), "Summarizer");
    await u.click(screen.getByRole("radio", { name: preset }));
    await u.click(screen.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Summarizer", expiresInDays: 90, toolScope: scope }));
  });

  it("blocks invalid exact names, permits renamed future tools, and displays stored personal scope", async () => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes(),
      "GET /v1/me/api-keys": () => [apiKey({ toolScope: { tools: ["RenamedFutureTool"] } })],
      "GET /v1/me/gateways": () => [],
      "POST /v1/me/api-keys": () => ({ key: apiKey(), secret: "one-time" }),
    });
    renderApp("/settings/api-keys");
    const table = await screen.findByRole("table", { name: "API keys" });
    expect(await within(table).findByText("RenamedFutureTool")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Create API key" }));
    await u.type(screen.getByRole("textbox", { name: "Name" }), "Exact");
    await u.click(screen.getByRole("radio", { name: "Custom" }));
    const names = screen.getByRole("textbox", { name: "Exact tool names" });
    await u.type(names, "*{Enter}");
    await u.click(screen.getByRole("button", { name: "Create key" }));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await u.click(screen.getByRole("button", { name: "Clear name draft" }));
    await u.type(names, "RenamedFutureTool{Enter}");
    await u.click(screen.getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Exact", expiresInDays: 90, toolScope: { classes: [], tools: ["RenamedFutureTool"] } }));
  });

  it("shows account and key ceilings separately and stores null keys under restricted accounts", async () => {
    const u = userEvent.setup();
    const account = serviceAccount({ toolScope: { classes: ["read"] } });
    const calls = mockApi(accountRoutes("owner", account, {
      [`POST ${saOne}/keys`]: () => ({ key: serviceAccountKey(), secret: "one-time" }),
    }));
    const { container } = renderApp(`${saPage}?tab=keys`);
    const table = await screen.findByRole("table", { name: "Keys of ci-release-bot" });
    expect(await within(table).findByText("Write")).toBeInTheDocument();
    expect(screen.getByText("Read")).toBeInTheDocument();
    expect(screen.getByText(/Keys may store Everything under a restricted account/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Create key" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Read")).toBeInTheDocument();
    expect(within(dialog).getByText(/Account ceiling/)).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Inherit");
    await u.click(within(dialog).getByRole("button", { name: "Create key" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Inherit", expiresInDays: 90, toolScope: null }));
  });

  it.each([
    { preset: "Everything", expected: null },
    { preset: "Custom", expected: { classes: ["write"] } },
  ])("replaces an account ceiling with $preset using If-Match", async ({ preset, expected }) => {
    const u = userEvent.setup();
    const initial = serviceAccount({ toolScope: { classes: ["read"] } });
    const calls = mockApi(accountRoutes("owner", initial, {
      [`PATCH ${saOne}`]: (body) => ({ ...initial, ...(body as Schemas["ServiceAccountUpdate"]), revision: 6 }),
    }));
    const { container } = renderApp(`${saPage}?tab=settings`);
    await u.click(await screen.findByRole("radio", { name: preset }));
    if (preset === "Custom") {
      await u.click(screen.getByRole("checkbox", { name: "Read" }));
      await u.click(screen.getByRole("checkbox", { name: "Write" }));
    }
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")).toBeDefined());
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(patch.headers.get("If-Match")).toBe('"5"');
    expect(patch.body).toMatchObject({ toolScope: expected });
  });

  it("omits an unchanged account ceiling and lets members read its badges without editing", async () => {
    const u = userEvent.setup();
    const account = serviceAccount({ toolScope: { tools: ["FutureTool"] } });
    const calls = mockApi(accountRoutes("owner", account, {
      [`PATCH ${saOne}`]: (body) => ({ ...account, ...(body as Schemas["ServiceAccountUpdate"]), revision: 6 }),
    }));
    const { unmount } = renderApp(`${saPage}?tab=settings`);
    await u.type(await screen.findByRole("textbox", { name: "Description" }), " updated");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")).toBeDefined());
    expect(calls.find((c) => c.method === "PATCH")?.body).not.toHaveProperty("toolScope");
    unmount();
    mockApi(accountRoutes("member", account));
    renderApp(`${saPage}?tab=settings`);
    expect(await screen.findByText("FutureTool")).toBeInTheDocument();
    expect(screen.queryByRole("radiogroup", { name: "Tool scope" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Save settings" })).toBeNull();
  });

  it("creates an account with a tool ceiling", async () => {
    const u = userEvent.setup();
    const calls = mockApi(accountRoutes("owner", serviceAccount(), { [`POST ${saBase}`]: () => serviceAccount({ toolScope: { classes: ["read"], tools: [] } }) }));
    renderApp(`/teams/${team.slug}/service-accounts?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "summary-bot");
    await u.click(screen.getByRole("radio", { name: "Read only" }));
    await u.click(screen.getByRole("button", { name: "Create service account" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ toolScope: { classes: ["read"], tools: [] } }));
  });

  it("adds a scoped platform grant, shows stored scope, and leaves auditors read-only", async () => {
    const u = userEvent.setup();
    const base = `/v1/admin/gateways/${gatewayId}`;
    const scoped = grant({ toolScope: { classes: ["read"] } });
    const routes = {
      ...shellRoutes("platform_admin", null),
      [`GET ${base}`]: () => platformGateway(),
      [`GET ${base}/grants`]: () => [scoped],
      "GET /v1/me/gateways": () => [],
      "GET /v1/admin/teams": () => page([teamSummary()]),
      [`POST ${base}/grants`]: () => scoped,
    };
    const calls = mockApi(routes);
    const { container, unmount } = renderApp(`/admin/gateways/${gatewayId}?tab=access`);
    const table = await screen.findByRole("table", { name: "Grants" });
    expect(await within(table).findByText("Read")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Add grant" }));
    const dialog = await screen.findByRole("dialog");
    const teamChoice = within(dialog).getByRole("combobox", { name: "Team" });
    await within(teamChoice).findByRole("option", { name: team.name });
    await u.selectOptions(teamChoice, team.slug);
    await u.click(within(dialog).getByRole("radio", { name: "Read only" }));
    expect(dialog).toHaveTextContent("Matching grants are alternatives");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(dialog).getByRole("button", { name: "Grant access" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ subjectKind: "team", team: team.slug, toolScope: { classes: ["read"], tools: [] } }));
    unmount();
    mockApi({ ...routes, ...shellRoutes("platform_auditor", null) });
    renderApp(`/admin/gateways/${gatewayId}?tab=access`);
    expect(await screen.findByText("Read")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add grant" })).toBeNull();
    expect(screen.queryByRole("radio", { name: "Custom" })).toBeNull();
  });

  it("shows connected app scopes, including old unrestricted fixtures, and labels scoped refusals", async () => {
    mockApi({
      ...shellRoutes(),
      "GET /v1/me/oauth-grants": () => [oauthGrant({ toolScope: { classes: ["read"] } }), oauthGrant({ id: "empty", client: { ...oauthGrant().client, name: "No tools app" }, toolScope: {} }), oauthGrant({ id: "legacy", client: { ...oauthGrant().client, name: "Legacy app" } })],
    });
    const { container } = renderApp("/settings/connected-apps");
    const table = await screen.findByRole("table", { name: "Your connected apps" });
    expect((await within(table).findByText("Claude Code")).closest("tr")).toHaveTextContent("Read");
    expect(within(table).getByText("No tools app").closest("tr")).toHaveTextContent("No tools");
    expect(within(table).getByText("Legacy app").closest("tr")).toHaveTextContent("Everything");
    expect(callErrorLabel("tool_scope")).toBe("Outside tool scope");
    expect(await axe(container)).toHaveNoViolations();
  });
});
