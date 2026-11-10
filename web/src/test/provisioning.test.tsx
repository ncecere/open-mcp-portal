/* Admin › Provisioning: set-up, the token secret once, adopt/unlink, mappings, read-only auditors (docs/scim.md). */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const directory: Schemas["ProvisioningDirectory"] = {
  id: "d1",
  issuer: "https://idp.example.test",
  issuerMatches: true,
  enabled: true,
  enrollment: "optional",
  scimBaseUrl: "https://portal.example.test/scim/v2",
  revision: 3,
  createdAt: "2026-10-01T10:00:00Z",
  updatedAt: "2026-10-02T10:00:00Z",
};
const token: Schemas["ProvisioningToken"] = {
  id: "t1",
  name: "Entra ID",
  prefix: "ompscim_Ab3dEf9h",
  status: "active",
  createdAt: "2026-10-01T10:00:00Z",
  expiresAt: "2027-01-01T10:00:00Z",
  createdByName: "Ada Admin",
};
const users: Schemas["ProvisionedUsers"] = {
  truncated: false,
  resources: [
    { id: "s1", userName: "pat@example.test", externalId: "sub-pat", active: true, displayName: "Pat", email: "pat@example.test", candidate: { id: "u1", email: "pat@example.test", adoptable: true } },
    { id: "s2", userName: "own@example.test", externalId: "sub-own", active: true, displayName: "", email: "", candidate: { id: "u2", email: "own@example.test", adoptable: false, reason: "protected_principal" } },
    { id: "s3", userName: "new@example.test", externalId: "sub-new", active: false, displayName: "", email: "" },
  ],
  people: [{ id: "u3", email: "lee@example.test", displayName: "Lee", status: "suspended", manualStatus: "active", directoryStanding: "inactive", scimUserId: "s4", cleanupPending: false }],
};
const mappings: Schemas["ProvisioningMapping"][] = [
  { id: "m1", groupId: "g1", groupName: "Engineering", teamId: "tm1", teamSlug: "tools", teamName: "Tools", role: "editor", memberCount: 4, createdAt: "2026-10-01T10:00:00Z" },
];

const routes = (extra: Record<string, Handler> = {}, role: Schemas["PlatformRole"] = "platform_admin"): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/provisioning": () => directory,
  "GET /v1/admin/provisioning/tokens": () => [token],
  "GET /v1/admin/provisioning/users": () => users,
  "GET /v1/admin/provisioning/mappings": () => mappings,
  "GET /v1/admin/provisioning/groups": () => [{ id: "g1", displayName: "Engineering", memberCount: 4 }],
  ...extra,
});

describe("Admin › Provisioning", () => {
  it("offers set-up before there is a directory", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes({
        "GET /v1/admin/provisioning": () => new Reply(404, { error: { code: "directory_not_found", message: "Provisioning is not set up" } }),
        "POST /v1/admin/provisioning": () => new Reply(201, { data: directory }),
      }),
    );
    const { container } = renderApp("/admin/provisioning");
    const setup = await screen.findByRole("button", { name: "Set up provisioning" });
    expect(screen.queryByRole("table", { name: "Provisioning tokens" })).toBeNull();
    await u.click(screen.getByRole("radio", { name: /Required/ }));
    await u.click(setup);
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ enabled: false, enrollment: "required" }));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows the directory, tokens, people with adopt and unlink, and mappings", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/admin/provisioning/users/s1/adopt": () => ({ ok: true }) }));
    const { container } = renderApp("/admin/provisioning");
    expect(await screen.findByText("https://idp.example.test")).toBeInTheDocument();
    expect(screen.getByText("https://portal.example.test/scim/v2")).toBeInTheDocument();
    const tokens = await screen.findByRole("table", { name: "Provisioning tokens" });
    expect(within(tokens).getByText("Entra ID").closest("tr")).toHaveTextContent("ompscim_Ab3dEf9h…");
    const accounts = await screen.findByRole("table", { name: "Provisioned accounts" });
    expect(within(accounts).getByText("Platform admins and team owners can't be directory managed.")).toBeInTheDocument();
    expect(within(accounts).getByText("Enrolls on first sign-in")).toBeInTheDocument();
    const people = screen.getByRole("table", { name: "Directory-managed people" });
    expect(within(people).getByText("lee@example.test").closest("tr")).toHaveTextContent("Deactivated in directory");
    expect(screen.getByRole("table", { name: "Group mappings" })).toHaveTextContent("Engineering");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(accounts).getByRole("button", { name: "Adopt" }));
    const confirm = await screen.findByRole("alertdialog");
    await u.click(within(confirm).getByRole("button", { name: "Adopt" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/v1/admin/provisioning/users/s1/adopt")).toBe(true));
  });

  it("creates a token and shows the secret once", async () => {
    const u = userEvent.setup();
    const secret = "ompscim_" + "x".repeat(43);
    const calls = mockApi(routes({ "POST /v1/admin/provisioning/tokens": () => new Reply(201, { data: { ...token, id: "t2", name: "Okta", secret } }) }));
    renderApp("/admin/provisioning");
    await u.click(await screen.findByRole("button", { name: "Create token" }));
    const dialog = await screen.findByRole("dialog", { name: "Create a provisioning token" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Okta");
    await u.click(within(dialog).getByRole("button", { name: "Create token" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Okta", expiresInDays: 90 }));
    const shown = await screen.findByRole("dialog", { name: "Token created" });
    expect(within(shown).getByText(secret)).toBeInTheDocument();
    await u.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(secret);
  });

  it("is read-only for auditors", async () => {
    mockApi(routes({}, "platform_auditor"));
    renderApp("/admin/provisioning");
    expect(await screen.findByRole("table", { name: "Provisioned accounts" })).toBeInTheDocument();
    for (const name of ["Save", "Create token", "Adopt", "Unlink", "Map a group"]) expect(screen.queryByRole("button", { name })).toBeNull();
  });
});
