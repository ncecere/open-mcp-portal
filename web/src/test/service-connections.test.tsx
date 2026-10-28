import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { redirectTo } from "../components/providers/labels";
import { serverId, serviceAccount, serviceAccountId, team } from "./fixtures";
import { providerId, providerSummary } from "./fixtures-providers";
import { mockApi, renderApp, shellRoutes, type Handler } from "./harness";

const base = `/v1/teams/${team.slug}/service-connections`;
const record = `/teams/${team.slug}/service-accounts/${serviceAccountId}?tab=connections`;
const shared: Schemas["ServiceConnection"] = { id: "25252525-2525-4525-8525-252525252525", teamId: team.id, providerId, providerName: "GitHub", name: "Release account", accountLabel: "release-bot", status: "active", scopes: ["repo"], revision: 3, accounts: [], servers: [] };
const destination: Schemas["AllowableServer"] = { server: { id: serverId, slug: "status", name: "Status", teamSlug: team.slug, teamName: team.name }, origin: "https://status.example.com", scopes: ["repo"], covered: true, allowed: false };
const routes = (role: Schemas["TeamRole"] = "owner", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET /v1/teams/${team.slug}/service-accounts/${serviceAccountId}`]: () => serviceAccount(),
  [`GET /v1/teams/${team.slug}/service-accounts`]: () => [serviceAccount()],
  [`GET ${base}`]: () => [shared],
  [`GET ${base}/${shared.id}/allowable-servers`]: () => [destination],
  "GET /v1/auth-providers": (_body, call) => { expect(call.search.get("serviceTeam")).toBe(team.slug); return [providerSummary()]; },
  ...extra,
});

describe("Service account shared connections", () => {
  it("opens team-owned connections directly from the service accounts list", async () => {
    mockApi(routes("owner"));
    const { container } = renderApp(`/teams/${team.slug}/service-accounts?tab=connections`);
    expect(await screen.findByRole("heading", { level: 1, name: "Service accounts" })).toBeInTheDocument();
    expect(await screen.findByRole("tab", { name: "Connections" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("GitHub · Shared account: release-bot")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Connect shared account" })).toBeDisabled();
    expect(await axe(container)).toHaveNoViolations();
  });
  it("shows shared account labels and conditional access, read-only for members, with accessible tabs", async () => {
    mockApi(routes("member"));
    const { container } = renderApp(record);
    expect(await screen.findByRole("tab", { name: "Connections" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("GitHub · Shared account: release-bot")).toBeInTheDocument();
    expect(screen.getByText("Not assigned to ci-release-bot")).toBeInTheDocument();
    expect(screen.getByText(/Relayed people still use their own connections/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect shared account" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Manage access to Release account" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("saves explicit accounts and exact destination origin/scopes atomically with If-Match", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("admin", { [`PUT ${base}/${shared.id}`]: () => ({ ...shared, revision: 4 }) }));
    const { container } = renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Manage access to Release account" }));
    await u.click(await screen.findByRole("checkbox", { name: "ci-release-bot" }));
    await u.click(await screen.findByRole("checkbox", { name: "Status (Platform Tools)" }));
    expect(screen.getByText(/https:\/\/status.example.com · repo/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Save access" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.url === `${base}/${shared.id}`)).toBe(true));
    const saved = calls.find((c) => c.method === "PUT" && c.url === `${base}/${shared.id}`)!;
    expect(saved.headers.get("If-Match")).toBe('"3"');
    expect(saved.body).toEqual({ accounts: [serviceAccountId], servers: [{ serverId, origin: destination.origin, scopes: ["repo"] }] });
  });

  it("starts explicit shared consent and reconnects with the current revision", async () => {
    const u = userEvent.setup();
    const target = "https://github.com/login/oauth/authorize?state=shared-state";
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => undefined);
    const started = { authorizeUrl: target, scopes: ["repo"], expiresAt: "2026-10-28T12:10:00Z" };
    const calls = mockApi(routes("owner", {
      [`POST ${base}`]: () => started,
      [`POST ${base}/${shared.id}/reconnect`]: () => started,
    }));
    renderApp(record);
    await u.type(await screen.findByRole("textbox", { name: "Connection name" }), "CI shared account");
    await u.click(screen.getByRole("combobox", { name: "Auth provider or OAuth server" }));
    await u.click(await screen.findByRole("option", { name: "GitHub" }));
    await u.click(screen.getByRole("button", { name: "Connect shared account" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(target));
    expect(calls.find((c) => c.method === "POST" && c.url === base)?.body).toEqual({ providerId, name: "CI shared account" });
    await u.click(screen.getByRole("button", { name: "Reconnect Release account" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/reconnect"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/reconnect"))?.headers.get("If-Match")).toBe('"3"');
    go.mockRestore();
  });

  it("requires confirmation before revoking the shared connection", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", { [`DELETE ${base}/${shared.id}`]: () => ({ ok: true }) }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Revoke Release account" }));
    expect(await screen.findByRole("alertdialog", { name: "Revoke Release account?" })).toHaveTextContent("erases its tokens");
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(screen.getByRole("button", { name: "Revoke connection" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `${base}/${shared.id}`)).toBe(true));
  });
});
