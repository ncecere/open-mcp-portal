import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "@/api/client";
import * as client from "@/api/client";
import { browserLabel } from "@/components/sessions/browser-sessions";
import { user } from "./fixtures";
import { mockApi, renderApp, Reply, shellRoutes } from "./harness";

const sessions: Schemas["BrowserSession"][] = [
  { id: "11111111-1111-4111-8111-111111111111", createdAt: "2026-01-01T10:00:00Z", lastSeenAt: "2026-01-01T11:00:00Z", expiresAt: "2099-01-01T22:00:00Z", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0 Safari/537.36", clientIp: "192.0.2.10", current: true },
  { id: "22222222-2222-4222-8222-222222222222", createdAt: "2026-01-01T10:00:00Z", lastSeenAt: "2026-01-01T10:30:00Z", expiresAt: "2099-01-01T22:00:00Z", userAgent: "Mozilla/5.0 (Windows NT 10.0) Firefox/120.0", clientIp: "198.51.100.8", current: false },
];

describe("Account › Sessions", () => {
  it("shows browser, stored address, current marker and activity dates accessibly", async () => {
    mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => sessions });
    const { container } = renderApp("/settings/sessions");
    expect(await screen.findByRole("heading", { level: 1, name: "Sessions" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Your browser sessions" });
    expect(await within(table).findByText("Chrome on macOS")).toBeInTheDocument();
    expect(within(table).getByText("192.0.2.10")).toBeInTheDocument();
    expect(within(table).getByText("Firefox on Windows")).toBeInTheDocument();
    expect(within(table).getAllByText("This session")).toHaveLength(1);
    for (const label of ["Signed in", "Last active", "Expires"]) expect(within(table).getByRole("columnheader", { name: new RegExp(label) })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Connected apps" })).toHaveAttribute("href", "/settings/connected-apps");
    await waitFor(() => expect(document.title).toBe("Sessions · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("confirms before revoking and refreshes the list", async () => {
    const u = userEvent.setup();
    let active = sessions;
    const calls = mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => active,
      [`DELETE /v1/me/sessions/${sessions[1]!.id}`]: () => { active = [sessions[0]!]; return { ok: true }; },
    });
    renderApp("/settings/sessions");
    await u.click(await screen.findByRole("button", { name: "Actions for Firefox on Windows" }));
    await u.click(await screen.findByRole("menuitem", { name: "Sign out…" }));
    let dialog = await screen.findByRole("alertdialog", { name: "Sign out this session?" });
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(await screen.findByRole("button", { name: "Actions for Firefox on Windows" }));
    await u.click(await screen.findByRole("menuitem", { name: "Sign out…" }));
    dialog = await screen.findByRole("alertdialog");
    await u.click(within(dialog).getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith(sessions[1]!.id))).toBe(true));
    await waitFor(() => expect(screen.queryByText("Firefox on Windows")).not.toBeInTheDocument());
    expect(await screen.findByText("Session signed out")).toBeInTheDocument();
  });

  it("defaults to ending this session and can keep it explicitly", async () => {
    const u = userEvent.setup();
    const calls = mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => sessions, "POST /v1/me/sessions/revoke-all": () => ({ ok: true }) });
    renderApp("/settings/sessions");
    await u.click(await screen.findByRole("button", { name: "Sign out everywhere" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Sign out everywhere?" });
    const keep = within(dialog).getByRole("checkbox", { name: "Keep this session signed in" });
    expect(keep).not.toBeChecked();
    expect(dialog).toHaveTextContent("Connected apps, API keys and provider connections are not disconnected");
    await u.click(keep);
    await u.click(within(dialog).getByRole("button", { name: "Sign out everywhere" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("revoke-all"))?.body).toEqual({ keepCurrent: true }));
    expect(await screen.findByText("Sessions signed out")).toBeInTheDocument();
  });

  it.each([false, true])("uses the submitted keep-current choice (%s) while the response is delayed", async (keepCurrent) => {
    const u = userEvent.setup();
    let finish!: (value: unknown) => void;
    const calls = mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => sessions,
      "POST /v1/me/sessions/revoke-all": () => new Promise((resolve) => { finish = resolve; }),
    });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const { qc } = renderApp("/settings/sessions");
    const clear = vi.spyOn(qc, "clear");
    const token = vi.spyOn(client, "setCsrfToken");
    await u.click(await screen.findByRole("button", { name: "Sign out everywhere" }));
    const dialog = await screen.findByRole("alertdialog");
    const keep = within(dialog).getByRole("checkbox", { name: "Keep this session signed in" });
    if (keepCurrent) await u.click(keep);
    await u.click(within(dialog).getByRole("button", { name: "Sign out everywhere" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("revoke-all"))?.body).toEqual({ keepCurrent }));
    expect(keep).toHaveAttribute("aria-disabled", "true");
    await u.click(keep);
    if (keepCurrent) expect(keep).toBeChecked();
    else expect(keep).not.toBeChecked();
    await act(async () => { finish({ ok: true }); });
    if (keepCurrent) {
      expect(await screen.findByText("Sessions signed out")).toBeInTheDocument();
      expect(assign).not.toHaveBeenCalled();
      expect(clear).not.toHaveBeenCalled();
    } else {
      await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
      expect(clear).toHaveBeenCalledOnce();
      expect(token).toHaveBeenCalledWith("");
    }
    token.mockRestore();
    clear.mockRestore();
  });

  it("clears credentials and navigates after revoking this single session", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => sessions,
      [`DELETE /v1/me/sessions/${sessions[0]!.id}`]: () => ({ ok: true }),
    });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const { qc } = renderApp("/settings/sessions");
    const clear = vi.spyOn(qc, "clear");
    const token = vi.spyOn(client, "setCsrfToken");
    await u.click(await screen.findByRole("button", { name: "Actions for Chrome on macOS (this session)" }));
    await u.click(await screen.findByRole("menuitem", { name: "Sign out…" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    expect(clear).toHaveBeenCalledOnce();
    expect(token).toHaveBeenCalledWith("");
    token.mockRestore();
  });

  it("keeps the confirmation open on a failed revocation", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => sessions,
      [`DELETE /v1/me/sessions/${sessions[1]!.id}`]: () => Reply.error(500, "internal", "Try again later"),
    });
    renderApp("/settings/sessions");
    await u.click(await screen.findByRole("button", { name: "Actions for Firefox on Windows" }));
    await u.click(await screen.findByRole("menuitem", { name: "Sign out…" }));
    const dialog = await screen.findByRole("alertdialog");
    await u.click(within(dialog).getByRole("button", { name: "Sign out" }));
    expect(await within(dialog).findByText("Try again later")).toBeInTheDocument();
    expect(screen.getByText("Firefox on Windows")).toBeInTheDocument();
  });

  it("handles an empty list and links from the account menu", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes(), "GET /v1/me/sessions": () => [] });
    renderApp("/settings/sessions");
    expect(await screen.findByText("No active browser sessions.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out everywhere" })).toBeDisabled();
    await u.click(screen.getByRole("button", { name: /Una User/ }));
    expect(await screen.findByRole("menuitem", { name: "Sessions" })).toHaveAttribute("href", "/settings/sessions");
  });
});

describe("Admin › person › Sessions", () => {
  const person = user({ id: "99999999-0000-4000-8000-000000000001", displayName: "Drew Member" });
  const path = `/v1/admin/users/${person.id}/sessions`;
  it("lets an admin list and revoke all, after confirmation", async () => {
    const u = userEvent.setup();
    const calls = mockApi({ ...shellRoutes("platform_admin", null),
      [`GET /v1/admin/users/${person.id}`]: () => ({ user: person, teams: [] }),
      [`GET ${path}`]: () => sessions.map((s) => ({ ...s, current: false })),
      [`DELETE ${path}`]: () => ({ ok: true }),
    });
    renderApp(`/admin/users/${person.id}`);
    const table = await screen.findByRole("table", { name: "Sessions for Drew Member" });
    expect(await within(table).findByText("Chrome on macOS")).toBeInTheDocument();
    expect(within(table).queryByRole("button", { name: /Actions for/ })).toBeNull();
    await u.click(screen.getByRole("button", { name: "Revoke all sessions" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Revoke all sessions?" });
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(dialog).getByRole("button", { name: "Revoke all sessions" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === path)).toBe(true));
  });
  it("clears credentials after an admin revokes their own sessions", async () => {
    const u = userEvent.setup();
    const self = user({ platformRole: "platform_admin" });
    mockApi({ ...shellRoutes("platform_admin", null),
      [`GET /v1/admin/users/${self.id}`]: () => ({ user: self, teams: [] }),
      [`GET /v1/admin/users/${self.id}/sessions`]: () => sessions,
      [`DELETE /v1/admin/users/${self.id}/sessions`]: () => ({ ok: true }),
    });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign });
    const { qc } = renderApp(`/admin/users/${self.id}`);
    const clear = vi.spyOn(qc, "clear");
    const token = vi.spyOn(client, "setCsrfToken");
    await u.click(await screen.findByRole("button", { name: "Revoke all sessions" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Revoke all sessions" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    expect(clear).toHaveBeenCalledOnce();
    expect(token).toHaveBeenCalledWith("");
    token.mockRestore();
  });

  it("does not offer or request sessions for auditors", async () => {
    const calls = mockApi({ ...shellRoutes("platform_auditor", null), [`GET /v1/admin/users/${person.id}`]: () => ({ user: person, teams: [] }) });
    renderApp(`/admin/users/${person.id}`);
    expect(await screen.findByRole("heading", { name: "Drew Member" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sessions" })).toBeNull();
    expect(calls.some((c) => c.url === path)).toBe(false);
  });
});

it("parses common browser agents without treating unknown text as markup", () => {
  expect(browserLabel("Chrome/1 Safari/2 Edg/3 Windows")).toBe("Edge on Windows");
  expect(browserLabel("iPhone Version/17 Safari/605")).toBe("Safari on iOS");
  expect(browserLabel("Android Chrome/120")).toBe("Chrome on Android");
  expect(browserLabel("<script>alert(1)</script>")).toBe("Unknown browser");
});
