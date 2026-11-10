/*
 * The session: the sign-in page with the dev personas from /v1/auth/config, the session page while /v1/me can't load
 * (a rate limit, a server error), keeping the app when a later refresh fails, and a 401 elsewhere signing out.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { nextPath } from "../session";
import { authConfig, meFor } from "./fixtures";
import { mockApi, Reply, shellRoutes } from "./harness";
import { renderApp } from "./render-app";
import { scaled } from "../../test-scale";

describe("signing in", () => {
  it("lists the development personas from the auth config and signs in as one", async () => {
    const user = userEvent.setup();
    let signedIn = false;
    const calls = mockApi({
      ...shellRoutes(),
      "GET /v1/me": () => (signedIn ? meFor() : null),
      "POST /auth/dev": () => {
        signedIn = true;
        return { ok: true };
      },
    });
    const { container } = renderApp("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Open MCP Portal" })).toBeInTheDocument();
    expect(screen.getByText("Choose an account to continue.")).toBeInTheDocument();
    const dev = screen.getByRole("region", { name: "Development accounts" });
    const accounts = within(dev).getAllByRole("button");
    expect(accounts.map((b) => b.textContent)).toEqual([
      expect.stringContaining("Ada Admin"),
      expect.stringContaining("Avery Auditor"),
      expect.stringContaining("Alex Owner"),
    ]);
    expect(accounts[0]).toHaveTextContent("platform admin");
    expect(accounts[2]).not.toHaveTextContent("platform");
    expect(screen.queryByText("An app is waiting to connect")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();

    await user.click(within(dev).getByRole("button", { name: /Alex Owner/ }));
    expect(await screen.findByRole("heading", { level: 1, name: "Welcome, Una" })).toBeInTheDocument();
    expect(calls.find((c) => c.url === "/auth/dev")?.body).toEqual({ account: "alex" });
    // Signed out was asked without a 401: GET /v1/me?optional=true.
    expect(calls.find((c) => c.url === "/v1/me")?.search.get("optional")).toBe("true");
  });

  it("says an app is waiting when an MCP client's sign-in sent the person here", async () => {
    window.history.replaceState(null, "", "/?next=" + encodeURIComponent("/oauth/authorize?client_id=https%3A%2F%2Fclaude.ai%2Fx&state=s"));
    try {
      mockApi({ ...shellRoutes(), "GET /v1/me": () => null });
      const { container } = renderApp("/");
      expect(await screen.findByText("An app is waiting to connect")).toBeInTheDocument();
      expect(screen.getByText(/you'll be asked to approve the app before it can use a gateway as you/)).toBeInTheDocument();
      expect(await axe(container)).toHaveNoViolations();
    } finally {
      window.history.replaceState(null, "", "/");
    }
  });

  it("offers single sign-on with the page to come back to", async () => {
    mockApi({ "GET /v1/me": () => null, "GET /v1/auth/config": () => authConfig({ oidcEnabled: true, devAuthEnabled: false, devAccounts: [] }) });
    renderApp("/teams/platform-tools/settings");
    const link = await screen.findByRole("link", { name: /Sign in with single sign-on/ });
    expect(link).toHaveAttribute("href", "/auth/login?next=" + encodeURIComponent("/"));
    expect(screen.queryByRole("region", { name: "Development accounts" })).toBeNull();
  });

  it("shows the server's refusal of a development sign-in", async () => {
    const user = userEvent.setup();
    mockApi({ ...shellRoutes(), "GET /v1/me": () => null, "POST /auth/dev": () => Reply.error(403, "forbidden", "Development sign-in is off.") });
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: /Ada Admin/ }));
    expect(await screen.findByText("Development sign-in is off.")).toBeInTheDocument();
  });

  it("only returns to a same-site ?next=", () => {
    expect(nextPath("?next=/teams/x")).toBe("/teams/x");
    expect(nextPath("?next=//evil.example")).toBeUndefined();
    expect(nextPath("?next=/\\evil.example")).toBeUndefined();
    expect(nextPath("?next=https://evil.example")).toBeUndefined();
    expect(nextPath("")).toBeUndefined();
  });
});

describe("the session page", () => {
  it("explains a rate limit, counts down and loads the app with Try again now", async () => {
    let refuse = true;
    mockApi({
      ...shellRoutes(),
      "GET /v1/me": () => (refuse ? Reply.error(429, "rate_limited", "Too many requests. Try again shortly.", undefined, { "Retry-After": "30" }) : meFor()),
    });
    const { container } = renderApp("/");
    expect(await screen.findByRole("heading", { name: "Too many requests" }, { timeout: scaled(3000) })).toBeInTheDocument();
    expect(screen.getByText(/Trying again in \d+ s\./)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    refuse = false;
    await userEvent.click(screen.getByRole("button", { name: "Try again now" }));
    expect(await screen.findByRole("navigation", { name: "Breadcrumb" })).toBeInTheDocument();
  });

  it("says the server isn't responding after a server error, and retries", async () => {
    let fail = true;
    mockApi({ ...shellRoutes(), "GET /v1/me": () => (fail ? Reply.error(500, "internal", "Something broke.") : meFor()) });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Open MCP Portal isn't responding" })).toBeInTheDocument();
    fail = false;
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Welcome, Una" })).toBeInTheDocument();
  });

  it("keeps the app when a later refresh of the session fails", async () => {
    let refuse = false;
    mockApi({ ...shellRoutes(), "GET /v1/me": () => (refuse ? Reply.error(500, "internal", "Something went wrong") : meFor()) });
    const { qc } = renderApp("/");
    await screen.findByRole("navigation", { name: "Breadcrumb" });
    refuse = true;
    await qc.refetchQueries({ queryKey: ["me"] });
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Try again/ })).toBeNull();
  });

  it("treats an expired session (401) as signed out", async () => {
    mockApi({ ...shellRoutes(), "GET /v1/me": () => Reply.error(401, "unauthenticated", "Sign in again.") });
    renderApp("/");
    expect(await screen.findByText("Choose an account to continue.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("navigation", { name: "Breadcrumb" })).toBeNull());
  });
});
