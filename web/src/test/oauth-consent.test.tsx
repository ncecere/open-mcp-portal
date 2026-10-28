/* The OAuth consent page: the client (verified or not), the gateway, where the browser goes back to, Allow and Deny, the first-use notice of a trusted client, invalid requests and signing in first. */
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { consentRequest, redirectTo, safeRedirect } from "../pages/oauth/consent";
import { authConfig, gatewayId, myGateway, oauthClient, oauthConsent, registeredClient } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const query =
  "client_id=https%3A%2F%2Fclaude.ai%2Foauth%2Fclaude-code-client-metadata&redirect_uri=http%3A%2F%2F127.0.0.1%3A53211%2Fcallback&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fmcp.example.com%2Fmcp%2Fsupport-tools&state=123";
const path = `/oauth/consent?${query}`;
const back = "http://127.0.0.1:53211/callback?code=ompac_x&state=123&iss=https%3A%2F%2Fmcp.example.com";

function openConsent(routes: Record<string, Handler>) {
  // The page reads the address the browser was sent to, as it arrived.
  window.history.replaceState({}, "", path);
  const calls = mockApi({ ...shellRoutes(), ...routes });
  return { calls, ...renderApp(path) };
}

afterEach(() => {
  vi.restoreAllMocks();
  window.history.replaceState({}, "", "/");
});

describe("OAuth consent page", () => {
  it("names a verified client and its host, the gateway and what it offers, and where the browser goes back to, without the app's shell", async () => {
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls, container } = openConsent({ "GET /v1/oauth/consent": () => oauthConsent() });
    expect(await screen.findByRole("heading", { level: 1, name: "Claude Code wants to use Support tools as you" })).toBeInTheDocument();
    expect(screen.getByRole("main", { name: "Claude Code wants to use Support tools as you" })).toBeInTheDocument();
    expect(screen.getByText("claude.ai")).toBeInTheDocument();
    expect(screen.queryByText("Unverified")).toBeNull();
    const gateway = screen.getByRole("region", { name: "The gateway" });
    expect(gateway).toHaveTextContent("Support tools");
    expect(gateway).toHaveTextContent("Platform Tools");
    expect(within(gateway).getByRole("link", { name: /3 capabilities/ })).toHaveAttribute("href", `/gateways/${gatewayId}`);
    // The shared text link (themed colours), not a bare anchor in the browser's default blue.
    expect(within(gateway).getByRole("link", { name: /3 capabilities/ })).toHaveAttribute("data-tone", "default");
    expect(screen.getAllByText("127.0.0.1:53211").length).toBeGreaterThan(0);
    expect(screen.getByText("una@example.com")).toBeInTheDocument();
    // No sidebar, breadcrumbs or command palette to wander off to.
    expect(screen.queryByRole("navigation", { name: "Main" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Search or jump to/ })).toBeNull();
    await waitFor(() => expect(document.title).toBe("Connect Claude Code · Open MCP Portal"));
    // The request's parameters, as the endpoint passed them on (state stays text, not a number).
    const get = calls.find((c) => c.method === "GET" && c.url === "/v1/oauth/consent")!;
    expect(get.search.get("client_id")).toBe("https://claude.ai/oauth/claude-code-client-metadata");
    expect(get.search.get("resource")).toBe("https://mcp.example.com/mcp/support-tools");
    expect(get.search.get("state")).toBe("123");
    expect(go).not.toHaveBeenCalled();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("marks a client that registered itself as Unverified and warns where the answer goes", async () => {
    const { container } = openConsent({ "GET /v1/oauth/consent": () => oauthConsent({ client: registeredClient() }) });
    expect(await screen.findByRole("heading", { level: 1, name: "Handy MCP Helper wants to use Support tools as you" })).toBeInTheDocument();
    expect(screen.getByText("Unverified")).toBeInTheDocument();
    expect(screen.getByText("It registered itself and says it's from helper.example.net")).toBeInTheDocument();
    expect(screen.getByText(/This app registered itself, so its name and website aren't checked/)).toHaveTextContent("Your answer goes to 127.0.0.1:53211.");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows a client's logo only from an https address", async () => {
    const { unmount, container } = openConsent({ "GET /v1/oauth/consent": () => oauthConsent({ client: oauthClient({ logoUrl: "https://claude.ai/logo.png" }) }) });
    await screen.findByRole("heading", { level: 1 });
    expect(container.querySelector("img")).toHaveAttribute("src", "https://claude.ai/logo.png");
    unmount();
    const other = openConsent({ "GET /v1/oauth/consent": () => oauthConsent({ client: oauthClient({ logoUrl: "http://tracker.example.net/pixel.png" }) }) });
    await screen.findByRole("heading", { level: 1 });
    expect(other.container.querySelector("img")).toBeNull();
  });

  it("allows: posts the request's query string as received, with the CSRF token, then sends the browser to the client", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls } = openConsent({ "GET /v1/oauth/consent": () => oauthConsent(), "POST /v1/oauth/consent": () => ({ redirectUrl: back }) });
    await u.click(await screen.findByRole("button", { name: "Allow" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(back));
    const post = calls.find((c) => c.method === "POST" && c.url === "/v1/oauth/consent")!;
    expect(post.body).toEqual({ query, decision: "allow", toolScope: null });
    expect(post.headers.get("X-CSRF-Token")).toBe("csrf-123");
    expect(screen.getByRole("status")).toHaveTextContent("Taking you back to 127.0.0.1:53211…");
    // Answered: neither button can send a second answer.
    expect(screen.getByRole("button", { name: "Allow" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Deny" })).toBeDisabled();
  });

  it("denies: posts deny and sends the browser back with the client's answer", async () => {
    const u = userEvent.setup();
    const denied = "http://127.0.0.1:53211/callback?error=access_denied&state=123";
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls } = openConsent({ "GET /v1/oauth/consent": () => oauthConsent(), "POST /v1/oauth/consent": () => ({ redirectUrl: denied }) });
    await u.click(await screen.findByRole("button", { name: "Deny" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(denied));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "deny" });
  });

  it("explains an invalid request and never redirects (400)", async () => {
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls, container } = openConsent({ "GET /v1/oauth/consent": () => Reply.error(400, "invalid_request", "redirect_uri isn't registered for this client") });
    expect(await screen.findByRole("heading", { level: 1, name: "Can't connect this app" })).toBeInTheDocument();
    expect(screen.getByText("redirect_uri isn't registered for this client")).toBeInTheDocument();
    expect(screen.getByText(/Nothing was shared with the app, and this page won't send you anywhere/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Allow" })).toBeNull();
    await waitFor(() => expect(document.title).toBe("Can't connect this app · Open MCP Portal"));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    expect(go).not.toHaveBeenCalled();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says when the gateway isn't one the person can use (404), and never redirects", async () => {
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    openConsent({ "GET /v1/oauth/consent": () => Reply.error(404, "not_found", "Not found") });
    expect(await screen.findByText(/The gateway this app asks for doesn't exist, is turned off, or isn't one you can use/)).toBeInTheDocument();
    expect(go).not.toHaveBeenCalled();
  });

  it("refuses an answer that would send the browser anywhere but http(s), and keeps the person here", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    openConsent({ "GET /v1/oauth/consent": () => oauthConsent(), "POST /v1/oauth/consent": () => ({ redirectUrl: "javascript:alert(1)" }) });
    await u.click(await screen.findByRole("button", { name: "Allow" }));
    expect(await screen.findByText("Couldn't send your answer")).toBeInTheDocument();
    expect(go).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Allow" })).toBeEnabled();
  });

  it("shows a refused answer without leaving (403)", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    openConsent({ "GET /v1/oauth/consent": () => oauthConsent(), "POST /v1/oauth/consent": () => Reply.error(403, "forbidden", "Your access to this gateway was removed.") });
    await u.click(await screen.findByRole("button", { name: "Allow" }));
    expect(await screen.findByText("Your access to this gateway was removed.")).toBeInTheDocument();
    expect(go).not.toHaveBeenCalled();
  });

  it("says when the person allowed this client before", async () => {
    openConsent({ "GET /v1/oauth/consent": () => oauthConsent({ remembered: true, gateway: myGateway({ ownerKind: "platform", teamSlug: undefined, teamName: undefined }) }) });
    expect(await screen.findByText(/You allowed this app on this gateway before/)).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "The gateway" })).toHaveTextContent("Platform gateway");
  });

  it("asks a trusted client's first sign-in from this computer once, as a notice with Continue and Cancel", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls, container } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ client: oauthClient({ trusted: true }), notice: true }),
      "POST /v1/oauth/consent": () => ({ redirectUrl: back }),
    });
    expect(await screen.findByRole("heading", { level: 1, name: "Claude Code wants to use Support tools as you" })).toBeInTheDocument();
    const notice = screen.getByText("Your administrators trust Claude Code").closest("[role]") ?? screen.getByText("Your administrators trust Claude Code").parentElement!;
    expect(notice).toHaveTextContent("It doesn't normally ask, but this is its first sign-in to Support tools from you");
    expect(notice).toHaveTextContent("it receives the result on this computer, at 127.0.0.1:53211");
    expect(notice).toHaveTextContent("If you didn't just start signing in from Claude Code, choose Cancel.");
    // The usual buttons are replaced, not added to.
    expect(screen.queryByRole("button", { name: "Allow" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deny" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(back));
    // The same answer as Allow: the server records it as a confirmation.
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "allow", toolScope: null });
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  });

  it("cancels the notice with deny", async () => {
    const u = userEvent.setup();
    const denied = "http://127.0.0.1:53211/callback?error=access_denied&state=123";
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ client: oauthClient({ trusted: true }), notice: true }),
      "POST /v1/oauth/consent": () => ({ redirectUrl: denied }),
    });
    await u.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(denied));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "deny" });
  });

  it("shows no notice for a request that isn't one", async () => {
    openConsent({ "GET /v1/oauth/consent": () => oauthConsent() });
    expect(await screen.findByRole("button", { name: "Allow" })).toBeInTheDocument();
    expect(screen.queryByText(/Your administrators trust/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Continue" })).toBeNull();
  });

  it("signed out, shows the sign-in page, which returns here with the whole request", async () => {
    window.history.replaceState({}, "", path);
    const calls = mockApi({
      ...shellRoutes(),
      "GET /v1/me": () => Reply.error(401, "unauthorized"),
      "GET /v1/auth/config": () => authConfig({ oidcEnabled: true }),
    });
    renderApp(path);
    const signIn = await screen.findByRole("link", { name: /Sign in with single sign-on/ });
    expect(signIn).toHaveAttribute("href", "/auth/login?next=" + encodeURIComponent(path));
    // Nothing about the request is asked for before the person signs in.
    expect(calls.some((c) => c.url === "/v1/oauth/consent")).toBe(false);
  });
});

describe("OAuth tool scope", () => {
  it("shows requested classes and narrows without names or widening", async () => {
    const u = userEvent.setup();
    vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls, container } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ requestedToolScope: { classes: ["read", "write"] } }),
      "POST /v1/oauth/consent": () => ({ redirectUrl: back }),
    });
    const scope = await screen.findByRole("region", { name: "Requested tool scope" });
    expect(scope).toHaveTextContent("Read");
    expect(scope).toHaveTextContent("Write");
    expect(within(scope).getByRole("radio", { name: "Everything" })).toHaveAttribute("aria-disabled", "true");
    const destructive = within(scope).getByRole("checkbox", { name: "Destructive" });
    expect(destructive).toHaveAttribute("aria-disabled", "true");
    await u.click(destructive);
    expect(destructive).not.toBeChecked();
    expect(within(scope).queryByRole("textbox")).toBeNull();
    await u.click(within(scope).getByRole("checkbox", { name: "Write" }));
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "allow", toolScope: { classes: ["read"] } }));
  });

  it("keeps explicit three classes distinct from an absent scope", async () => {
    const u = userEvent.setup();
    vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const requested = { classes: ["read", "write", "destructive"] as const };
    const { calls } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ requestedToolScope: { classes: [...requested.classes] } }),
      "POST /v1/oauth/consent": () => ({ redirectUrl: back }),
    });
    expect(await screen.findByRole("checkbox", { name: "Destructive" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Everything" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText(/Even all three classes exclude unclassified/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "allow", toolScope: requested }));
  });

  it("allows a null request to narrow to no tools, but deny never submits a scope", async () => {
    const u = userEvent.setup();
    vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent(),
      "POST /v1/oauth/consent": () => ({ redirectUrl: back }),
    });
    await u.click(await screen.findByRole("radio", { name: "Custom" }));
    expect(screen.getByText("No tools. Prompts and resources are unaffected.")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Deny" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "deny" }));
  });

  it("freezes request and ceiling across a refetch, and captures the submitted scope while inputs are disabled", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    let finish!: (value: { redirectUrl: string }) => void;
    let response = oauthConsent({ requestedToolScope: { classes: ["read", "write"] } });
    const { calls, qc } = openConsent({
      "GET /v1/oauth/consent": () => response,
      "POST /v1/oauth/consent": () => new Promise<{ redirectUrl: string }>((resolve) => { finish = resolve; }),
    });
    await u.click(await screen.findByRole("checkbox", { name: "Write" }));
    window.history.replaceState({}, "", "/oauth/consent?scope=omp:destructive");
    response = oauthConsent({ requestedToolScope: null });
    await act(() => qc.invalidateQueries({ queryKey: ["oauth", "consent"] }));
    expect(screen.getByRole("radio", { name: "Everything" })).toHaveAttribute("aria-disabled", "true");
    await u.click(screen.getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")).toBeDefined());
    expect(screen.getByRole("checkbox", { name: "Read" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("button", { name: "Deny" })).toBeDisabled();
    await u.click(screen.getByRole("checkbox", { name: "Read" }));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "allow", toolScope: { classes: ["read"] } });
    await act(async () => finish({ redirectUrl: back }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(back));
  });

  it("narrows an unrestricted request to read without changing the authorization query", async () => {
    const u = userEvent.setup();
    vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const { calls } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ requestedToolScope: null }),
      "POST /v1/oauth/consent": () => ({ redirectUrl: back }),
    });
    expect(await screen.findByRole("radio", { name: "Everything" })).toBeChecked();
    await u.click(screen.getByRole("radio", { name: "Read only" }));
    await u.click(screen.getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "allow", toolScope: { classes: ["read"], tools: [] } }));
  });

  it("does not offer the read preset when only write was requested", async () => {
    const u = userEvent.setup();
    const { calls } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ requestedToolScope: { classes: ["write"] } }),
      "POST /v1/oauth/consent": () => ({ redirectUrl: back }),
    });
    const read = await screen.findByRole("radio", { name: "Read only" });
    expect(read).toHaveAttribute("aria-disabled", "true");
    await u.click(read);
    expect(read).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Write" })).toBeChecked();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("can allow an empty class ceiling and reports scope errors plainly", async () => {
    const u = userEvent.setup();
    const { calls } = openConsent({
      "GET /v1/oauth/consent": () => oauthConsent({ requestedToolScope: {} }),
      "POST /v1/oauth/consent": () => Reply.error(400, "oauth_invalid_scope", "The requested tool scope changed. Start connecting again."),
    });
    await u.click(await screen.findByRole("button", { name: "Allow" }));
    expect(await screen.findByText("The requested tool scope changed. Start connecting again.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ query, decision: "allow", toolScope: {} });
  });
});

describe("consent helpers", () => {
  it("reads the request's parameters and keeps the raw query", () => {
    const r = consentRequest(`?${query}`);
    expect(r.raw).toBe(query);
    expect(r.params).toMatchObject({ response_type: "code", code_challenge_method: "S256", state: "123" });
    expect(consentRequest("client_id=x").params).not.toHaveProperty("state");
  });

  it("allows only http(s) addresses to go back to", () => {
    expect(safeRedirect(back)).toBe(back);
    expect(safeRedirect("https://claude.ai/api/mcp/auth_callback?code=x")).toBeDefined();
    expect(safeRedirect("javascript:alert(1)")).toBeUndefined();
    expect(safeRedirect("data:text/html,hi")).toBeUndefined();
    expect(safeRedirect("not a url")).toBeUndefined();
  });
});
