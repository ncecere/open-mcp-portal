/*
 * Add server with OAuth sign-in (docs/phase7-upstream-oauth.md): Detect sign-in and what it shows (a client to
 * enter, automatic registration, a matching platform provider, problems, a suggested URL, other outcomes), the
 * request body, the refusals, and "Authorize to read its tools" after a create that needs a sign-in.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { redirectTo } from "../components/providers/labels";
import { capabilities, healthCheck, page, serverId, team, teamPublishing } from "./fixtures";
import { detectDcr, detectResult, githubUrl, oauthServer, setupConnection } from "./fixtures-oauth";
import { providerId, providerRef } from "./fixtures-providers";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers`;
const authorizeUrl = "https://github.com/login/oauth/authorize?client_id=Iv1.c0ffee&state=s1";
const fresh = oauthServer({ refreshedAt: null, counts: { tools: 0, resources: 0, resourceTemplates: 0, prompts: 0 } }, { setupConnection: setupConnection({ status: "missing", personId: null, personName: null, authorizedAt: null }), connectionCount: 0 });
const created: Schemas["McpServerCreated"] = { server: fresh, refresh: null, refreshError: null, setupRequired: true };

const routes = (detect: () => unknown, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "editor"),
  [`GET ${base}`]: () => page([]),
  [`POST ${base}/detect-auth`]: detect,
  [`POST ${base}`]: () => new Reply(201, { data: created }),
  [`GET ${base}/${serverId}`]: () => fresh,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck({ signInRequired: true })],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  ...extra,
});

async function fillAndDetect(u: ReturnType<typeof userEvent.setup>, url = githubUrl) {
  await u.type(await screen.findByRole("textbox", { name: "Name" }), "GitHub MCP");
  await u.type(screen.getByRole("textbox", { name: "URL" }), url);
  await u.click(screen.getByRole("button", { name: "Detect sign-in" }));
}

const posted = (calls: { method: string; url: string; body?: unknown }[]) => calls.find((c) => c.method === "POST" && c.url === base)?.body as Record<string, unknown> | undefined;

afterEach(() => vi.restoreAllMocks());

describe("Add server › Detect sign-in", () => {
  it("finds GitHub's sign-in, needs a client, preselects its usual scopes, and opens the setup sign-in after the create", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const calls = mockApi(routes(() => detectResult(), { [`POST ${base}/${serverId}/oauth/authorize-setup`]: () => ({ authorizeUrl, scopes: ["repo"], expiresAt: "2026-10-16T08:10:00Z" }) }));
    const { container } = renderApp(`/teams/${team.slug}/servers?form=new`);
    await fillAndDetect(u);
    const found = await screen.findByRole("region", { name: "What the server says about signing in" });
    expect(calls.find((c) => c.url === `${base}/detect-auth`)?.body).toEqual({ url: githubUrl });
    expect(found).toHaveTextContent("https://github.com/login/oauth");
    expect(found).toHaveTextContent("S256 supported");
    expect(found).toHaveTextContent(/No automatic registration: create an OAuth app at github\.com/);
    expect(screen.getByRole("radio", { name: "Sign-in with OAuth, per person" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Enter a client ID and secret" })).toBeChecked();
    expect(screen.getByRole("button", { name: /Copy callback URL/ })).toBeInTheDocument();
    expect(screen.getAllByText("https://mcp.example.com/connect/callback").length).toBe(2);
    for (const scope of ["repo", "read:org", "read:user"]) expect(screen.getByRole("checkbox", { name: scope })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "gist" })).not.toBeChecked();
    expect(screen.getByText("Run outside the company?")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("button", { name: "Add server" }));
    expect(await screen.findByText(/Enter the client ID of the OAuth app/)).toBeInTheDocument();
    expect(screen.getByText(/Enter the client secret, or choose None/)).toBeInTheDocument();
    expect(posted(calls)).toBeUndefined();

    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "Iv1.c0ffee");
    await u.type(screen.getByLabelText("Client secret"), "s3cret");
    await u.click(screen.getByRole("switch", { name: "Send identity token" }));
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() =>
      expect(posted(calls)).toEqual({
        slug: "github-mcp",
        name: "GitHub MCP",
        url: githubUrl,
        authMode: "oauth",
        oauth: { registration: "manual", clientId: "Iv1.c0ffee", tokenAuthMethod: "client_secret_post", clientSecret: "s3cret", scopes: ["repo", "read:org", "read:user"], sendResource: true },
        sendIdentity: false,
        timeoutSeconds: 30,
        enabled: true,
        capturePayloads: false,
      }),
    );

    // The record: nobody has signed in yet, so its tools weren't read.
    const notice = await screen.findByText("GitHub MCP was added. Authorize to read its tools");
    const alert = notice.closest("[role=status]") as HTMLElement;
    expect(alert).toHaveTextContent("You'll sign in at github.com and allow repo, read:org, read:user");
    await u.click(within(alert).getByRole("button", { name: "Authorize to read its tools" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    expect(calls.find((c) => c.url.endsWith("/oauth/authorize-setup"))?.body).toEqual({});
  });

  it("registers automatically (DCR) with the challenge's scopes, and needs no client", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(() => detectDcr()));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await fillAndDetect(u, "https://wiki.example.com/mcp");
    expect(await screen.findByText(/Automatic: the portal registers itself \(dynamic client registration\)/)).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Automatic: register a client" })).toBeChecked();
    expect(screen.queryByRole("textbox", { name: "Client ID" })).toBeNull();
    expect(screen.getByRole("checkbox", { name: "wiki.read" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "wiki.write" })).not.toBeChecked();
    // The authorization server is on another host than the server: flagged.
    expect(screen.getByText("Another host: sso.example.com")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(posted(calls)?.oauth).toEqual({ registration: "dcr", scopes: ["wiki.read"], sendResource: true }));
    expect(posted(calls)?.sendIdentity).toBe(true);
  });

  it("offers a platform provider with the same endpoints, and the resource switch under Advanced", async () => {
    const u = userEvent.setup();
    const base0 = detectResult();
    const calls = mockApi(routes(() => detectResult({ registration: { ...base0.registration!, matchingProviders: [providerRef()] } })));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await fillAndDetect(u);
    expect(await screen.findByText(/Platform providers with the same endpoints: GitHub/)).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Use platform provider GitHub" })).toBeChecked();
    await u.click(screen.getByRole("button", { name: /Advanced/ }));
    await u.click(screen.getByRole("switch", { name: "Send resource indicator" }));
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() =>
      expect(posted(calls)?.oauth).toEqual({ registration: "platform_provider", platformProviderId: providerId, scopes: ["repo", "read:org", "read:user"], sendResource: false }),
    );
  });

  it("explains blocking problems and keeps OAuth off; applies a suggested URL and asks again", async () => {
    const u = userEvent.setup();
    const bare = "https://api.githubcopilot.com/mcp";
    let answer = detectResult({ url: bare, suggestedUrl: githubUrl, problems: [{ code: "no_pkce", blocking: true, message: "The authorization server doesn't support PKCE (S256)." }] });
    const calls = mockApi(routes(() => answer));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await fillAndDetect(u, bare);
    expect(await screen.findByText("Can't use OAuth sign-in")).toBeInTheDocument();
    expect(screen.getByText("The authorization server doesn't support PKCE (S256).")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Sign-in with OAuth, per person" })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /^None/ })).toBeChecked();

    answer = detectResult();
    await u.click(screen.getByRole("button", { name: `Use ${githubUrl}` }));
    expect(screen.getByRole("textbox", { name: "URL" })).toHaveValue(githubUrl);
    await waitFor(() => expect(calls.filter((c) => c.url === `${base}/detect-auth`).at(-1)?.body).toEqual({ url: githubUrl }));
    await waitFor(() => expect(screen.getByRole("radio", { name: "Sign-in with OAuth, per person" })).toBeChecked());
  });

  it("suggests None or a static header for servers without OAuth", async () => {
    const u = userEvent.setup();
    let answer: Schemas["DetectAuthResult"] = detectResult({ outcome: "no_auth", httpStatus: 200, challenge: null, resourceMetadata: null, authorizationServer: null, registration: null, problems: [], steps: [] });
    mockApi(routes(() => answer));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await fillAndDetect(u, "https://status.example.com/mcp");
    expect(await screen.findByText("Answers without sign-in")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /^None/ })).toBeChecked();
    answer = { ...answer, outcome: "other_auth", httpStatus: 401 };
    await u.click(screen.getByRole("button", { name: "Detect sign-in" }));
    expect(await screen.findByText("Needs credentials, but doesn't offer OAuth sign-in")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /^Static credential/ })).toBeChecked();
    expect(screen.getByRole("textbox", { name: /Header name/ })).toBeInTheDocument();
  });

  it("says why a create was refused (discovery failed on save, a registration refused)", async () => {
    const u = userEvent.setup();
    let reply = Reply.error(422, "oauth_discovery_failed", "discovery failed", { problems: [{ code: "issuer_mismatch", blocking: true, message: "The issuer doesn't match." }] });
    mockApi(routes(() => detectDcr(), { [`POST ${base}`]: () => reply }));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await fillAndDetect(u, "https://wiki.example.com/mcp");
    await screen.findByRole("radio", { name: "Automatic: register a client" });
    await u.click(screen.getByRole("button", { name: "Add server" }));
    expect(await screen.findByText("The server's sign-in couldn't be discovered")).toBeInTheDocument();
    expect(screen.getByText(/The issuer doesn't match\./)).toBeInTheDocument();
    reply = Reply.error(502, "oauth_registration_failed", "registration failed");
    await u.click(screen.getByRole("button", { name: "Add server" }));
    expect(await screen.findByText("The authorization server refused to register the portal")).toBeInTheDocument();
  });
});
