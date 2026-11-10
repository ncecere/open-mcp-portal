/*
 * Test helpers: a fetch mock keyed by "METHOD /path" with status codes, the routes every signed-in page needs, and
 * renderBare. renderApp (the whole app at a path) is in render-app.tsx, so a test that only needs these doesn't
 * evaluate the router and every page's route.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory, createRootRoute, createRouter } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import type { Schemas } from "../api/client";
import { authConfig, invite, meFor, members, page, team } from "./fixtures";
import { overview, teamAttention } from "./fixtures-v02";

export type Call = { method: string; url: string; search: URLSearchParams; body?: unknown; headers: Headers };

/** A reply with a status: JSON data (wrapped in {data}) or an error. */
export class Reply {
  constructor(
    readonly status: number,
    readonly payload: unknown,
    readonly headers: Record<string, string> = {},
  ) {}
  static error(status: number, code: string, message = code, details?: Record<string, unknown>, headers: Record<string, string> = {}) {
    return new Reply(status, { error: { code, message, details } }, headers);
  }
}

export type Handler = (body: unknown, call: Call) => unknown;

/** Replaces fetch; routes are keyed "METHOD /path". Unmatched routes return 404. Returns the calls made. */
export function mockApi(routes: Record<string, Handler>) {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", async (input: Request | string, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(new URL(String(input), "http://localhost"), init);
    const url = new URL(req.url);
    const raw = req.method === "GET" ? "" : await req.clone().text();
    let body: unknown;
    try {
      body = raw ? JSON.parse(raw) : undefined;
    } catch {
      body = undefined;
    }
    const call: Call = { method: req.method, url: url.pathname, search: url.searchParams, body, headers: req.headers };
    calls.push(call);
    const handler = routes[`${req.method} ${url.pathname}`];
    const json = (status: number, payload: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json", ...headers } });
    if (!handler) return json(404, { error: { code: "not_found", message: "Not found" } });
    const out = await handler(body, call);
    if (out instanceof Response) return out;
    if (out instanceof Reply) return json(out.status, out.payload, out.headers);
    return json(200, { data: out });
  });
  return calls;
}

const teamPath = `/v1/teams/${team.slug}`;

/** Routes every signed-in page needs (session, shell, breadcrumbs), and the team's lists. */
export const shellRoutes = (platformRole: Schemas["PlatformRole"] = "none", teamRole: Schemas["TeamRole"] | null = "owner"): Record<string, Handler> => ({
  "GET /v1/me": () => meFor(platformRole, teamRole),
  "GET /v1/auth/config": () => authConfig(),
  [`GET ${teamPath}`]: (): Schemas["TeamView"] => (teamRole ? { team, role: teamRole } : { team }),
  [`GET ${teamPath}/members`]: () => members,
  [`GET ${teamPath}/invites`]: () => [invite()],
  [`GET ${teamPath}/audit`]: () => page([]),
  // v0.2: the team's attention card, the admin overview and the bell's count (nothing to report by default).
  [`GET ${teamPath}/attention`]: () => teamAttention(),
  "GET /v1/admin/overview": () => overview(),
  "GET /v1/me/notifications/unread-count": () => ({ count: 0 }),
});

/** Renders a component inside a bare router and query client (me preloaded). */
export function renderBare(ui: ReactNode, me: unknown = meFor()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(["me"], me);
  const root = createRootRoute({ component: () => <>{ui}</> });
  const router = createRouter({ routeTree: root, history: createMemoryHistory({ initialEntries: ["/"] }) });
  return {
    ...render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router as never} />
      </QueryClientProvider>,
    ),
    qc,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
  sessionStorage.clear();
});
beforeAll(() => {
  window.scrollTo = () => {};
});
