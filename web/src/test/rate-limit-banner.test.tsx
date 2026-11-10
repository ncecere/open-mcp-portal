/*
 * In-app rate limiting: while a rate-limited query waits for its retry, the shell says so and counts down, with Try
 * again now; the pre-session page keeps focus after Try again now.
 */
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { ApiError } from "../api/client";
import { SessionUnavailable } from "../components/layout/session-unavailable";
import { appRetryDelay, clearRateLimit, noteRateLimit, rateLimitedUntil } from "../lib/retry";
import { mockApi, renderBare, shellRoutes } from "./harness";
import { renderApp } from "./render-app";
import { scaled } from "../../test-scale";

afterEach(() => {
  act(() => clearRateLimit());
});

const limited = (retryAfter = 30) => new ApiError(429, "rate_limited", "Too many requests.", undefined, retryAfter);

describe("the rate-limit banner", () => {
  it("records when a rate-limited query tries again, and nothing for other errors", () => {
    const now = Date.now();
    const ms = appRetryDelay(1, limited(30));
    expect(ms).toBeGreaterThanOrEqual(30_000);
    expect(rateLimitedUntil()).toBeGreaterThanOrEqual(now + 30_000);
    act(() => clearRateLimit());
    appRetryDelay(1, new ApiError(500, "internal", "Oops"));
    expect(rateLimitedUntil()).toBe(0);
  });

  it("says the account is rate-limited, counts down and tries again now on request", async () => {
    const user = userEvent.setup();
    mockApi({ ...shellRoutes("platform_admin"), "GET /v1/admin/teams": () => ({ items: [], nextCursor: null }) });
    const { container } = renderApp("/admin/teams");
    await screen.findByRole("heading", { level: 1, name: "Teams" }, { timeout: scaled(4000) });
    expect(screen.queryByText(/Too many requests/)).toBeNull();
    act(() => noteRateLimit(30_000));
    expect(await screen.findByText("Too many requests: waiting before trying again")).toBeInTheDocument();
    expect(screen.getByText(/Trying again in (29|30) s\./)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: "Try again now" }));
    await waitFor(() => expect(screen.queryByText(/Too many requests/)).toBeNull());
    expect(rateLimitedUntil()).toBe(0);
  });
});

describe("the pre-session rate-limit page", () => {
  it("puts focus on its heading when it comes back after Try again now", async () => {
    mockApi(shellRoutes());
    renderBare(<SessionUnavailable error={limited(5)} retrying onRetry={() => {}} />);
    expect(await screen.findByRole("heading", { level: 1, name: "Too many requests" })).toHaveFocus();
  });
});
