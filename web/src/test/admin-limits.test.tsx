/* Admin → Limits: defaults and ceilings, bounds, the save with If-Match after a confirmation, conflicts and refusals. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { parseRate, rateProblem, rateText } from "../lib/limits";
import { limitSettings } from "./fixtures-operations";
import { type Call, type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/settings/limits": () => limitSettings(),
  ...extra,
});

const puts = (calls: Call[]) => calls.filter((c) => c.method === "PUT" && c.url === "/v1/admin/settings/limits");

async function retype(u: ReturnType<typeof userEvent.setup>, name: string, value: string) {
  const input = screen.getByRole("textbox", { name });
  await u.clear(input);
  if (value) await u.type(input, value);
}

describe("Admin → Limits", () => {
  it("shows each limit's default and ceiling and saves the changed ones after confirming (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        "PUT /v1/admin/settings/limits": (body) => {
          const items = (body as Schemas["LimitSettingsUpdate"]).items;
          const next = limitSettings().items.map((it) => {
            const c = items.find((x) => x.key === it.key);
            return c ? { ...it, default: c.default, ceiling: c.ceiling, cappedTeams: it.key === "service_account_per_minute" ? 2 : 0 } : it;
          });
          return limitSettings({ items: next, revision: 5 });
        },
      }),
    );
    const { container } = renderApp("/admin/limits");
    const table = await screen.findByRole("table", { name: "Rate limits: defaults and ceilings" });
    expect(within(table).getByText("Per person")).toBeInTheDocument();
    // Keys teams can't override have no ceiling.
    expect(within(table).getAllByText("Not overridable")).toHaveLength(2);
    await waitFor(() => expect(document.title).toBe("Limits · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();

    await retype(u, "Default for Per person (requests per minute)", "500");
    await retype(u, "Ceiling for Per service account (requests per minute)", "4000");
    expect(screen.getByText(/keep their values, capped to it/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Save the rate limits?" });
    expect(ask).toHaveTextContent("2 limits changed");
    expect(ask).toHaveTextContent("Per person: default 500 per minute");
    expect(ask).toHaveTextContent("Per service account: default 1,200 per minute, ceiling 4,000 per minute");
    expect(puts(calls)).toHaveLength(0);
    await u.click(within(ask).getByRole("button", { name: "Save limits" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect(puts(calls)[0]?.headers.get("If-Match")).toBe('"4"');
    expect(puts(calls)[0]?.body).toEqual({
      items: [
        { key: "person_per_minute", default: 500, ceiling: null },
        { key: "service_account_per_minute", default: 1200, ceiling: 4000 },
      ],
    });
    expect(await screen.findByText("Limits saved")).toBeInTheDocument();
    expect(screen.getByText(/Capped by a ceiling: 2 teams for Per service account/)).toBeInTheDocument();
  });

  it("checks the bounds and the default against the ceiling before saving", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp("/admin/limits");
    await screen.findByRole("table", { name: "Rate limits: defaults and ceilings" });
    await retype(u, "Default for Per person (requests per minute)", "0");
    expect(screen.getByText("Enter a whole number from 1 to 1,000,000, or leave it empty.")).toBeInTheDocument();
    await retype(u, "Default for Per person (requests per minute)", "2000000");
    expect(screen.getByText("Enter a whole number from 1 to 1,000,000, or leave it empty.")).toBeInTheDocument();
    await retype(u, "Default for Per person (requests per minute)", "");
    await retype(u, "Default for Per service account (requests per minute)", "6000");
    expect(screen.getByText("The default can't be above the ceiling.")).toBeInTheDocument();
    // A ceiling on gateways with an unlimited default: the default must come down to it.
    await retype(u, "Default for Per service account (requests per minute)", "1200");
    await retype(u, "Ceiling for Per gateway (requests per minute)", "100");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(screen.getByText(/Unlimited is above the ceiling/)).toBeInTheDocument();
    expect(screen.getByText("Not saved: fix the highlighted limits")).toBeInTheDocument();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(puts(calls)).toHaveLength(0);
  });

  it("keeps the edits through a save conflict (412) and overwrites on the latest revision", async () => {
    const u = userEvent.setup();
    let current = limitSettings();
    let conflict = true;
    const calls = mockApi(
      routes("platform_admin", {
        "GET /v1/admin/settings/limits": () => current,
        "PUT /v1/admin/settings/limits": () => {
          if (!conflict) return limitSettings({ revision: 7 });
          conflict = false;
          current = limitSettings({ revision: 6, items: limitSettings().items.map((it) => (it.key === "credential_per_minute" ? { ...it, default: 250 } : it)) });
          return Reply.error(412, "revision_conflict", "Changed");
        },
      }),
    );
    renderApp("/admin/limits");
    await screen.findByRole("table", { name: "Rate limits: defaults and ceilings" });
    await retype(u, "Default for Per person (requests per minute)", "500");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save limits" }));
    expect(await screen.findByText("Someone else changed these settings while you were editing")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Changed elsewhere" })).toHaveTextContent("Per API key or connected app");
    expect(screen.getByRole("textbox", { name: "Default for Per person (requests per minute)" })).toHaveValue("500");
    await u.click(screen.getByRole("button", { name: "Overwrite with mine" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save limits" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(2));
    expect(puts(calls)[1]?.headers.get("If-Match")).toBe('"6"');
  });

  it("shows a refusal on its row, and is read-only for auditors", async () => {
    const u = userEvent.setup();
    mockApi(routes("platform_admin", { "PUT /v1/admin/settings/limits": () => Reply.error(422, "invalid_limit", "bad", { key: "person_per_minute", reason: "duplicate" }) }));
    const { unmount } = renderApp("/admin/limits");
    await screen.findByRole("table", { name: "Rate limits: defaults and ceilings" });
    await retype(u, "Default for Per person (requests per minute)", "700");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save limits" }));
    expect(await screen.findByText("Listed twice.")).toBeInTheDocument();
    unmount();

    mockApi(routes("platform_auditor"));
    const { container } = renderApp("/admin/limits");
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.getByText("Unlimited")).toBeInTheDocument();
    expect(screen.getByText("5,000 per minute")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("rate limit helpers", () => {
  it("parse and check requests per minute", () => {
    expect(parseRate("")).toBeNull();
    expect(parseRate(" 42 ")).toBe(42);
    expect(parseRate("1.5")).toBeNaN();
    expect(rateProblem("")).toBeUndefined();
    expect(rateProblem("1000000")).toBeUndefined();
    expect(rateProblem("1000001")).toMatch(/1 to 1,000,000/);
    expect(rateProblem("3001", 3000)).toBe("At most the ceiling, 3,000 per minute.");
    expect(rateText(null)).toBe("Unlimited");
    expect(rateText(null, "No ceiling")).toBe("No ceiling");
    expect(rateText(1200)).toBe("1,200 per minute");
  });
});
