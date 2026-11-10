/* Admin → Retention (bounds, a shorter period confirmed, If-Match, the last run) and Admin → Payload capture (patterns, the tester, refusals). */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { daysProblem } from "../lib/retention";
import { checkPattern } from "../pages/admin/operations/pattern-dialog";
import { ruleLabel } from "../pages/admin/operations/redaction-tester";
import { captureSettings, retentionSettings } from "./fixtures-operations";
import { type Call, type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const routes = (role: "platform_admin" | "platform_auditor", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/settings/retention": () => retentionSettings(),
  "GET /v1/admin/settings/capture": () => captureSettings(),
  ...extra,
});

const sent = (calls: Call[], method: string, url: string) => calls.filter((c) => c.method === method && c.url === url);

async function retype(u: ReturnType<typeof userEvent.setup>, name: string, value: string) {
  const input = screen.getByRole("textbox", { name });
  await u.clear(input);
  if (value) await u.type(input, value);
}

describe("Admin → Retention", () => {
  it("shows the periods and the last run, checks the bounds, and saves a longer period without asking (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { "PUT /v1/admin/settings/retention": () => retentionSettings({ revision: 3 }) }));
    const { container } = renderApp("/admin/retention");
    const table = await screen.findByRole("table", { name: "Retention periods" });
    expect(within(table).getByText("Recorded call contents")).toBeInTheDocument();
    expect(within(table).getByText("1–90 days")).toBeInTheDocument();
    expect(screen.getByText("1,250 deleted")).toBeInTheDocument();
    // Zero counts read as words, not "0 deleted".
    expect(screen.getAllByText("Nothing deleted")).toHaveLength(2);
    expect(screen.queryByText("0 deleted")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();

    await retype(u, "Recorded call contents: days", "91");
    expect(screen.getByText("Between 1 and 90 days.")).toBeInTheDocument();
    await retype(u, "Audit log: days", "10");
    expect(screen.getByText("Between 30 and 3,650 days.")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(sent(calls, "PUT", "/v1/admin/settings/retention")).toHaveLength(0);

    await retype(u, "Recorded call contents: days", "60");
    await retype(u, "Audit log: days", "400");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(sent(calls, "PUT", "/v1/admin/settings/retention")).toHaveLength(1));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    const put = sent(calls, "PUT", "/v1/admin/settings/retention")[0]!;
    expect(put.headers.get("If-Match")).toBe('"2"');
    expect(put.body).toEqual({ periods: [{ kind: "captured_payloads", days: 60 }] });
  });

  it("asks before a shorter period deletes records sooner", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { "PUT /v1/admin/settings/retention": () => retentionSettings({ revision: 3 }) }));
    renderApp("/admin/retention");
    await screen.findByRole("table", { name: "Retention periods" });
    await retype(u, "Call records: days", "30");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Delete records sooner?" });
    expect(ask).toHaveTextContent("Call records: 90 days → 30 days");
    expect(sent(calls, "PUT", "/v1/admin/settings/retention")).toHaveLength(0);
    await u.click(within(ask).getByRole("button", { name: "Save periods" }));
    await waitFor(() => expect(sent(calls, "PUT", "/v1/admin/settings/retention")[0]?.body).toEqual({ periods: [{ kind: "call_metadata", days: 30 }] }));
  });

  it("is read-only for auditors and says when a kind failed in the last run", async () => {
    mockApi(
      routes("platform_auditor", {
        "GET /v1/admin/settings/retention": () => retentionSettings({ lastRun: { startedAt: "2026-10-16T07:45:00Z", finishedAt: "2026-10-16T07:46:00Z", deleted: { call_metadata: 3 }, errors: { audit_log: "timeout" } } }),
      }),
    );
    renderApp("/admin/retention");
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.getByText("Failed (timeout)")).toBeInTheDocument();
    expect(screen.getByText(/Audit log couldn't be deleted/)).toBeInTheDocument();
  });

  it("says a run that reported no kinds deleted nothing", async () => {
    mockApi(routes("platform_auditor", { "GET /v1/admin/settings/retention": () => retentionSettings({ lastRun: { startedAt: "2026-10-16T07:45:00Z", finishedAt: "2026-10-16T07:46:00Z", deleted: {}, errors: {} } }) }));
    renderApp("/admin/retention");
    const card = (await screen.findByRole("heading", { name: "Last run" })).closest("section")!;
    expect(within(card).getByText("Nothing deleted")).toBeInTheDocument();
  });

  it("checks days against the bounds", () => {
    expect(daysProblem("14", 1, 90)).toBeUndefined();
    expect(daysProblem("0", 1, 90)).toBe("Between 1 and 90 days.");
    expect(daysProblem("1.5", 1, 90)).toMatch(/whole number/);
  });
});

describe("Admin → Payload capture", () => {
  it("lists the built-in rules, adds a pattern, tests it unsaved, and saves the list (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        "POST /v1/admin/settings/capture/test": (): Schemas["RedactionTestResult"] => ({
          redacted: '{"note":"<script>alert(1)</script> [REDACTED]","token":"[REDACTED]"}',
          redactions: 2,
          rules: [
            { rule: "sensitive_keys", count: 1 },
            { rule: "pattern:1", count: 1 },
          ],
          truncated: false,
        }),
        "PUT /v1/admin/settings/capture": (body) => captureSettings({ patterns: (body as Schemas["CaptureSettingsUpdate"]).patterns, revision: 6 }),
      }),
    );
    const { container } = renderApp("/admin/capture");
    expect(await screen.findByText("GitHub tokens")).toBeInTheDocument();
    expect(screen.getByText("apikey")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Redaction patterns" });
    expect(within(table).getByText("EMP-[0-9]{6}")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Payload capture · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("button", { name: "Add pattern" }));
    const dialog = await screen.findByRole("dialog", { name: "Add pattern" });
    await u.click(within(dialog).getByRole("button", { name: "Add pattern" }));
    expect(within(dialog).getByText("Enter a regular expression.")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Regular expression" }), "ACCT-\\d{{8}");
    await u.type(within(dialog).getByRole("textbox", { name: "Note" }), "Account numbers");
    await u.click(within(dialog).getByRole("button", { name: "Add pattern" }));
    expect(within(table).getByText("ACCT-\\d{8}")).toBeInTheDocument();

    await u.type(screen.getByRole("textbox", { name: "Sample" }), '{{"note":"x","token":"abc"}');
    expect(screen.getByText("Tested with the patterns above, including your unsaved changes.")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Test redaction" }));
    expect(await screen.findByText("2 values redacted")).toBeInTheDocument();
    const test = sent(calls, "POST", "/v1/admin/settings/capture/test")[0]!;
    expect(test.body).toEqual({ sample: '{"note":"x","token":"abc"}', patterns: [{ pattern: "EMP-[0-9]{6}", note: "Employee numbers" }, { pattern: "ACCT-\\d{8}", note: "Account numbers" }] });
    // The redacted sample is text: a script tag in it is shown, not run or parsed.
    expect(screen.getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    const rules = screen.getByRole("table", { name: "Rules that matched" });
    expect(within(rules).getByText("Sensitive member names")).toBeInTheDocument();
    expect(within(rules).getByText("Pattern 2 (ACCT-\\d{8})")).toBeInTheDocument();

    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(sent(calls, "PUT", "/v1/admin/settings/capture")).toHaveLength(1));
    const put = sent(calls, "PUT", "/v1/admin/settings/capture")[0]!;
    expect(put.headers.get("If-Match")).toBe('"5"');
    expect((put.body as Schemas["CaptureSettingsUpdate"]).patterns).toHaveLength(2);
    expect(await screen.findByText("Redaction patterns saved")).toBeInTheDocument();
  });

  it("shows a refused pattern on its row, and lets auditors test the saved patterns only", async () => {
    const u = userEvent.setup();
    mockApi(routes("platform_admin", { "PUT /v1/admin/settings/capture": () => Reply.error(422, "invalid_pattern", "bad", { index: 0, reason: "matches_empty" }) }));
    const { unmount } = renderApp("/admin/capture");
    const table = await screen.findByRole("table", { name: "Redaction patterns" });
    await u.click(within(table).getByRole("button", { name: "Actions for EMP-[0-9]{6}" }));
    await u.click(await screen.findByRole("menuitem", { name: "Edit…" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit pattern" });
    const input = within(dialog).getByRole("textbox", { name: "Regular expression" });
    await u.clear(input);
    // RE2-only syntax (a non-greedy flag): not checked in the browser, so the server's refusal is what shows.
    await u.type(input, "(?U)x*");
    expect(within(dialog).getByText(/uses syntax only RE2 has, so it can't be checked here/)).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Update pattern" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await within(table).findByText("Matches empty text, so it would redact everywhere.")).toBeInTheDocument();
    unmount();

    const calls = mockApi(
      routes("platform_auditor", {
        "POST /v1/admin/settings/capture/test": (): Schemas["RedactionTestResult"] => ({ redacted: "plain", redactions: 0, rules: [], truncated: true }),
      }),
    );
    renderApp("/admin/capture");
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add pattern" })).toBeNull();
    expect(screen.getByText("Tested with the saved patterns.")).toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: "Sample" }), "plain");
    await u.click(screen.getByRole("button", { name: "Test redaction" }));
    expect(await screen.findByText("Nothing redacted")).toBeInTheDocument();
    expect(screen.getByText("Cut to 16 KiB")).toBeInTheDocument();
    expect(sent(calls, "POST", "/v1/admin/settings/capture/test")[0]?.body).toEqual({ sample: "plain" });
  });

  it("checks a pattern's syntax in the browser where RegExp reads it as RE2 does", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin"));
    renderApp("/admin/capture");
    await u.click(await screen.findByRole("button", { name: "Add pattern" }));
    const dialog = await screen.findByRole("dialog", { name: "Add pattern" });
    const input = within(dialog).getByRole("textbox", { name: "Regular expression" });
    expect(input).toHaveAccessibleDescription(/the server's RE2 rules decide when you save/);
    await u.type(input, "ACCT-(\\d+");
    await u.click(within(dialog).getByRole("button", { name: "Add pattern" }));
    expect(within(dialog).getByText("Not a valid regular expression: unterminated group.")).toBeInTheDocument();
    await u.clear(input);
    await u.type(input, "(?<=id:)\\d+");
    expect(within(dialog).getByText("RE2 doesn't support lookahead, lookbehind or backreferences.")).toBeInTheDocument();
    await u.clear(input);
    await u.type(input, "(?i)\\d*");
    expect(within(dialog).getByText("Matches empty text, so it would redact everywhere.")).toBeInTheDocument();
    await u.clear(input);
    await u.type(input, "(?i)acct-\\d{{8}");
    await u.click(within(dialog).getByRole("button", { name: "Add pattern" }));
    expect(await within(screen.getByRole("table", { name: "Redaction patterns" })).findByText("(?i)acct-\\d{8}")).toBeInTheDocument();
    expect(sent(calls, "PUT", "/v1/admin/settings/capture")).toHaveLength(0);
  });

  it("knows which syntax the browser can check", () => {
    // Checked: common syntax, a leading flag group.
    expect(checkPattern("EMP-[0-9]{6}")).toEqual({ checked: true });
    expect(checkPattern("(?is)secret: .+")).toEqual({ checked: true });
    expect(checkPattern("(?:ab|cd)+(?<tail>x)")).toEqual({ checked: true });
    expect(checkPattern("a{2,1}")).toMatchObject({ checked: true, problem: expect.stringMatching(/^Not a valid regular expression: /) });
    expect(checkPattern("x|")).toEqual({ checked: true, problem: "Matches empty text, so it would redact everywhere." });
    // JavaScript-only features RE2 refuses (but not when escaped or inside a class).
    expect(checkPattern("(a)\\1")).toMatchObject({ problem: expect.stringMatching(/backreferences/) });
    expect(checkPattern("x(?!y)")).toMatchObject({ problem: expect.stringMatching(/lookahead/) });
    expect(checkPattern("\\(?=x")).toEqual({ checked: true });
    expect(checkPattern("[(?=]x")).toEqual({ checked: true });
    expect(checkPattern("\\12x")).toEqual({ checked: true }); // an octal escape in both
    // RE2-only syntax: left to the server.
    for (const p of ["(?U)a+", "(?i:a)b", "a(?i)b", "(?P<n>a)", "\\Aabc\\z", "\\pL+", "[[:alpha:]]+", "[]a]", "\\Q.*\\E"]) {
      expect(checkPattern(p)).toEqual({ checked: false });
    }
  });

  it("names the rules that matched", () => {
    expect(ruleLabel("github", [])).toBe("github");
    expect(ruleLabel("pattern:0", [{ pattern: "EMP" }])).toBe("Pattern 1 (EMP)");
  });
});
