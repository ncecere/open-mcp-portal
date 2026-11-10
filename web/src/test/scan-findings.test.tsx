import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { CapabilityFindings, ScanFindings } from "../components/servers/scan-findings";
import { CapabilitiesTab } from "../components/servers/capabilities-tab";
import { adminAbilities, readOnly } from "../components/servers/scope";
import { PublishDialog, ReviewDialog } from "../components/servers/publish-dialogs";
import { mockApi, renderBare, shellRoutes, Reply } from "./harness";
import { renderApp } from "./render-app";
import { mcpServer, capability } from "./fixtures";
import type { Schemas } from "../api/client";

type Scan = Schemas["DefinitionScanPage"][number]["scan"];
const scan: Scan = { status: "scanned", rulesetVersion: "v1", scannedAt: "2026-11-05T12:34:56Z", findings: [] };
const sv = mcpServer();
const base = `/v1/teams/${sv.teamSlug}/mcp-servers/${sv.id}`;
const adminBase = `/v1/admin/mcp-servers/${sv.id}`;
const routes = (prefix = base) => ({
  [`GET ${prefix}/capabilities`]: () => [],
  [`GET ${prefix}/scan-findings`]: () => [{ capabilityId: "cap-1", scan }],
});

describe("Definition findings", () => {
  it("A9: says found nothing with ruleset version and a limitation, without a success verdict", async () => {
    const { container } = renderBare(<CapabilityFindings scan={scan} />);
    expect(await screen.findByText("Heuristics found nothing in this definition (ruleset v1). This does not mean the definition is safe.")).toBeInTheDocument();
    const withoutDisclaimer = container.textContent?.replace("This does not mean the definition is safe.", "");
    expect(withoutDisclaimer).not.toMatch(/\b(passed|safe|clean)\b/i);
    expect(container.querySelector('[data-tone="success"], [class*="success"]')).toBeNull();
    expect(container.querySelector("time")).toHaveAttribute("datetime", new Date(scan.scannedAt!).toISOString());
    expect(await axe(container)).toHaveNoViolations();
  });

  it.each([
    ["incomplete", "Reason: budget. Findings may be missing."],
    ["stale", "Not yet scanned under the current definition/ruleset."],
    ["off", "Scanning disabled. No current scan is available."],
  ] as const)("explains %s without suggesting a zero-finding result", async (status, text) => {
    const { container } = renderBare(<CapabilityFindings scan={{ ...scan, status, reason: "budget", scannedAt: status === "incomplete" ? scan.scannedAt : undefined }} />);
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(screen.queryByText(/Heuristics found nothing/)).not.toBeInTheDocument();
    expect(container.querySelector('[data-tone="success"], [class*="success"]')).toBeNull();
    expect(Boolean(container.querySelector("time"))).toBe(status === "incomplete");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("renders adversarial locations as inert text and names severity, group and count", async () => {
    const location = '/<script>alert(1)</script><img src=x onerror=alert(2)>\u202e\u{e0001}';
    const { container } = renderBare(<CapabilityFindings scan={{ ...scan, findings: [{ ruleId: "unicode.tag_chars", group: "unicode", severity: "high", count: 2, location }] }} />);
    await screen.findByText(/unicode.tag_chars/);
    expect(container.querySelector("code")).toHaveTextContent(location);
    expect(container.querySelector("script, img")).toBeNull();
    expect(screen.getByText(/Group: unicode · Severity: high · Count: 2/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it.each([[403, "forbidden", "You don't have permission"], [404, "not_found", "no longer available"], [409, "conflict", "definitions changed"], [403, "token_not_allowed", "browser session"]])("handles rescan %s %s", async (status, code, message) => {
    mockApi({ ...routes(), [`POST ${base}/scan`]: () => Reply.error(Number(status), String(code)) });
    renderBare(<ScanFindings scope={{ kind: "team", team: sv.teamSlug }} serverId={sv.id} canRescan />);
    await screen.findByText(/Heuristics found nothing/);
    await userEvent.setup().click(screen.getByRole("button", { name: "Rescan definitions" }));
    expect(await screen.findByText(new RegExp(String(message)))).toBeInTheDocument();
  });

  it.each(["member", "editor", "auditor", "admin"])("rescan visibility for %s follows the server abilities", async (role) => {
    const admin = role === "auditor" || role === "admin";
    mockApi(routes(admin ? adminBase : base));
    const { container } = renderBare(<><h1>Server</h1><CapabilitiesTab server={sv} scope={admin ? { kind: "admin" } : { kind: "team", team: sv.teamSlug }} abilities={admin ? adminAbilities(role === "admin") : { ...readOnly, canEdit: role === "editor" }} /></>);
    await screen.findByText(/Heuristics found nothing/);
    expect(Boolean(screen.queryByRole("button", { name: "Rescan definitions" }))).toBe(role === "editor" || role === "admin");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("keeps capability filter counts in their visible accessible labels", async () => {
    mockApi({ ...routes(), [`GET ${base}/capabilities`]: () => [capability({ id: "cap-1" })] });
    renderBare(<CapabilitiesTab server={sv} scope={{ kind: "team", team: sv.teamSlug }} abilities={readOnly} />);
    const tools = await screen.findByRole("button", { name: "Tools 1" });
    expect(tools).toHaveTextContent("Tools 1");
    expect(tools).not.toHaveAttribute("aria-label");
    await userEvent.setup().click(tools);
    expect(tools).toHaveAttribute("aria-pressed", "true");
  });

  it.each(["publish", "review"])("includes findings and limitations in the %s dialog", async (dialog) => {
    mockApi(routes(dialog === "publish" ? base : adminBase));
    const { container } = renderBare(dialog === "publish" ? <PublishDialog server={sv} onClose={() => {}} /> : <ReviewDialog server={sv} decision="approve" onClose={() => {}} />);
    await screen.findByText(/Heuristics found nothing/);
    expect(screen.getByRole("link", { name: "What scanning will not catch" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows findings in the capability-change review and supports keyboard rescan", async () => {
    const cap = capability({ id: "cap-1", changed: true });
    const calls = mockApi({ ...routes(), [`GET ${base}/capabilities`]: () => [cap], [`POST ${base}/scan`]: () => [{ capabilityId: cap.id, scan }] });
    renderBare(<CapabilitiesTab server={sv} scope={{ kind: "team", team: sv.teamSlug }} abilities={{ ...readOnly, canEdit: true, canApproveChanges: true }} />);
    await screen.findByRole("button", { name: `Approve the change to ${cap.name}` });
    const u = userEvent.setup();
    const rescan = screen.getByRole("button", { name: "Rescan definitions" });
    await u.tab();
    expect(screen.getByRole("link", { name: "What scanning will not catch" })).toHaveFocus();
    await u.tab();
    expect(rescan).toHaveFocus();
    await u.keyboard("{Enter}");
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    await u.click(screen.getByRole("button", { name: `Approve the change to ${cap.name}` }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("Definition scan findings");
    await waitFor(() => expect(dialog).toHaveTextContent("Heuristics found nothing"));
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it("updates findings from a successful rescan", async () => {
    mockApi({ ...routes(), [`POST ${base}/scan`]: () => [{ capabilityId: "cap-1", scan: { ...scan, status: "incomplete", reason: "budget" } }] });
    renderBare(<ScanFindings scope={{ kind: "team", team: sv.teamSlug }} serverId={sv.id} canRescan />);
    await screen.findByText(/Heuristics found nothing/);
    await userEvent.setup().click(screen.getByRole("button", { name: "Rescan definitions" }));
    await screen.findByText(/Reason: budget/);
    expect(screen.queryByText(/Heuristics found nothing/)).not.toBeInTheDocument();
  });
});

describe("Admin scanning settings", () => {
  const settingsRoutes = (role: "platform_admin" | "platform_auditor" = "platform_admin") => ({
    ...shellRoutes(role, null),
    "GET /v1/admin/settings/scanning": () => ({ definitionMode: "shadow", revision: 7 }),
    "GET /v1/admin/scanning/rules": () => ({ rulesetVersion: "v1", rules: [{ id: "poison.override_instructions", group: "poison", severity: "high", description: "Known instruction patterns" }] }),
  });
  it("uses If-Match and explains a 409 conflict while keeping edits", async () => {
    const calls = mockApi({ ...settingsRoutes(), "PUT /v1/admin/settings/scanning": () => Reply.error(409, "revision_conflict") });
    const { container } = renderApp("/admin/scanning");
    const select = await screen.findByRole("combobox", { name: "Definition scanning mode" });
    expect(await axe(container)).toHaveNoViolations();
    const u = userEvent.setup();
    await u.selectOptions(select, "off");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await screen.findByText(/Scanning settings changed elsewhere/);
    expect(select).toHaveValue("off");
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.headers.get("If-Match")).toBe('"7"'));
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ definitionMode: "off" });
  });
  it("auditors read the mode and rule catalog", async () => {
    mockApi(settingsRoutes("platform_auditor"));
    const { container } = renderApp("/admin/scanning");
    expect(await screen.findByRole("combobox", { name: "Definition scanning mode" })).toBeDisabled();
    expect(await screen.findByText("poison.override_instructions")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save settings" })).not.toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
