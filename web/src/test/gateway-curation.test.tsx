import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { gatewayCapabilitiesQuery } from "../components/gateways/scope";
import { policyOf, previewOf } from "../components/gateways/curation-fields";
import { gateway, gatewayCapabilities, gatewayCapability, gatewayId, gatewayOptions, optionsPage, team } from "./fixtures";
import { type Handler, mockApi, renderApp, Reply, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/gateways/${gatewayId}`;
const tab = `/teams/${team.slug}/gateways/${gatewayId}?tab=capabilities`;
const definition = { name: "get_status", description: "Original server words", inputSchema: { type: "object", properties: { owner: { type: "string" }, limit: { type: "integer" }, active: { type: "boolean" }, config: { type: "object", properties: { enabled: { type: "boolean" } } } }, required: ["owner"] } };
const capability = (extra: Partial<Schemas["GatewayCapability"]> = {}) => gatewayCapability({ fingerprint: "fingerprint-reviewed", originalDefinition: definition, effectiveDefinition: definition, ...extra });
const routes = (cap = capability(), extra: Record<string, Handler> = {}, role: Schemas["TeamRole"] = "owner"): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => gateway(),
  [`GET ${base}/capabilities`]: () => gatewayCapabilities([cap]),
  [`GET /v1/teams/${team.slug}/gateway-options`]: (_b, call) => optionsPage(gatewayOptions, call.search),
  ...extra,
});
async function open(u: ReturnType<typeof userEvent.setup>, name = "service-status__get_status") {
  await u.click(await screen.findByRole("button", { name: `Curate ${name}` }));
  return screen.findByRole("dialog", { name: `Curate ${name}` });
}

describe("Gateway tool curation", () => {
  it("edits typed fixed/allowed arguments, previews the model definition and saves both review guards", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(capability(), { [`PUT ${base}/capabilities`]: () => gatewayCapabilities([capability()], 8) }));
    const { container } = renderApp(tab);
    const dialog = await open(u);
    expect(await axe(dialog)).toHaveNoViolations();
    await u.type(within(dialog).getByRole("textbox", { name: "Exposed name" }), "our_status");
    await u.click(within(dialog).getByRole("checkbox", { name: "Override description for this gateway" }));
    await u.clear(within(dialog).getByRole("textbox", { name: "Model-facing description" }));
    await u.type(within(dialog).getByRole("textbox", { name: "Model-facing description" }), "For our team");
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Policy for owner" }), "fixed");
    await u.type(within(dialog).getByRole("textbox", { name: "Fixed value for owner" }), "our-org");
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Policy for limit" }), "allowed");
    const allowed = within(dialog).getByRole("textbox", { name: "Allowed values for limit" });
    await u.clear(allowed);
    await u.click(allowed);
    await u.paste("[2,3]");
    await u.click(within(dialog).getByText("Model definition preview (server validates on save)"));
    expect(within(dialog).getByText(/"name": "our_status"/)).not.toHaveTextContent("our-org");
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")).toBeDefined());
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.headers.get("If-Match")).toBe('"7"');
    expect(put.body).toEqual({ items: [{ capabilityId: capability().capabilityId, expectedFingerprint: "fingerprint-reviewed", curation: { nameOverride: "our_status", descriptionOverride: "For our team", constraints: { owner: { fixed: "our-org" }, limit: { allowed: [2, 3] } } } }] });
    expect(await axe(container)).toHaveNoViolations();
  });

  it("keeps policies out of ordinary selection/minimum-role edits rather than clearing them", async () => {
    const u = userEvent.setup();
    const cap = capability({ curation: { constraints: { owner: { fixed: "our-org" } } } });
    const calls = mockApi(routes(cap, { [`PUT ${base}/capabilities`]: () => gatewayCapabilities([cap], 8) }));
    renderApp(tab);
    expect(await screen.findByText("Edited for this gateway")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Edit selection" }));
    await u.selectOptions(await screen.findByRole("combobox", { name: "Who may use service-status__get_status" }), "editor");
    expect(screen.getByRole("button", { name: "Curate service-status__get_status" })).toBeDisabled();
    await u.click(screen.getByRole("button", { name: "Save selection" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ items: [{ capabilityId: cap.capabilityId, minRole: "editor" }] }));
  });

  it("restores name and description independently while retaining argument policy", async () => {
    const u = userEvent.setup();
    const cap = capability({ exposedName: "our_status", curation: { nameOverride: "our_status", descriptionOverride: "Edited description", constraints: { owner: { fixed: "org" } } } });
    const calls = mockApi(routes(cap, { [`PUT ${base}/capabilities`]: () => gatewayCapabilities([capability()], 8) }));
    renderApp(tab);
    const dialog = await open(u, "our_status");
    await u.clear(within(dialog).getByRole("textbox", { name: "Exposed name" }));
    await u.click(within(dialog).getByRole("checkbox", { name: "Override description for this gateway" }));
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ items: [{ capabilityId: cap.capabilityId, expectedFingerprint: cap.fingerprint, curation: { nameOverride: null, descriptionOverride: null, constraints: { owner: { fixed: "org" } } } }] }));
  });

  it("does not turn a long original description into an invalid override during rename-only edits", async () => {
    const u = userEvent.setup();
    const cap = capability({ originalDefinition: { ...definition, description: "x".repeat(2500) } });
    const calls = mockApi(routes(cap, { [`PUT ${base}/capabilities`]: () => gatewayCapabilities([capability()], 8) }));
    renderApp(tab);
    const dialog = await open(u);
    await u.type(within(dialog).getByRole("textbox", { name: "Exposed name" }), "our_status");
    expect(within(dialog).getByRole("textbox", { name: "Model-facing description" })).toBeDisabled();
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ items: [{ capabilityId: cap.capabilityId, expectedFingerprint: cap.fingerprint, curation: { nameOverride: "our_status", descriptionOverride: null, constraints: {} } }] }));
  });

  it("clears explicitly with null and the current fingerprint", async () => {
    const u = userEvent.setup();
    const cap = capability({ curation: { nameOverride: "our_status", constraints: { owner: { fixed: "org" } } }, exposedName: "our_status" });
    const calls = mockApi(routes(cap, { [`PUT ${base}/capabilities`]: () => gatewayCapabilities([capability()], 8) }));
    renderApp(tab);
    const dialog = await open(u, "our_status");
    await u.click(within(dialog).getByRole("button", { name: "Clear policy and restore defaults" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ items: [{ capabilityId: cap.capabilityId, expectedFingerprint: cap.fingerprint, curation: null }] }));
  });

  it.each([[409, "changed_since_review"], [412, "revision_conflict"]])("freezes policy review on %s %s, including across background reloads", async (status, code) => {
    const u = userEvent.setup();
    const calls = mockApi(routes(capability(), { [`PUT ${base}/capabilities`]: () => Reply.error(Number(status), String(code), "Definition changed") }));
    const { qc } = renderApp(tab);
    const dialog = await open(u);
    act(() => qc.setQueryData(gatewayCapabilitiesQuery({ kind: "team", team: team.slug }, gatewayId).queryKey, gatewayCapabilities([capability({ fingerprint: "new" })], 20)));
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    expect(await within(dialog).findByText(/Close it and review the refreshed definition/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Save policy" })).toBeDisabled();
    expect(within(dialog).getByRole("textbox", { name: "Exposed name" })).toBeDisabled();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.headers.get("If-Match")).toBe('"7"');
    expect(JSON.stringify(put.body)).toContain("fingerprint-reviewed");
  });

  it("shows a name collision without rebasing and allows correcting the name", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(capability(), { [`PUT ${base}/capabilities`]: () => Reply.error(409, "name_taken", "Two selected tools expose the same name") }));
    renderApp(tab);
    const dialog = await open(u);
    await u.type(within(dialog).getByRole("textbox", { name: "Exposed name" }), "taken");
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    expect(await within(dialog).findByText("Two selected tools expose the same name")).toBeInTheDocument();
    expect(within(dialog).getByRole("textbox", { name: "Exposed name" })).not.toBeDisabled();
    await u.clear(within(dialog).getByRole("textbox", { name: "Exposed name" }));
    await u.type(within(dialog).getByRole("textbox", { name: "Exposed name" }), "unique");
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
  });

  it("makes stale policy review explicit and resaves against the fresh fingerprint", async () => {
    const u = userEvent.setup();
    const cap = capability({ stale: true, available: false, unavailableReason: "curation_stale", curation: { constraints: { owner: { fixed: "org" } } }, fingerprint: "fresh" });
    const calls = mockApi(routes(cap, { [`PUT ${base}/capabilities`]: () => gatewayCapabilities([capability()], 8) }));
    renderApp(tab);
    expect(await screen.findByText("Tool policy needs review")).toBeInTheDocument();
    const dialog = await open(u);
    expect(within(dialog).getByText("Definition changed")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Review and resave policy" }));
    await waitFor(() => expect(JSON.stringify(calls.find((c) => c.method === "PUT")?.body)).toContain('"expectedFingerprint":"fresh"'));
  });

  it("supports complex JSON values and rejects malformed/unsafe-number input without a request", () => {
    expect(policyOf("", "", { config: { mode: "fixed", text: '{"enabled":true}' } }, definition.inputSchema.properties).constraints).toEqual({ config: { fixed: { enabled: true } } });
    expect(() => policyOf("", "", { limit: { mode: "fixed", text: "9007199254740993" } }, definition.inputSchema.properties)).toThrow();
    const preview = previewOf(definition, { constraints: { owner: { fixed: "org" } } }, "fallback");
    expect(preview.inputSchema).toMatchObject({ required: [], properties: { limit: { type: "integer" } } });
    expect(JSON.stringify(preview)).not.toContain('"owner"');
  });

  it.each(["fixed", "allowed"] as const)("saves and reloads %s dictionary edge keys through the dialog", async (mode) => {
    const u = userEvent.setup();
    const keys = ["__proto__", "constructor", "prototype", "normal"];
    const specialDefinition = { ...definition, inputSchema: { type: "object", properties: Object.fromEntries(keys.map((key) => [key, { type: "string" }])), required: keys } };
    let cap = capability({ originalDefinition: specialDefinition, effectiveDefinition: specialDefinition });
    const calls = mockApi(routes(cap, {
      [`GET ${base}/capabilities`]: () => gatewayCapabilities([cap], 8),
      [`PUT ${base}/capabilities`]: (body) => {
        const curation = (body as { items: { curation: Schemas["GatewayToolCuration"] }[] }).items[0]!.curation;
        cap = { ...cap, curation };
        return gatewayCapabilities([cap], 8);
      },
    }));
    renderApp(tab);
    let dialog = await open(u);
    for (const key of keys) {
      const select = within(dialog).getByRole("combobox", { name: `Policy for ${key}` });
      expect(select).toHaveValue("");
      await u.selectOptions(select, mode);
      const input = within(dialog).getByRole("textbox", { name: `${mode === "fixed" ? "Fixed value" : "Allowed values"} for ${key}` });
      await u.clear(input);
      await u.click(input);
      await u.paste(mode === "fixed" ? `${key} value` : JSON.stringify([`${key} value`]));
    }
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const expected = Object.fromEntries(keys.map((key) => [key, mode === "fixed" ? { fixed: `${key} value` } : { allowed: [`${key} value`] }]));
    expect(cap.curation?.constraints).toEqual(expected);
    dialog = await open(u);
    for (const key of keys) {
      expect(within(dialog).getByRole("combobox", { name: `Policy for ${key}` })).toHaveValue(mode);
      expect(within(dialog).getByRole("textbox", { name: `${mode === "fixed" ? "Fixed value" : "Allowed values"} for ${key}` })).toHaveValue(mode === "fixed" ? `${key} value` : JSON.stringify([`${key} value`]));
    }
    await u.type(within(dialog).getByRole("textbox", { name: "Exposed name" }), "renamed");
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.filter((call) => call.method === "PUT")).toHaveLength(2));
    expect(cap.curation).toMatchObject({ nameOverride: "renamed", constraints: expected });
  });

  it.each([
    ["limit", "fixed", "9007199254740990.5"],
    ["config", "fixed", '{"enabled":true,"nested":[0.10000000000000001]}'],
    ["config", "allowed", '[{"nested":[1e-9999]}]'],
    ["limit", "allowed", "[1e99999]"],
  ])("rejects raw %s %s numeric input without a request", async (arg, mode, text) => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(tab);
    const dialog = await open(u);
    await u.selectOptions(within(dialog).getByRole("combobox", { name: `Policy for ${arg}` }), mode);
    const input = within(dialog).getByRole("textbox", { name: `${mode === "fixed" ? "Fixed value" : "Allowed values"} for ${arg}` });
    await u.clear(input);
    await u.click(input);
    await u.paste(text);
    expect(input).toHaveDisplayValue(text);
    expect(within(dialog).getByRole("status")).toHaveTextContent("Numbers must be finite, use safe integers, and round-trip through JSON without rounding or underflow");
    const save = within(dialog).getByRole("button", { name: "Save policy" });
    expect(save).toBeDisabled();
    await u.click(save);
    expect(calls.filter((call) => call.method === "PUT" || call.method === "POST")).toHaveLength(0);
  });

  it("saves safe nested decimals, reloads, and changes only name and description without changing constraints", async () => {
    const u = userEvent.setup();
    let cap = capability();
    const calls = mockApi(routes(cap, {
      [`GET ${base}/capabilities`]: () => gatewayCapabilities([cap], 8),
      [`PUT ${base}/capabilities`]: (body) => {
        cap = { ...cap, curation: (body as { items: { curation: Schemas["GatewayToolCuration"] }[] }).items[0]!.curation };
        return gatewayCapabilities([cap], 8);
      },
    }));
    renderApp(tab);
    let dialog = await open(u);
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Policy for config" }), "allowed");
    const input = within(dialog).getByRole("textbox", { name: "Allowed values for config" });
    await u.clear(input);
    await u.click(input);
    await u.paste('[{"values":[0.1,1e-1,1.5],"quoted":"9007199254740990.5"}]');
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const expected = { config: { allowed: [{ values: [0.1, 0.1, 1.5], quoted: "9007199254740990.5" }] } };
    expect(cap.curation?.constraints).toEqual(expected);
    dialog = await open(u);
    expect(within(dialog).getByRole("textbox", { name: "Allowed values for config" })).toHaveValue(JSON.stringify(expected.config.allowed));
    await u.type(within(dialog).getByRole("textbox", { name: "Exposed name" }), "renamed");
    await u.click(within(dialog).getByRole("checkbox", { name: "Override description for this gateway" }));
    await u.clear(within(dialog).getByRole("textbox", { name: "Model-facing description" }));
    await u.type(within(dialog).getByRole("textbox", { name: "Model-facing description" }), "New description");
    await u.click(within(dialog).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.filter((call) => call.method === "PUT")).toHaveLength(2));
    expect(cap.curation).toEqual({ nameOverride: "renamed", descriptionOverride: "New description", constraints: expected });
  });

  it("lets read-only platform staff inspect original and model definitions without mutation controls", async () => {
    const u = userEvent.setup();
    mockApi({ ...routes(capability({ curation: { nameOverride: "our_status" } })), ...shellRoutes("platform_auditor", "member") });
    renderApp(tab);
    await u.click(await screen.findByRole("button", { name: "View definitions for service-status__get_status" }));
    const dialog = await screen.findByRole("dialog", { name: "Tool definitions: service-status__get_status" });
    expect(within(dialog).getByText("Original server definition")).toBeInTheDocument();
    expect(within(dialog).getByText("Model-facing definition")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Save policy" })).toBeNull();
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it.each(["member", "editor"] as const)("keeps %s read-only", async (role) => {
    mockApi(routes(capability(), {}, role));
    renderApp(tab);
    await screen.findByRole("listitem", { name: "tool: service-status__get_status" });
    expect(screen.queryByRole("button", { name: /Curate/ })).toBeNull();
  });
});
