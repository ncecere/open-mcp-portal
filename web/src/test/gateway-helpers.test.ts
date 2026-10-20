/* Pure gateway helpers: the clients' snippets, the refused-selection mapping (422) and the audit words. */
import { ApiError } from "../api/client";
import { actionLabel, areaOf, areaOptions, targetTypeLabel } from "../components/audit/labels";
import { authFor, clientName, keyPlaceholder, snippet, snippetClients } from "../components/gateways/connect-snippets";
import { selectionProblem } from "../components/gateways/picker-errors";
import { callErrorLabel, callErrorLabels, grantCountLabel } from "../components/gateways/labels";
import { grantSummary } from "../components/gateways/overview-tab";
import { filterOptions } from "../components/gateways/picker-options";
import { expiryText } from "../pages/account/api-keys";
import { grant, gatewayOptions, user } from "./fixtures";

const url = "https://mcp.example.com/mcp/support-tools";

describe("connect snippets", () => {
  it("default to OAuth sign-in for Claude Code, VS Code and Cursor: the URL only, no header and no secret", () => {
    expect(snippet("claude", { name: "support-tools", url })).toBe(`claude mcp add --transport http support-tools ${url}`);
    expect(JSON.parse(snippet("vscode", { name: "support-tools", url }))).toEqual({ servers: { "support-tools": { type: "http", url } } });
    expect(JSON.parse(snippet("cursor", { name: "x", url }))).toEqual({ mcpServers: { x: { url } } });
    // Even a secret passed by mistake never reaches an OAuth snippet.
    for (const c of ["claude", "vscode", "cursor"] as const) {
      const text = snippet(c, { name: "s", url, secret: "omp_secret" });
      expect(text, c).not.toMatch(/omp_secret|Authorization|header/i);
    }
    expect(authFor("claude", "oauth")).toBe("oauth");
    // curl can't open a browser: it always uses a key.
    expect(authFor("curl", "oauth")).toBe("key");
    expect(snippet("curl", { name: "s", url })).toContain(`-H "Authorization: Bearer ${keyPlaceholder}"`);
  });

  it("keep the API-key variants: the URL and a placeholder, never a key unless one is passed", () => {
    for (const c of snippetClients) {
      const text = snippet(c.id, { name: "support-tools", url, auth: "key" });
      expect(text, c.id).toContain(url);
      expect(text, c.id).not.toContain("omp_");
    }
    expect(snippet("claude", { name: "support-tools", url, auth: "key" })).toBe(`claude mcp add --transport http support-tools ${url} --header "Authorization: Bearer ${keyPlaceholder}"`);
    expect(snippet("cursor", { name: "s", url, secret: "omp_secret", auth: "key" })).toContain('"Authorization": "Bearer omp_secret"');
    expect(snippet("curl", { name: "s", url, secret: "omp_secret" })).toContain('-H "Authorization: Bearer omp_secret"');
  });

  it("give VS Code a password prompt instead of the key, even when one is passed", () => {
    const parsed = JSON.parse(snippet("vscode", { name: "support-tools", url, secret: "omp_secret", auth: "key" }));
    expect(parsed).toEqual({
      inputs: [{ type: "promptString", id: "omp-key", description: "Open MCP Portal API key", password: true }],
      servers: { "support-tools": { type: "http", url, headers: { Authorization: "Bearer ${input:omp-key}" } } },
    });
    expect(JSON.parse(snippet("cursor", { name: "x", url, auth: "key" }))).toEqual({ mcpServers: { x: { url, headers: { Authorization: `Bearer ${keyPlaceholder}` } } } });
  });

  it("keep client names shell- and JSON-safe", () => {
    expect(clientName("Support tools!", "fallback")).toBe("Support-tools");
    expect(clientName("  ;rm -rf /  ", "fallback")).toBe("rm--rf");
    expect(clientName("", "support-tools")).toBe("support-tools");
  });
});

describe("refused selections", () => {
  const sel = [
    { capabilityId: "a", exposedName: "x__one" },
    { capabilityId: "b", exposedName: "y__one" },
    { capabilityId: "c", exposedName: "x__one" },
  ];

  it("map capability_not_selectable to the capabilities it names", () => {
    const p = selectionProblem(new ApiError(422, "capability_not_selectable", "no", { capabilityIds: ["a", "b"] }), sel);
    expect(p?.ids).toEqual(["a", "b"]);
    expect(p?.message).toMatch(/^2 selected capabilities can't be selected any more/);
  });

  it("map name_clash to the capabilities sharing the name", () => {
    const p = selectionProblem(new ApiError(422, "name_clash", "no", { exposedName: "x__one" }), sel);
    expect(p?.ids).toEqual(["a", "c"]);
    expect(p?.message).toContain("x__one");
  });

  it("say how many to remove when there are too many", () => {
    const many = Array.from({ length: 203 }, (_, i) => ({ capabilityId: String(i) }));
    expect(selectionProblem(new ApiError(422, "too_many", "no"), many)?.message).toBe("A gateway can hold at most 200 capabilities. Remove 3 and save again.");
  });

  it("leave other errors alone", () => {
    expect(selectionProblem(new ApiError(412, "revision_conflict", "no"), sel)).toBeUndefined();
    expect(selectionProblem(new ApiError(422, "something_else", "no"), sel)).toBeUndefined();
    expect(selectionProblem(new Error("x"), sel)).toBeUndefined();
  });
});

describe("picker filtering", () => {
  it("searches names, descriptions, servers and teams, and filters by kind", () => {
    expect(filterOptions(gatewayOptions, "docs team", "").map((o) => o.exposedName)).toEqual(["wiki__search"]);
    expect(filterOptions(gatewayOptions, "", "prompt").map((o) => o.exposedName)).toEqual(["service-status__incident_summary"]);
    expect(filterOptions(gatewayOptions, "", "", { [gatewayOptions[0]!.capabilityId]: "" })).toHaveLength(1);
  });
});

describe("gateway audit words", () => {
  it("name the gateway and API key actions, areas and targets", () => {
    expect(actionLabel("gateway.create")).toBe("Created gateway");
    expect(actionLabel("gateway.capabilities_set")).toBe("Changed gateway capabilities");
    expect(actionLabel("gateway.grant_add")).toBe("Granted gateway access");
    expect(actionLabel("gateway.grant_remove")).toBe("Removed gateway access");
    expect(actionLabel("api_key.create")).toBe("Created API key");
    expect(actionLabel("api_key.revoke")).toBe("Revoked API key");
    expect(areaOf("gateway.update")).toBe("Gateways");
    expect(areaOf("api_key.revoke")).toBe("API keys");
    expect(targetTypeLabel("gateway")).toBe("Gateway");
    expect(targetTypeLabel("api_key")).toBe("API key");
    // Personal keys aren't a team's: their area is only in the platform log.
    expect(areaOptions(false).map((o) => o.value)).not.toContain("api_key.");
    expect(areaOptions(true).map((o) => o.value)).toContain("api_key.");
    expect(areaOptions(false).map((o) => o.value)).toContain("gateway.");
  });
});

describe("call error classes", () => {
  // Every class internal/mcpgw records: refusals, unavailable reasons, invalid requests and the registry's upstream classes.
  const recorded = [
    "gateway_disabled", "no_access", "role", "unknown",
    "server_disabled", "not_published", "not_approved", "changed", "gone", "team_archived",
    "invalid_params", "invalid_cursor",
    "unavailable", "auth", "not_found", "rate_limited", "bad_request", "bad_response", "config", "timeout", "too_large", "not_allowed", "tls",
  ];

  it("have a plain label for every class the backend records", () => {
    for (const code of recorded) {
      expect(Object.hasOwn(callErrorLabels, code), code).toBe(true);
      expect(callErrorLabel(code), code).not.toContain("_");
      expect(callErrorLabel(code), code).not.toBe(code);
    }
    expect(callErrorLabel("unknown")).toBe("Not offered by the gateway");
    expect(callErrorLabel("no_access")).toBe("No access to the gateway");
    expect(callErrorLabel("role")).toBe("Needs a higher team role");
  });

  it("humanise a class they don't know, never showing it raw", () => {
    expect(callErrorLabel("quota_exceeded")).toBe("Quota exceeded");
    expect(callErrorLabel("upstream.reset-by_peer")).toBe("Upstream reset by peer");
    expect(callErrorLabel("toString")).toBe("Tostring");
    expect(callErrorLabel("__")).toBe("Other error");
  });
});

describe("grants", () => {
  it("count in words", () => {
    expect(grantCountLabel(0)).toBe("No grants");
    expect(grantCountLabel(1)).toBe("1 grant");
    expect(grantCountLabel(3)).toBe("3 grants");
  });

  it("summarise who a gateway is granted to, by kind", () => {
    const person = grant({ id: "u", subjectKind: "user", team: undefined, user: { id: user().id, email: user().email, displayName: user().displayName, status: "active" } });
    const group = grant({ id: "g", subjectKind: "group", team: undefined, group: "engineering" });
    expect(grantSummary([grant(), person, group])).toBe("teams: Platform Tools; people: Una User; SSO groups: engineering");
    expect(grantSummary([group])).toBe("SSO groups: engineering");
    expect(grantSummary([])).toBe("");
  });
});

describe("API key expiry", () => {
  const now = new Date(2026, 9, 16, 12, 0);
  it("counts whole days, never weeks", () => {
    expect(expiryText(new Date(2026, 9, 23, 12, 0).toISOString(), now)).toBe("in 7 days");
    expect(expiryText(new Date(2026, 9, 17, 9, 0).toISOString(), now)).toBe("tomorrow");
    expect(expiryText(new Date(2027, 0, 14, 12, 0).toISOString(), now)).toBe("in 90 days");
    expect(expiryText(new Date(2026, 9, 13, 12, 0).toISOString(), now)).toBe("3 days ago");
    expect(expiryText(new Date(2026, 9, 16, 17, 0).toISOString(), now)).toBe("in 5 hours");
    expect(expiryText(null, now)).toBe("");
  });
});
