/* Audit words: the initial platform role, humanized roles, and "Not set" in both the list and the record. */
import { auditChange, changedRows, changeSummary, valueText } from "../components/audit/changes";
import { actionLabel, areaOf, targetTypeLabel } from "../components/audit/labels";

describe("audit labels", () => {
  it("names the bootstrap grant neutrally and shows its role in words", () => {
    const e = { action: "platform.bootstrap_role", before: { platformRole: "none" }, after: { platformRole: "platform_admin" } };
    expect(actionLabel(e.action)).toBe("Granted initial platform role");
    expect(changeSummary(e)).toBe("Platform role None → Platform admin");
    expect(changedRows(auditChange(e))).toEqual([{ field: "Platform role", before: "None", after: "Platform admin" }]);
  });

  it("says Not set for a missing value in the list, as the record does", () => {
    const e = { action: "team.update", before: { description: "" }, after: { description: "Tools" } };
    expect(changeSummary(e)).toBe("Description Not set → Tools");
    expect(valueText(undefined)).toBe("Not set");
  });

  it("knows the registry's target types", () => {
    expect(targetTypeLabel("mcp_server")).toBe("MCP server");
    expect(targetTypeLabel("mcp_capability")).toBe("Capability");
  });

  it("names the server grants' actions (F-3) and why they ended", () => {
    expect(actionLabel("provider_connection.server_allow")).toBe("Allowed a server to use an account");
    expect(areaOf("provider_connection.server_allow")).toBe("Connected accounts");
    expect(actionLabel("mcp_server.provider_grants_reset", { metadata: { reason: "origin_changed" } })).toBe("Ended permission to use people's accounts after its URL moved to another host");
    expect(actionLabel("mcp_server.provider_grants_reset", { metadata: { reason: "server_deleted" } })).toBe("Ended permission to use people's accounts when it was deleted");
    expect(areaOf("mcp_server.provider_grants_reset")).toBe("MCP servers");
  });

  it("names the registry's actions and areas", () => {
    expect(actionLabel("mcp_server.publish_request")).toBe("Requested catalog review");
    expect(actionLabel("mcp_capability.approve")).toBe("Approved capability");
    expect(areaOf("mcp_server.refresh")).toBe("MCP servers");
    expect(areaOf("settings.publishing_update")).toBe("Platform settings");
    expect(actionLabel("settings.network_update")).toBe("Changed internal networks");
    expect(areaOf("settings.network_update")).toBe("Platform settings");
    const e = {
      action: "settings.network_update",
      before: { entries: [] },
      after: { entries: [{ kind: "cidr", value: "10.20.0.0/16", allowHttp: false }, { kind: "host", value: "*.corp.example.com", allowHttp: true, note: "Wiki" }] },
    };
    expect(changedRows(auditChange(e))).toEqual([{ field: "Allowed networks and hosts", before: [], after: ["10.20.0.0/16", "*.corp.example.com (http) · Wiki"] }]);
    expect(valueText(changedRows(auditChange(e))[0]?.after)).toBe("10.20.0.0/16, *.corp.example.com (http) · Wiki");
  });

  it("names the agent platform actions (decisions 65 and 66) and their changes", () => {
    expect(actionLabel("agent_platform.create")).toBe("Trusted an agent platform");
    expect(actionLabel("agent_platform.delete")).toBe("Stopped trusting an agent platform");
    expect(areaOf("agent_platform.update")).toBe("Agent platforms");
    expect(targetTypeLabel("agent_platform")).toBe("Agent platform");
    expect(actionLabel("service_account.relay_set")).toBe("Marked service account as an agent platform relay");
    expect(areaOf("service_account.relay_clear")).toBe("Service accounts");
    expect(actionLabel("mcp_capability.presence_set")).toBe("Changed whether a capability needs a present person");
    const e = { action: "mcp_capability.presence_set", before: { mode: "inherit", effective: true }, after: { mode: "not_required", effective: false } };
    expect(changedRows(auditChange(e))).toEqual([
      { field: "Present person", before: "Same as the server", after: "Doesn't need a present person" },
      { field: "Needs a present person", before: "Yes", after: "No" },
    ]);
    const s = { action: "mcp_server.update", before: { requiresPresentPerson: false }, after: { requiresPresentPerson: true } };
    expect(changedRows(auditChange(s))).toEqual([{ field: "Require a present person", before: "Off", after: "On" }]);
    const p = { action: "agent_platform.update", before: { enabled: true, audience: "a" }, after: { enabled: false, audience: "a" } };
    expect(changedRows(auditChange(p))).toEqual([{ field: "Enabled", before: "On", after: "Off" }]);
  });
});
