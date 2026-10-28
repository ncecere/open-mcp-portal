/*
 * The app's vocabulary, in one place so the sidebar, page titles,
 * breadcrumbs and tables agree. Use these instead of typing the words:
 *
 *   import { terms } from "@/lib/terms";
 *   <PageHeader title={terms.teamSettings} />
 *
 * Rules:
 *   - Switchable objects (gateways, servers, keys) are Enabled / Disabled.
 *     Lifecycle states are Active / Archived / Suspended (teams, users).
 */

export const terms = {
  home: "Home",
  teamSettings: "Team settings",
  auditLog: "Audit log",
  adminOverview: "Overview",
  dangerZone: "Danger zone",
  readOnly: "Read-only",
  mcpServers: "MCP servers",
  catalog: "Catalog",
  publishing: "Publishing",
  internalNetworks: "Internal networks",
  gateways: "Gateways",
  myGateways: "My gateways",
  apiKeys: "API keys",
  connectedApps: "Connected apps",
  trustedClients: "Trusted clients",
  serviceAccounts: "Service accounts",
  calls: "Calls",
  authProviders: "Auth providers",
  myConnections: "My connections",
  usage: "Usage",
  limits: "Limits",
  retention: "Retention",
  payloadCapture: "Payload capture",
  limitsAndRetention: "Limits & retention",
  notifications: "Notifications",
  inbox: "Inbox",
  automationTokens: "Automation tokens",
} as const;

/** A switchable object's state. */
export const switchLabel = (enabled: boolean) => (enabled ? "Enabled" : "Disabled");

export type Lifecycle = "active" | "archived" | "suspended";

/** A lifecycle state's label. */
export const lifecycleLabels: Record<Lifecycle, string> = {
  active: "Active",
  archived: "Archived",
  suspended: "Suspended",
};

/** The read-only note on admin settings pages (auditors see them, only admins change them). */
export const adminOnly = "You can view these settings. Only platform admins can change them.";
