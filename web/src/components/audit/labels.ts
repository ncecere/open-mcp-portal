/* Human-readable audit actions, action groups (areas), actors and target types. */
import type { Schemas } from "../../api/client";
import type { FacetOption } from "@/components/ui/filter-bar/filter-bar";

type AuditEntry = Schemas["AuditEntry"];

/** Where a log is shown. On a team's log, `member` is false for platform staff. */
export type AuditScope = { kind: "team"; team: string; member?: boolean } | { kind: "platform" };

/** The query key prefix of a log's queries (invalidated together). */
export const auditKey = (scope: AuditScope) => (scope.kind === "team" ? ["team", scope.team, "audit"] : ["admin", "audit"]);

const actionLabels: Record<string, string> = {
  "auth.login": "Signed in",
  "auth.logout": "Signed out",
  "auth.login_denied": "Sign-in denied",
  "platform.bootstrap_role": "Granted initial platform role",
  "platform.user_update": "Changed user",
  "platform.user_role_change": "Changed platform role",
  "platform.user_suspend": "Suspended user",
  "platform.user_reactivate": "Reactivated user",
  "team.create": "Created team",
  "team.update": "Changed team",
  "team.archive": "Archived team",
  "team.unarchive": "Unarchived team",
  "team.member_add": "Added member",
  "team.member_remove": "Removed member",
  "team.member_leave": "Left team",
  "team.member_role_change": "Changed member role",
  "team.owner_assign": "Assigned owner",
  "team.invite_create": "Invited member",
  "team.invite_revoke": "Revoked invite",
  "team.invite_accept": "Accepted invite",
  "team.publishing_override": "Changed team publishing policy",
  "mcp_server.create": "Added MCP server",
  "mcp_server.update": "Changed MCP server",
  "mcp_server.delete": "Deleted MCP server",
  "mcp_server.refresh": "Read MCP server capabilities",
  "mcp_server.publish_request": "Requested catalog review",
  "mcp_server.publish": "Published MCP server",
  "mcp_server.reject": "Rejected MCP server",
  "mcp_server.unpublish": "Unpublished MCP server",
  "mcp_server.auth_update": "Changed MCP server sign-in",
  "mcp_capability.approve": "Approved capability",
  "mcp_capability.requirement_set": "Changed capability's account requirement",
  "mcp_capability.presence_set": "Changed whether a capability needs a present person",
  "settings.publishing_update": "Changed default publishing policy",
  "settings.network_update": "Changed internal networks",
  "gateway.create": "Created gateway",
  "gateway.update": "Changed gateway",
  "gateway.delete": "Deleted gateway",
  "gateway.capabilities_set": "Changed gateway capabilities",
  "gateway.grant_add": "Granted gateway access",
  "gateway.grant_remove": "Removed gateway access",
  "api_key.create": "Created API key",
  "api_key.revoke": "Revoked API key",
  "oauth.client_register": "Registered OAuth client",
  "oauth.consent": "Allowed connected app",
  "oauth.grant_confirmed": "Confirmed connected app",
  "oauth.token_issue": "Issued tokens to an app",
  "oauth.revoke": "Disconnected app",
  "settings.oauth_clients_update": "Changed trusted clients",
  "service_account.create": "Created service account",
  "service_account.update": "Changed service account",
  "service_account.delete": "Deleted service account",
  "service_account.relay_set": "Marked service account as an agent platform relay",
  "service_account.relay_clear": "Removed a service account's relay mark",
  "service_account_key.create": "Created service account key",
  "service_account_key.revoke": "Revoked service account key",
  "auth_provider.create": "Added auth provider",
  "auth_provider.update": "Changed auth provider",
  "auth_provider.delete": "Deleted auth provider",
  "auth_provider.access_update": "Changed who may use an auth provider",
  "provider_connection.create": "Connected account",
  "provider_connection.refresh_failed": "Account needs reconnecting",
  "provider_connection.revoke": "Disconnected account",
  "provider_connection.server_allow": "Allowed a server to use an account",
  "mcp_server.provider_grants_reset": "Ended permission to use people's accounts",
  // Agent platforms (decisions 65 and 66, docs/agent-platforms.md).
  "agent_platform.create": "Trusted an agent platform",
  "agent_platform.update": "Changed a trusted agent platform",
  "agent_platform.delete": "Stopped trusting an agent platform",
  // Operations (docs/phase6-operations.md).
  "settings.limits_update": "Changed rate limits",
  "team.limits_update": "Changed team rate limits",
  "settings.capture_update": "Changed redaction patterns",
  "settings.retention_update": "Changed retention periods",
  "team.retention_update": "Changed team retention",
  "mcp_call.payload_view": "Viewed call contents",
  "retention.purge": "Deleted old records",
  "api_key.pepper_rehash": "Re-secured API key after key rotation",
  "service_account_key.pepper_rehash": "Re-secured service account key after key rotation",
  "platform.secrets_reencrypt": "Re-encrypted stored secrets",
  "platform.key_rotation": "Rotated encryption keys",
  // Notifications (docs/notifications.md) and automation tokens (docs/automation-tokens.md).
  "notification_destination.create": "Added webhook destination",
  "notification_destination.update": "Changed webhook destination",
  "notification_destination.delete": "Deleted webhook destination",
  "notification_destination.test": "Sent a test to a webhook destination",
  "notification_destination.rotate_secret": "Rotated webhook signing secret",
  "notification_destination.disable": "Webhook destination stopped after repeated failures",
  "settings.notifications_test_email": "Sent a test email",
  "automation_token.create": "Created automation token",
  "automation_token.revoke": "Revoked automation token",
  "automation_token.pepper_rehash": "Re-secured automation token after key rotation",
};

/** Whose view of a call's contents it was (mcp_call.payload_view, metadata.via). */
export const payloadViewVia: Record<string, string> = { team: "on the team's page", admin: "in Admin" };

/** Why an account was disconnected (provider_connection.revoke, metadata.reason). */
export const connectionRevokeReasons: Record<string, string> = {
  user: "by its person",
  admin: "by a platform admin",
  provider_deleted: "when its provider was deleted",
  server_auth_changed: "when its MCP server's sign-in changed",
  server_deleted: "when its MCP server was deleted",
};

/** Why people's permission for a server to use their accounts ended (mcp_server.provider_grants_reset, metadata.reason). */
export const grantsResetReasons: Record<string, string> = {
  origin_changed: "after its URL moved to another host",
  provider_changed: "after the account it requires changed",
  server_deleted: "when it was deleted",
};

/** Why a published server went back to review (mcp_server.publish_request, metadata.reason). */
export const publishRequestReasons: Record<string, string> = {
  url_changed: "after its URL changed",
  requirement_changed: "after what it receives changed",
  upstream_auth_changed: "after its sign-in changed",
};

/** Why a connected app's sign-in ended (oauth.revoke, metadata.reason). */
export const oauthRevokeReasons: Record<string, string> = {
  user: "by its person",
  admin: "by a platform admin",
  client: "by the app",
  refresh_reuse: "after a refresh token was reused",
  expired_absolute: "after its sign-in expired",
};

/** "Added member" for team.member_add; unknown actions are spelled out ("foo.bar_baz" → "Foo: bar baz"). */
export function actionLabel(action: string, entry?: Partial<Pick<AuditEntry, "after" | "metadata">>) {
  const known = actionLabels[action];
  // A disconnection says why, when the reason is one we know ("Disconnected app after the person was suspended").
  const withReason = ["oauth.revoke", "provider_connection.revoke", "mcp_server.publish_request", "mcp_server.provider_grants_reset"];
  const reason = withReason.includes(action) ? entry?.metadata?.reason : undefined;
  const reasons =
    action === "oauth.revoke"
      ? oauthRevokeReasons
      : action === "mcp_server.publish_request"
        ? publishRequestReasons
        : action === "mcp_server.provider_grants_reset"
          ? grantsResetReasons
          : connectionRevokeReasons;
  if (known && typeof reason === "string" && reasons[reason]) return `${known} ${reasons[reason]}`;
  const via = action === "mcp_call.payload_view" ? entry?.metadata?.via : undefined;
  if (known && typeof via === "string" && payloadViewVia[via]) return `${known} ${payloadViewVia[via]}`;
  if (known) return known;
  const [group = "", rest = ""] = action.split(".");
  const words = rest.replace(/_/g, " ");
  return `${group.charAt(0).toUpperCase()}${group.slice(1)}${words ? `: ${words}` : ""}`;
}

/**
 * Action groups for the filter; `platform` groups are only offered in the platform log. Later phases add theirs.
 */
export const actionGroups: { prefix: string; label: string; platform?: boolean }[] = [
  { prefix: "team.", label: "Team and members" },
  { prefix: "mcp_server.", label: "MCP servers" },
  { prefix: "mcp_capability.", label: "Capability approvals" },
  { prefix: "gateway.", label: "Gateways" },
  { prefix: "service_account.", label: "Service accounts" },
  { prefix: "service_account_key.", label: "Service account keys" },
  { prefix: "mcp_call.", label: "Call contents" },
  { prefix: "notification_destination.", label: "Webhook destinations" },
  { prefix: "automation_token.", label: "Automation tokens" },
  { prefix: "api_key.", label: "API keys", platform: true },
  { prefix: "oauth.", label: "Connected apps", platform: true },
  { prefix: "auth_provider.", label: "Auth providers", platform: true },
  { prefix: "agent_platform.", label: "Agent platforms", platform: true },
  { prefix: "provider_connection.", label: "Connected accounts", platform: true },
  { prefix: "settings.", label: "Platform settings", platform: true },
  { prefix: "retention.", label: "Retention", platform: true },
  { prefix: "platform.", label: "Platform and users", platform: true },
  { prefix: "auth.", label: "Sign-in", platform: true },
];

/** The area an action belongs to, by its code's group. */
export function areaOf(action: string): string | undefined {
  return actionGroups.find((g) => action.startsWith(g.prefix))?.label;
}

/**
 * The audit log's Area filter: every area, then every known action under its area, so typing "invite" finds "Invited
 * member". An area's value is its prefix ("team."), an action's its code; the API takes both.
 */
export function areaOptions(platform: boolean): FacetOption[] {
  const areas = actionGroups.filter((g) => platform || !g.platform);
  const shown = new Set(areas.map((g) => g.label));
  const actions = Object.entries(actionLabels)
    .map(([value, label]) => ({ value, label, group: areaOf(value) }))
    .filter((o): o is FacetOption & { group: string } => Boolean(o.group && shown.has(o.group)))
    .sort((a, b) => a.group.localeCompare(b.group) || a.label.localeCompare(b.label));
  return [...areas.map((g) => ({ value: g.prefix, label: `${g.label} (all)`, group: "Areas" })), ...actions];
}

/** The Person filter's entry for changes the system made (the API's actorKind=system). */
export const systemPerson = "system";
export const systemPersonOption: FacetOption = { value: systemPerson, label: "System" };

/** The Person filter's entry for what automation tokens did (the API's actorKind=automation_token). */
export const tokenPerson = "automation_token";
export const tokenPersonOption: FacetOption = { value: tokenPerson, label: "Automation tokens" };

/** The Person filter's value as API filters: a person's ID, the system or automation tokens as the actor. */
export function personFilter(value: string | undefined): { actorUserId?: string; actorKind?: "system" | "automation_token" } {
  if (!value) return {};
  if (value === tokenPerson) return { actorKind: "automation_token" };
  return value === systemPerson ? { actorKind: "system" } : { actorUserId: value };
}

/** The kind of an automation token that acted, as a badge's words. */
export const tokenKindLabels = { platform_admin: "Platform admin token", team_publisher: "Team publisher token" } as const;

/** "Team publisher token" for an automation token's actor; undefined for other actors. */
export function tokenKindLabel(actor: AuditEntry["actor"]): string | undefined {
  return actor.kind === "automation_token" ? (actor.automationTokenKind ? tokenKindLabels[actor.automationTokenKind] : "Automation token") : undefined;
}

/** Who did it: a person's name, the token's name (as recorded when it acted), or "System". */
export function actorName(actor: AuditEntry["actor"], _entry?: Pick<AuditEntry, "metadata" | "teamName">) {
  if (actor.kind === "system") return "System";
  if (actor.kind === "automation_token") return actor.automationTokenName || "Automation token";
  return actor.displayName || actor.email || (actor.userId ? "Unknown user" : "Unknown");
}

/** How the person acted, in words ("Signed in", "API key: Nightly sync", "Connected app: Claude Code"); "" for the system. */
export function viaLabel(via: AuditEntry["via"]) {
  if (!via) return "";
  const named = (what: string) => (via.name ? `${what}: ${via.name}` : what);
  return via.kind === "api_key" ? named("API key") : via.kind === "oauth" ? named("Connected app") : "Signed in";
}

type ActedFields = Pick<AuditEntry, "actor" | "metadata"> & Partial<Pick<AuditEntry, "via">>;

/** How the person acted, when it wasn't in the app: "API key: Nightly sync" or "Connected app: Claude Code". */
export function actedVia(e: ActedFields): string | undefined {
  if (e.via) return e.via.kind === "api_key" || e.via.kind === "oauth" ? viaLabel(e.via) : undefined;
  if (e.actor.kind === "api_key") return `API key${e.actor.apiKeyName ? `: ${e.actor.apiKeyName}` : ""}`;
  return undefined;
}

/** The same for the record page's How row: a person without a key or an app acted in the app. */
export function actedHow(e: ActedFields): string | undefined {
  if (e.actor.kind === "automation_token") return `Automation token (${tokenKindLabel(e.actor)?.toLowerCase().replace(/ token$/, "")})`;
  if (e.via) return viaLabel(e.via) || undefined;
  return actedVia(e) ?? (e.actor.kind === "user" ? "Signed in" : undefined);
}

export const targetTypeLabels: Record<string, string> = {
  team: "Team",
  team_invite: "Invite",
  user: "User",
  mcp_server: "MCP server",
  mcp_capability: "Capability",
  gateway: "Gateway",
  gateway_grant: "Gateway grant",
  api_key: "API key",
  platform_settings: "Platform settings",
  service_account: "Service account",
  service_account_key: "Service account key",
  oauth_client: "OAuth client",
  oauth_grant: "Connected app",
  auth_provider: "Auth provider",
  provider_connection: "Connected account",
  mcp_call: "Call",
  notification_destination: "Webhook destination",
  automation_token: "Automation token",
  agent_platform: "Agent platform",
};

/** An entry's action and target in one line for a short list ("Added member: Una User"). */
export function entryTitle(e: Pick<AuditEntry, "action" | "after" | "targetLabel">) {
  const action = actionLabel(e.action, e);
  return e.targetLabel && !action.toLowerCase().includes(e.targetLabel.toLowerCase()) ? `${action}: ${e.targetLabel}` : action;
}

export const targetTypeLabel = (type: string) => targetTypeLabels[type] ?? type.replace(/_/g, " ");
