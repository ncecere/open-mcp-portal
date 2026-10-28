/*
 * The sidebar's navigation, as data: the workspace's own pages, the active
 * team's pages and the admin portal's groups. The sidebar, the breadcrumbs
 * and the ⌘K palette all read these lists, so a page added here shows up in
 * all three.
 *
 * Adding a section:
 *   1. add its route in router.tsx (the `to` paths below are typed against
 *      the route tree, so an item can't point at a page that doesn't exist);
 *   2. add an item to `workspaceNav` (pages for everyone: Catalog, My
 *      gateways), `teamNav` (the team's own pages: MCP servers, Gateways,
 *      with an `access` rule) or a group of `adminSections` (catalog
 *      approvals, platform gateways, calls);
 *   3. add its breadcrumb in breadcrumbs.tsx.
 * Only list pages that exist: no placeholders or "coming soon" links.
 */
import { Activity, BadgeCheck, BarChart3, Bell, Bot, Eraser, FileClock, Gauge, Home, KeySquare, LayoutDashboard, Library, Network, Server, Settings, ShieldCheck, Terminal, Timer, Users, UsersRound, Waypoints } from "lucide-react";
import { type ReactNode } from "react";
import { terms } from "../../lib/terms";
import { type Me } from "../../session";

export const icon = (C: typeof Home) => <C aria-hidden />;

/* ---------------- workspace ---------------- */

export type WorkspacePath = "/" | "/catalog" | "/gateways";

export type WorkspaceNavItem = { to: WorkspacePath; label: string; icon: ReactNode; exact?: boolean; keywords?: string[] };

/** Pages for everyone signed in, at the top of the workspace sidebar. */
export const workspaceNav: WorkspaceNavItem[] = [
  { to: "/", label: terms.home, icon: icon(Home), exact: true, keywords: ["start", "welcome", "teams"] },
  { to: "/catalog", label: terms.catalog, icon: icon(Library), keywords: ["mcp", "servers", "published", "tools", "resources", "prompts", "browse"] },
  { to: "/gateways", label: terms.myGateways, icon: icon(Network), keywords: ["gateway", "connect", "mcp", "url", "claude", "vs code", "cursor", "tools", "access"] },
];

/* ---------------- team ---------------- */

type Membership = Me["teams"][number];

/** Who may see what in a team (the same rules as the pages and the server). */
export type TeamAccess = {
  /** On the team (any role). */
  member: boolean;
  /** An active team's editors, admins and owners. */
  canEdit: boolean;
  /** An active team's admins and owners. */
  isManager: boolean;
  /** A platform admin or auditor (may view any team's overview, settings, MCP servers, gateways and service accounts). */
  staff: boolean;
  /** Owners, admins and editors, archived or not (the team's usage). */
  canReadUsage: boolean;
};

export function teamAccess(me: Me, mine: Membership | undefined): TeamAccess {
  const active = mine?.status === "active";
  const role = mine?.role;
  const isManager = active && (role === "owner" || role === "admin");
  return {
    member: Boolean(mine),
    canEdit: isManager || (active && role === "editor"),
    isManager,
    staff: me.capabilities.platformAdmin || me.capabilities.platformAuditor,
    canReadUsage: role === "owner" || role === "admin" || role === "editor",
  };
}

export type TeamPath = "/teams/$team" | "/teams/$team/servers" | "/teams/$team/gateways" | "/teams/$team/service-accounts" | "/teams/$team/usage" | "/teams/$team/settings";

export type TeamNavItem = {
  to: TeamPath;
  label: string;
  icon: ReactNode;
  exact?: boolean;
  /** Who gets the item. Platform staff who aren't members get the overview, the MCP servers, the gateways, the service accounts and settings. */
  access: (a: TeamAccess) => boolean;
  /** Extra command-palette search words. */
  keywords?: string[];
};

const teamNav: TeamNavItem[] = [
  { to: "/teams/$team", label: "Overview", icon: icon(LayoutDashboard), exact: true, access: (a) => a.member || a.staff, keywords: ["team", "dashboard"] },
  // Platform staff read any team's servers and gateways (the API allows it).
  {
    to: "/teams/$team/servers",
    label: terms.mcpServers,
    icon: icon(Server),
    access: (a) => a.member || a.staff,
    keywords: ["mcp", "server", "servers", "register", "tools", "capabilities", "publish", "health"],
  },
  {
    to: "/teams/$team/gateways",
    label: terms.gateways,
    icon: icon(Network),
    access: (a) => a.member || a.staff,
    keywords: ["gateway", "gateways", "endpoint", "url", "curate", "tools", "prompts", "connect", "calls", "activity"],
  },
  {
    to: "/teams/$team/service-accounts",
    label: terms.serviceAccounts,
    icon: icon(Bot),
    access: (a) => a.member || a.staff,
    keywords: ["service account", "bot", "robot", "automation", "ci", "headless", "agent", "script", "key", "keys", "rotate", "omp_sa"],
  },
  // Owners, admins and editors (as the API allows; an archived team's editors still read it), and platform staff.
  {
    to: "/teams/$team/usage",
    label: terms.usage,
    icon: icon(BarChart3),
    access: (a) => a.canReadUsage || a.staff,
    keywords: ["usage", "calls", "analytics", "dashboard", "latency", "errors", "p95", "traffic", "statistics"],
  },
  {
    to: "/teams/$team/settings",
    label: terms.teamSettings,
    icon: icon(Settings),
    access: (a) => a.member || a.staff,
    keywords: ["members", "invites", "audit", "general", "leave", "limits", "rate limit", "retention", "notifications", "webhooks", "automation tokens"],
  },
];

/** The team pages the user can open in the team at `slug`. */
export function teamNavFor(me: Me, slug: string): TeamNavItem[] {
  const a = teamAccess(
    me,
    me.teams.find((t) => t.slug === slug),
  );
  return teamNav.filter((item) => item.access(a));
}

/* ---------------- admin ---------------- */

export type AdminPath =
  | "/admin"
  | "/admin/users"
  | "/admin/teams"
  | "/admin/servers"
  | "/admin/publishing"
  | "/admin/networks"
  | "/admin/gateways"
  | "/admin/trusted-clients"
  | "/admin/auth-providers"
  | "/admin/automation-tokens"
  | "/admin/audit"
  | "/admin/calls"
  | "/admin/usage"
  | "/admin/limits"
  | "/admin/retention"
  | "/admin/capture"
  | "/admin/notifications";

export type AdminNavItem = { to: AdminPath; label: string; icon: ReactNode; exact?: boolean };

/**
 * Admin sidebar groups. The first has no label: Overview, the page the admin portal opens on. Later phases add
 * groups here (Settings), each with the pages it holds.
 * `defaultOpen`: shown open until the person closes it (groups added since the first release, so
 * nobody misses them; see admin-groups.ts).
 */
export const adminSections: { label?: string; defaultOpen?: boolean; items: AdminNavItem[] }[] = [
  { items: [{ to: "/admin", label: terms.adminOverview, icon: icon(LayoutDashboard), exact: true }] },
  {
    label: "People",
    items: [
      { to: "/admin/users", label: "Users", icon: icon(Users) },
      { to: "/admin/teams", label: "Teams", icon: icon(UsersRound) },
    ],
  },
  {
    label: "Catalog",
    items: [
      { to: "/admin/servers", label: terms.mcpServers, icon: icon(Server) },
      { to: "/admin/publishing", label: terms.publishing, icon: icon(BadgeCheck) },
      { to: "/admin/networks", label: terms.internalNetworks, icon: icon(Waypoints) },
    ],
  },
  {
    label: "Access",
    defaultOpen: true,
    items: [
      { to: "/admin/gateways", label: terms.gateways, icon: icon(Network) },
      { to: "/admin/trusted-clients", label: terms.trustedClients, icon: icon(ShieldCheck) },
      { to: "/admin/auth-providers", label: terms.authProviders, icon: icon(KeySquare) },
      { to: "/admin/automation-tokens", label: terms.automationTokens, icon: icon(Terminal) },
    ],
  },
  {
    label: "Records",
    defaultOpen: true,
    items: [
      { to: "/admin/audit", label: terms.auditLog, icon: icon(FileClock) },
      { to: "/admin/calls", label: terms.calls, icon: icon(Activity) },
      { to: "/admin/usage", label: terms.usage, icon: icon(BarChart3) },
    ],
  },
  {
    label: "Operations",
    defaultOpen: true,
    items: [
      { to: "/admin/limits", label: terms.limits, icon: icon(Gauge) },
      { to: "/admin/retention", label: terms.retention, icon: icon(Timer) },
      { to: "/admin/capture", label: terms.payloadCapture, icon: icon(Eraser) },
      { to: "/admin/notifications", label: terms.notifications, icon: icon(Bell) },
    ],
  },
];

export const adminNav = adminSections.flatMap((section) => section.items);

/** The label of the admin group holding the page at `pathname`. */
export function activeAdminGroup(pathname: string): string | undefined {
  const inside = (to: string, exact?: boolean) => pathname === to || (!exact && pathname.startsWith(to + "/"));
  return adminSections.find((s) => s.items.some((i) => inside(i.to, i.exact)))?.label;
}

/** Extra command-palette search words for admin pages. */
export const adminKeywords: Partial<Record<AdminPath, string[]>> = {
  "/admin": ["overview", "attention", "needs attention", "dashboard", "home", "health", "status", "errors", "failing", "summary"],
  "/admin/automation-tokens": ["automation", "token", "tokens", "ci", "pipeline", "script", "bearer", "ompadm", "omppub", "platform:read", "platform:write", "terraform", "api"],
  "/admin/notifications": ["notifications", "email", "smtp", "webhook", "webhooks", "slack", "alerts", "destinations", "test email", "deliveries"],
  "/admin/users": ["people", "person", "suspend", "reactivate", "platform role", "platform admin", "auditor"],
  "/admin/teams": ["team", "create team", "archive", "owner", "assign owner"],
  "/admin/servers": ["mcp", "servers", "review", "approve", "reject", "pending", "catalog", "capabilities", "changes"],
  "/admin/publishing": ["policy", "approval required", "self publish", "default", "catalog"],
  "/admin/networks": ["internal", "network", "cidr", "allowlist", "private address", "host", "http", "ssrf", "egress"],
  "/admin/gateways": ["gateway", "platform gateway", "grant", "grants", "access", "sso group", "team gateway", "disable"],
  "/admin/trusted-clients": ["oauth", "trusted", "client", "clients", "consent", "skip consent", "allowlist", "claude", "vs code", "metadata document", "cimd"],
  "/admin/auth-providers": ["oauth", "provider", "providers", "github", "google", "microsoft", "atlassian", "slack", "gitlab", "delegated", "token", "client secret", "redirect uri", "connections", "scopes"],
  "/admin/audit": ["audit log", "history", "changes", "who changed", "sign-ins", "export", "csv"],
  "/admin/calls": ["calls", "call log", "tool calls", "activity", "denied", "errors", "latency", "rate limited", "contents", "payload"],
  "/admin/usage": ["usage", "analytics", "dashboard", "calls per day", "latency", "p50", "p95", "error rate", "traffic", "bytes"],
  "/admin/limits": ["rate limit", "rate limits", "429", "throttle", "quota", "requests per minute", "ceiling", "default"],
  "/admin/retention": ["retention", "delete", "purge", "keep", "days", "audit log", "call records", "gdpr"],
  "/admin/capture": ["payload", "capture", "record", "redaction", "redact", "secrets", "pattern", "regex", "arguments", "results", "privacy"],
};
