/*
 * The command palette's groups: pages (the workspace's, the account's and the
 * active team's), the team's places (Team settings' tabs), team actions,
 * teams and admin pages. Everything is local and instant: the palette reads
 * the same navigation lists as the sidebar (nav.tsx), so a new section shows
 * up here when it's added there.
 */
import { useNavigate } from "@tanstack/react-router";
import { BadgeCheck, Bell, Bot, Boxes, FileClock, Gauge, Inbox, KeyRound, KeySquare, Link2, Network, Plug, Plus, ServerCog, Settings, Terminal, User, UserPlus, Users } from "lucide-react";
import { useMemo } from "react";
import { requestIntent } from "../../lib/intents";
import { type TeamSettingsTab } from "../../lib/tabs";
import { terms } from "../../lib/terms";
import { type Me } from "../../session";
import { type CommandGroup } from "@/components/ui/command-palette/command-palette";
import { type ColorMode, useColorMode } from "@/components/ui/color-mode/color-mode";
import { roleLabels } from "../roles";
import { type ActiveTeam } from "./active-team";
import { useCapabilities } from "./location";
import { adminKeywords, adminNav, icon, teamAccess, teamNavFor, workspaceNav } from "./nav";
import { themeCommands } from "./theme";

/** The palette's accessible name; its combobox carries it too. */
export const PALETTE_LABEL = "Command palette";

type Navigate = ReturnType<typeof useNavigate>;
type Membership = Me["teams"][number];
type Item = CommandGroup["items"][number];

function pageGroup(navigate: Navigate, me: Me, slug: string | undefined, mine: Membership | undefined, mode: ColorMode): CommandGroup {
  const items: Item[] = [
    ...workspaceNav.map((n) => ({ id: "page:" + n.to, label: n.label, icon: n.icon, hint: "Page", keywords: n.keywords, onSelect: () => void navigate({ to: n.to }) })),
    {
      id: "profile",
      label: "Profile",
      icon: icon(User),
      hint: "Page",
      keywords: ["account", "me", "email", "name", "teams"],
      onSelect: () => void navigate({ to: "/settings/profile" }),
    },
    {
      id: "api-keys",
      label: terms.apiKeys,
      icon: icon(KeyRound),
      hint: "Page",
      keywords: ["account", "key", "keys", "token", "secret", "bearer", "revoke", "connect"],
      onSelect: () => void navigate({ to: "/settings/api-keys" }),
    },
    {
      id: "connected-apps",
      label: terms.connectedApps,
      icon: icon(Plug),
      hint: "Page",
      keywords: ["account", "oauth", "apps", "clients", "claude", "vs code", "cursor", "disconnect", "sign-in", "authorized"],
      onSelect: () => void navigate({ to: "/settings/connected-apps" }),
    },
    {
      id: "my-connections",
      label: terms.myConnections,
      icon: icon(Link2),
      hint: "Page",
      keywords: ["account", "connections", "connect", "github", "google", "oauth", "provider", "token", "disconnect", "reconnect", "authorize", "scopes"],
      onSelect: () => void navigate({ to: "/settings/connections" }),
    },
    {
      id: "sessions",
      label: "Sessions",
      icon: icon(User),
      hint: "Page",
      keywords: ["account", "browser", "devices", "sign out", "revoke", "lost laptop"],
      onSelect: () => void navigate({ to: "/settings/sessions" }),
    },
    {
      id: "inbox",
      label: terms.inbox,
      icon: icon(Inbox),
      hint: "Page",
      keywords: ["notifications", "unread", "alerts", "messages", "bell", "mark read"],
      onSelect: () => void navigate({ to: "/notifications" }),
    },
    {
      id: "notification-settings",
      label: terms.notifications,
      icon: icon(Bell),
      hint: "Page",
      keywords: ["account", "settings", "preferences", "email", "in-app", "events", "mute", "alerts"],
      onSelect: () => void navigate({ to: "/settings/notifications" }),
    },
    {
      id: "create-api-key",
      label: "Create API key",
      icon: <Plus aria-hidden />,
      hint: "Action",
      keywords: ["new key", "token", "secret", "connect", "claude", "cursor", "vs code"],
      onSelect: () => {
        void navigate({ to: "/settings/api-keys" });
        requestIntent("create-api-key");
      },
    },
    ...themeCommands(mode),
  ];
  if (slug) {
    for (const item of teamNavFor(me, slug)) {
      items.push({
        id: "team:" + item.to,
        label: item.label,
        icon: item.icon,
        hint: mine?.name ?? "Team",
        keywords: ["team", mine?.name ?? "", ...(item.keywords ?? [])],
        onSelect: () => void navigate({ to: item.to, params: { team: slug } }),
      });
    }
  }
  return { label: "Pages", items };
}

/** Team settings' tabs, with the words people use for them; each only where its tab shows. */
function teamPlacesGroup(navigate: Navigate, me: Me, team: { slug: string; name: string }, mine: Membership | undefined): CommandGroup {
  const a = teamAccess(me, mine);
  const hint = terms.teamSettings;
  const go = (tab: TeamSettingsTab) => () =>
    void navigate({ to: "/teams/$team/settings", params: { team: team.slug }, search: { tab: tab === "members" ? undefined : tab } });
  const items: (Item & { show: boolean })[] = [
    {
      id: "team-tab:members",
      label: "Members",
      icon: <Users aria-hidden />,
      keywords: ["member", "people", "invite", "invites", "role", "roles", "who", "access", "owner", "editor"],
      show: a.member || a.staff,
      hint,
      onSelect: go("members"),
    },
    {
      id: "team-tab:audit",
      label: terms.auditLog,
      icon: <FileClock aria-hidden />,
      keywords: ["audit", "history", "changes", "who changed", "log", "activity"],
      show: a.canEdit || (!a.member && a.staff),
      hint,
      onSelect: go("audit"),
    },
    {
      id: "team-tab:limits",
      label: terms.limitsAndRetention,
      icon: <Gauge aria-hidden />,
      keywords: ["limits", "rate limit", "requests per minute", "429", "retention", "kept", "deleted", "days"],
      show: a.member || a.staff,
      hint,
      onSelect: go("limits"),
    },
    {
      id: "team-tab:notifications",
      label: terms.notifications,
      icon: <Bell aria-hidden />,
      keywords: ["webhook", "webhooks", "slack", "destination", "alerts", "delivery log", "deliveries", "signing secret"],
      show: a.member || a.staff,
      hint,
      onSelect: go("notifications"),
    },
    {
      id: "team-tab:automation-tokens",
      label: terms.automationTokens,
      icon: <Terminal aria-hidden />,
      keywords: ["token", "tokens", "ci", "pipeline", "publisher", "omppub", "servers:write", "servers:read", "bearer", "script"],
      show: a.member || a.staff,
      hint,
      onSelect: go("automation-tokens"),
    },
    {
      id: "team-tab:general",
      label: "General",
      icon: <Settings aria-hidden />,
      keywords: ["name", "description", "address", "leave", "archive", "danger zone"],
      show: a.member || a.staff,
      hint,
      onSelect: go("general"),
    },
  ];
  return { label: team.name, items: items.filter((i) => i.show).map(({ show: _show, ...item }) => item) };
}

/** Actions in the current team, by what the user's role allows. */
function teamActionGroup(navigate: Navigate, slug: string, mine: Membership): CommandGroup {
  const actions: CommandGroup = { label: "Actions", items: [] };
  if (mine.status === "active" && mine.role !== "member") {
    actions.items.push({
      id: "add-server",
      label: "Add MCP server",
      icon: <ServerCog aria-hidden />,
      keywords: ["register", "new server", "mcp", "connect", "url"],
      // The list's add form is its URL (?form=new).
      onSelect: () => void navigate({ to: "/teams/$team/servers", params: { team: slug }, search: { form: "new" } }),
    });
  }
  if (mine.status === "active" && (mine.role === "owner" || mine.role === "admin")) {
    actions.items.push({
      id: "create-gateway",
      label: "Create gateway",
      icon: <Network aria-hidden />,
      keywords: ["new gateway", "gateway", "endpoint", "curate", "tools", "mcp"],
      // The list's create form is its URL (?form=new).
      onSelect: () => void navigate({ to: "/teams/$team/gateways", params: { team: slug }, search: { form: "new" } }),
    });
    actions.items.push({
      id: "create-service-account",
      label: "Create service account",
      icon: <Bot aria-hidden />,
      keywords: ["new service account", "bot", "automation", "ci", "headless", "agent", "script"],
      // The list's create form is its URL (?form=new).
      onSelect: () => void navigate({ to: "/teams/$team/service-accounts", params: { team: slug }, search: { form: "new" } }),
    });
    actions.items.push({
      id: "add-member",
      label: "Add member",
      icon: <UserPlus aria-hidden />,
      keywords: ["invite", "people", "team", "role"],
      onSelect: () => {
        void navigate({ to: "/teams/$team/settings", params: { team: slug } });
        requestIntent("add-member");
      },
    });
  }
  return actions;
}

function teamsGroup(navigate: Navigate, teams: Me["teams"]): CommandGroup {
  return {
    label: "Teams",
    items: teams.map((t) => ({
      id: "t:" + t.slug,
      label: t.name,
      icon: icon(Boxes),
      hint: roleLabels[t.role],
      keywords: [t.slug, "team"],
      onSelect: () => void navigate({ to: "/teams/$team", params: { team: t.slug } }),
    })),
  };
}

/** Admin pages, plus create actions for platform admins (not auditors). */
function adminGroup(navigate: Navigate, platformAdmin: boolean): CommandGroup {
  const items: Item[] = adminNav.map((n) => ({
    id: "admin:" + n.to,
    label: n.label,
    icon: n.icon,
    hint: "Admin",
    keywords: ["admin", ...(adminKeywords[n.to] ?? [])],
    onSelect: () => void navigate({ to: n.to }),
  }));
  items.push({
    id: "admin:pending-servers",
    label: "Servers waiting for review",
    icon: <BadgeCheck aria-hidden />,
    hint: "Admin",
    keywords: ["review", "approve", "reject", "pending", "publish", "catalog", "mcp"],
    onSelect: () => void navigate({ to: "/admin/servers", search: { publishState: "pending" } }),
  });
  if (platformAdmin) {
    items.push({
      id: "admin:create-gateway",
      label: "Create platform gateway",
      icon: <Network aria-hidden />,
      hint: "Admin",
      keywords: ["new gateway", "platform gateway", "grant", "share", "mcp"],
      onSelect: () => void navigate({ to: "/admin/gateways", search: { form: "new" } }),
    });
    items.push({
      id: "admin:add-auth-provider",
      label: "Add auth provider",
      icon: <KeySquare aria-hidden />,
      hint: "Admin",
      keywords: ["new provider", "oauth", "github", "google", "microsoft", "atlassian", "slack", "gitlab", "client id", "client secret"],
      // The list's add form is its URL (?form=new).
      onSelect: () => void navigate({ to: "/admin/auth-providers", search: { form: "new" } }),
    });
    items.push({
      id: "admin:create-team",
      label: "Create team",
      icon: <Plus aria-hidden />,
      hint: "Admin",
      keywords: ["new team", "create", "owner"],
      onSelect: () => {
        void navigate({ to: "/admin/teams" });
        requestIntent("create-team");
      },
    });
  }
  return { label: "Admin", items };
}

/** The palette's groups. */
export function useCommands(me: Me, active: ActiveTeam): { groups: CommandGroup[] } {
  const navigate = useNavigate();
  const { canAdmin } = useCapabilities(me);
  const slug = active.slug;
  const mine = active.membership;
  const teamName = active.name ?? "Team";
  const { mode } = useColorMode();
  const groups = useMemo(() => {
    const groups: CommandGroup[] = [pageGroup(navigate, me, slug, mine, mode)];
    if (slug) groups.push(teamPlacesGroup(navigate, me, { slug, name: teamName }, mine));
    if (slug && mine) groups.push(teamActionGroup(navigate, slug, mine));
    groups.push(teamsGroup(navigate, me.teams));
    if (canAdmin) groups.push(adminGroup(navigate, me.capabilities.platformAdmin));
    return groups.filter((g) => g.items.length > 0);
    // `me` is only read for its teams and capabilities, which are dependencies.
  }, [navigate, slug, mine, teamName, me.teams, me.capabilities, canAdmin, mode]); // eslint-disable-line react-hooks/exhaustive-deps
  return { groups };
}
