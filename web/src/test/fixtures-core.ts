/* Fixtures every page test needs: the instance, sign-in, a team with members and invites, audit entries, pages. */
import type { Schemas } from "../api/client";

type PlatformRole = Schemas["PlatformRole"];
type TeamRole = Schemas["TeamRole"];

export const instance: Schemas["InstanceInfo"] = { name: "Open MCP Portal", orgName: "", theme: "neutral", logoUrl: null, supportUrl: null };

export const authConfig = (extra: Partial<Schemas["AuthConfig"]> = {}): Schemas["AuthConfig"] => ({
  instance,
  oidcEnabled: false,
  devAuthEnabled: true,
  loginUrl: "/auth/login",
  teamRequestUrl: null,
  devAccounts: [
    { id: "admin", name: "Ada Admin", email: "admin@example.com", platformRole: "platform_admin" },
    { id: "auditor", name: "Avery Auditor", email: "auditor@example.com", platformRole: "platform_auditor" },
    { id: "alex", name: "Alex Owner", email: "alex@example.com", platformRole: "none" },
  ],
  ...extra,
});

export const team: Schemas["Team"] = {
  id: "11111111-1111-4111-8111-111111111111",
  slug: "platform-tools",
  name: "Platform Tools",
  description: "Internal MCP servers for developer tooling.",
  status: "active",
  revision: 3,
  createdAt: "2026-09-01T10:00:00Z",
  updatedAt: "2026-09-01T10:00:00Z",
  archivedAt: null,
};

export const myTeam = (role: TeamRole = "owner", extra: Partial<Schemas["MyTeam"]> = {}): Schemas["MyTeam"] => ({
  id: team.id,
  slug: team.slug,
  name: team.name,
  status: "active",
  role,
  ...extra,
});

export const user = (extra: Partial<Schemas["User"]> = {}): Schemas["User"] => ({
  id: "22222222-2222-4222-8222-222222222222",
  email: "una@example.com",
  displayName: "Una User",
  platformRole: "none",
  status: "active",
  revision: 1,
  createdAt: "2026-09-01T09:00:00Z",
  lastLoginAt: "2026-10-15T09:00:00Z",
  ...extra,
});

/** The signed-in user: a platform role and their teams (one team with `teamRole`, or none with null). */
export const meFor = (platformRole: PlatformRole = "none", teamRole: TeamRole | null = "owner"): Schemas["Me"] => ({
  user: user({ platformRole }),
  teams: teamRole ? [myTeam(teamRole)] : [],
  groups: ["everyone", "engineering"],
  csrfToken: "csrf-123",
  capabilities: { platformAdmin: platformRole === "platform_admin", platformAuditor: platformRole === "platform_auditor" },
});

export const member = (role: TeamRole, extra: Partial<Schemas["MemberUser"]> = {}, revision = 1): Schemas["Member"] => ({
  user: { id: user().id, email: user().email, displayName: user().displayName, status: "active", ...extra },
  role,
  revision,
  createdAt: "2026-09-02T10:00:00Z",
});

export const members: Schemas["Member"][] = [
  member("owner"),
  member("admin", { id: "33333333-3333-4333-8333-333333333333", email: "blair@example.com", displayName: "Blair Admin" }),
  member("editor", { id: "44444444-4444-4444-8444-444444444444", email: "casey@example.com", displayName: "Casey Editor" }),
  member("member", { id: "55555555-5555-4555-8555-555555555555", email: "drew@example.com", displayName: "Drew Member" }),
];

export const invite = (extra: Partial<Schemas["Invite"]> = {}): Schemas["Invite"] => ({
  id: "66666666-6666-4666-8666-666666666666",
  email: "new.person@example.com",
  role: "editor",
  invitedBy: user().id,
  createdAt: "2026-10-10T10:00:00Z",
  expiresAt: "2026-11-09T10:00:00Z",
  ...extra,
});

export const teamSummary = (extra: Partial<Schemas["TeamSummary"]> = {}): Schemas["TeamSummary"] => ({
  team,
  memberCount: 4,
  ownerCount: 1,
  ownerInvites: 0,
  ...extra,
});

export const auditEntry = (extra: Partial<Schemas["AuditEntry"]> = {}): Schemas["AuditEntry"] => ({
  id: 101,
  occurredAt: "2026-10-15T12:00:00Z",
  actorKind: "user",
  actorUserId: user().id,
  teamId: team.id,
  teamName: team.name,
  teamSlug: team.slug,
  action: "team.member_role_change",
  actor: { kind: "user", userId: user().id, displayName: "Una User", email: "una@example.com" },
  targetType: "user",
  targetId: "44444444-4444-4444-8444-444444444444",
  targetLabel: "Casey Editor",
  targetExists: true,
  before: { role: "member" },
  after: { role: "editor" },
  metadata: {},
  requestId: "req-1",
  via: { kind: "session" },
  clientIp: null,
  ...extra,
});

export const page = <T>(items: T[], nextCursor: string | null = null) => ({ items, nextCursor });
