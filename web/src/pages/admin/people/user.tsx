/*
 * Admin → Users › one person: one page with sections (Profile and access,
 * Teams, Connected apps, Connections, Activity). Suspend is a menu action; a
 * platform-role change is confirmed with what the role can do. Platform admins
 * disconnect a person's apps and accounts; auditors read them.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { Boxes, UserCheck, UserX } from "lucide-react";
import { useRef, useState } from "react";
import { api, ifMatch, unwrap, type Schemas } from "@/api/client";
import { adminUserQuery } from "@/api/queries";
import { ConnectedApps } from "@/components/oauth/connected-apps";
import { ProviderConnections } from "@/components/providers/connections";
import { BrowserSessions } from "@/components/sessions/browser-sessions";
import { ServerSecrets } from "@/components/secrets/server-secrets";
import { ActionMenu } from "@/components/templates/action-menu";
import { Time } from "@/components/ui/time/time";
import { isNotFound, NotFoundState } from "@/components/not-found";
import { PageSkeleton } from "@/components/page-skeleton";
import { roleLabels } from "@/components/roles";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Card } from "@/components/ui/card/card";
import { AlertDialog } from "@/components/ui/dialog/dialog";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import { useCurrentUser } from "@/session";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { platformRoleLabels, UserStatusBadge } from "./common";
import p from "./people.module.css";
import { UserActivity } from "./user-activity";

type UserDetail = Schemas["UserDetail"];
type Update = ReturnType<typeof useUserUpdate>;

/** PATCH the user (status or platform role) against the loaded revision. */
function useUserUpdate(userId: string, revision: number | undefined, onDone: () => void) {
  const me = useCurrentUser();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Schemas["UserUpdate"]) => unwrap(await api.PATCH("/v1/admin/users/{userId}", { params: { path: { userId }, header: ifMatch(revision!) }, body })),
    onSuccess: (_, body) => {
      onDone();
      qc.invalidateQueries({ queryKey: ["admin"] });
      if (userId === me.user.id) qc.invalidateQueries({ queryKey: ["me"] });
      if (body.status === "suspended") toast.success("User suspended");
      else if (body.status === "active") toast.success("User reactivated");
      else toast.success("Platform role updated");
    },
  });
}

export function AdminUserPage() {
  const { userId } = useParams({ from: "/app/admin/users/$userId" });
  const isAdmin = useIsPlatformAdmin();
  const detail = useQuery(adminUserQuery(userId));
  const me = useCurrentUser();
  const [confirmSuspend, setConfirmSuspend] = useState(false);
  const update = useUserUpdate(userId, detail.data?.user.revision, () => setConfirmSuspend(false));
  // An admin can't suspend themselves (they could be the last one); say why instead of failing.
  const self = userId === me.user.id;

  if (detail.isLoading) return <PageSkeleton />;
  if (isNotFound(detail.error)) return <NotFoundState what="user" />;
  if (detail.error || !detail.data) return <ErrorAlert error={detail.error} title="Couldn't load this user" />;
  const { user, teams } = detail.data;
  const suspended = user.status === "suspended";
  const name = user.displayName || user.email;

  return (
    <Stack gap={6} className={s.page}>
      <PageHeader
        title={name}
        description={self && isAdmin && !suspended ? `${user.email} · This is you: another platform admin can suspend your account.` : user.email}
        meta={
          <>
            <UserStatusBadge status={user.status} />
            {user.platformRole !== "none" && <Badge tone="info">{platformRoleLabels[user.platformRole]}</Badge>}
          </>
        }
        actions={
          isAdmin && (
            <ActionMenu
              label="More actions"
              size="md"
              actions={[
                { label: "Reactivate", icon: <UserCheck aria-hidden />, hidden: !suspended, onSelect: () => update.mutate({ status: "active" }) },
                {
                  label: "Suspend…",
                  icon: <UserX aria-hidden />,
                  danger: true,
                  hidden: suspended,
                  disabled: self,
                  disabledReason: self ? "You can't suspend yourself. Ask another platform admin." : undefined,
                  onSelect: () => setConfirmSuspend(true),
                },
              ]}
            />
          )
        }
      />
      <div className={p.sections}>
        <UserAccessCard user={user} isAdmin={isAdmin} update={update} self={self} otherDialogOpen={confirmSuspend} />
        <UserTeamsCard teams={teams} />
        {isAdmin && <Card title="Sessions" description="Browser sign-ins. Revoking them does not disconnect apps or other credentials.">
          <BrowserSessions owner={{ self: false, userId: user.id, name }} />
        </Card>}
        <Card
          title="Connected apps"
          description={`MCP clients ${self ? "you" : name} allowed with OAuth sign-in, per gateway.${isAdmin ? " Disconnecting one stops it at once." : ""}`}
        >
          <ConnectedApps owner={{ self: false, userId: user.id, name }} canDisconnect={isAdmin} />
        </Card>
        <Card
          title="Connections"
          description={`Accounts ${self ? "you" : name} connected with auth providers so tools can act as ${self ? "you" : "them"}. Tokens are never shown.${
            isAdmin ? " Disconnecting one erases its tokens at once." : ""
          }`}
        >
          <ProviderConnections owner={{ self: false, userId: user.id, name }} canDisconnect={isAdmin} />
        </Card>
        <Card
          title="Keys for servers"
          description={`Keys ${self ? "you" : name} entered for servers that ask each person for their own. The keys are never shown.${isAdmin ? " Removing one deletes it at once." : ""}`}
        >
          <ServerSecrets owner={{ self: false, userId: user.id, name }} canRevoke={isAdmin} />
        </Card>
        <Card title="Activity" description={`Changes ${name} made, newest first, from the audit log.`}>
          <UserActivity user={user} />
        </Card>
      </div>
      <AlertDialog
        open={confirmSuspend}
        onOpenChange={setConfirmSuspend}
        title={`Suspend ${name}?`}
        description="They are signed out immediately and can't sign in until reactivated. While suspended, their connected apps, their API keys and their access to teams and gateways stop working. Reactivating restores them (an app may ask them to sign in again)."
        confirmLabel="Suspend"
        busy={update.isPending}
        error={update.error}
        onConfirm={() => update.mutate({ status: "suspended" })}
      />
    </Stack>
  );
}

/** What each platform role can do, named in the confirmation. */
const rolePowers: Record<Schemas["PlatformRole"], { title: (name: string) => string; description: string; confirm: string }> = {
  platform_admin: {
    title: (name) => `Make ${name} a platform admin?`,
    description:
      "Platform admins manage the whole platform: every team, its members and owners, users and their platform roles, and the audit log. The role doesn't give access to a team's captured call payloads.",
    confirm: "Make platform admin",
  },
  platform_auditor: {
    title: (name) => `Make ${name} a platform auditor?`,
    description: "Auditors can open every admin page and the audit log, but can't change anything. The role doesn't give access to a team's captured call payloads.",
    confirm: "Make auditor",
  },
  none: {
    title: (name) => `Remove ${name}'s platform role?`,
    description: "They lose access to the admin portal. Their team memberships don't change.",
    confirm: "Remove platform role",
  },
};

type AccessProps = { user: UserDetail["user"]; isAdmin: boolean; update: Update; self: boolean; otherDialogOpen: boolean };

const selfDemotion: Record<string, string> = {
  none: "You'll lose access to the admin portal at once. Your team memberships don't change.",
  platform_auditor: "You'll keep read-only access to the admin portal and can't change anything. Your team memberships don't change.",
};

function UserAccessCard({ user, isAdmin, update, self, otherDialogOpen }: AccessProps) {
  const [pending, setPending] = useState<Schemas["PlatformRole"] | null>(null);
  const base = pending ? rolePowers[pending] : undefined;
  // On your own record the dialog speaks to you.
  const powers =
    base && self && pending !== "platform_admin"
      ? { ...base, title: () => (pending === "none" ? "Remove your platform role?" : "Make yourself a platform auditor?"), description: selfDemotion[pending!] }
      : base;
  // Cancelling returns focus to the select whose change opened the dialog.
  const roleSelect = useRef<HTMLSelectElement>(null);
  return (
    <Card title="Profile and access">
      <Stack gap={5}>
        {/* Said once: while a dialog is open, its own alert shows the error. */}
        {pending === null && !otherDialogOpen && <ErrorAlert error={update.error} />}
        <Field label="Platform role" description="Platform admins manage the platform. Auditors have read-only access to it." className={s.form}>
          <NativeSelect ref={roleSelect} value={user.platformRole} disabled={!isAdmin || update.isPending} onChange={(e) => setPending(e.target.value as Schemas["PlatformRole"])}>
            {Object.entries(platformRoleLabels).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </NativeSelect>
        </Field>
        <DescriptionList
          items={[
            { label: "Email", value: user.email },
            { label: "First signed in", value: <Time value={user.createdAt} fallback="—" /> },
            { label: "Last sign-in", value: user.lastLoginAt ? <Time value={user.lastLoginAt} /> : "Never" },
          ]}
        />
      </Stack>
      <AlertDialog
        open={pending !== null}
        onOpenChange={(o) => {
          if (!o) {
            setPending(null);
            update.reset();
          }
        }}
        title={powers?.title(user.displayName) ?? ""}
        description={powers?.description ?? ""}
        confirmLabel={powers?.confirm ?? "Confirm"}
        tone={pending === "platform_admin" ? "danger" : "primary"}
        finalFocus={roleSelect}
        busy={update.isPending}
        error={update.error}
        onConfirm={() => pending && update.mutate({ platformRole: pending }, { onSuccess: () => setPending(null) })}
      />
    </Card>
  );
}

function UserTeamsCard({ teams }: { teams: UserDetail["teams"] }) {
  return (
    <Card title="Teams" description="Owners manage their team's members; a platform admin can assign an owner on the team's page." flush={teams.length > 0}>
      {teams.length === 0 ? (
        <EmptyState size="compact" icon={<Boxes />} title="Not a member of any team." description="A team owner or admin adds people from Team settings › Members." />
      ) : (
        <Table caption="Team memberships" columns={["Team", "Role"]}>
          {teams.map((t) => (
            <Tr key={t.id}>
              <Td>
                <TextLink render={<Link to="/admin/teams/$team" params={{ team: t.slug }} />} className={s.primary}>
                  {t.name}
                </TextLink>
                {t.status === "archived" && <span className={s.secondary}>Archived</span>}
              </Td>
              <Td>
                <Badge tone={t.role === "owner" ? "info" : "neutral"}>{roleLabels[t.role]}</Badge>
              </Td>
            </Tr>
          ))}
        </Table>
      )}
    </Card>
  );
}
