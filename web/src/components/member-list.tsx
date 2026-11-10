/*
 * The team's members (Team settings › Members): a data table with each
 * person's role (a select when the viewer may change it), and Leave / Remove
 * in the row's "…" menu. The only owner gets no role select, with the reason
 * shown. A search box appears once the team has more than 20 members.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogOut, UserMinus, Users } from "lucide-react";
import { useState } from "react";
import { api, ifMatch, unwrap, type Schemas } from "../api/client";
import { membersQuery } from "../api/queries";
import s from "../pages/shared.module.css";
import { ConfirmMutationDialog } from "./confirm-dialog";
import { leaveBlockedReason } from "./members";
import { RoleBadge } from "./role-badge";
import { canManage, roleLabels, teamRoles, type TeamRole } from "./roles";
import { ActionMenu } from "./templates/action-menu";
import { RelativeTime } from "./templates/relative-time";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Avatar } from "@/components/ui/avatar/avatar";
import { Badge } from "@/components/ui/badge/badge";
import { type DataTableColumn, DataTable } from "@/components/ui/data-table/data-table";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { NativeSelect } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";

type Member = Schemas["Member"];

/** Past this many members the list gets a search box. */
export const MEMBER_SEARCH_AT = 20;

/** Change a member's role, and remove a member (or leave the team). */
function useMemberMutations(team: string, myUserId: string, onRemoved: () => void) {
  const qc = useQueryClient();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["team", team] });
    qc.invalidateQueries({ queryKey: ["me"] });
  };
  const changeRole = useMutation({
    mutationFn: async ({ m, role }: { m: Member; role: TeamRole }) =>
      unwrap(await api.PATCH("/v1/teams/{team}/members/{userId}", { params: { path: { team, userId: m.user.id }, header: ifMatch(m.revision) }, body: { role } })),
    onSuccess: (_, { m, role }) => toast.success(`${m.user.displayName} is now ${roleLabels[role].toLowerCase()}`),
    onSettled: invalidate,
  });
  const remove = useMutation({
    mutationFn: async (m: Member) => unwrap(await api.DELETE("/v1/teams/{team}/members/{userId}", { params: { path: { team, userId: m.user.id } } })),
    onSuccess: (_, m) => {
      onRemoved();
      if (m.user.id === myUserId) window.location.assign("/");
      else toast.success(`${m.user.displayName} was removed from the team`);
    },
    onSettled: invalidate,
  });
  return { changeRole, remove };
}

export function MemberList({ team, myRole, myUserId }: { team: string; myRole?: TeamRole; myUserId: string }) {
  const members = useQuery(membersQuery(team));
  const [removing, setRemoving] = useState<Member | null>(null);
  // Making someone an owner hands them the team (they can remove other owners): asked first.
  const [promoting, setPromoting] = useState<Member | null>(null);
  const [filter, setFilter] = useState("");
  const { changeRole, remove } = useMemberMutations(team, myUserId, () => setRemoving(null));
  const list = members.data ?? [];
  const owners = list.filter((m) => m.role === "owner").length;
  const leaving = removing?.user.id === myUserId;
  const leaveBlocked = leaveBlockedReason(members.data, myRole);

  const roleCell = (m: Member) => {
    const soleOwner = m.role === "owner" && owners <= 1;
    if (soleOwner || !canManage(myRole, m.role)) {
      return (
        <span>
          <RoleBadge role={m.role} />
          {soleOwner && canManage(myRole, m.role) && <span className={s.secondary}>The only owner. Make someone else an owner to change this.</span>}
        </span>
      );
    }
    // The select's wrapper is full width (and holds the chevron): the span sizes both.
    return (
      <span className={s.roleSelect}>
      <NativeSelect
        size="sm"
        aria-label={`Role for ${m.user.displayName}`}
        value={m.role}
        disabled={changeRole.isPending}
        onChange={(e) => {
          const role = e.target.value as TeamRole;
          if (role === "owner") setPromoting(m);
          else changeRole.mutate({ m, role });
        }}
      >
        {teamRoles
          .filter((r) => canManage(myRole, m.role, r))
          .map((r) => (
            <option key={r} value={r}>
              {roleLabels[r]}
            </option>
          ))}
      </NativeSelect>
      </span>
    );
  };

  const columns: DataTableColumn<Member>[] = [
    {
      id: "person",
      header: "Person",
      accessor: (m) => `${m.user.displayName} ${m.user.email}`,
      rowHeader: true,
      cell: (m) => (
        <span className={s.person}>
          <Avatar name={m.user.displayName || m.user.email} size="sm" decorative />
          <span className={s.personText}>
            <span className={s.primary}>
              {m.user.displayName}
              {m.user.id === myUserId && <span className={s.you}>(you)</span>}
            </span>
            <span className={s.secondary}>{m.user.email}</span>
          </span>
          {m.user.status === "suspended" && <Badge tone="danger">Suspended</Badge>}
        </span>
      ),
    },
    { id: "role", header: "Role", accessor: (m) => roleLabels[m.role], cell: roleCell },
    { id: "added", header: "Added", accessor: (m) => new Date(m.createdAt), filterable: false, cell: (m) => <RelativeTime value={m.createdAt} /> },
  ];

  const searchable = list.length > MEMBER_SEARCH_AT;
  return (
    <>
      {changeRole.error ? (
        <div className={s.pad}>
          <ErrorAlert error={changeRole.error} />
        </div>
      ) : null}
      <DataTable<Member>
        caption="Team members"
        // On a phone each member is a block: the person on its own line, the role and date under it.
        stack
        columns={columns}
        data={list}
        getRowId={(m) => m.user.id}
        rowLabel={(m) => m.user.displayName || m.user.email}
        loading={members.isLoading}
        error={members.error}
        onRetry={() => void members.refetch()}
        filterable={searchable}
        filter={searchable ? filter : undefined}
        onFilterChange={setFilter}
        filterLabel="Search members"
        filterPlaceholder="Name or email"
        pageSize={searchable ? 25 : undefined}
        empty={<EmptyState size="compact" icon={<Users />} title="No members yet." />}
        rowActions={(m) => {
          const isMe = m.user.id === myUserId;
          return (
            <ActionMenu
              label={`Actions for ${m.user.displayName || m.user.email}`}
              actions={[
                { label: "Leave team", icon: <LogOut aria-hidden />, danger: true, hidden: !isMe || !myRole, disabled: Boolean(leaveBlocked), disabledReason: leaveBlocked, onSelect: () => setRemoving(m) },
                { label: "Remove from team…", icon: <UserMinus aria-hidden />, danger: true, hidden: isMe || !canManage(myRole, m.role), onSelect: () => setRemoving(m) },
              ]}
            />
          );
        }}
      />
      <ConfirmMutationDialog
        target={promoting}
        onClose={() => setPromoting(null)}
        mutation={changeRole}
        onConfirm={(m) => changeRole.mutate({ m, role: "owner" }, { onSuccess: () => setPromoting(null) })}
        tone="primary"
        title={`Make ${promoting?.user.displayName || promoting?.user.email} an owner?`}
        description="Owners can do everything an admin can, and also add and remove other owners, you included."
        confirmLabel="Make owner"
      />
      <ConfirmMutationDialog
        target={removing}
        onClose={() => setRemoving(null)}
        mutation={remove}
        onConfirm={(m) => remove.mutate(m)}
        title={leaving ? "Leave this team?" : `Remove ${removing?.user.displayName}?`}
        description={leaving ? "You will lose access to this team and the gateways it grants you." : "They will lose access to this team and the gateways it grants them."}
        confirmLabel={leaving ? "Leave team" : "Remove"}
      />
    </>
  );
}
