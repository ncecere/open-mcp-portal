/*
 * Connected apps: the MCP clients a person allowed with OAuth sign-in, one
 * row per client and gateway (decision 21), with the host that vouches for
 * the client (or "Unverified" for one that registered itself), when it was
 * connected, last used and when its sign-in expires (the app signs in again
 * by then, decision 63), and Disconnect (asked first; its tokens stop at
 * once). Account › Connected apps shows the person's own; Admin › Users ›
 * person shows anyone's, where platform admins disconnect and auditors read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Plug, Unplug } from "lucide-react";
import { type ReactNode, useState } from "react";
import { api, type Schemas, unwrap } from "../../api/client";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { ListPage, RelativeTime, timeColumn } from "../templates/list-page";
import { Badge } from "@/components/ui/badge/badge";
import { formatDate } from "@/lib/bitop-format";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { ClientHost } from "./client-host";

export type OAuthGrant = Schemas["OAuthGrant"];

/** Whose apps: the signed-in person's, or a person's on their admin page. */
export type ConnectedAppsOwner = { self: true } | { self: false; userId: string; name: string };

export const grantsKey = (owner: ConnectedAppsOwner) => (owner.self ? ["my", "oauth-grants"] : ["admin", "user", owner.userId, "oauth-grants"]);

function useGrants(owner: ConnectedAppsOwner) {
  return useQuery({
    queryKey: grantsKey(owner),
    queryFn: async () =>
      owner.self
        ? unwrap(await api.GET("/v1/me/oauth-grants"))
        : unwrap(await api.GET("/v1/admin/users/{userId}/oauth-grants", { params: { path: { userId: owner.userId } } })),
  });
}

function useDisconnect(owner: ConnectedAppsOwner, onDone: () => void) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (g: OAuthGrant) =>
      owner.self
        ? unwrap(await api.DELETE("/v1/me/oauth-grants/{grantId}", { params: { path: { grantId: g.id } } }))
        : unwrap(await api.DELETE("/v1/admin/users/{userId}/oauth-grants/{grantId}", { params: { path: { userId: owner.userId, grantId: g.id } } })),
    onSuccess: (_, g) => {
      onDone();
      toast.success(`${g.client.name} was disconnected from ${g.gateway.name}`);
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: grantsKey(owner) }),
  });
}

function GatewayCell({ g, admin }: { g: OAuthGrant; admin: boolean }) {
  if (!g.gateway.exists) {
    return (
      <span>
        {g.gateway.name}
        <span className={s.secondary}>Deleted</span>
      </span>
    );
  }
  const link = admin ? <Link to="/admin/gateways/$gatewayId" params={{ gatewayId: g.gateway.id }} /> : <Link to="/gateways/$gatewayId" params={{ gatewayId: g.gateway.id }} />;
  return <TextLink render={link}>{g.gateway.name}</TextLink>;
}

function columns(admin: boolean): DataTableColumn<OAuthGrant>[] {
  return [
    {
      id: "client",
      header: "App",
      accessor: (g) => g.client.name,
      rowHeader: true,
      hideable: false,
      sortable: true,
      cell: (g) => (
        <CellText
          wrap="anywhere"
          primary={
            <span className={s.badges}>
              {g.client.name}
              {g.client.kind === "registered" && (
                <Badge size="sm" tone="warning">
                  Unverified
                </Badge>
              )}
            </span>
          }
          secondary={<ClientHost client={g.client} />}
        />
      ),
    },
    { id: "gateway", header: "Gateway", accessor: (g) => g.gateway.name, sortable: true, cell: (g) => <GatewayCell g={g} admin={admin} /> },
    timeColumn<OAuthGrant>("createdAt", "Connected", (g) => g.createdAt),
    {
      ...timeColumn<OAuthGrant>("lastUsedAt", "Last used", (g) => g.lastUsedAt),
      cell: (g) => (g.lastUsedAt ? <span className={s.nowrap}><RelativeTime value={g.lastUsedAt} /></span> : <span className={s.muted}>Not used yet</span>),
    },
    { ...timeColumn<OAuthGrant>("expiresAt", "Sign-in expires", (g) => g.expiresAt), cell: (g) => <Expires grant={g} /> },
  ];
}

/** When the app has to sign in again (the portal's refresh lifetime), or that there's no limit. */
function Expires({ grant }: { grant: OAuthGrant }) {
  if (!grant.expiresAt) return <span className={s.muted}>No limit</span>;
  const expired = new Date(grant.expiresAt).getTime() <= Date.now();
  return (
    <span className={s.nowrap}>
      <time dateTime={grant.expiresAt}>{formatDate(grant.expiresAt, { style: "date" })}</time>
      {expired && (
        <>
          {" "}
          <Badge size="sm" tone="warning">
            Expired
          </Badge>
        </>
      )}
    </span>
  );
}

type Props = {
  owner: ConnectedAppsOwner;
  canDisconnect: boolean;
  /** A page of its own (Account › Connected apps): its title and description. Without one, only the list. */
  title?: string;
  description?: string;
  /** Alerts under the page's header. */
  notices?: ReactNode;
};

export function ConnectedApps({ owner, canDisconnect, title, description, notices }: Props) {
  const grants = useGrants(owner);
  const [target, setTarget] = useState<OAuthGrant | null>(null);
  const disconnect = useDisconnect(owner, () => setTarget(null));
  return (
    <>
      <ListPage<OAuthGrant>
        id={owner.self ? "my-connected-apps" : "admin-user-connected-apps"}
        title={title}
        description={description}
        notices={notices}
        caption={owner.self ? "Your connected apps" : `Apps ${owner.name} connected`}
        columns={columns(!owner.self)}
        data={grants.data ?? []}
        getRowId={(g) => g.id}
        rowLabel={(g) => `${g.client.name} on ${g.gateway.name}`}
        loading={grants.isLoading}
        error={grants.error}
        onRetry={() => void grants.refetch()}
        rowActions={canDisconnect ? (g) => [{ label: "Disconnect…", icon: <Unplug aria-hidden />, danger: true, onSelect: () => setTarget(g) }] : undefined}
        empty={{
          icon: <Plug />,
          title: "No connected apps.",
          description: `MCP clients ${owner.self ? "you connect" : `${owner.name} connects`} with OAuth sign-in, such as Claude Code, VS Code or Cursor, are listed here, one per gateway.`,
        }}
        tableProps={{ columnsMenuMin: 5 }}
      />
      <ConfirmMutationDialog
        target={target}
        onClose={() => setTarget(null)}
        mutation={disconnect}
        onConfirm={(g) => disconnect.mutate(g)}
        title={`Disconnect ${target?.client.name ?? "this app"}?`}
        description={`It loses access to ${target?.gateway.name ?? "the gateway"} at once: its sign-in stops working on its next request. ${
          owner.self ? "To use it again, connect it again and allow it." : `${owner.name} can connect it again by signing in and allowing it.`
        }`}
        confirmLabel="Disconnect"
      />
    </>
  );
}
