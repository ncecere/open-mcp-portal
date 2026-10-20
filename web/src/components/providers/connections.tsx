/*
 * Connected accounts (decision 29): the provider accounts a person connected
 * so tools can act as them, one per provider, with the scopes granted, the
 * status (active, or needs reconnecting after a failed refresh or a new
 * client ID), when it was connected and last used, and Disconnect (asked
 * first; the tokens are erased at once and revoked at the provider where it
 * can). Account › My connections shows the person's own, with Connect again;
 * Admin › Users › person shows anyone's, where platform admins disconnect
 * and auditors read. Tokens are never shown anywhere. "Allowed servers" lists
 * the MCP servers the person allowed to use a platform provider's account
 * (name and team); on My connections, "Allow servers…" opens the dialog that
 * allows a server (with no call and no link: an agent can't open one) and takes
 * a single server back (allow-servers.tsx); disconnecting removes them all. A sign-in to an MCP
 * server in oauth mode (provider.kind mcp_server) is named after the server,
 * with an "MCP server" badge and its team.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, RefreshCw, ShieldCheck, Unplug } from "lucide-react";
import { type ReactNode, useState } from "react";
import { api, errorMessage, unwrap } from "../../api/client";
import { myConnectionsKey } from "../../api/queries";
import { formatDate, toDate } from "../../lib/bitop-format";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { ListPage, RelativeTime, timeColumn } from "../templates/list-page";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { AllowServersDialog } from "./allow-servers";
import { connectedReturnTo, connectionName, connectionStatusLabels, connectionStatusTone, isServerSignIn, narrowingText, type ProviderConnection, scopesText, serverWithTeam } from "./labels";
import { useStartConnection } from "./requires";

/** Whose accounts: the signed-in person's, or a person's on their admin page. */
export type ConnectionsOwner = { self: true } | { self: false; userId: string; name: string };

export const connectionsKey = (owner: ConnectionsOwner) => (owner.self ? myConnectionsKey : ["admin", "user", owner.userId, "connections"]);

export { connectedReturnTo };

export function useConnections(owner: ConnectionsOwner) {
  return useQuery({
    queryKey: connectionsKey(owner),
    queryFn: async () =>
      owner.self
        ? unwrap(await api.GET("/v1/me/connections"))
        : unwrap(await api.GET("/v1/admin/users/{userId}/connections", { params: { path: { userId: owner.userId } } })),
  });
}

function useDisconnect(owner: ConnectionsOwner, onDone: () => void) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (c: ProviderConnection) =>
      owner.self
        ? unwrap(await api.DELETE("/v1/me/connections/{connectionId}", { params: { path: { connectionId: c.id } } }))
        : unwrap(await api.DELETE("/v1/admin/users/{userId}/connections/{connectionId}", { params: { path: { userId: owner.userId, connectionId: c.id } } })),
    onSuccess: (_, c) => {
      onDone();
      toast.success(`${connectionName(c.provider)} was disconnected`, owner.self ? "Its tokens were erased." : undefined);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: connectionsKey(owner) });
      // What My gateways says about being connected changes too.
      if (owner.self) void qc.invalidateQueries({ queryKey: ["my", "gateways"] });
    },
  });
}

/** "in 40 minutes" (the exact time as its tooltip); "No expiry" when the provider gave none. */
function TokenExpiry({ c }: { c: ProviderConnection }) {
  const date = toDate(c.expiresAt);
  if (c.status !== "active") return <span className={s.muted}>—</span>;
  if (!date) return <span className={s.muted}>No expiry</span>;
  return (
    <span className={s.nowrap} title={formatDate(date, { style: "long" })}>
      <RelativeTime value={c.expiresAt!} />
      {c.refreshable ? <span className={s.secondary}>Renewed automatically</span> : null}
    </span>
  );
}

function columns(): DataTableColumn<ProviderConnection>[] {
  return [
    {
      id: "provider",
      header: "Provider",
      accessor: (c) => connectionName(c.provider),
      rowHeader: true,
      hideable: false,
      sortable: true,
      cell: (c) => (
        <CellText
          wrap="anywhere"
          primary={
            <span className={s.badges}>
              {connectionName(c.provider)}
              {isServerSignIn(c.provider) && (
                <Badge size="sm" variant="outline">
                  MCP server
                </Badge>
              )}
            </span>
          }
          secondary={[c.provider.server ? `Team: ${c.provider.server.teamSlug}` : "", c.accountLabel ? `Account: ${c.accountLabel}` : ""].filter(Boolean).join(" · ") || undefined}
        />
      ),
    },
    // On a phone the provider (with its account) and status stay in view; the Columns menu still offers the rest.
    { id: "scopes", header: "Scopes", accessor: (c) => scopesText(c.scopes), defaultHiddenNarrow: true, cell: (c) => <span className={s.mono}>{scopesText(c.scopes, "—")}</span> },
    {
      // A platform provider's token goes only to the servers listed (the person allowed each one); an MCP server's own sign-in is for that server alone.
      id: "servers",
      header: "Allowed servers",
      accessor: (c) => c.allowedServers.map((g) => serverWithTeam(g.server)).join(", "),
      defaultHiddenNarrow: true,
      cell: (c) =>
        isServerSignIn(c.provider) ? (
          <span className={s.muted}>That server only</span>
        ) : c.allowedServers.length === 0 ? (
          <span className={s.muted}>None yet</span>
        ) : (
          <CellText wrap="anywhere" primary={c.allowedServers.map((g) => serverWithTeam(g.server)).join(", ")} secondary={c.allowedServers.map((g) => `${g.server.name}: ${g.origin}`).join(" · ")} />
        ),
    },
    {
      // What a server that may use the account receives (decision 69): only the scopes its call needs, or the stored token with every scope granted.
      id: "tokens",
      header: "Token sent",
      accessor: (c) => (isServerSignIn(c.provider) ? "" : narrowingText(c)),
      defaultHiddenNarrow: true,
      cell: (c) =>
        isServerSignIn(c.provider) ? (
          <span className={s.muted}>—</span>
        ) : c.narrowsScopes ? (
          <span>{narrowingText(c)}</span>
        ) : (
          <span className={s.badges} title="This token holds all the scopes granted, whichever server it goes to">
            <Badge size="sm" variant="outline">
              All granted scopes
            </Badge>
          </span>
        ),
    },
    {
      id: "status",
      header: "Status",
      accessor: (c) => connectionStatusLabels[c.status],
      sortable: true,
      cell: (c) => <StatusBadge tone={connectionStatusTone[c.status]}>{connectionStatusLabels[c.status]}</StatusBadge>,
    },
    { ...timeColumn<ProviderConnection>("connectedAt", "Connected", (c) => c.connectedAt), defaultHiddenNarrow: true },
    {
      ...timeColumn<ProviderConnection>("lastUsedAt", "Last used", (c) => c.lastUsedAt),
      defaultHiddenNarrow: true,
      cell: (c) => (c.lastUsedAt ? <span className={s.nowrap}><RelativeTime value={c.lastUsedAt} /></span> : <span className={s.muted}>Not used yet</span>),
    },
    { id: "expiresAt", header: "Token expires", accessor: (c) => (c.expiresAt ? new Date(c.expiresAt) : null), defaultHidden: true, cell: (c) => <TokenExpiry c={c} /> },
  ];
}

/** What disconnecting does to the servers allowed to use the account (they are allowed again, one by one, after reconnecting). */
function allowedAgain(c: ProviderConnection | null, owner: ConnectionsOwner) {
  const n = c && !isServerSignIn(c.provider) ? c.allowedServers.length : 0;
  if (n === 0) return "";
  return ` ${owner.self ? "You" : owner.name} will also be asked again to allow ${n === 1 ? "the server" : `each of the ${n} servers`} that may use it now.`;
}

type Props = {
  owner: ConnectionsOwner;
  canDisconnect: boolean;
  /** A page of its own (Account › My connections): its title, description and primary action. Without a title, only the list. */
  title?: string;
  description?: string;
  primaryAction?: ReactNode;
  notices?: ReactNode;
  /** The empty list's action (Connect an account). */
  emptyAction?: ReactNode;
};

export function ProviderConnections({ owner, canDisconnect, title, description, primaryAction, notices, emptyAction }: Props) {
  const connections = useConnections(owner);
  const [target, setTarget] = useState<ProviderConnection | null>(null);
  // The connection whose servers are being allowed (the dialog reads its allowed servers from the list, so it stays current).
  const [allowingId, setAllowingId] = useState<string | null>(null);
  const allowing = connections.data?.find((c) => c.id === allowingId);
  const disconnect = useDisconnect(owner, () => setTarget(null));
  const start = useStartConnection();
  const reconnect = (c: ProviderConnection) =>
    start.mutate(
      { providerId: c.provider.id, ...(c.scopes.length ? { scopes: c.scopes } : {}), returnTo: connectedReturnTo(c.provider.slug) },
      { onError: (err) => toast.error(`Couldn't start connecting ${connectionName(c.provider)}`, errorMessage(err)) },
    );
  const who = owner.self ? "you" : owner.name;
  return (
    <>
      <ListPage<ProviderConnection>
        id={owner.self ? "my-connections" : "admin-user-connections"}
        title={title}
        description={description}
        primaryAction={primaryAction}
        notices={notices}
        caption={owner.self ? "Your connected accounts" : `Accounts ${owner.name} connected`}
        columns={columns()}
        data={connections.data ?? []}
        getRowId={(c) => c.id}
        rowLabel={(c) => connectionName(c.provider)}
        loading={connections.isLoading}
        error={connections.error}
        onRetry={() => void connections.refetch()}
        rowActions={(c) => [
          {
            label: c.status === "needs_reconsent" ? "Reconnect" : "Connect again",
            icon: <RefreshCw aria-hidden />,
            hidden: !owner.self,
            disabled: start.isPending || start.isSuccess,
            onSelect: () => reconnect(c),
          },
          {
            label: "Allow servers…",
            icon: <ShieldCheck aria-hidden />,
            // A platform provider's account only; an MCP server's own sign-in is for that server alone.
            hidden: !owner.self || isServerSignIn(c.provider),
            onSelect: () => setAllowingId(c.id),
          },
          { label: "Disconnect…", icon: <Unplug aria-hidden />, danger: true, hidden: !canDisconnect, onSelect: () => setTarget(c) },
        ]}
        empty={{
          icon: <KeyRound />,
          title: "No connected accounts.",
          description: owner.self
            ? "Some tools act as you on another service, such as GitHub or Google. The first time you use one, your AI client shows a link to connect your account here, once. You can also connect one ahead of time."
            : `Accounts ${who} connects so tools can act as them, such as GitHub or Google, are listed here, one per provider.`,
          action: emptyAction,
        }}
        tableProps={{ columnsMenuMin: 5 }}
      />
      {allowing && <AllowServersDialog connection={allowing} onClose={() => setAllowingId(null)} />}
      <ConfirmMutationDialog
        target={target}
        onClose={() => setTarget(null)}
        mutation={disconnect}
        onConfirm={(c) => disconnect.mutate(c)}
        title={`Disconnect ${target ? connectionName(target.provider) : "this account"}${owner.self ? "" : ` for ${owner.name}`}?`}
        description={`Its tokens are erased now${target ? " and revoked at the provider where it allows it" : ""}. Tools that need ${owner.self ? "your" : `${owner.name}'s`} ${
          target ? connectionName(target.provider) : ""
        } ${target && isServerSignIn(target.provider) ? "sign-in" : "account"} ask ${owner.self ? "you" : "them"} to connect it again the next time.${allowedAgain(target, owner)}`}
        confirmLabel="Disconnect"
      />
    </>
  );
}
