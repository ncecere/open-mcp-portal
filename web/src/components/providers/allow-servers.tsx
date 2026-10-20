/*
 * Allow a server from Account › My connections (decision 68, issue #60): the
 * servers that require a connected account's provider and that the person may
 * use through a gateway (their teams' servers, and published ones they have
 * access to), each with Allow, its team, the address it has now and the
 * scopes it asks for. Allowing records the same consent the link's Allow
 * button does, with no call and no trip to the provider: an agent can't open a
 * link, so this is where a person allows the servers their agent uses. The
 * page sends back the address and scopes it showed; a server that moved or
 * asks for more since the list loaded is refused (409 server_changed) and the
 * list reloads. An account that lacks the scopes shows "Grant more access",
 * the normal provider round trip. Allowed servers can be taken back one by one.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link2 } from "lucide-react";
import { api, ApiError, errorMessage, type Schemas, unwrap } from "../../api/client";
import { myConnectionsKey } from "../../api/queries";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemTitle } from "@/components/ui/item/item";
import { Loading } from "@/components/ui/spinner/spinner";
import { toast } from "@/components/ui/toast/toast";
import { connectedReturnTo, connectionName, type ProviderConnection, scopesText, serverWithTeam } from "./labels";
import { useStartConnection } from "./requires";

type Allowable = Schemas["AllowableServer"];

const allowableKey = (connectionId: string) => [...myConnectionsKey, connectionId, "allowable-servers"];

function useAllowable(connectionId: string) {
  return useQuery({
    queryKey: allowableKey(connectionId),
    queryFn: async () => unwrap(await api.GET("/v1/me/connections/{connectionId}/allowable-servers", { params: { path: { connectionId } } })),
  });
}

/** What the person sees after a change: the lists, and My gateways' "connected" marks. */
function useRefreshAfterChange(connectionId: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: myConnectionsKey });
    void qc.invalidateQueries({ queryKey: allowableKey(connectionId) });
    void qc.invalidateQueries({ queryKey: ["my", "gateways"] });
  };
}

type Props = { connection: ProviderConnection; onClose: () => void };

export function AllowServersDialog({ connection, onClose }: Props) {
  const p = connectionName(connection.provider);
  const list = useAllowable(connection.id);
  const refresh = useRefreshAfterChange(connection.id);
  const start = useStartConnection();

  const allow = useMutation({
    mutationFn: async (a: Allowable) =>
      unwrap(
        await api.POST("/v1/me/connections/{connectionId}/allow-server", {
          params: { path: { connectionId: connection.id } },
          body: { serverId: a.server.id, origin: a.origin, scopes: a.scopes },
        }),
      ),
    onSuccess: (_, a) => toast.success(`${a.server.name} was allowed`, `It can use your ${p} account now. An agent acting for you can use it too.`),
    onError: (err, a) => {
      // The server moved or asks for more since this list loaded: show what it is now.
      if (err instanceof ApiError && (err.code === "server_changed" || err.code === "connect_required")) {
        toast.error(`${a.server.name} wasn't allowed`, err.message);
      }
    },
    onSettled: refresh,
  });
  const revoke = useMutation({
    mutationFn: async (server: Schemas["ConnectServer"]) =>
      unwrap(await api.DELETE("/v1/me/connections/{connectionId}/allowed-servers/{serverId}", { params: { path: { connectionId: connection.id, serverId: server.id } } })),
    onSuccess: (_, server) => toast.success(`${server.name} is no longer allowed`, `It asks again the next time a call needs your ${p} account.`),
    onSettled: refresh,
  });
  const grantMore = (a: Allowable) => {
    const scopes = [...new Set([...connection.scopes, ...a.scopes])];
    start.mutate(
      { providerId: connection.provider.id, scopes, returnTo: connectedReturnTo(connection.provider.slug) },
      { onError: (err) => toast.error(`Couldn't start connecting ${p}`, errorMessage(err)) },
    );
  };

  const items = list.data ?? [];
  const listed = new Set(items.map((a) => a.server.id));
  // Allowed before, but not offered to the person now (the server moved to another team's gateway, was unpublished, or they lost access): only taking it back makes sense.
  const stale = connection.allowedServers.filter((g) => !listed.has(g.server.id));
  const busy = allow.isPending || revoke.isPending;

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={`Allowed servers for ${p}`}
      description={`Servers that use your ${p} account${connection.accountLabel ? ` (${connection.accountLabel})` : ""}. You don't need to make a call first, and an agent acting for you can't ask.`}
      footer={<DialogClose>Close</DialogClose>}
    >
      <Alert tone="info">
        The portal keeps the token and sends it only to servers you allow, and only while a server stays at the address shown here. Your AI client and its model never see it. Take
        an allowance back any time.
      </Alert>
      {list.isLoading && <Loading label="Loading servers…" />}
      <ErrorAlert error={list.error} title="Couldn't load the servers" onRetry={() => void list.refetch()} />
      <ErrorAlert error={allow.error instanceof ApiError && (allow.error.code === "server_changed" || allow.error.code === "connect_required") ? null : allow.error} title="Couldn't allow the server" />
      <ErrorAlert error={revoke.error} title="Couldn't take back the allowance" />
      {list.data && items.length === 0 && (
        <p>
          No server you can use requires {p}. A server needs {p} when its team requires it, and shows up here once it is on a gateway you can use.
        </p>
      )}
      {items.length > 0 && (
        <ItemGroup aria-label={`Servers that need ${p}`}>
          {items.map((a) => (
            <Item key={a.server.id} variant="outline">
              <ItemContent>
                <ItemTitle>{serverWithTeam(a.server)}</ItemTitle>
                <ItemDescription>
                  Asks for {scopesText(a.scopes, "the provider's default access")} · {a.origin}
                </ItemDescription>
              </ItemContent>
              <ItemActions>
                {a.allowed ? (
                  <>
                    <Badge size="sm" tone="success">
                      Allowed
                    </Badge>
                    <Button size="sm" variant="secondary" disabled={busy} onClick={() => revoke.mutate(a.server)} aria-label={`Take back ${a.server.name}`}>
                      Take back
                    </Button>
                  </>
                ) : a.covered ? (
                  <Button size="sm" disabled={busy} loading={allow.isPending && allow.variables?.server.id === a.server.id} onClick={() => allow.mutate(a)} aria-label={`Allow ${a.server.name}`}>
                    Allow
                  </Button>
                ) : (
                  <Button size="sm" variant="secondary" disabled={start.isPending || start.isSuccess} loading={start.isPending} onClick={() => grantMore(a)} aria-label={`Grant more access for ${a.server.name}`}>
                    <Link2 aria-hidden /> Grant more access
                  </Button>
                )}
              </ItemActions>
            </Item>
          ))}
        </ItemGroup>
      )}
      {stale.length > 0 && (
        <>
          <h3>Allowed, but not offered to you now</h3>
          <ItemGroup aria-label="Allowed servers you can't use now">
            {stale.map((g) => (
              <Item key={g.server.id} variant="outline">
                <ItemContent>
                  <ItemTitle>{serverWithTeam(g.server)}</ItemTitle>
                  <ItemDescription>
                    {scopesText(g.scopes)} · {g.origin}
                  </ItemDescription>
                </ItemContent>
                <ItemActions>
                  <Button size="sm" variant="secondary" disabled={busy} onClick={() => revoke.mutate(g.server)} aria-label={`Take back ${g.server.name}`}>
                    Take back
                  </Button>
                </ItemActions>
              </Item>
            ))}
          </ItemGroup>
        </>
      )}
    </Dialog>
  );
}
