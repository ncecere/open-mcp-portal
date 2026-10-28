import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type Schemas, unwrap } from "../../../api/client";
import { serviceAccountsKey, serviceAccountsQuery } from "../../../api/queries";
import { FormPage, FormSection } from "../../../components/templates/form-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { sharedConnectionsKey, type SharedConnection } from "./connections-tab";

type Grant = Schemas["ServiceConnectionGrant"];
export function ConnectionEditor({ team, connection, onClose }: { team: string; connection: SharedConnection; onClose: () => void }) {
  const qc = useQueryClient();
  const [accounts, setAccounts] = useState(connection.accounts);
  const [grants, setGrants] = useState<Grant[]>(connection.servers);
  const allAccounts = useQuery(serviceAccountsQuery(team));
  const destinations = useQuery({
    queryKey: [...sharedConnectionsKey(team), connection.id, "allowable"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/service-connections/{connectionId}/allowable-servers", { params: { path: { team, connectionId: connection.id } } })),
  });
  const update = useMutation({
    mutationFn: async () => unwrap(await api.PUT("/v1/teams/{team}/service-connections/{connectionId}", {
      params: { path: { team, connectionId: connection.id }, header: { "If-Match": `"${connection.revision}"` } }, body: { accounts, servers: grants },
    })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: sharedConnectionsKey(team) });
      void qc.invalidateQueries({ queryKey: serviceAccountsKey(team) });
      onClose();
    },
  });
  const staleGrants = grants.filter((g) => !destinations.data?.some((d) => d.server.id === g.serverId));
  return <FormPage label="Manage shared connection access" title={`Access to ${connection.name}`} description={`Shared upstream account: ${connection.accountLabel || "Account label unavailable"}. One connection per service account and provider; conflicting assignments are refused.`} onClose={onClose} onSubmit={() => update.mutate()} submitLabel="Save access" busy={update.isPending || destinations.isLoading || allAccounts.isLoading}>
    <FormSection title="Allowed service accounts">
      {allAccounts.data?.map((a) => <Checkbox key={a.id} label={a.name} description={a.enabled ? undefined : "Disabled: cannot call until enabled"} checked={accounts.includes(a.id)} onCheckedChange={(checked) => setAccounts((old) => checked ? [...old, a.id] : old.filter((id) => id !== a.id))} />)}
    </FormSection>
    <FormSection title="Allowed destination servers">
      <Alert tone="warning">Only the exact origin and scopes shown are granted. Another team's published server also needs this explicit allowance. Saving access cancels any pending consent; reconnect afterwards if more scopes are needed.</Alert>
      {destinations.data?.length === 0 && <p>No reachable servers require this provider. Add an appropriate capability to a gateway you can use first.</p>}
      {destinations.data?.map((d) => <Checkbox key={d.server.id} label={`${d.server.name} (${d.server.teamName})`} description={`${d.origin} · ${d.scopes.join(", ") || "No scopes"}${d.covered ? "" : " · Reconnect required"}`} checked={grants.some((g) => g.serverId === d.server.id)} onCheckedChange={(checked) => setGrants((old) => checked ? [...old.filter((g) => g.serverId !== d.server.id), { serverId: d.server.id, origin: d.origin, scopes: d.scopes }] : old.filter((g) => g.serverId !== d.server.id))} />)}
      {staleGrants.map((g) => <Checkbox key={g.serverId} label={`Remove unavailable server ${g.serverId}`} description={g.origin} checked={false} onCheckedChange={() => setGrants((old) => old.filter((x) => x.serverId !== g.serverId))} />)}
    </FormSection>
    <ErrorAlert error={update.error ?? destinations.error ?? allAccounts.error} title="Couldn't save access" />
  </FormPage>;
}
