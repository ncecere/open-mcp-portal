import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api, type Schemas, unwrap } from "../../../api/client";
import { serviceAccountsKey, serviceAccountsQuery } from "../../../api/queries";
import { FormPage, FormSection } from "../../../components/templates/form-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { sharedConnectionsKey, type SharedConnection } from "./connections-tab";

type Grant = Schemas["ServiceConnectionGrant"];
type EditorProps = { team: string; connection: SharedConnection; onClose: () => void };
type Submission = { team: string; id: string; revision: number; accounts: string[]; grants: Grant[] };
export function ConnectionEditor(props: EditorProps) {
  // A new target/revision gets its own fields and FormPage submit lifecycle.
  return <AccessEditor key={`${props.team}:${props.connection.id}:${props.connection.revision}`} {...props} />;
}
function AccessEditor({ team, connection, onClose }: EditorProps) {
  const qc = useQueryClient();
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [accounts, setAccounts] = useState(connection.accounts);
  const [grants, setGrants] = useState<Grant[]>(connection.servers);
  const allAccounts = useQuery(serviceAccountsQuery(team));
  const destinations = useQuery({
    queryKey: [...sharedConnectionsKey(team), connection.id, "allowable"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/service-connections/{connectionId}/allowable-servers", { params: { path: { team, connectionId: connection.id } } })),
  });
  const update = useMutation({
    mutationFn: async (submitted: Submission) => unwrap(await api.PUT("/v1/teams/{team}/service-connections/{connectionId}", {
      params: { path: { team: submitted.team, connectionId: submitted.id }, header: { "If-Match": `"${submitted.revision}"` } }, body: { accounts: submitted.accounts, servers: submitted.grants },
    })),
    onSuccess: (_data, submitted) => {
      void qc.invalidateQueries({ queryKey: sharedConnectionsKey(submitted.team) });
      void qc.invalidateQueries({ queryKey: serviceAccountsKey(submitted.team) });
      // Closing/reopening (even the same target) retires this editor. Its
      // delayed response must not close or mark a new FormPage as saved.
      if (mounted.current) onClose();
    },
  });
  const staleGrants = grants.filter((g) => !destinations.data?.some((d) => d.server.id === g.serverId));
  return <FormPage label="Manage shared connection access" title={`Access to ${connection.name}`} description={`Shared upstream account: ${connection.accountLabel || "Account label unavailable"}. One connection per service account and provider; conflicting assignments are refused.`} onClose={onClose} onSubmit={() => {
    if (!update.isPending) update.mutate({ team, id: connection.id, revision: connection.revision, accounts: [...accounts], grants: grants.map((g) => ({ ...g, scopes: [...g.scopes] })) });
  }} submitLabel="Save access" busy={update.isPending || destinations.isLoading || allAccounts.isLoading}>
    <FormSection title="Allowed service accounts">
      {allAccounts.data?.map((a) => <Checkbox key={a.id} disabled={update.isPending} label={a.name} description={a.enabled ? undefined : "Disabled: cannot call until enabled"} checked={accounts.includes(a.id)} onCheckedChange={(checked) => setAccounts((old) => checked ? [...old, a.id] : old.filter((id) => id !== a.id))} />)}
    </FormSection>
    <FormSection title="Allowed destination servers">
      <Alert tone="warning">Only the exact origin and scopes shown are granted. Another team's published server also needs this explicit allowance. Saving access cancels any pending consent; reconnect afterwards if more scopes are needed.</Alert>
      {destinations.data?.length === 0 && <p>No reachable servers require this provider. Add an appropriate capability to a gateway you can use first.</p>}
      {destinations.data?.map((d) => <Checkbox key={d.server.id} disabled={update.isPending} label={`${d.server.name} (${d.server.teamName})`} description={`${d.origin} · ${d.scopes.join(", ") || "No scopes"}${d.covered ? "" : " · Reconnect required"}`} checked={grants.some((g) => g.serverId === d.server.id)} onCheckedChange={(checked) => setGrants((old) => checked ? [...old.filter((g) => g.serverId !== d.server.id), { serverId: d.server.id, origin: d.origin, scopes: d.scopes }] : old.filter((g) => g.serverId !== d.server.id))} />)}
      {staleGrants.map((g) => <Checkbox key={g.serverId} disabled={update.isPending} label={`Remove unavailable server ${g.serverId}`} description={g.origin} checked={false} onCheckedChange={() => setGrants((old) => old.filter((x) => x.serverId !== g.serverId))} />)}
    </FormSection>
    <ErrorAlert error={update.error ?? destinations.error ?? allAccounts.error} title="Couldn't save access" />
  </FormPage>;
}
