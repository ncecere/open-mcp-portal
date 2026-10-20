/*
 * Account › My connections (/settings/connections), from the account menu
 * next to Connected apps: the accounts the person connected with auth
 * providers (GitHub, Google…) so tools can act as them. A tool that needs
 * one asks with a link the first time (/connect/{provider}); Connect here
 * does it ahead of time with the provider's default scopes. Connect again
 * keeps the granted scopes; Disconnect asks first. Connecting from here
 * comes back with ?connected=<provider slug>, said as a notice when that
 * provider's connection is active (nothing else from the address is shown).
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Link2 } from "lucide-react";
import { useState } from "react";
import { authProvidersQuery } from "../../api/queries";
import { FormDialog } from "../../components/form-dialog";
import { connectedReturnTo, ProviderConnections, useConnections } from "../../components/providers/connections";
import { scopesText } from "../../components/providers/labels";
import { useStartConnection } from "../../components/providers/requires";
import { terms } from "../../lib/terms";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { Loading } from "@/components/ui/spinner/spinner";
import { TextLink } from "@/components/ui/text-link/text-link";

/** The notice after coming back from the provider: the connection named by ?connected=, when it's active. */
function ConnectedNotice() {
  const search: Record<string, unknown> = useSearch({ strict: false });
  const navigate = useNavigate();
  const slug = typeof search.connected === "string" ? search.connected : "";
  const connections = useConnections({ self: true });
  const c = slug ? connections.data?.find((x) => x.provider.slug === slug && x.status === "active") : undefined;
  if (!c) return null;
  return (
    <Alert tone="success" title={`${c.provider.name} is connected`} onDismiss={() => void navigate({ to: "/settings/connections", replace: true })}>
      Tools that need your {c.provider.name} account can use it now. If a tool asked you to connect, run it again in your AI client.
    </Alert>
  );
}

export function MyConnectionsPage() {
  const [connecting, setConnecting] = useState(false);
  const connect = (
    <Button onClick={() => setConnecting(true)}>
      <Link2 aria-hidden /> Connect account
    </Button>
  );
  return (
    <>
      <ProviderConnections
        owner={{ self: true }}
        canDisconnect
        title={terms.myConnections}
        description="Accounts you connected so tools can act as you on another service, such as creating a GitHub issue. The portal keeps the tokens and sends them only to the server that needs them; your AI client and its model never see them."
        primaryAction={connect}
        emptyAction={connect}
        notices={
          <>
            <ConnectedNotice />
            <Alert tone="info">
              A tool that needs an account you haven&apos;t connected answers with a link: open it, check what it asks for, and connect. Then run the tool again. An agent
              acting for you can&apos;t open links: connect the account here, then choose Allow servers… on it to allow the servers your agent uses. These are different from <TextLink render={<Link to="/settings/connected-apps" />}>{terms.connectedApps}</TextLink>, the AI clients you let use gateways as you.
            </Alert>
          </>
        }
      />
      {connecting && <ConnectDialog onClose={() => setConnecting(false)} />}
    </>
  );
}

/** Pick an enabled provider and connect it with its default scopes. */
function ConnectDialog({ onClose }: { onClose: () => void }) {
  const providers = useQuery(authProvidersQuery());
  const [providerId, setProviderId] = useState("");
  const start = useStartConnection();
  const list = providers.data ?? [];
  const chosen = list.find((p) => p.id === (providerId || list[0]?.id));
  return (
    <FormDialog
      title="Connect an account"
      description="You'll go to the provider to sign in and approve. Then you come back here."
      onClose={onClose}
      onSubmit={() => chosen && start.mutate({ providerId: chosen.id, returnTo: connectedReturnTo(chosen.slug) })}
      submitLabel={chosen ? `Continue to ${chosen.name}` : "Continue"}
      submitDisabled={!chosen || start.isSuccess}
      busy={start.isPending}
    >
      {providers.isLoading && <Loading label="Loading providers…" />}
      <ErrorAlert error={providers.error} title="Couldn't load the providers" />
      {providers.data && list.length === 0 && <Alert tone="info">No auth providers are set up yet. Platform admins add them in Admin › {terms.authProviders}.</Alert>}
      {list.length > 0 && (
        <Field label="Provider" description={chosen ? `Asks for ${scopesText(chosen.defaultScopes, "the provider's default access")}.` : undefined}>
          <NativeSelect value={chosen?.id ?? ""} onChange={(e) => setProviderId(e.target.value)}>
            {list.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </NativeSelect>
        </Field>
      )}
      <ErrorAlert error={start.error} title="Couldn't start connecting" />
    </FormDialog>
  );
}
