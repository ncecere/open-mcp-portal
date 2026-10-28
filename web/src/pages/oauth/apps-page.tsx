/*
 * Account › Connected apps (/settings/connected-apps), from the account menu
 * next to Profile and API keys: the MCP clients the person allowed with
 * OAuth sign-in, per gateway, with Disconnect. Reachable for everyone,
 * including people in no team.
 */
import { Link } from "@tanstack/react-router";
import { ConnectedApps } from "../../components/oauth/connected-apps";
import { terms } from "../../lib/terms";
import { Alert } from "@/components/ui/alert/alert";
import { TextLink } from "@/components/ui/text-link/text-link";

export function ConnectedAppsPage() {
  return (
    <ConnectedApps
      owner={{ self: true }}
      canDisconnect
      title={terms.connectedApps}
      description="MCP clients you allowed to use gateways as you, with OAuth sign-in. Each one reaches only the gateway you connected it to, within its tool scope and your access. Tool scopes do not restrict prompts or resources. Disconnecting one stops it at once."
      notices={
        <Alert tone="info">
          Connect a client from <TextLink render={<Link to="/gateways" />}>{terms.myGateways}</TextLink>: it signs you in through your browser the first time it
          connects. Scripts and CI use <TextLink render={<Link to="/settings/api-keys" />}>{terms.apiKeys}</TextLink> or a team&apos;s service account instead.
        </Alert>
      }
    />
  );
}
