/*
 * The account a capability needs, as a badge ("Needs GitHub (repo)"), and
 * Connect: POST /v1/me/connections/start (browser session, CSRF token),
 * then the browser goes to the provider's authorization page. The scopes
 * asked for are the union of what's granted, what's asked here and, when
 * nothing is, the provider's defaults (the server decides).
 */
import { useMutation } from "@tanstack/react-query";
import { Link2 } from "lucide-react";
import { api, errorMessage, type Schemas, unwrap } from "../../api/client";
import { Badge } from "@/components/ui/badge/badge";
import { Button, type ButtonProps } from "@/components/ui/button/button";
import { toast } from "@/components/ui/toast/toast";
import { type CapabilityRequirement, needsText, redirectTo, safeAuthorizeUrl } from "./labels";

/**
 * "Needs GitHub (repo)", or "Needs sign-in to GitHub MCP" when the capability's server is in oauth mode (each
 * person signs in to the server itself). `note` explains any additional credential policy, including shared connections.
 */
export function RequiresBadge({ req, note }: { req: Pick<CapabilityRequirement, "providerName" | "scopes" | "providerKind">; note?: string }) {
  const scopes = req.providerKind === "mcp_server" && req.scopes.length ? `Each person signs in to ${req.providerName} and allows ${req.scopes.join(", ")}.` : undefined;
  return (
    <Badge size="sm" tone="info" title={[scopes, note].filter(Boolean).join(" ") || undefined}>
      {needsText(req)}
    </Badge>
  );
}

/** Starts connecting an account and sends the browser to the provider; refused starts throw (shown by the caller). */
export function useStartConnection() {
  return useMutation({
    mutationFn: async (body: Schemas["ConnectStart"]) => {
      const out = unwrap(await api.POST("/v1/me/connections/start", { body }));
      const target = safeAuthorizeUrl(out.authorizeUrl);
      if (!target) throw new Error("The portal answered with an address your browser can't go to, so you weren't sent anywhere.");
      return target;
    },
    onSuccess: (target) => redirectTo.go(target),
  });
}

type ConnectButtonProps = {
  size?: ButtonProps["size"];
  variant?: ButtonProps["variant"];
  disabled?: boolean;
  providerId: string;
  providerName: string;
  /** Scopes to ask for (absent: the provider's defaults, plus whatever is granted already). */
  scopes?: string[];
  /** Where the browser comes back to afterwards (a path on this site). */
  returnTo?: string;
  label?: string;
};

/** "Connect GitHub": starts connecting and leaves for the provider; a refusal shows as a toast and the person stays. */
export function ConnectButton({ providerId, providerName, scopes, returnTo, label, size = "sm", variant = "secondary", disabled }: ConnectButtonProps) {
  const start = useStartConnection();
  return (
    <Button
      size={size}
      variant={variant}
      loading={start.isPending}
      disabled={disabled || start.isSuccess}
      onClick={() =>
        start.mutate(
          { providerId, ...(scopes?.length ? { scopes } : {}), ...(returnTo ? { returnTo } : {}) },
          { onError: (err) => toast.error(`Couldn't start connecting ${providerName}`, errorMessage(err)) },
        )
      }
    >
      <Link2 aria-hidden /> {label ?? `Connect ${providerName}`}
    </Button>
  );
}
