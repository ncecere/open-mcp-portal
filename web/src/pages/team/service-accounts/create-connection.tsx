import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, unwrap } from "../../../api/client";
import { redirectTo, safeAuthorizeUrl } from "../../../components/providers/labels";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Select } from "@/components/ui/select/select";
import s from "../../../components/servers/servers.module.css";

export function CreateConnection({ team }: { team: string }) {
  const providers = useQuery({
    queryKey: ["team", team, "service-connection-providers"],
    queryFn: async () => unwrap(await api.GET("/v1/auth-providers", { params: { query: { serviceTeam: team } } })),
  });
  const [providerId, setProviderId] = useState("");
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("");
  const start = useMutation({
    mutationFn: async () => {
      const out = unwrap(await api.POST("/v1/teams/{team}/service-connections", {
        params: { path: { team } },
        body: { providerId, name: name.trim(), ...(scopes.trim() ? { scopes: [...new Set(scopes.trim().split(/\s+/))] } : {}) },
      }));
      const target = safeAuthorizeUrl(out.authorizeUrl);
      if (!target) throw new Error("The provider returned an unsafe authorization address");
      return target;
    },
    onSuccess: (target) => redirectTo.go(target),
  });
  return <Card title="Connect a shared account" description="The account you choose at the provider will be shared with the service accounts you explicitly assign afterwards, not your personal connection.">
    <form className={s.stack} onSubmit={(e) => { e.preventDefault(); start.mutate(); }}>
      <Field label="Connection name"><Input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <Select label="Auth provider or OAuth server" items={(providers.data ?? []).map((p) => ({ value: p.id, label: `${p.name}${p.kind === "mcp_server" ? " (server sign-in)" : ""}` }))} value={providerId} onValueChange={(v) => setProviderId(v ?? "")} required />
      <Field label="Scopes" description="Space-separated; leave empty for provider defaults. Review these at the provider. Add server grants before reconnecting to request their required scopes."><Input value={scopes} onChange={(e) => setScopes(e.target.value)} /></Field>
      <ErrorAlert error={providers.error ?? start.error} title="Couldn't start connecting" />
      <Button type="submit" loading={start.isPending} disabled={!providerId || !name.trim() || start.isSuccess}>Connect shared account</Button>
    </form>
  </Card>;
}
