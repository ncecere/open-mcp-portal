/*
 * A server's Overview tab: what it offers (a tile per capability kind, each
 * opening the Capabilities tab on that kind), the connection with its
 * health and last refresh, Test and Refresh for editors and above (with
 * their results here), what it receives on behalf of its callers
 * (requirement-card.tsx), and its place in the catalog (catalog-card.tsx).
 * Right after Add, the first discovery's result shows on top, until it's
 * dismissed or a Test or Refresh shows a newer result.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Box, FileText, FlaskConical, MessageSquareText, RefreshCw, Wrench } from "lucide-react";
import { useState } from "react";
import { api, type Schemas, unwrap } from "../../api/client";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { StatCard } from "@/components/ui/stat-card/stat-card";
import { Time } from "@/components/ui/time/time";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { EnabledBadge, HealthBadge } from "./badges";
import { CatalogCard } from "./catalog-card";
import { PersonSecretCard } from "./person-secret-card";
import { ProtocolText } from "./protocol";
import { RequirementCard } from "./requirement-card";
import { SetupConnectedNotice, SetupNotice } from "./setup";
import { MachineCard, SignInCard } from "./sign-in-card";
import { partsOf, partSummary } from "./credentials";
import { authModeLabels, authModeOf } from "./upstream-auth";
import { type CapabilityKind, countOf, kindTitle, type McpServer } from "./labels";
import { FailureLine, FirstDiscovery, RefreshError, refreshChanges, RefreshSummary, TestResultAlert } from "./results";
import { capabilitiesQuery, firstDiscoveryKey, invalidateServer, type ServerAbilities, type ServerScope } from "./scope";
import m from "./servers.module.css";

const kindIcons: Record<CapabilityKind, typeof Wrench> = { tool: Wrench, resource: FileText, resource_template: Box, prompt: MessageSquareText };

type Props = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

export function OverviewTab({ server, scope, abilities }: Props) {
  const qc = useQueryClient();
  // Shown once, until dismissed or the page is left (not kept across a reload: the server keeps the last error).
  const [created, setCreated] = useState(() => qc.getQueryData<Schemas["McpServerCreated"]>(firstDiscoveryKey(server.id)));
  const dismiss = () => {
    if (!created) return;
    qc.removeQueries({ queryKey: firstDiscoveryKey(server.id) });
    setCreated(undefined);
  };
  return (
    <>
      <SetupConnectedNotice server={server} />
      <SetupNotice server={server} scope={scope} abilities={abilities} justCreated={Boolean(created?.setupRequired)} />
      {created && <FirstDiscovery created={created} onDismiss={dismiss} />}
      <div className={s.stats} role="group" aria-label="What the server offers">
        {(Object.keys(kindIcons) as CapabilityKind[]).map((kind) => {
          const Icon = kindIcons[kind];
          return (
            <StatCard
              key={kind}
              label={kindTitle(kind)}
              value={countOf(server.counts, kind).toLocaleString()}
              icon={<Icon />}
              render={<Link to="." search={{ tab: "capabilities", kind } as never} />}
            />
          );
        })}
      </div>
      <ConnectionCard server={server} scope={scope} abilities={abilities} onRun={dismiss} />
      <SignInCard server={server} scope={scope} abilities={abilities} />
      <PersonSecretCard server={server} scope={scope} abilities={abilities} />
      <MachineCard server={server} />
      {!["oauth", "person_secret", "machine_oauth"].includes(authModeOf(server)) && <RequirementCard server={server} scope={scope} />}
      <CatalogCard server={server} scope={scope} abilities={abilities} />
    </>
  );
}

/** `onRun`: a Test or Refresh started (its result replaces the first discovery's). */
function ConnectionCard({ server, scope, abilities, onRun }: Props & { onRun: () => void }) {
  const qc = useQueryClient();
  const path = { team: server.teamSlug, serverId: server.id };
  const test = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/test", { params: { path } })),
    // A test is stored as a health check.
    onSettled: () => invalidateServer(qc, server),
  });
  const refresh = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/refresh", { params: { path } })),
    onSuccess: (r) => {
      qc.setQueryData(capabilitiesQuery(scope, server.id).queryKey, r.capabilities);
      toast.success("Capabilities refreshed", `Read ${r.listed}: ${refreshChanges(r)}.`);
    },
    onSettled: () => invalidateServer(qc, server),
  });
  const run = (which: "test" | "refresh") => {
    // One result at a time: the newest.
    test.reset();
    refresh.reset();
    onRun();
    (which === "test" ? test : refresh).mutate();
  };
  const h = server.health;
  const mode = authModeOf(server);
  const auth =
    mode === "static_header" && server.hasAuth ? (
      <code className={s.mono}>{partsOf(server).map(partSummary).join(", ")}</code>
    ) : (
      authModeLabels[mode]
    );
  return (
    <Card
      title="Connection"
      description="The portal reaches the server over Streamable HTTP. A scheduled check keeps its health up to date."
      actions={
        abilities.canEdit && (
          <div className={m.actions}>
            <Button size="sm" variant="secondary" loading={test.isPending} disabled={refresh.isPending} onClick={() => run("test")}>
              <FlaskConical aria-hidden /> Test connection
            </Button>
            <Button size="sm" variant="secondary" loading={refresh.isPending} disabled={test.isPending} onClick={() => run("refresh")}>
              <RefreshCw aria-hidden /> Refresh capabilities
            </Button>
          </div>
        )
      }
    >
      <div className={m.stack}>
        {test.data && <TestResultAlert result={test.data} />}
        {test.error && <ErrorAlert error={test.error} title="Couldn't run the test" />}
        {refresh.data && <RefreshSummary result={refresh.data} published={server.publishState === "published"} />}
        {refresh.error && <RefreshError error={refresh.error} />}
        <DescriptionList
          dividers
          items={[
            { label: "URL", value: <code className={m.url}>{server.url}</code> },
            { label: "Transport", value: "Streamable HTTP" },
            { label: "Upstream", value: <ProtocolText protocol={server.protocol} /> },
            { label: mode === "static_header" ? "Header" : "Authentication", value: auth },
            { label: "Timeout", value: `${server.timeoutSeconds} s` },
            { label: "Status", value: <EnabledBadge enabled={server.enabled} /> },
            { label: "Health", value: <HealthBadge health={h} /> },
            ...(h.checkedAt
              ? [{ label: "Last checked", value: <>{<Time value={h.checkedAt} />}{h.status === "healthy" && h.latencyMs !== undefined ? ` (${h.latencyMs.toLocaleString()} ms)` : ""}</> }]
              : []),
            ...(h.status === "failing"
              ? [
                  {
                    label: "Error",
                    value: (
                      <span className={m.message}>
                        <FailureLine result={h} />
                      </span>
                    ),
                  },
                ]
              : []),
            { label: "Capabilities read", value: server.refreshedAt ? <Time value={server.refreshedAt} /> : "Not yet" },
            ...(server.lastRefreshError ? [{ label: "Last refresh", value: <span className={m.danger}>Failed: {server.lastRefreshError}</span> }] : []),
          ]}
        />
      </div>
    </Card>
  );
}
