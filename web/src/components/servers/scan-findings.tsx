import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, unwrap, type Schemas } from "@/api/client";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Time } from "@/components/ui/time/time";
import { capabilitiesQuery, type ServerScope } from "./scope";
import m from "./scan-findings.module.css";

export const scanningDocs = "https://github.com/ncecere/open-mcp-portal/blob/main/docs/content-scanning.md#9-what-this-will-not-catch";
type Scan = Schemas["DefinitionScanPage"][number]["scan"];

export function describeScanError(error: unknown) {
  if (!(error instanceof ApiError)) return undefined;
  if (error.code === "token_not_allowed") return { message: "Use a browser session to view or rescan definitions." };
  if (error.status === 403) return { message: "You don't have permission to view or rescan these definitions." };
  if (error.status === 404) return { message: "The server or its findings are no longer available." };
  if (error.status === 409) return { message: "The definitions changed or scanning is unavailable. Reload the findings and try again." };
  return undefined;
}

export function CapabilityFindings({ scan }: { scan: Scan }) {
  return (
    <div className={m.stack}>
      <p>Ruleset {scan.rulesetVersion}</p>
      {(scan.status === "scanned" || scan.status === "incomplete") && scan.scannedAt && <p>Scanned <Time value={scan.scannedAt} /></p>}
      {scan.status === "off" ? <Alert tone="warning">Scanning disabled. No current scan is available.</Alert>
        : scan.status === "stale" ? <Alert tone="warning">Not yet scanned under the current definition/ruleset.</Alert>
        : scan.status === "incomplete" ? <Alert tone="warning" title="Scan incomplete">Reason: {scan.reason || "Not provided"}. Findings may be missing.</Alert>
        : scan.findings.length === 0 ? <p>Heuristics found nothing in this definition (ruleset {scan.rulesetVersion}). This does not mean the definition is safe.</p> : null}
      {(scan.status === "scanned" || scan.status === "incomplete") && scan.findings.length > 0 && (
        <ul className={m.stack}>
          {scan.findings.map((f, i) => <li key={i}>
            <p><strong>{f.ruleId}</strong> · Group: {f.group || "Unknown (no longer in catalog)"} · Severity: {f.severity} · Count: {f.count}</p>
            <p>Location: <bdi><code>{f.location}</code></bdi></p>
          </li>)}
        </ul>
      )}
    </div>
  );
}

export function ScanFindings({ scope, serverId, canRescan = false, capabilityId }: { scope: ServerScope; serverId: string; canRescan?: boolean; capabilityId?: string }) {
  const qc = useQueryClient();
  const caps = useQuery(capabilitiesQuery(scope, serverId));
  const queryKey = ["definition-findings", scope, serverId, caps.data?.map((c) => c.fingerprint)];
  const findings = useQuery({ queryKey, queryFn: async () => scope.kind === "team"
    ? unwrap(await api.GET("/v1/teams/{team}/mcp-servers/{serverId}/scan-findings", { params: { path: { team: scope.team, serverId } } }))
    : unwrap(await api.GET("/v1/admin/mcp-servers/{serverId}/scan-findings", { params: { path: { serverId } } })) });
  const rescan = useMutation({ mutationFn: async () => scope.kind === "team"
    ? unwrap(await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/scan", { params: { path: { team: scope.team, serverId } } }))
    : unwrap(await api.POST("/v1/admin/mcp-servers/{serverId}/scan", { params: { path: { serverId } } })),
    onSuccess: (data) => qc.setQueryData(queryKey, data) });
  return <section aria-label="Definition scan findings" className={m.stack}>
    <h2>Definition scan findings</h2>
    <p>Shadow mode only: findings inform review; nothing is blocked, redacted or rewritten. <a href={scanningDocs}>What scanning will not catch</a>.</p>
    {canRescan && <Button variant="secondary" disabled={rescan.isPending} onClick={() => rescan.mutate()}>{rescan.isPending ? "Rescanning…" : "Rescan definitions"}</Button>}
    <ErrorAlert error={rescan.error} describe={describeScanError} />
    {findings.isPending && <p role="status">Loading findings…</p>}
    <ErrorAlert error={findings.error} describe={describeScanError} onRetry={() => void findings.refetch()} />
    {findings.data?.length === 0 && <p>No capability definitions to scan.</p>}
    {findings.data?.filter((c) => !capabilityId || c.capabilityId === capabilityId).map((c) => <section
      key={c.capabilityId}
      className={m.capability}
      aria-label={`Findings for ${caps.data?.find((cap) => cap.id === c.capabilityId)?.name ?? c.capabilityId}`}
    >
      <h3>{caps.data?.find((cap) => cap.id === c.capabilityId)?.name ?? c.capabilityId}</h3>
      <CapabilityFindings scan={c.scan} />
    </section>)}
  </section>;
}
