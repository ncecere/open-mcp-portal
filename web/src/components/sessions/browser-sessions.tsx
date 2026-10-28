/* Browser-session controls are session-only, including the admin view. User
 * agents are self-reported; these labels are a convenience, not proof of a device. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Monitor, LogOut } from "lucide-react";
import { useState } from "react";
import { api, setCsrfToken, unwrap, type Schemas } from "@/api/client";
import { ConfirmMutationDialog } from "@/components/confirm-dialog";
import { ListPage, timeColumn } from "@/components/templates/list-page";
import { Alert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { Stack } from "@/components/ui/layout/layout";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";

export type BrowserSession = Schemas["BrowserSession"];
type Owner = { self: true } | { self: false; userId: string; name: string };
type Target = { kind: "one"; session: BrowserSession } | { kind: "all" };
type Submission = { target: Target; keepCurrent: boolean; endsCurrent: boolean };

export function browserLabel(ua: string): string {
  const browser = /Edg(?:e|A|iOS)?\//.test(ua) ? "Edge" : /(?:Firefox|FxiOS)\//.test(ua) ? "Firefox" : /(?:Chrome|CriOS)\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Unknown browser";
  const device = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Macintosh|Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return device ? `${browser} on ${device}` : browser;
}

const columns: DataTableColumn<BrowserSession>[] = [
  { id: "browser", header: "Browser", rowHeader: true, accessor: (x) => browserLabel(x.userAgent), cell: (x) => <CellText primary={<>{browserLabel(x.userAgent)} {x.current && <Badge tone="info">This session</Badge>}</>} secondary={x.clientIp || "Address unavailable"} /> },
  timeColumn("createdAt", "Signed in", (x: BrowserSession) => x.createdAt),
  timeColumn("lastSeenAt", "Last active", (x: BrowserSession) => x.lastSeenAt),
  timeColumn("expiresAt", "Expires", (x: BrowserSession) => x.expiresAt),
];

export function BrowserSessions({ owner }: { owner: Owner }) {
  const qc = useQueryClient();
  const key = owner.self ? ["my", "sessions"] : ["admin", "user", owner.userId, "sessions"];
  const sessions = useQuery({
    queryKey: key,
    queryFn: async () => owner.self ? unwrap(await api.GET("/v1/me/sessions")) : unwrap(await api.GET("/v1/admin/users/{userId}/sessions", { params: { path: { userId: owner.userId } } })),
  });
  const [target, setTarget] = useState<Target | null>(null);
  const [keepCurrent, setKeepCurrent] = useState(false);
  const revoke = useMutation({
    mutationFn: async ({ target: t, keepCurrent }: Submission) => {
      if (!owner.self) return unwrap(await api.DELETE("/v1/admin/users/{userId}/sessions", { params: { path: { userId: owner.userId } } }));
      if (t.kind === "one") return unwrap(await api.DELETE("/v1/me/sessions/{sessionId}", { params: { path: { sessionId: t.session.id } } }));
      return unwrap(await api.POST("/v1/me/sessions/revoke-all", { body: { keepCurrent } }));
    },
    onSuccess: (_, { target: t, endsCurrent }) => {
      setTarget(null);
      if (endsCurrent) {
        setCsrfToken("");
        qc.clear();
        window.location.assign("/");
      } else {
        void qc.invalidateQueries({ queryKey: key });
        toast.success(t.kind === "one" ? "Session signed out" : "Sessions signed out");
      }
    },
  });
  const allLabel = owner.self ? "Sign out everywhere" : "Revoke all sessions";
  return <Stack gap={4}>
    <Stack gap={3}>
      <Button variant="secondary" disabled={sessions.isLoading || !sessions.data?.length} onClick={() => { setKeepCurrent(false); setTarget({ kind: "all" }); }}><LogOut aria-hidden />{allLabel}</Button>
      {owner.self && <TextLink render={<Link to="/settings/connected-apps" />}>Connected apps</TextLink>}
    </Stack>
    <Alert tone="info">Browser and device names are reported by the browser. Last activity is recorded at most once a minute. The expiry shown is the absolute limit; inactivity may end a session sooner.</Alert>
    <ListPage<BrowserSession>
      id={owner.self ? "my-sessions" : "admin-user-sessions"}
      caption={owner.self ? "Your browser sessions" : `Sessions for ${owner.name}`}
      columns={columns} data={sessions.data ?? []} getRowId={(x) => x.id}
      rowLabel={(x) => `${browserLabel(x.userAgent)}${x.current ? " (this session)" : ""}`}
      loading={sessions.isLoading} error={sessions.error} onRetry={() => void sessions.refetch()}
      rowActions={owner.self ? (x) => [{ label: "Sign out…", icon: <LogOut aria-hidden />, danger: true, onSelect: () => setTarget({ kind: "one", session: x }) }] : undefined}
      empty={{ icon: <Monitor />, title: "No active browser sessions." }}
    />
    <ConfirmMutationDialog target={target} onClose={() => setTarget(null)} mutation={revoke} onConfirm={(t) => revoke.mutate({ target: t, keepCurrent, endsCurrent: t.kind === "one" ? t.session.current : owner.self ? !keepCurrent : Boolean(sessions.data?.some((x) => x.current)) })}
      title={target?.kind === "one" ? "Sign out this session?" : `${allLabel}?`}
      description={target?.kind === "one" ? "Its next request is refused. Any unfinished connect flow in that session is cancelled." : "Ends browser sign-ins and cancels their unfinished connect flows. Connected apps, API keys and provider connections are not disconnected."}
      confirmLabel={target?.kind === "one" ? "Sign out" : allLabel}
    >
      {owner.self && target?.kind === "all" && <Checkbox checked={keepCurrent} disabled={revoke.isPending} onCheckedChange={(v) => setKeepCurrent(v === true)} label="Keep this session signed in" />}
    </ConfirmMutationDialog>
  </Stack>;
}
