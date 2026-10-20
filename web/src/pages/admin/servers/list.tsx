/*
 * Admin → MCP servers: every team's servers as a ListPage, filtered by the
 * server (publish state, changes waiting for approval, team, the auth
 * provider they require, how the portal authenticates (OAuth sign-in per
 * person, a static header or none), search; all in the URL). How many wait for review
 * shows above the list, with a link to them. Platform admins review;
 * auditors read.
 */
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Server } from "lucide-react";
import { api, type Schemas, unwrap } from "@/api/client";
import { adminAuthProvidersKey, adminServersKey, pendingReviewsQuery } from "@/api/queries";
import { type McpServer, publishStateLabels } from "@/components/servers/labels";
import { serverColumns } from "@/components/servers/server-columns";
import { ListPage, useListFilters } from "@/components/templates/list-page";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import type { Facet } from "@/components/ui/filter-bar/filter-bar";
import { plural } from "@/lib/format";
import { terms } from "@/lib/terms";
import { one, useDebounced, useIsPlatformAdmin } from "../hooks";

type PublishState = Schemas["PublishState"];
type AuthMode = Schemas["McpServerAuthMode"];

const authModeOptions: { value: AuthMode; label: string }[] = [
  { value: "oauth", label: "OAuth sign-in" },
  { value: "static_header", label: "Static credential" },
  { value: "person_secret", label: "Own key per person" },
  { value: "machine_oauth", label: "Portal's OAuth client" },
  { value: "none", label: "None" },
];

function useTeamOptions() {
  return useQuery({
    queryKey: ["admin", "teams", "server-filter"],
    queryFn: async () => unwrap(await api.GET("/v1/admin/teams", { params: { query: { limit: 200 } } })),
    select: (p) => p.items.map((t) => ({ value: t.team.slug, label: t.team.name })),
  });
}

/** Every auth provider, enabled or not, as filter options. */
function useProviderOptions() {
  return useQuery({
    queryKey: [...adminAuthProvidersKey, "list"],
    queryFn: async () => unwrap(await api.GET("/v1/admin/auth-providers")),
    select: (list) => list.map((p) => ({ value: p.id, label: p.name })),
  });
}

export function AdminServersPage() {
  const isAdmin = useIsPlatformAdmin();
  const teams = useTeamOptions();
  const providers = useProviderOptions();
  const pending = useQuery(pendingReviewsQuery());
  const facets: Facet<McpServer>[] = [
    {
      id: "publishState",
      label: "Catalog",
      type: "toggle",
      allLabel: "All",
      options: (["pending", "published", "rejected", "private"] as PublishState[]).map((v) => ({ value: v, label: publishStateLabels[v] })),
    },
    { id: "changes", label: "Changes", type: "toggle", allLabel: "Any", options: [{ value: "true", label: "Waiting for approval" }] },
    { id: "team", label: "Team", type: "select", placeholder: "Any team", options: teams.data ?? [] },
    { id: "provider", label: "Auth provider", type: "select", placeholder: "Any or none", options: providers.data ?? [] },
    { id: "authMode", label: "Authentication", type: "toggle", allLabel: "Any", options: authModeOptions },
  ];
  const { values, setValues, query } = useListFilters(facets);
  const q = useDebounced(query.trim());
  const publishState = one(values, "publishState") as PublishState | "";
  const changes = one(values, "changes") === "true";
  const team = one(values, "team");
  const provider = one(values, "provider");
  const authMode = one(values, "authMode") as AuthMode | "";
  const servers = useInfiniteQuery({
    queryKey: [...adminServersKey, "list", q, publishState, changes, team, provider, authMode],
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/v1/admin/mcp-servers", {
          params: { query: { q: q || undefined, publishState: publishState || undefined, changes: changes || undefined, team: team || undefined, provider: provider || undefined, authMode: authMode || undefined, cursor: pageParam, limit: 50 } },
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = servers.data?.pages.flatMap((p) => p.items) ?? [];
  const link = (x: McpServer) => <Link to="/admin/servers/$serverId" params={{ serverId: x.id }} />;
  const waiting = pending.data?.count ?? 0;
  const filtered = Boolean(q || publishState || changes || team || provider || authMode);
  return (
    <ListPage<McpServer>
      id="admin-servers"
      title={terms.mcpServers}
      description={
        isAdmin
          ? "Every team's MCP servers. Review the ones waiting to be published, and approve changed capabilities of published ones."
          : "Every team's MCP servers and where they are on the way to the catalog. Platform admins review them."
      }
      notices={
        waiting > 0 && publishState !== "pending" ? (
          <Alert
            tone="info"
            title={`${pending.data?.more ? `${waiting}+ servers` : plural(waiting, "server")} waiting for review`}
            actions={
              <Button size="sm" variant="secondary" onClick={() => setValues({ ...values, publishState: ["pending"] })}>
                Show them
              </Button>
            }
          >
            Teams that need approval asked to publish {waiting === 1 ? "it" : "them"} to the catalog.
          </Alert>
        ) : undefined
      }
      caption={terms.mcpServers}
      columns={serverColumns(link, { team: true })}
      data={items}
      getRowId={(x) => x.id}
      rowLabel={(x) => x.name}
      facets={facets}
      search={{ label: "Search servers", placeholder: "Name, slug or URL" }}
      manual
      loading={servers.isLoading}
      error={servers.error}
      onRetry={() => void servers.refetch()}
      rowActions={(x) => [
        { label: "Open", render: link(x) },
        { label: "Capabilities", render: <Link to="/admin/servers/$serverId" params={{ serverId: x.id }} search={{ tab: "capabilities" }} /> },
        { label: "Team", render: <Link to="/admin/teams/$team" params={{ team: x.teamSlug }} /> },
      ]}
      empty={{
        icon: <Server />,
        title: filtered ? "No servers match." : "No MCP servers yet.",
        description: filtered ? undefined : "Teams register the MCP servers they run on their own pages. They show up here, private until a team asks to publish one.",
      }}
      tableProps={{ facetCounts: false, loadMore: { hasMore: Boolean(servers.hasNextPage), loading: servers.isFetchingNextPage, onLoadMore: () => void servers.fetchNextPage() } }}
    />
  );
}
