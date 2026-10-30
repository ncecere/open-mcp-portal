/*
 * A team's MCP servers: a ListPage (search in ?q=, filtered by the server)
 * with each server's host, health, catalog state and what it offers. Editors
 * and above add servers on a form page (?form=new); members and platform
 * staff read. Owners and admins can ask again for a rejected server's
 * review, or make it private, from its row menu.
 */
import { useInfiniteQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Plus, Server } from "lucide-react";
import { useState } from "react";
import { api, unwrap } from "../../../api/client";
import { teamServersKey } from "../../../api/queries";
import { AddServerForm } from "../../../components/servers/add-server-form";
import { type McpServer, publishStateLabels } from "../../../components/servers/labels";
import { PublishDialog, publishBlocked, UnpublishDialog } from "../../../components/servers/publish-dialogs";
import { TransfersCard } from "../../../components/servers/transfers-card";
import { serverColumns } from "../../../components/servers/server-columns";
import { useFormParam } from "../../../components/templates/form-page";
import { ListPage, useListFilters } from "../../../components/templates/list-page";
import { terms } from "../../../lib/terms";
import { Button } from "@/components/ui/button/button";
import type { Facet } from "@/components/ui/filter-bar/filter-bar";
import { one, useDebounced } from "../../admin/hooks";
import { ReadOnlyNotice } from "../access";
import { useTeam } from "../common";
import { ArchivedNotice } from "../layout";

/** What an MCP server is, for the empty list. */
export const whatIsAServer =
  "An MCP server offers tools, resources and prompts to AI clients such as Claude Code or Cursor over the Model Context Protocol. Register the remote servers your team runs: the portal reads what they offer, checks their health, and can publish them to the company catalog.";

type PublishState = McpServer["publishState"];

/** Catalog state (?publishState=pending, the link of "servers waiting for review"). The API has no such filter: it applies to the servers loaded. */
const facets: Facet<McpServer>[] = [
  {
    id: "publishState",
    label: "Catalog",
    type: "toggle",
    allLabel: "All",
    options: (["pending", "published", "rejected", "private"] as PublishState[]).map((v) => ({ value: v, label: publishStateLabels[v] })),
  },
];

export function TeamServersPage() {
  const { slug, team, role, canEdit, isManager, archived } = useTeam();
  const form = useFormParam();
  const [dialog, setDialog] = useState<{ server: McpServer; kind: "publish" | "unpublish" } | null>(null);
  const manage = isManager && !archived;
  const { query, values } = useListFilters(facets);
  const publishState = one(values, "publishState");
  const q = useDebounced(query.trim());
  const servers = useInfiniteQuery({
    queryKey: [...teamServersKey(slug), "list", q],
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/v1/teams/{team}/mcp-servers", { params: { path: { team: slug }, query: { q: q || undefined, cursor: pageParam, limit: 50 } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = (servers.data?.pages.flatMap((p) => p.items) ?? []).filter((x) => !publishState || x.publishState === publishState);
  const link = (x: McpServer) => <Link to="/teams/$team/servers/$serverId" params={{ team: slug, serverId: x.id }} />;
  const add = canEdit && (
    <Button onClick={() => form.open("new")}>
      <Plus aria-hidden /> Add server
    </Button>
  );
  return (
    <>
      <ListPage<McpServer>
        id="team-servers"
        title={terms.mcpServers}
        description={`The remote MCP servers ${team.name} runs. They're private to the team until they're published to the company catalog.`}
        primaryAction={add}
        notices={
          <>
            <ArchivedNotice />
            <ReadOnlyNotice what="the team's servers" change="add and change them" />
            <TransfersCard team={slug} owner={role === "owner" && !archived} manager={isManager} />
          </>
        }
        caption={terms.mcpServers}
        columns={serverColumns(link)}
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
          { label: "Capabilities", render: <Link to="/teams/$team/servers/$serverId" params={{ team: slug, serverId: x.id }} search={{ tab: "capabilities" }} /> },
          { label: "Settings", hidden: !canEdit, render: <Link to="/teams/$team/servers/$serverId" params={{ team: slug, serverId: x.id }} search={{ tab: "settings" }} /> },
          ...rejectedActions(x, manage, (kind) => setDialog({ server: x, kind })),
        ]}
        empty={
          q || publishState
            ? { icon: <Server />, title: "No servers match." }
            : { icon: <Server />, title: "No MCP servers yet.", description: whatIsAServer, action: add || undefined }
        }
        tableProps={{ loadMore: { hasMore: Boolean(servers.hasNextPage), loading: servers.isFetchingNextPage, onLoadMore: () => void servers.fetchNextPage() } }}
      />
      {canEdit && form.id === "new" && <AddServerForm team={slug} onClose={form.close} />}
      {dialog?.kind === "publish" && <PublishDialog server={dialog.server} onClose={() => setDialog(null)} />}
      {dialog && <UnpublishDialog server={dialog.server} open={dialog.kind === "unpublish"} onClose={() => setDialog(null)} />}
    </>
  );
}

/** A rejected server's way on (owners and admins): ask for a review again, or make it private. */
function rejectedActions(x: McpServer, manage: boolean, open: (kind: "publish" | "unpublish") => void) {
  if (!manage || x.publishState !== "rejected") return [];
  const blocked = publishBlocked(x);
  return [
    {
      label: x.effectivePublishPolicy === "self_publish" ? "Publish\u2026" : "Request review again\u2026",
      disabled: Boolean(blocked),
      disabledReason: blocked,
      onSelect: () => open("publish"),
    },
    { label: "Make private\u2026", onSelect: () => open("unpublish") },
  ];
}
