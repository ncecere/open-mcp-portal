/*
 * Admin → Gateways: every gateway, team and platform, as a ListPage
 * filtered by the server (owner kind, team, search; all in the URL).
 * Platform admins create platform gateways (?form=new); auditors read.
 */
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Network, Plus } from "lucide-react";
import { api, type Schemas, unwrap } from "@/api/client";
import { adminGatewaysKey, adminTeamOptionsQuery } from "@/api/queries";
import { CreateGatewayForm } from "@/components/gateways/create-gateway-form";
import { gatewayColumns } from "@/components/gateways/gateway-columns";
import { type Gateway, whatIsAPlatformGateway } from "@/components/gateways/labels";
import { useFormParam } from "@/components/templates/form-page";
import { ListPage, useListFilters } from "@/components/templates/list-page";
import { Button } from "@/components/ui/button/button";
import type { Facet } from "@/components/ui/filter-bar/filter-bar";
import { NARROW_QUERY, useMediaQuery } from "@/lib/bitop-utils";
import { terms } from "@/lib/terms";
import { one, useDebounced, useIsPlatformAdmin } from "../hooks";

type OwnerKind = Schemas["GatewayOwnerKind"];

/** The teams as filter options (the first 200). */
export function useTeamOptions() {
  return useQuery({ ...adminTeamOptionsQuery(), select: (p) => p.items.map((t) => ({ value: t.team.slug, label: t.team.name })) });
}

export function AdminGatewaysPage() {
  const isAdmin = useIsPlatformAdmin();
  const teams = useTeamOptions();
  const form = useFormParam();
  const facets: Facet<Gateway>[] = [
    {
      id: "ownerKind",
      label: "Owner",
      type: "toggle",
      allLabel: "All",
      options: [
        { value: "platform", label: "Platform" },
        { value: "team", label: "Team" },
      ],
    },
    { id: "team", label: "Team", type: "select", placeholder: "Any team", options: teams.data ?? [] },
  ];
  const { values, query } = useListFilters(facets);
  const narrow = useMediaQuery(NARROW_QUERY);
  const q = useDebounced(query.trim());
  const ownerKind = one(values, "ownerKind") as OwnerKind | "";
  const team = one(values, "team");
  const gateways = useInfiniteQuery({
    queryKey: [...adminGatewaysKey, "list", q, ownerKind, team],
    queryFn: async ({ pageParam }) =>
      unwrap(await api.GET("/v1/admin/gateways", { params: { query: { q: q || undefined, ownerKind: ownerKind || undefined, team: team || undefined, cursor: pageParam, limit: 50 } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = gateways.data?.pages.flatMap((p) => p.items) ?? [];
  const link = (x: Gateway) => <Link to="/admin/gateways/$gatewayId" params={{ gatewayId: x.id }} />;
  const filtered = Boolean(q || ownerKind || team);
  const create = isAdmin && (
    <Button onClick={() => form.open("new")}>
      <Plus aria-hidden /> Create platform gateway
    </Button>
  );
  return (
    <>
      <ListPage<Gateway>
        id="admin-gateways"
        title={terms.gateways}
        description={
          isAdmin
            ? "Every gateway on the platform. Create platform gateways and grant them to teams, people or SSO groups; team gateways belong to their teams, and you can switch them off."
            : "Every gateway on the platform: the teams' own and the platform gateways shared with teams, people or SSO groups."
        }
        primaryAction={create}
        caption={terms.gateways}
        columns={gatewayColumns(link, { admin: true, narrow })}
        data={items}
        getRowId={(x) => x.id}
        rowLabel={(x) => x.name}
        facets={facets}
        search={{ label: "Search gateways", placeholder: "Name or slug" }}
        manual
        loading={gateways.isLoading}
        error={gateways.error}
        onRetry={() => void gateways.refetch()}
        rowActions={(x) => [
          { label: "Open", render: link(x) },
          { label: "Capabilities", render: <Link to="/admin/gateways/$gatewayId" params={{ gatewayId: x.id }} search={{ tab: "capabilities" }} /> },
          { label: "Access", hidden: x.ownerKind !== "platform", render: <Link to="/admin/gateways/$gatewayId" params={{ gatewayId: x.id }} search={{ tab: "access" }} /> },
          { label: "Team", hidden: !x.teamSlug, render: x.teamSlug ? <Link to="/admin/teams/$team" params={{ team: x.teamSlug }} /> : undefined },
        ]}
        empty={{
          icon: <Network />,
          title: filtered ? "No gateways match." : "No gateways yet.",
          description: filtered ? undefined : `${whatIsAPlatformGateway} Teams create their own gateways on their pages.`,
          action: filtered ? undefined : create || undefined,
        }}
        tableProps={{ facetCounts: false, loadMore: { hasMore: Boolean(gateways.hasNextPage), loading: gateways.isFetchingNextPage, onLoadMore: () => void gateways.fetchNextPage() } }}
      />
      {isAdmin && form.id === "new" && <CreateGatewayForm scope={{ kind: "admin" }} onClose={form.close} />}
    </>
  );
}
