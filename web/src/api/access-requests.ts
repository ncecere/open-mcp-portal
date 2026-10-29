import { queryOptions } from "@tanstack/react-query";
import { api, ifMatch, type Schemas, unwrap } from "./client";

export type AccessRequest = Schemas["AccessRequest"];
export type RequestableGateway = Schemas["RequestableGateway"];
export const accessRequestsKey = ["access-requests"];
export const requestableKey = ["requestable-gateways"];
export const accessRequestKey = (requestId: string) => [...accessRequestsKey, "detail", requestId];
export const accessSettingsKey = (gatewayId: string) => ["gateway-access-settings", gatewayId];
export const requestableQuery = (cursor?: string) => queryOptions({
  queryKey: [...requestableKey, cursor],
  queryFn: async ({ signal }) => unwrap(await api.GET("/v1/gateways/requestable", { params: { query: { cursor, limit: 25 } }, signal })),
});
export const accessRequestsQuery = (view: "requested" | "review", cursor?: string) => queryOptions({
  queryKey: [...accessRequestsKey, "list", view, cursor],
  queryFn: async ({ signal }) => unwrap(await api.GET("/v1/me/access-requests", { params: { query: { view, cursor, limit: 25 } }, signal })),
  gcTime: 0,
  staleTime: 0,
});
export const accessRequestQuery = (requestId: string) => queryOptions({
  queryKey: accessRequestKey(requestId),
  queryFn: async ({ signal }) => unwrap(await api.GET("/v1/access-requests/{requestId}", { params: { path: { requestId } }, signal })),
  gcTime: 0,
  staleTime: 0,
  refetchInterval: 30_000,
});
export const accessSettingsQuery = (gatewayId: string) => queryOptions({
  queryKey: accessSettingsKey(gatewayId),
  queryFn: async ({ signal }) => unwrap(await api.GET("/v1/admin/gateways/{gatewayId}/access-settings", { params: { path: { gatewayId } }, signal })),
});
export async function createAccessRequest(body: Schemas["AccessRequestCreate"]) {
  return unwrap(await api.POST("/v1/me/access-requests", { body }));
}
export async function decideAccessRequest(submitted: { id: string; body: Schemas["AccessRequestDecision"] }) {
  return unwrap(await api.POST("/v1/access-requests/{requestId}/decision", { params: { path: { requestId: submitted.id } }, body: submitted.body }));
}
export async function withdrawAccessRequest(requestId: string) {
  return unwrap(await api.POST("/v1/access-requests/{requestId}/withdraw", { params: { path: { requestId } } }));
}
export async function saveAccessSettings(submitted: { id: string; revision: number; body: Schemas["GatewayAccessSettingsUpdate"] }) {
  return unwrap(await api.PUT("/v1/admin/gateways/{gatewayId}/access-settings", { params: { path: { gatewayId: submitted.id }, header: ifMatch(submitted.revision) }, body: submitted.body }));
}
