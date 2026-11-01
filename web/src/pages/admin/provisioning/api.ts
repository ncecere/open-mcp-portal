/*
 * SCIM provisioning (Admin › Provisioning, docs/scim.md): the directory, its tokens, provisioned people and groups,
 * and group → team role mappings. All browser-session only; the token secret comes back once, from create.
 */
import { queryOptions } from "@tanstack/react-query";
import { api, ApiError, ifMatch, type Schemas, unwrap } from "../../../api/client";

export type Directory = Schemas["ProvisioningDirectory"];
export type ProvisioningToken = Schemas["ProvisioningToken"];
export type ProvisionedUser = Schemas["ProvisionedUser"];
export type ManagedPerson = Schemas["ManagedPerson"];
export type ProvisionedGroup = Schemas["ProvisionedGroup"];
export type Mapping = Schemas["ProvisioningMapping"];
export type Enrollment = Schemas["ProvisioningEnrollment"];

export const provisioningKey = ["admin", "provisioning"] as const;

/** The directory, or null before it is set up (404 directory_not_found). */
export const directoryQuery = queryOptions({
  queryKey: [...provisioningKey, "directory"],
  queryFn: async (): Promise<Directory | null> => {
    try {
      return unwrap(await api.GET("/v1/admin/provisioning"));
    } catch (e) {
      if (e instanceof ApiError && e.code === "directory_not_found") return null;
      throw e;
    }
  },
});

export const tokensQuery = queryOptions({
  queryKey: [...provisioningKey, "tokens"],
  queryFn: async (): Promise<ProvisioningToken[]> => unwrap(await api.GET("/v1/admin/provisioning/tokens")),
});

export const usersQuery = queryOptions({
  queryKey: [...provisioningKey, "users"],
  queryFn: async (): Promise<Schemas["ProvisionedUsers"]> => unwrap(await api.GET("/v1/admin/provisioning/users")),
});

export const groupsQuery = queryOptions({
  queryKey: [...provisioningKey, "groups"],
  queryFn: async (): Promise<ProvisionedGroup[]> => unwrap(await api.GET("/v1/admin/provisioning/groups")),
});

export const mappingsQuery = queryOptions({
  queryKey: [...provisioningKey, "mappings"],
  queryFn: async (): Promise<Mapping[]> => unwrap(await api.GET("/v1/admin/provisioning/mappings")),
});

export const createDirectory = async (body: Schemas["ProvisioningSettings"]) => unwrap(await api.POST("/v1/admin/provisioning", { body }));

export const updateDirectory = async (body: Schemas["ProvisioningSettings"], revision: number) =>
  unwrap(await api.PATCH("/v1/admin/provisioning", { body, params: { header: ifMatch(revision) } }));

export const createToken = async (body: Schemas["ProvisioningTokenCreate"]) => unwrap(await api.POST("/v1/admin/provisioning/tokens", { body }));

export const revokeToken = async (t: ProvisioningToken) =>
  unwrap(await api.DELETE("/v1/admin/provisioning/tokens/{tokenId}", { params: { path: { tokenId: t.id } } }));

export const adopt = async (u: ProvisionedUser) =>
  unwrap(await api.POST("/v1/admin/provisioning/users/{scimUserId}/adopt", { params: { path: { scimUserId: u.id } } }));

export const unlink = async (p: ManagedPerson) =>
  unwrap(await api.POST("/v1/admin/provisioning/people/{userId}/unlink", { params: { path: { userId: p.id } } }));

export const createMapping = async (body: Schemas["ProvisioningMappingCreate"]) => unwrap(await api.POST("/v1/admin/provisioning/mappings", { body }));

export const deleteMapping = async (m: Mapping) =>
  unwrap(await api.DELETE("/v1/admin/provisioning/mappings/{mappingId}", { params: { path: { mappingId: m.id } } }));

export const enrollmentLabels: Record<Enrollment, string> = { optional: "Optional", required: "Required" };

export const standingLabels: Record<Schemas["DirectoryStanding"], string> = {
  none: "Not managed",
  active: "Active in directory",
  inactive: "Deactivated in directory",
  deleted: "Deleted from directory",
};

export const reasonText: Record<NonNullable<NonNullable<ProvisionedUser["candidate"]>["reason"]>, string> = {
  protected_principal: "Platform admins and team owners can't be directory managed.",
  cleanup_pending: "Their deprovisioning clean-up hasn't finished yet.",
  already_managed: "Already directory managed.",
};
