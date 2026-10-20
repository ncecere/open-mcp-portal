/* Fixtures for trusted agent platforms, relay accounts and agent calls (decisions 65 and 66). */
import type { Schemas } from "../api/client";
import { serviceAccountId, team } from "./fixtures";

export const platformId = "21212121-2121-4121-8121-212121212121";
export const otherPlatformId = "22222222-2222-4222-8222-222222222222";

export const agentPlatform = (extra: Partial<Schemas["AgentPlatform"]> = {}): Schemas["AgentPlatform"] => ({
  id: platformId,
  name: "Pi Durable Platform",
  issuer: "https://agents.example.com",
  jwksUrl: "https://agents.example.com/.well-known/mcp-identity-jwks.json",
  audience: "https://mcp.example.com",
  enabled: true,
  relayCount: 1,
  lastFetch: { at: "2026-10-20T10:00:00Z", ok: true },
  keyIds: ["Z3k1aXQ", "B9fR2sA"],
  revision: 3,
  createdAt: "2026-10-18T10:00:00Z",
  updatedAt: "2026-10-19T10:00:00Z",
  ...extra,
});

export const relayAccount = (extra: Partial<Schemas["AgentPlatformRelay"]> = {}): Schemas["AgentPlatformRelay"] => ({
  serviceAccountId,
  name: "pdp-relay",
  teamId: team.id,
  teamSlug: team.slug,
  teamName: team.name,
  role: "editor",
  enabled: true,
  markedAt: "2026-10-19T11:00:00Z",
  ...extra,
});

/** A call an agent platform relayed for a person (the principal is the relay service account). */
export const agentCall = (extra: Partial<Schemas["AgentCall"]> = {}): Schemas["AgentCall"] => ({
  platformId,
  platformName: "Pi Durable Platform",
  agentId: "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21",
  agentName: "Mail assistant",
  personPresent: true,
  person: { userId: "10101010-1010-4101-8101-101010101010", email: "una@example.com", displayName: "Una User" },
  ...extra,
});
