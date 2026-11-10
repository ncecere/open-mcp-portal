/*
 * API fixtures for the page tests, typed from the generated contract (schema.gen.ts), so they break when it changes.
 * One import path for the tests; the fixtures live by area:
 *
 *   fixtures-core.ts      the instance, sign-in, a team with members and invites, audit entries, pages
 *   fixtures-registry.ts  MCP servers, capabilities, health checks, publishing, the catalog
 *   fixtures-gateways.ts  gateways, grants, calls and API keys
 *   fixtures-apps.ts      OAuth sign-in (consent, connected apps, trusted clients) and service accounts
 *
 * (fixtures-v02.ts, fixtures-oauth.ts and the others next to them are imported by their own names.)
 */
export * from "./fixtures-core";
export * from "./fixtures-registry";
export * from "./fixtures-gateways";
export * from "./fixtures-apps";
