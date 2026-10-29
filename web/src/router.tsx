import { Outlet, createRootRoute, createRoute, createRouter, lazyRouteComponent } from "@tanstack/react-router";
import { type ReactNode } from "react";
import { AppLayout } from "./components/layout/shell";
import { NotFoundState } from "./components/not-found";
import { adminTeamTabs, authProviderTabs, gatewayTabs, serverTabs, serviceAccountTabs, tabSearch, teamSettingsTabs } from "./lib/tabs";
import { InstanceSync, SignInPage, useCurrentUser, useMe } from "./session";
import { useSessionUnavailable } from "./components/layout/session-unavailable";
import { ColorModeSync } from "./components/layout/theme";
import { Loading } from "@/components/ui/spinner/spinner";
import { Toaster } from "@/components/ui/toast/toast";
import styles from "./router.module.css";

/*
 * Pages load on demand, one chunk per page module (a feature folder's
 * routes.ts groups its pages into one); the shell (router, session, layout
 * and UI library) stays in the main bundle.
 *
 * Areas: the team's MCP servers and gateways under teams/$team, the Catalog
 * and My gateways at the top level, API keys, Connected apps and Notification
 * settings next to Profile, the Inbox (/notifications), the team's Service
 * accounts, MCP servers, Publishing, Internal networks, Gateways, Trusted
 * clients, Auth providers, Automation tokens, Notifications and Calls under
 * admin (the Overview is the admin portal's first page).
 * The OAuth consent page (/oauth/consent) and the account-connect pages
 * (/connect/$provider, /connect/done) sit outside the app's shell. Later
 * phases add theirs here and in components/layout/nav.tsx.
 */
const pages = {
  home: () => import("./pages/home"),
  account: () => import("./pages/account/routes"),
  people: () => import("./pages/admin/people/routes"),
  adminAudit: () => import("./pages/admin/audit/page"),
  teamLayout: () => import("./pages/team/layout"),
  teamSettings: () => import("./pages/team/settings/page"),
  teamServers: () => import("./pages/team/servers/routes"),
  catalog: () => import("./pages/catalog/routes"),
  adminServers: () => import("./pages/admin/servers/routes"),
  adminNetworks: () => import("./pages/admin/networks/routes"),
  teamGateways: () => import("./pages/team/gateways/routes"),
  myGateways: () => import("./pages/gateways/routes"),
  adminGateways: () => import("./pages/admin/gateways/routes"),
  oauth: () => import("./pages/oauth/routes"),
  adminOAuth: () => import("./pages/admin/oauth/routes"),
  serviceAccounts: () => import("./pages/team/service-accounts/routes"),
  adminProviders: () => import("./pages/admin/providers/routes"),
  connect: () => import("./pages/connect/routes"),
  teamUsage: () => import("./pages/team/usage"),
  teamCalls: () => import("./pages/team/calls/routes"),
  adminOperations: () => import("./pages/admin/operations/routes"),
  adminOverview: () => import("./pages/admin/overview/routes"),
  adminNotifications: () => import("./pages/admin/notifications/routes"),
  adminTokens: () => import("./pages/admin/automation-tokens/routes"),
  inbox: () => import("./pages/notifications/routes"),
  approvals: () => import("./pages/approvals/routes"),
  accessRequests: () => import("./pages/access-requests/routes"),
};
const lazy = lazyRouteComponent;
type Page = ReturnType<typeof lazyRouteComponent>;

/**
 * Shows the sign-in page until there is a session. While the session can't
 * load (a rate limit, a server error), a page says so and retries; once it
 * has loaded, a failed background refresh keeps the app as it is.
 */
function SessionGate({ children }: { children: ReactNode }) {
  const me = useMe();
  const unavailable = useSessionUnavailable(me);
  if (me.data === undefined) return unavailable ?? <Loading className={styles.fullPage} label="Loading…" />;
  if (!me.data) return <SignInPage />;
  return <>{children}</>;
}

/**
 * The admin portal is only for platform admins and auditors. Others get the
 * no-access page in the workspace shell, and no admin page (or admin API
 * request) is loaded.
 */
function AdminGate() {
  const { capabilities } = useCurrentUser();
  if (!capabilities.platformAdmin && !capabilities.platformAuditor) return <NotFoundState what="forbidden" />;
  return <Outlet />;
}

function Root() {
  // Toasts sit over the sidebar's footer, so they never cover page content.
  return (
    <>
      <InstanceSync />
      <ColorModeSync />
      <Outlet />
      <Toaster position="bottom-left" />
    </>
  );
}

// The session gate wraps the app (not the root), so routes outside it stay possible. Route ids are "/app/...".
const rootRoute = createRootRoute({
  component: Root,
  notFoundComponent: () => (
    <SessionGate>
      <AppLayout>
        <NotFoundState />
      </AppLayout>
    </SessionGate>
  ),
});
const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  component: () => (
    <SessionGate>
      <AppLayout />
    </SessionGate>
  ),
});

const approvalsRoute = createRoute({ getParentRoute: () => appRoute, path: "approvals", component: lazy(pages.approvals, "ApprovalsPage") });
const approvalRoute = createRoute({ getParentRoute: () => appRoute, path: "approvals/$approvalId", component: lazy(pages.approvals, "ApprovalPage") });
const accessRequestsRoute = createRoute({ getParentRoute: () => appRoute, path: "access-requests", component: lazy(pages.accessRequests, "AccessRequestsPage") });
const accessRequestRoute = createRoute({ getParentRoute: () => appRoute, path: "access-requests/$requestId", component: lazy(pages.accessRequests, "AccessRequestPage") });
const homeRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: lazy(pages.home, "HomePage") });
const sessionsRoute = createRoute({ getParentRoute: () => appRoute, path: "settings/sessions", component: lazy(pages.account, "SessionsPage") });
const profileRoute = createRoute({ getParentRoute: () => appRoute, path: "settings/profile", component: lazy(pages.account, "ProfilePage") });
/** The person's API keys; the status filter (?status=) passes through. */
const apiKeysRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "settings/api-keys",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.account, "ApiKeysPage"),
});
/** The MCP clients the person allowed with OAuth sign-in. */
const connectedAppsRoute = createRoute({ getParentRoute: () => appRoute, path: "settings/connected-apps", component: lazy(pages.oauth, "ConnectedAppsPage") });
/** The accounts the person connected with auth providers (GitHub, Google…) so tools can act as them; ?connected= after connecting from here. */
const myConnectionsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "settings/connections",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.account, "MyConnectionsPage"),
});

/** The person's notification preferences: events x In-app / Email. */
const notificationSettingsRoute = createRoute({ getParentRoute: () => appRoute, path: "settings/notifications", component: lazy(pages.account, "NotificationSettingsPage") });
/** The inbox (the bell's "View all"); ?unread=true passes through. */
const inboxRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "notifications",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.inbox, "InboxPage"),
});

/* ---------------- my gateways (everyone signed in) ---------------- */

/** Gateways the person can use; ?q= passes through. */
const myGatewaysRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "gateways",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.myGateways, "MyGatewaysPage"),
});
const myGatewayRoute = createRoute({ getParentRoute: () => appRoute, path: "gateways/$gatewayId", component: lazy(pages.myGateways, "MyGatewayPage") });

/* ---------------- the catalog (everyone signed in) ---------------- */

/** Published servers; ?q= passes through. */
const catalogRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "catalog",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.catalog, "CatalogPage"),
});
const catalogServerRoute = createRoute({ getParentRoute: () => appRoute, path: "catalog/$serverId", component: lazy(pages.catalog, "CatalogServerPage") });

/* ---------------- a team (workspace) ---------------- */

const teamRoute = createRoute({ getParentRoute: () => appRoute, path: "teams/$team", component: lazy(pages.teamLayout, "TeamLayout") });
const teamApprovalRulesRoute = createRoute({ getParentRoute: () => teamRoute, path: "approval-rules", component: lazy(pages.approvals, "TeamApprovalRulesPage") });
const teamIndexRoute = createRoute({ getParentRoute: () => teamRoute, path: "/", component: lazy(pages.teamLayout, "TeamOverviewPage") });
/** Members · Audit log · General; ?record= (an audit entry) and the log's filters pass through. */
const teamSettingsRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "settings",
  validateSearch: tabSearch(teamSettingsTabs, { passthrough: true }),
  component: lazy(pages.teamSettings, "TeamSettingsPage"),
});
/** The team's MCP servers; ?q= and the add form (?form=new) pass through. */
const teamServersRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "servers",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.teamServers, "TeamServersPage"),
});
/** A server: Overview · Capabilities · Health · Settings; the capabilities' filters (?kind=, ?state=) pass through. */
const teamServerRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "servers/$serverId",
  validateSearch: tabSearch(serverTabs, { passthrough: true }),
  component: lazy(pages.teamServers, "TeamServerPage"),
});

/** The team's gateways; ?q= and the create form (?form=new) pass through. */
const teamGatewaysRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "gateways",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.teamGateways, "TeamGatewaysPage"),
});
/** A gateway: Overview · Capabilities · Activity · Settings; the activity's filters pass through. */
const teamGatewayRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "gateways/$gatewayId",
  validateSearch: tabSearch(gatewayTabs, { passthrough: true }),
  component: lazy(pages.teamGateways, "TeamGatewayPage"),
});

/** The team's service accounts; ?q= and the create form (?form=new) pass through. */
const teamServiceAccountsRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "service-accounts",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.serviceAccounts, "ServiceAccountsPage"),
});
/** A service account: Overview · Keys · Settings; the keys' filters pass through. */
const teamServiceAccountRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "service-accounts/$serviceAccountId",
  validateSearch: tabSearch(serviceAccountTabs, { passthrough: true }),
  component: lazy(pages.serviceAccounts, "ServiceAccountPage"),
});

/** The team's usage; the range and grouping (?range=, ?groupBy=…) pass through. */
const teamUsageRoute = createRoute({
  getParentRoute: () => teamRoute,
  path: "usage",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: lazy(pages.teamUsage, "TeamUsagePage"),
});
/** One of the team's call records (linked from the gateways' Activity tabs). */
const teamCallRoute = createRoute({ getParentRoute: () => teamRoute, path: "calls/$callId", component: lazy(pages.teamCalls, "TeamCallPage") });

/* ---------------- admin ---------------- */

const adminRoute = createRoute({ getParentRoute: () => appRoute, path: "admin", component: AdminGate });
/** The admin portal opens on the Overview: what needs attention. */
const adminIndexRoute = createRoute({ getParentRoute: () => adminRoute, path: "/", component: lazy(pages.adminOverview, "AdminOverviewPage") });
/** An admin list page whose filters (?q=, ?status=…) and open record (?record=) live in the URL. */
const adminList = <P extends string>(path: P, component: Page) =>
  createRoute({ getParentRoute: () => adminRoute, path, validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s, component });
/** An admin page with tabs; list filters, ?q= and ?record= pass through. */
const adminTabs = <P extends string, T extends string>(path: P, tabs: readonly T[], component: Page) =>
  createRoute({ getParentRoute: () => adminRoute, path, validateSearch: tabSearch(tabs, { passthrough: true }), component });

const appTree = appRoute.addChildren([
  homeRoute,
  approvalsRoute,
  approvalRoute,
  accessRequestsRoute,
  accessRequestRoute,
  profileRoute,
  sessionsRoute,
  apiKeysRoute,
  connectedAppsRoute,
  myConnectionsRoute,
  notificationSettingsRoute,
  inboxRoute,
  catalogRoute,
  catalogServerRoute,
  myGatewaysRoute,
  myGatewayRoute,
  teamRoute.addChildren([
    teamIndexRoute,
    teamApprovalRulesRoute,
    teamSettingsRoute,
    teamServersRoute,
    teamServerRoute,
    teamGatewaysRoute,
    teamGatewayRoute,
    teamServiceAccountsRoute,
    teamServiceAccountRoute,
    teamUsageRoute,
    teamCallRoute,
  ]),
  adminRoute.addChildren([
    adminIndexRoute,
    adminList("approval-rules", lazy(pages.approvals, "AdminApprovalRulesPage")),
    adminList("users", lazy(pages.people, "AdminUsersPage")),
    adminList("users/$userId", lazy(pages.people, "AdminUserPage")),
    adminList("teams", lazy(pages.people, "AdminTeamsPage")),
    adminTabs("teams/$team", adminTeamTabs, lazy(pages.people, "AdminTeamPage")),
    adminList("servers", lazy(pages.adminServers, "AdminServersPage")),
    adminTabs("servers/$serverId", serverTabs, lazy(pages.adminServers, "AdminServerPage")),
    adminList("publishing", lazy(pages.adminServers, "AdminPublishingPage")),
    adminList("networks", lazy(pages.adminNetworks, "AdminNetworksPage")),
    adminList("gateways", lazy(pages.adminGateways, "AdminGatewaysPage")),
    adminTabs("gateways/$gatewayId", gatewayTabs, lazy(pages.adminGateways, "AdminGatewayPage")),
    adminList("trusted-clients", lazy(pages.adminOAuth, "AdminTrustedClientsPage")),
    adminList("auth-providers", lazy(pages.adminProviders, "AdminAuthProvidersPage")),
    adminTabs("auth-providers/$providerId", authProviderTabs, lazy(pages.adminProviders, "AdminAuthProviderPage")),
    adminList("automation-tokens", lazy(pages.adminTokens, "AdminAutomationTokensPage")),
    adminList("notifications", lazy(pages.adminNotifications, "AdminNotificationsPage")),
    adminList("calls", lazy(pages.adminGateways, "AdminCallsPage")),
    adminList("calls/$callId", lazy(pages.adminGateways, "AdminCallPage")),
    adminList("usage", lazy(pages.adminOperations, "AdminUsagePage")),
    adminList("limits", lazy(pages.adminOperations, "AdminLimitsPage")),
    adminList("retention", lazy(pages.adminOperations, "AdminRetentionPage")),
    adminList("capture", lazy(pages.adminOperations, "AdminCapturePage")),
    adminList("audit", lazy(pages.adminAudit, "AdminAuditPage")),
  ]),
]);

/*
 * The OAuth consent page: no app shell (nothing to wander off to while a client waits), but it needs a
 * session. Signed out, the sign-in page returns here with the whole authorization request.
 */
const ConsentPage = lazy(pages.oauth, "OAuthConsentPage");
const oauthConsentRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "oauth/consent",
  component: () => (
    <SessionGate>
      <ConsentPage />
    </SessionGate>
  ),
});

/*
 * Connecting an account (docs/phase5-delegated-credentials.md): the link a tool's -32042 answer carries
 * (/connect/{provider}?request=…) and where the callback sends the browser afterwards (/connect/done). No app
 * shell, like the consent page. The confirm page needs the session of the person the link was made for; signed
 * out, the sign-in page returns here with the whole query. The result page says only what happened.
 */
const ConnectPage = lazy(pages.connect, "ConnectPage");
const connectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "connect/$provider",
  validateSearch: (s: Record<string, unknown>): Record<string, unknown> => s,
  component: () => (
    <SessionGate>
      <ConnectPage />
    </SessionGate>
  ),
});
const connectDoneRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "connect/done",
  validateSearch: ({ context, ...s }: Record<string, unknown>): Record<string, unknown> => ({ ...s, ...(context === "service" ? { context } : {}) }),
  component: lazy(pages.connect, "ConnectDonePage"),
});

/** The link a call returns when a server wants the person's own key (decision 72). */
const ConnectSecretPage = lazy(pages.connect, "ConnectSecretPage");
const connectSecretRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "connect/secret/$requestId",
  component: () => (
    <SessionGate>
      <ConnectSecretPage />
    </SessionGate>
  ),
});

export const routeTree = rootRoute.addChildren([appTree, oauthConsentRoute, connectDoneRoute, connectRoute, connectSecretRoute]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  // Shown while a page's chunk loads (after a short delay, so fast loads don't flash).
  defaultPendingComponent: () => <Loading className={styles.pending} label="Loading…" />,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
