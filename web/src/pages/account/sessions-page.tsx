import { BrowserSessions } from "@/components/sessions/browser-sessions";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";

export function SessionsPage() {
  return <Stack gap={6}>
    <PageHeader title="Sessions" description="Where you are signed in to the portal. Sign out a lost device, or end every browser sign-in." />
    <BrowserSessions owner={{ self: true }} />
  </Stack>;
}
