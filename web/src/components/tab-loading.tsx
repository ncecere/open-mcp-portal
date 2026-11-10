/*
 * A record's heavy tabs (a server's Settings and Capabilities, a gateway's Settings and capability picker) load
 * when first opened, not with the record: TabsPanel only renders the active tab, so their code isn't needed before.
 * `lazyTab` wraps React.lazy for a named export; `TabLoading` is the Suspense fallback while the chunk arrives.
 */
import { type ComponentType, lazy, type ReactNode, Suspense } from "react";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";

/** React.lazy for a module's named component: `lazyTab(() => import("./settings-tab"), "ServerSettingsTab")`. */
// `any`: a component with any props, as React.lazy itself takes it.
export function lazyTab<M extends Record<K, ComponentType<any>>, K extends keyof M & string>(load: () => Promise<M>, name: K) {
  return lazy(async () => ({ default: (await load())[name] }));
}

/** Shows a few skeleton lines until the tab's code has loaded. */
export function TabLoading({ children }: { children: ReactNode }) {
  return (
    <Suspense
      fallback={
        <div role="status" aria-label="Loading…">
          <SkeletonText lines={4} />
        </div>
      }
    >
      {children}
    </Suspense>
  );
}
