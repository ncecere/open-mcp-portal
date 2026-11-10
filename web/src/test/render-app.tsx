/* Renders the whole app (the real route tree) at a path. Apart from harness.tsx: importing this evaluates the router. */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory, createRouter } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import { routeTree } from "../router";
// For its hooks (unstubbing fetch, clearing storage, window.scrollTo): a test may import only renderApp.
import "./harness";

export function renderApp(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: [path] }) });
  const utils = render(
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { ...utils, router, qc };
}
