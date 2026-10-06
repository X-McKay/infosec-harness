import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Link,
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router";
import { FileText, ListFilter, Settings2, ShieldCheck } from "lucide-react";
import { RuntimeIndicator } from "@/components/RuntimeIndicator";
import { ThemeProvider, ThemeSelect } from "@/components/ThemeProvider";
import { Card, CardContent } from "@/components/ui/card";
import { parseDetailSearch, parseInvestigationSearch } from "@/lib/search";
import { InvestigationDetail } from "@/routes/InvestigationDetail";
import { Investigations } from "@/routes/Investigations";
import { Runtime } from "@/routes/Runtime";
import { Qualification, Reports } from "@/routes/placeholders";
import "./index.css";

const navigation = [
  ["/", "Investigations", ListFilter],
  ["/reports", "Reports", FileText],
  ["/qualification", "Qualification", ShieldCheck],
  ["/runtime", "Runtime", Settings2],
] as const;

function Shell() {
  return (
    <div className="min-h-screen md:pl-56">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 z-50 bg-background p-3"
      >
        Skip to content
      </a>
      <aside className="sidebar flex gap-4 border-b p-4 md:fixed md:inset-y-0 md:left-0 md:w-56 md:flex-col md:border-r">
        <Link
          to="/"
          className="flex items-center gap-2 py-3 text-sm font-semibold"
        >
          <ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />{" "}
          InfoSec Harness
        </Link>
        <RuntimeIndicator />
        <nav
          aria-label="Main navigation"
          className="flex min-w-0 flex-1 gap-1 overflow-x-auto md:flex-col"
        >
          {navigation.map(([to, label, Icon]) => (
            <Link
              key={to}
              to={to}
              activeOptions={{ exact: to === "/" }}
              className="nav-link"
              activeProps={{
                className: "nav-link selected",
                "aria-current": "page",
              }}
            >
              <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{label}</span>
            </Link>
          ))}
        </nav>
        <label className="appearance-control shrink-0 text-xs text-muted-foreground md:mt-auto">
          Appearance
          <ThemeSelect className="field mt-2 w-full" />
        </label>
      </aside>
      <main id="content" className="mx-auto max-w-[1600px] px-5 py-8 lg:px-10">
        <Outlet />
      </main>
    </div>
  );
}

function NotFound() {
  return (
    <Card>
      <CardContent className="space-y-3 pt-6">
        <h1>Page not found</h1>
        <Link to="/" className="text-sm text-primary underline">
          Back to investigations
        </Link>
      </CardContent>
    </Card>
  );
}

const rootRoute = createRootRoute({
  component: Shell,
  notFoundComponent: NotFound,
});
const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: Investigations,
  validateSearch: parseInvestigationSearch,
});
const detailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/runs/$runId",
  component: InvestigationDetail,
  validateSearch: parseDetailSearch,
});
const runtimeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/runtime",
  component: Runtime,
});
// Placeholders; the reports and qualification change replaces these two routes.
const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reports",
  component: Reports,
});
const qualificationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/qualification",
  component: Qualification,
});
const router = createRouter({
  routeTree: rootRoute.addChildren([
    indexRoute,
    detailRoute,
    runtimeRoute,
    reportsRoute,
    qualificationRoute,
  ]),
});
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 2000, retry: 1, refetchIntervalInBackground: false },
  },
});
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <RouterProvider router={router} />
      </ThemeProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
