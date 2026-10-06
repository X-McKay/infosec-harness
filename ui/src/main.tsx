import React, { useEffect, useRef } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Link,
  Outlet,
  RouterProvider,
  createRootRoute,
  createRoute,
  createRouter,
  useNavigate,
  useParams,
  useRouterState,
  useSearch,
} from "@tanstack/react-router";
import {
  ChartLine,
  FileText,
  ListFilter,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import { RuntimeIndicator } from "@/components/RuntimeIndicator";
import { ThemeProvider, ThemeSelect } from "@/components/ThemeProvider";
import {
  EvaluationLinkProvider,
  type EvalLinkProps,
} from "@/components/evaluations/links";
import { Card, CardContent } from "@/components/ui/card";
import { isReportName } from "@/lib/reports";
import {
  ownedSearch,
  parseCaseFilters,
  parseDetailSearch,
  parseInvestigationSearch,
  parseReportsSearch,
} from "@/lib/search";
import { InvestigationDetail } from "@/routes/InvestigationDetail";
import { Investigations } from "@/routes/Investigations";
import { Metrics } from "@/routes/Metrics";
import { Qualification } from "@/routes/Qualification";
import { ReportDetail } from "@/routes/ReportDetail";
import { Reports } from "@/routes/Reports";
import { Runtime } from "@/routes/Runtime";
import "./index.css";

const navigation = [
  ["/", "Investigations", ListFilter],
  ["/reports", "Reports", FileText],
  ["/metrics", "Metrics", ChartLine],
  ["/qualification", "Qualification", ShieldCheck],
  ["/runtime", "Runtime", Settings2],
] as const;

/**
 * Evaluation views build hrefs only with `reportPath`/`runPath` from validated report names
 * and workflow IDs (or the literal "/reports"); this renders them as client-side links.
 */
function RouterLink({ href, ...props }: EvalLinkProps) {
  return <Link to={href} {...props} />;
}

/**
 * At 768px and wider: the fixed sidebar (brand, runtime summary, navigation, appearance).
 * Below that: a compact header with the brand, runtime summary and appearance on one row and
 * the navigation as a horizontally scrolling row that keeps the current route in view.
 */
function Shell() {
  const pathname = useRouterState({
    select: (state) => state.location.pathname,
  });
  const nav = useRef<HTMLElement>(null);
  useEffect(() => {
    const element = nav.current;
    const current = element?.querySelector<HTMLElement>("[aria-current=page]");
    if (!element || !current || element.scrollWidth <= element.clientWidth)
      return;
    // Horizontal only: never scroll the page itself.
    element.scrollLeft =
      current.offsetLeft - (element.clientWidth - current.offsetWidth) / 2;
  }, [pathname]);
  return (
    <div className="min-h-screen md:pl-56">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 z-50 bg-background p-3"
      >
        Skip to content
      </a>
      <aside className="sidebar border-b md:fixed md:inset-y-0 md:left-0 md:flex md:w-56 md:flex-col md:gap-4 md:border-b-0 md:border-r md:p-4">
        <div className="flex items-start gap-3 px-4 pb-2 pt-3 md:block md:p-0">
          <div className="min-w-0 flex-1 space-y-1 md:space-y-0">
            <Link
              to="/"
              className="flex w-fit items-center gap-2 rounded text-sm font-semibold md:py-3"
            >
              <ShieldCheck
                className="h-5 w-5 shrink-0 text-primary"
                aria-hidden="true"
              />
              InfoSec Harness
            </Link>
            <RuntimeIndicator />
          </div>
          <ThemeSelect className="field h-8 w-[6.5rem] shrink-0 py-1 text-xs md:hidden" />
        </div>
        <nav
          ref={nav}
          aria-label="Main navigation"
          className="nav-row flex min-w-0 gap-1 overflow-x-auto px-3 pb-2 md:flex-1 md:flex-col md:overflow-visible md:p-0"
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
        <label className="hidden w-32 shrink-0 text-xs text-muted-foreground md:mt-auto md:block">
          Appearance
          <ThemeSelect className="field mt-2 w-full" />
        </label>
      </aside>
      <main
        id="content"
        className="mx-auto max-w-[1600px] px-4 py-5 sm:px-5 md:py-8 lg:px-10"
      >
        <Outlet />
      </main>
    </div>
  );
}

/** `/reports/$name`: only a validated report file name reaches the view or the API. */
function ReportRoute() {
  const { name } = useParams({ from: "/reports/$name" });
  const filters = useSearch({ from: "/reports/$name" });
  const navigate = useNavigate({ from: "/reports/$name" });
  if (!isReportName(name)) return <NotFound />;
  return (
    <ReportDetail
      name={name}
      caseFilters={filters}
      onCaseFilters={(next) =>
        void navigate({ search: next, replace: true, resetScroll: false })
      }
    />
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
  validateSearch: ownedSearch(
    ["q", "status", "verdict", "page"],
    parseInvestigationSearch,
  ),
});
const detailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/runs/$runId",
  component: InvestigationDetail,
  validateSearch: ownedSearch(
    ["q", "status", "verdict", "page", "from_queue"],
    parseDetailSearch,
  ),
});
const runtimeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/runtime",
  component: Runtime,
});
const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reports",
  component: Reports,
  validateSearch: ownedSearch(["kind"], parseReportsSearch),
});
const reportRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reports/$name",
  component: ReportRoute,
  validateSearch: ownedSearch(
    ["case", "outcome", "language"],
    parseCaseFilters,
  ),
});
const metricsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/metrics",
  component: Metrics,
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
    reportRoute,
    metricsRoute,
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
        <EvaluationLinkProvider value={RouterLink}>
          <RouterProvider router={router} />
        </EvaluationLinkProvider>
      </ThemeProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
