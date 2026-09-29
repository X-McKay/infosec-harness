import { parseFindingSearch } from "@/lib/search";
import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Link,
  Outlet,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import {
  Activity,
  ChartNoAxesCombined,
  FlaskConical,
  ListFilter,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import { ConfigView } from "./routes/ConfigView";
import { Experiments } from "./routes/Experiments";
import { FindingDetail } from "./routes/FindingDetail";
import { Metrics } from "./routes/Metrics";
import { TriageQueue } from "./routes/TriageQueue";
import { Workflows } from "./routes/Workflows";
import "./index.css";

const navigation = [
  ["/", "Findings", ListFilter],
  ["/workflows", "Workflows", Activity],
  ["/experiments", "Evaluations", FlaskConical],
  ["/metrics", "Metrics", ChartNoAxesCombined],
  ["/config", "Settings", Settings2],
] as const;

function Shell() {
  const [theme, setTheme] = useState(
    () => localStorage.getItem("harness-theme") || "system",
  );
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () =>
      document.documentElement.classList.toggle(
        "dark",
        theme === "dark" || (theme === "system" && media.matches),
      );
    apply();
    localStorage.setItem("harness-theme", theme);
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
  return (
    <div className="min-h-screen md:pl-56">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 z-50 bg-background p-3"
      >
        Skip to content
      </a>
      <aside className="sidebar flex gap-4 border-b p-4 md:fixed md:inset-y-0 md:left-0 md:w-56 md:flex-col md:border-r">
        <div className="flex items-center gap-2 py-3 text-sm font-semibold">
          <ShieldCheck className="h-5 w-5 text-primary" /> Harness{" "}
          <span className="rounded border px-1 text-[10px] text-muted-foreground">
            LOCAL
          </span>
        </div>
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
              <Icon className="h-4 w-4 shrink-0" />
              <span>{label}</span>
            </Link>
          ))}
        </nav>
        <label className="appearance-control shrink-0 text-xs text-muted-foreground md:mt-auto">
          Appearance
          <select
            aria-label="Appearance"
            className="field mt-2 w-full"
            value={theme}
            onChange={(event) => setTheme(event.target.value)}
          >
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
      </aside>
      <main id="content" className="mx-auto max-w-[1600px] px-5 py-8 lg:px-10">
        <Outlet />
      </main>
    </div>
  );
}

const rootRoute = createRootRoute({ component: Shell });
const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: TriageQueue,
  validateSearch: parseFindingSearch,
});
const detailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/runs/$runId",
  component: FindingDetail,
});
const expRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/experiments",
  component: Experiments,
});
const cfgRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/config",
  component: ConfigView,
});
const metricsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/metrics",
  component: Metrics,
});
const workflowsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/workflows",
  component: Workflows,
});
const router = createRouter({
  routeTree: rootRoute.addChildren([
    indexRoute,
    detailRoute,
    expRoute,
    cfgRoute,
    metricsRoute,
    workflowsRoute,
  ]),
});
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5000, retry: 1, refetchIntervalInBackground: false },
  },
});
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
