import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  RouterProvider, createRouter, createRootRoute, createRoute, Outlet, Link,
} from "@tanstack/react-router";
import { TriageQueue } from "./routes/TriageQueue";
import { FindingDetail } from "./routes/FindingDetail";
import { Experiments } from "./routes/Experiments";
import { ConfigView } from "./routes/ConfigView";
import { ShieldCheck } from "lucide-react";
import "./index.css";

const rootRoute = createRootRoute({
  component: () => (
    <div className="min-h-screen">
      <header className="border-b sticky top-0 bg-background/95 backdrop-blur z-10">
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center gap-6">
          <div className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="h-5 w-5 text-primary" /> InfoSec Harness
          </div>
          <nav className="flex gap-4 text-sm text-muted-foreground">
            <Link to="/" className="[&.active]:text-foreground hover:text-foreground">Triage</Link>
            <Link to="/experiments" className="[&.active]:text-foreground hover:text-foreground">Experiments</Link>
            <Link to="/config" className="[&.active]:text-foreground hover:text-foreground">Config</Link>
          </nav>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-4 py-6"><Outlet /></main>
    </div>
  ),
});

const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: TriageQueue });
const detailRoute = createRoute({ getParentRoute: () => rootRoute, path: "/runs/$runId", component: FindingDetail });
const expRoute = createRoute({ getParentRoute: () => rootRoute, path: "/experiments", component: Experiments });
const cfgRoute = createRoute({ getParentRoute: () => rootRoute, path: "/config", component: ConfigView });

const routeTree = rootRoute.addChildren([indexRoute, detailRoute, expRoute, cfgRoute]);
const router = createRouter({ routeTree });
declare module "@tanstack/react-router" { interface Register { router: typeof router } }

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5000, refetchInterval: 8000 } } });

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>
);
