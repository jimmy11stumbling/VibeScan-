import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";

import { Layout } from "@/components/layout";
import LandingPage from "@/pages/landing";
import DashboardPage from "@/pages/dashboard";
import ScanFormPage from "@/pages/scan-form";
import ScanProgressPage from "@/pages/scan-progress";
import ReportViewer from "@/pages/report-viewer";
import MonitorPage from "@/pages/monitor";
import SharedReport from "@/pages/shared-report";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

function Router() {
  return (
    <Switch>
      {/* Public share page — rendered without the app Layout (no nav/auth required) */}
      <Route path="/share/:token" component={SharedReport} />

      {/* All other routes wrapped in the authenticated Layout */}
      <Route>
        <Layout>
          <Switch>
            <Route path="/" component={LandingPage} />
            <Route path="/dashboard" component={DashboardPage} />
            <Route path="/scan" component={ScanFormPage} />
            <Route path="/scan/:id" component={ScanProgressPage} />
            <Route path="/report/:id" component={ReportViewer} />
            <Route path="/monitor" component={MonitorPage} />
            <Route component={NotFound} />
          </Switch>
        </Layout>
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
