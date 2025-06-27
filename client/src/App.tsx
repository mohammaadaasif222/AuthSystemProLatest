import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/hooks/use-auth";
import { ProtectedRoute } from "./lib/protected-route";
import NotFound from "@/pages/not-found";
import AuthPage from "@/pages/auth-page";
import SuperAdminDashboard from "@/pages/super-admin-dashboard";
import CompanyAdminDashboard from "@/pages/company-admin-dashboard";
import EmployeeDashboard from "@/pages/employee-dashboard";

function Router() {
  return (
    <Switch>
      <ProtectedRoute path="/" component={SuperAdminDashboard} allowedRoles={["super_admin"]} />
      <ProtectedRoute path="/company-admin" component={CompanyAdminDashboard} allowedRoles={["company_admin"]} />
      <ProtectedRoute path="/employee" component={EmployeeDashboard} allowedRoles={["employee"]} />
      <Route path="/auth" component={AuthPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <AuthProvider>
          <Toaster />
          <Router />
        </AuthProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
