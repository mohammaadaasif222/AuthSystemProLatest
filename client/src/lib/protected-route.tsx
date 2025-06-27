import { useAuth } from "@/hooks/use-auth";
import { Loader2 } from "lucide-react";
import { Redirect, Route, useLocation } from "wouter";
import { useEffect } from "react";

interface ProtectedRouteProps {
  path: string;
  component: () => React.JSX.Element;
  allowedRoles: string[];
}

export function ProtectedRoute({
  path,
  component: Component,
  allowedRoles,
}: ProtectedRouteProps) {
  const { user, isLoading } = useAuth();
  const [, setLocation] = useLocation();

  useEffect(() => {
    if (user && allowedRoles.includes(user.role)) {
      // User is authorized for this route
      return;
    }
    
    if (user && !allowedRoles.includes(user.role)) {
      // User is authenticated but not authorized - redirect to their dashboard
      switch (user.role) {
        case "super_admin":
          setLocation("/");
          break;
        case "company_admin":
          setLocation("/company-admin");
          break;
        case "employee":
          setLocation("/employee");
          break;
        default:
          setLocation("/auth");
      }
    }
  }, [user, allowedRoles, setLocation]);

  if (isLoading) {
    return (
      <Route path={path}>
        <div className="flex items-center justify-center min-h-screen">
          <Loader2 className="h-8 w-8 animate-spin text-border" />
        </div>
      </Route>
    );
  }

  if (!user) {
    return (
      <Route path={path}>
        <Redirect to="/auth" />
      </Route>
    );
  }

  if (!allowedRoles.includes(user.role)) {
    return null; // Will be handled by useEffect redirect
  }

  return (
    <Route path={path}>
      <Component />
    </Route>
  );
}
