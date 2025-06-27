import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { UserPlus, Shield, ShieldOff, Monitor, Smartphone, Calendar, MapPin } from "lucide-react";
import { UserCreationForm } from "./user-creation-form";
import { format } from "date-fns";

interface User {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  companyId?: number;
  isActive: boolean;
  isBlocked: boolean;
  lastLoginAt?: string;
  lastIpAddress?: string;
  deviceInfo?: {
    browser: string;
    os: string;
    device: string;
    userAgent: string;
  };
  createdAt: string;
}

interface UserManagementTableProps {
  users: User[];
  currentUserRole: "super_admin" | "company_admin";
  currentCompanyId?: number;
}

export function UserManagementTable({ users, currentUserRole, currentCompanyId }: UserManagementTableProps) {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const { toast } = useToast();

  const blockUserMutation = useMutation({
    mutationFn: async ({ userId, isBlocked }: { userId: number; isBlocked: boolean }) => {
      const res = await apiRequest("PATCH", `/api/users/${userId}/block`, { isBlocked });
      return res.json();
    },
    onSuccess: (data, variables) => {
      toast({
        title: variables.isBlocked ? "User blocked" : "User unblocked",
        description: `User has been ${variables.isBlocked ? "blocked" : "unblocked"} successfully.`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleBlockUser = (userId: number, isBlocked: boolean) => {
    blockUserMutation.mutate({ userId, isBlocked: !isBlocked });
  };

  const getDeviceIcon = (deviceType?: string) => {
    return deviceType === "Mobile" ? <Smartphone className="h-4 w-4" /> : <Monitor className="h-4 w-4" />;
  };

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case "super_admin": return "bg-red-100 text-red-800";
      case "company_admin": return "bg-blue-100 text-blue-800";
      case "employee": return "bg-green-100 text-green-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusBadgeColor = (isActive: boolean, isBlocked: boolean) => {
    if (isBlocked) return "bg-red-100 text-red-800";
    if (isActive) return "bg-green-100 text-green-800";
    return "bg-gray-100 text-gray-800";
  };

  const getStatusText = (isActive: boolean, isBlocked: boolean) => {
    if (isBlocked) return "Blocked";
    if (isActive) return "Active";
    return "Inactive";
  };

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>User Management</CardTitle>
            <Button onClick={() => setShowCreateForm(true)} className="gap-2">
              <UserPlus className="h-4 w-4" />
              Add User
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Login</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="h-8 w-8 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-medium">
                          {user.firstName[0]}{user.lastName[0]}
                        </div>
                        <div>
                          <div className="font-medium">{user.firstName} {user.lastName}</div>
                          <div className="text-sm text-gray-500">{user.email}</div>
                        </div>
                      </div>
                    </TableCell>
                    
                    <TableCell>
                      <Badge className={getRoleBadgeColor(user.role)}>
                        {user.role.replace('_', ' ').toUpperCase()}
                      </Badge>
                    </TableCell>
                    
                    <TableCell>
                      <Badge className={getStatusBadgeColor(user.isActive, user.isBlocked)}>
                        {getStatusText(user.isActive, user.isBlocked)}
                      </Badge>
                    </TableCell>
                    
                    <TableCell>
                      {user.lastLoginAt ? (
                        <div className="flex items-center gap-1 text-sm">
                          <Calendar className="h-3 w-3" />
                          {format(new Date(user.lastLoginAt), "MMM dd, HH:mm")}
                        </div>
                      ) : (
                        <span className="text-gray-400">Never</span>
                      )}
                    </TableCell>
                    
                    <TableCell>
                      {user.deviceInfo ? (
                        <div className="flex items-center gap-2">
                          {getDeviceIcon(user.deviceInfo.device)}
                          <div className="text-sm">
                            <div>{user.deviceInfo.browser}</div>
                            <div className="text-gray-500">{user.deviceInfo.os}</div>
                          </div>
                        </div>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </TableCell>
                    
                    <TableCell>
                      {user.lastIpAddress ? (
                        <div className="flex items-center gap-1 text-sm">
                          <MapPin className="h-3 w-3" />
                          {user.lastIpAddress}
                        </div>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </TableCell>
                    
                    <TableCell>
                      <Button
                        variant={user.isBlocked ? "outline" : "destructive"}
                        size="sm"
                        onClick={() => handleBlockUser(user.id, user.isBlocked)}
                        disabled={blockUserMutation.isPending}
                        className="gap-1"
                      >
                        {user.isBlocked ? (
                          <>
                            <Shield className="h-3 w-3" />
                            Unblock
                          </>
                        ) : (
                          <>
                            <ShieldOff className="h-3 w-3" />
                            Block
                          </>
                        )}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          
          {users.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              No users found. Click "Add User" to create the first user.
            </div>
          )}
        </CardContent>
      </Card>

      {showCreateForm && (
        <UserCreationForm
          onClose={() => setShowCreateForm(false)}
          userRole={currentUserRole}
          currentCompanyId={currentCompanyId}
        />
      )}
    </>
  );
}