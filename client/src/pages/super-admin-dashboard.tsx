import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Crown, Building, UserCheck, Users, Video, Plus, Edit, Trash2, LogOut, Database } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { insertCompanySchema, insertUserSchema } from "@shared/schema";
import { z } from "zod";
import { useToast } from "@/hooks/use-toast";
import { DatabaseQueryInterface } from "@/components/database-query-interface";
import { UserManagementTable } from "@/components/user-management-table";
import { VideoMeeting } from "@/components/video-meeting";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function SuperAdminDashboard() {
  const { user, logoutMutation } = useAuth();
  const { toast } = useToast();
  const [showCreateCompany, setShowCreateCompany] = useState(false);
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [showDatabaseQuery, setShowDatabaseQuery] = useState(false);

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ["/api/stats"],
  });

  // Fetch companies
  const { data: companies = [] } = useQuery({
    queryKey: ["/api/companies"],
  });

  // Fetch users
  const { data: users = [] } = useQuery({
    queryKey: ["/api/users"],
  });

  // Create company form
  const companyForm = useForm<z.infer<typeof insertCompanySchema>>({
    resolver: zodResolver(insertCompanySchema),
    defaultValues: {
      name: "",
      description: "",
      isActive: true,
    },
  });

  // Create user form
  const userForm = useForm<z.infer<typeof insertUserSchema>>({
    resolver: zodResolver(insertUserSchema),
    defaultValues: {
      email: "",
      password: "",
      firstName: "",
      lastName: "",
      role: "employee",
      companyId: null,
      isActive: true,
    },
  });

  // Create company mutation
  const createCompanyMutation = useMutation({
    mutationFn: async (data: z.infer<typeof insertCompanySchema>) => {
      const res = await apiRequest("POST", "/api/companies", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/companies"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      setShowCreateCompany(false);
      companyForm.reset();
      toast({
        title: "Company created",
        description: "Company has been created successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Create user mutation
  const createUserMutation = useMutation({
    mutationFn: async (data: z.infer<typeof insertUserSchema>) => {
      const endpoint = data.role === "company_admin" 
        ? "/api/users/create-company-admin" 
        : "/api/users/create-employee";
      const res = await apiRequest("POST", endpoint, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      setShowCreateUser(false);
      userForm.reset();
      toast({
        title: "User created",
        description: "User has been created successfully.",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="bg-red-500 text-white p-2 rounded-lg mr-3">
                <Crown className="h-5 w-5" />
              </div>
              <h1 className="text-xl font-semibold text-gray-900">Super Admin Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDatabaseQuery(true)}
                className="text-gray-600 hover:text-gray-900"
              >
                <Database className="h-4 w-4" />
              </Button>
              <span className="text-sm text-gray-600">{user?.firstName} {user?.lastName}</span>
              <div className="h-8 w-8 bg-red-500 text-white rounded-full flex items-center justify-center text-sm font-medium">
                {user?.firstName?.[0]}{user?.lastName?.[0]}
              </div>
              <Button variant="ghost" size="sm" onClick={handleLogout}>
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="bg-blue-100 p-3 rounded-full">
                  <Building className="h-6 w-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm text-gray-600">Total Companies</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats?.companies || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="bg-orange-100 p-3 rounded-full">
                  <UserCheck className="h-6 w-6 text-orange-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm text-gray-600">Company Admins</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats?.companyAdmins || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="bg-green-100 p-3 rounded-full">
                  <Users className="h-6 w-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm text-gray-600">Employees</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats?.employees || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="bg-purple-100 p-3 rounded-full">
                  <Video className="h-6 w-6 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm text-gray-600">Active Meetings</p>
                  <p className="text-2xl font-semibold text-gray-900">{stats?.meetings || 0}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="users" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="users">User Management</TabsTrigger>
            <TabsTrigger value="companies">Companies</TabsTrigger>
            <TabsTrigger value="meetings">Meetings</TabsTrigger>
            <TabsTrigger value="database">Database</TabsTrigger>
          </TabsList>

          <TabsContent value="users" className="space-y-6">
            <UserManagementTable 
              users={users as any[]} 
              currentUserRole="super_admin"
            />
          </TabsContent>

          <TabsContent value="companies" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <CardTitle>Company Management</CardTitle>
                  <Dialog open={showCreateCompany} onOpenChange={setShowCreateCompany}>
                    <DialogTrigger asChild>
                      <Button className="bg-blue-600 hover:bg-blue-700">
                        <Plus className="h-4 w-4 mr-2" />
                        Create Company
                      </Button>
                    </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Create New Company</DialogTitle>
                      <DialogDescription>
                        Add a new company to the system.
                      </DialogDescription>
                    </DialogHeader>
                    <Form {...companyForm}>
                      <form onSubmit={companyForm.handleSubmit((data) => createCompanyMutation.mutate(data))} className="space-y-4">
                        <FormField
                          control={companyForm.control}
                          name="name"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Company Name</FormLabel>
                              <FormControl>
                                <Input placeholder="Tech Solutions Inc." {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={companyForm.control}
                          name="description"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Description</FormLabel>
                              <FormControl>
                                <Input placeholder="Technology consulting company" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <Button type="submit" disabled={createCompanyMutation.isPending}>
                          {createCompanyMutation.isPending ? "Creating..." : "Create Company"}
                        </Button>
                      </form>
                    </Form>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {companies.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No companies created yet</p>
                ) : (
                  companies.map((company: any) => (
                    <div key={company.id} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                      <div>
                        <h3 className="font-medium text-gray-900">{company.name}</h3>
                        <p className="text-sm text-gray-600">{company.description}</p>
                      </div>
                      <div className="flex space-x-2">
                        <Button variant="ghost" size="sm">
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* User Management */}
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>User Management</CardTitle>
                <Dialog open={showCreateUser} onOpenChange={setShowCreateUser}>
                  <DialogTrigger asChild>
                    <Button className="bg-green-600 hover:bg-green-700">
                      <Plus className="h-4 w-4 mr-2" />
                      Create User
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Create New User</DialogTitle>
                      <DialogDescription>
                        Add a new user to the system.
                      </DialogDescription>
                    </DialogHeader>
                    <Form {...userForm}>
                      <form onSubmit={userForm.handleSubmit((data) => createUserMutation.mutate(data))} className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <FormField
                            control={userForm.control}
                            name="firstName"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>First Name</FormLabel>
                                <FormControl>
                                  <Input placeholder="John" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={userForm.control}
                            name="lastName"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Last Name</FormLabel>
                                <FormControl>
                                  <Input placeholder="Doe" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>
                        
                        <FormField
                          control={userForm.control}
                          name="email"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Email</FormLabel>
                              <FormControl>
                                <Input placeholder="john@example.com" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={userForm.control}
                          name="password"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Password</FormLabel>
                              <FormControl>
                                <Input type="password" placeholder="Password" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={userForm.control}
                          name="role"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Role</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="employee">Employee</SelectItem>
                                  <SelectItem value="company_admin">Company Admin</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={userForm.control}
                          name="companyId"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Company</FormLabel>
                              <Select 
                                onValueChange={(value) => field.onChange(value ? parseInt(value) : null)} 
                                defaultValue={field.value?.toString()}
                              >
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select a company" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  {companies.map((company: any) => (
                                    <SelectItem key={company.id} value={company.id.toString()}>
                                      {company.name}
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <Button type="submit" disabled={createUserMutation.isPending}>
                          {createUserMutation.isPending ? "Creating..." : "Create User"}
                        </Button>
                      </form>
                    </Form>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {users.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No users created yet</p>
                ) : (
                  users.slice(0, 5).map((user: any) => (
                    <div key={user.id} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                      <div className="flex items-center">
                        <div className={`h-10 w-10 text-white rounded-full flex items-center justify-center text-sm font-medium mr-3 ${
                          user.role === 'company_admin' ? 'bg-orange-500' : 'bg-green-500'
                        }`}>
                          {user.firstName?.[0]}{user.lastName?.[0]}
                        </div>
                        <div>
                          <h3 className="font-medium text-gray-900">{user.firstName} {user.lastName}</h3>
                          <p className="text-sm text-gray-600 capitalize">{user.role.replace('_', ' ')}</p>
                        </div>
                      </div>
                      <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">
                        Active
                      </span>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
          </TabsContent>

          <TabsContent value="meetings" className="space-y-6">
            <div className="grid gap-6">
              {(companies as any[]).map((company: any) => (
                company.zoomMeetingId && (
                  <Card key={company.id}>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Video className="h-5 w-5" />
                        {company.name} - Meeting Room
                      </CardTitle>
                      <CardDescription>
                        Join and monitor company meeting as Super Admin
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <VideoMeeting 
                        meetingId={company.zoomMeetingId}
                        isHost={true}
                      />
                    </CardContent>
                  </Card>
                )
              ))}
              {(companies as any[]).filter((c: any) => c.zoomMeetingId).length === 0 && (
                <Card>
                  <CardContent className="text-center py-8">
                    <Video className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                    <p className="text-gray-500">No active meetings found</p>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="database" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Database Management</CardTitle>
                <CardDescription>
                  Execute SQL queries and manage database directly
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button onClick={() => setShowDatabaseQuery(true)} className="gap-2">
                  <Database className="h-4 w-4" />
                  Open Database Interface
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Database Query Interface */}
      <DatabaseQueryInterface 
        open={showDatabaseQuery} 
        onOpenChange={setShowDatabaseQuery} 
      />
    </div>
  );
}
