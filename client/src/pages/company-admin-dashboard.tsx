import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Building, Video, Settings, Users, MessageSquare, LogOut, Plus, Play, Mic } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { VideoMeeting } from "@/components/video-meeting";
import { UserManagementTable } from "@/components/user-management-table";

export default function CompanyAdminDashboard() {
  const { user, logoutMutation } = useAuth();
  const { toast } = useToast();
  const [meetingActive, setMeetingActive] = useState(false);

  // Fetch company info
  const { data: companies = [] } = useQuery({
    queryKey: ["/api/companies"],
  });

  // Fetch employees
  const { data: employees = [] } = useQuery({
    queryKey: ["/api/users"],
  });

  // Fetch messages
  const { data: messages = [] } = useQuery({
    queryKey: ["/api/messages"],
  });

  const company = (companies as any[])?.[0];
  const unreadMessages = (messages as any[]).filter((msg: any) => !msg.isRead);

  // Create meeting mutation
  const createMeetingMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/zoom/create-meeting", {});
      return res.json();
    },
    onSuccess: () => {
      setMeetingActive(true);
      queryClient.invalidateQueries({ queryKey: ["/api/companies"] });
      toast({
        title: "Meeting Created",
        description: "Your 24/7 company meeting has been created successfully.",
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

  const handleConnectMeeting = () => {
    if (company?.zoomMeetingUrl) {
      window.open(company.zoomMeetingUrl, '_blank');
    } else {
      createMeetingMutation.mutate();
    }
  };

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
              <div className="bg-orange-500 text-white p-2 rounded-lg mr-3">
                <Building className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900">Company Admin Dashboard</h1>
                <p className="text-sm text-gray-600">{company?.name || 'Loading...'}</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">{user?.firstName} {user?.lastName}</span>
              <div className="h-8 w-8 bg-orange-500 text-white rounded-full flex items-center justify-center text-sm font-medium">
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
        {/* 24/7 Video Meeting */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Video className="h-5 w-5" />
              24/7 Company Meeting Room
            </CardTitle>
            <CardDescription>
              Always-on video meeting for your team - no need to create or schedule meetings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <VideoMeeting 
              meetingId={company?.zoomMeetingId || "123456789"}
              isHost={true}
            />
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Meeting Status */}
          <Card>
            <CardHeader>
              <CardTitle>Meeting Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-600">Status</span>
                  <span className={`px-3 py-1 text-sm rounded-full flex items-center ${
                    company?.zoomMeetingUrl 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-gray-100 text-gray-800'
                  }`}>
                    <div className={`w-2 h-2 rounded-full mr-2 ${
                      company?.zoomMeetingUrl ? 'bg-green-500' : 'bg-gray-500'
                    }`}></div>
                    {company?.zoomMeetingUrl ? 'Active' : 'Inactive'}
                  </span>
                </div>
                
                {company?.zoomMeetingUrl && (
                  <>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Meeting ID</span>
                      <span className="font-mono text-sm">{company.zoomMeetingId}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Password</span>
                      <span className="font-mono text-sm">{company.zoomMeetingPassword}</span>
                    </div>
                  </>
                )}
                
                <div className="flex items-center justify-between">
                  <span className="text-gray-600">Employees</span>
                  <span className="font-medium">{(employees as any[]).length}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Employee Management */}
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>Employees</CardTitle>
                <Button size="sm" className="bg-green-600 hover:bg-green-700">
                  <Plus className="h-4 w-4 mr-1" />
                  Add
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(employees as any[]).length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No employees yet</p>
                ) : (
                  (employees as any[]).map((employee: any) => (
                    <div key={employee.id} className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                      <div className="flex items-center">
                        <div className="h-8 w-8 bg-green-500 text-white rounded-full flex items-center justify-center text-xs font-medium mr-3">
                          {employee.firstName?.[0]}{employee.lastName?.[0]}
                        </div>
                        <div>
                          <h4 className="font-medium text-gray-900">{employee.firstName} {employee.lastName}</h4>
                          <p className="text-xs text-gray-600">Active</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* Messages */}
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>Messages</CardTitle>
                {unreadMessages.length > 0 && (
                  <span className="bg-red-100 text-red-800 text-xs px-2 py-1 rounded-full">
                    {unreadMessages.length} new
                  </span>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(messages as any[]).length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No messages yet</p>
                ) : (
                  (messages as any[]).slice(0, 5).map((message: any) => (
                    <div key={message.id} className="p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium text-gray-900">Employee</span>
                        <span className="text-xs text-gray-500">
                          {new Date(message.createdAt).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-700 truncate">{message.content}</p>
                      <div className="flex items-center mt-2">
                        <span className={`text-xs mr-3 ${
                          message.messageType === 'voice' ? 'text-orange-600' : 'text-blue-600'
                        }`}>
                          {message.messageType === 'voice' ? (
                            <><Mic className="h-3 w-3 inline mr-1" />Voice</>
                          ) : (
                            <><MessageSquare className="h-3 w-3 inline mr-1" />Text</>
                          )}
                        </span>
                        {message.messageType === 'voice' && (
                          <Button variant="ghost" size="sm" className="text-xs text-blue-600 hover:text-blue-800 p-0 h-auto">
                            <Play className="h-3 w-3 mr-1" />
                            Play
                          </Button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* User Management */}
        <div className="mt-6">
          <UserManagementTable 
            users={employees as any[]} 
            currentUserRole="company_admin"
            currentCompanyId={user?.companyId}
          />
        </div>
      </div>
    </div>
  );
}
