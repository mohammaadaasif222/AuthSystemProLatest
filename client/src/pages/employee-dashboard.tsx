import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { User, Video, MessageSquare, LogOut, Send } from "lucide-react";
import { VoiceRecorder } from "@/components/voice-recorder";
import { VideoMeeting } from "@/components/video-meeting";
import { useToast } from "@/hooks/use-toast";

export default function EmployeeDashboard() {
  const { user, logoutMutation } = useAuth();
  const { toast } = useToast();
  const [textMessage, setTextMessage] = useState("");

  // Fetch company info
  const { data: companies = [] } = useQuery({
    queryKey: ["/api/companies"],
  });

  const company = (companies as any[])?.[0];

  // Send text message mutation
  const sendMessageMutation = useMutation({
    mutationFn: async (content: string) => {
      const res = await apiRequest("POST", "/api/messages/send", {
        messageType: "text",
        content,
      });
      return res.json();
    },
    onSuccess: () => {
      setTextMessage("");
      toast({
        title: "Message sent",
        description: "Your message has been sent to the company admin.",
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

  // Send voice message mutation
  const sendVoiceMessageMutation = useMutation({
    mutationFn: async (audioBlob: Blob) => {
      const formData = new FormData();
      formData.append('voice', audioBlob, 'voice-message.wav');
      
      const res = await fetch('/api/messages/voice', {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });
      
      if (!res.ok) {
        throw new Error('Failed to send voice message');
      }
      
      return res.json();
    },
    onSuccess: () => {
      toast({
        title: "Voice message sent",
        description: "Your voice message has been sent to the company admin.",
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

  const handleJoinMeeting = () => {
    if (company?.zoomMeetingUrl) {
      window.open(company.zoomMeetingUrl, '_blank');
    } else {
      toast({
        title: "No meeting available",
        description: "The company admin hasn't created a meeting yet.",
        variant: "destructive",
      });
    }
  };

  const handleSendTextMessage = () => {
    if (textMessage.trim()) {
      sendMessageMutation.mutate(textMessage);
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
              <div className="bg-green-500 text-white p-2 rounded-lg mr-3">
                <User className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-gray-900">Employee Dashboard</h1>
                <p className="text-sm text-gray-600">{company?.name || 'Loading...'}</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">{user?.firstName} {user?.lastName}</span>
              <div className="h-8 w-8 bg-green-500 text-white rounded-full flex items-center justify-center text-sm font-medium">
                {user?.firstName?.[0]}{user?.lastName?.[0]}
              </div>
              <Button variant="ghost" size="sm" onClick={handleLogout}>
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto py-6 sm:px-6 lg:px-8">
        {/* 24/7 Video Meeting */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Video className="h-5 w-5" />
              Company Meeting Room
            </CardTitle>
            <CardDescription>
              Join your team's always-on video meeting - available 24/7
            </CardDescription>
          </CardHeader>
          <CardContent>
            <VideoMeeting 
              meetingId={company?.zoomMeetingId || "123456789"}
              isHost={false}
            />
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Company Info */}
          <Card>
            <CardHeader>
              <CardTitle>Company Information</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-600">Company</span>
                  <span className="font-medium">{company?.name || 'Loading...'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-600">Your Role</span>
                  <span className="font-medium">Employee</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-600">Meeting Status</span>
                  <span className="px-3 py-1 text-sm rounded-full flex items-center bg-green-100 text-green-800">
                    <div className="w-2 h-2 rounded-full mr-2 bg-green-500"></div>
                    Always Available
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Message Center */}
          <Card>
            <CardHeader>
              <CardTitle>Message Company Admin</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* Text Message */}
                <div>
                  <Label htmlFor="textMessage">Text Message</Label>
                  <Textarea
                    id="textMessage"
                    rows={4}
                    placeholder="Type your message to the company admin..."
                    value={textMessage}
                    onChange={(e) => setTextMessage(e.target.value)}
                    className="mt-1"
                  />
                  <Button
                    onClick={handleSendTextMessage}
                    disabled={!textMessage.trim() || sendMessageMutation.isPending}
                    className="mt-2 bg-green-500 hover:bg-green-600"
                  >
                    <Send className="h-4 w-4 mr-2" />
                    {sendMessageMutation.isPending ? "Sending..." : "Send Message"}
                  </Button>
                </div>

                {/* Voice Message */}
                <div className="border-t pt-4">
                  <Label>Voice Message</Label>
                  <div className="mt-2">
                    <VoiceRecorder
                      onRecordingComplete={(audioBlob) => sendVoiceMessageMutation.mutate(audioBlob)}
                      disabled={sendVoiceMessageMutation.isPending}
                    />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Profile Settings */}
        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Profile Settings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <Label htmlFor="firstName">First Name</Label>
                <Input
                  id="firstName"
                  value={user?.firstName || ''}
                  readOnly
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="lastName">Last Name</Label>
                <Input
                  id="lastName"
                  value={user?.lastName || ''}
                  readOnly
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  value={user?.email || ''}
                  readOnly
                  className="mt-1 bg-gray-50"
                />
              </div>
              <div>
                <Label htmlFor="company">Company</Label>
                <Input
                  id="company"
                  value={company?.name || ''}
                  readOnly
                  className="mt-1 bg-gray-50"
                />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
