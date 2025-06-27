import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Video, VideoOff, Mic, MicOff, PhoneOff, Users, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

interface VideoMeetingProps {
  meetingId: string;
  isHost?: boolean;
  onLeave?: () => void;
}

export function VideoMeeting({ meetingId, isHost = false, onLeave }: VideoMeetingProps) {
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);
  const [isVideoOn, setIsVideoOn] = useState(true);
  const [isAudioOn, setIsAudioOn] = useState(true);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [participants, setParticipants] = useState<number>(1);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');

  useEffect(() => {
    initializeMedia();
    
    // Simulate connection after 2 seconds
    const timer = setTimeout(() => {
      setIsConnected(true);
      setConnectionStatus('connected');
      setParticipants(Math.floor(Math.random() * 5) + 2); // 2-6 participants
    }, 2000);

    return () => {
      clearTimeout(timer);
      cleanup();
    };
  }, []);

  const initializeMedia = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true
      });
      
      setLocalStream(stream);
      
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }
      
      // Simulate remote video with a placeholder
      if (remoteVideoRef.current) {
        // In a real implementation, this would be the remote stream
        remoteVideoRef.current.srcObject = null;
      }
    } catch (error) {
      console.error('Error accessing media devices:', error);
      setConnectionStatus('disconnected');
    }
  };

  const cleanup = () => {
    if (localStream) {
      localStream.getTracks().forEach(track => track.stop());
    }
  };

  const toggleVideo = () => {
    if (localStream) {
      const videoTrack = localStream.getVideoTracks()[0];
      if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        setIsVideoOn(videoTrack.enabled);
      }
    }
  };

  const toggleAudio = () => {
    if (localStream) {
      const audioTrack = localStream.getAudioTracks()[0];
      if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        setIsAudioOn(audioTrack.enabled);
      }
    }
  };

  const handleLeave = () => {
    cleanup();
    onLeave?.();
  };

  return (
    <Card className="w-full h-full">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CardTitle className="text-lg">Company Meeting</CardTitle>
            <Badge variant={connectionStatus === 'connected' ? 'default' : 'secondary'}>
              {connectionStatus === 'connecting' && 'Connecting...'}
              {connectionStatus === 'connected' && '24/7 Live'}
              {connectionStatus === 'disconnected' && 'Disconnected'}
            </Badge>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Users className="h-4 w-4" />
            <span>{participants} participants</span>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Video Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-[400px]">
          {/* Remote Video */}
          <div className="relative bg-gray-900 rounded-lg overflow-hidden">
            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              className="w-full h-full object-cover"
              poster="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='300' viewBox='0 0 400 300'%3E%3Crect width='400' height='300' fill='%23374151'/%3E%3Ctext x='200' y='150' font-family='Arial' font-size='16' fill='white' text-anchor='middle' dy='.3em'%3ERemote Participants%3C/text%3E%3C/svg%3E"
            />
            {!isConnected && (
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center text-white">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white mx-auto mb-2"></div>
                  <p className="text-sm">Connecting to meeting...</p>
                </div>
              </div>
            )}
            {isConnected && (
              <div className="absolute bottom-2 left-2 bg-black/50 text-white px-2 py-1 rounded text-sm">
                Company Team
              </div>
            )}
          </div>
          
          {/* Local Video */}
          <div className="relative bg-gray-900 rounded-lg overflow-hidden">
            <video
              ref={localVideoRef}
              autoPlay
              playsInline
              muted
              className={cn(
                "w-full h-full object-cover",
                !isVideoOn && "hidden"
              )}
            />
            {!isVideoOn && (
              <div className="absolute inset-0 flex items-center justify-center bg-gray-800">
                <div className="text-center text-white">
                  <VideoOff className="h-12 w-12 mx-auto mb-2" />
                  <p className="text-sm">Camera Off</p>
                </div>
              </div>
            )}
            <div className="absolute bottom-2 left-2 bg-black/50 text-white px-2 py-1 rounded text-sm">
              You {isHost && "(Host)"}
            </div>
          </div>
        </div>
        
        {/* Meeting Controls */}
        <div className="flex items-center justify-center gap-2 pt-4 border-t">
          <Button
            variant={isAudioOn ? "default" : "destructive"}
            size="sm"
            onClick={toggleAudio}
            className="gap-2"
          >
            {isAudioOn ? <Mic className="h-4 w-4" /> : <MicOff className="h-4 w-4" />}
            {isAudioOn ? "Mute" : "Unmute"}
          </Button>
          
          <Button
            variant={isVideoOn ? "default" : "destructive"}
            size="sm"
            onClick={toggleVideo}
            className="gap-2"
          >
            {isVideoOn ? <Video className="h-4 w-4" /> : <VideoOff className="h-4 w-4" />}
            {isVideoOn ? "Stop Video" : "Start Video"}
          </Button>
          
          <Button
            variant="outline"
            size="sm"
            className="gap-2"
          >
            <Settings className="h-4 w-4" />
            Settings
          </Button>
          
          <Button
            variant="destructive"
            size="sm"
            onClick={handleLeave}
            className="gap-2"
          >
            <PhoneOff className="h-4 w-4" />
            Leave
          </Button>
        </div>
        
        {/* Meeting Info */}
        <div className="text-center text-sm text-muted-foreground pt-2 border-t">
          <p>Meeting ID: {meetingId}</p>
          <p className="text-xs mt-1">This meeting runs 24/7 and is always available for your team</p>
        </div>
      </CardContent>
    </Card>
  );
}