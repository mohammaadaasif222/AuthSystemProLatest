import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Mic, Square, Play, Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface VoiceRecorderProps {
  onRecordingComplete: (audioBlob: Blob) => void;
  disabled?: boolean;
}

export function VoiceRecorder({ onRecordingComplete, disabled = false }: VoiceRecorderProps) {
  const [isRecording, setIsRecording] = useState(false);
  const [audioURL, setAudioURL] = useState<string | null>(null);
  const [recordingTime, setRecordingTime] = useState(0);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const { toast } = useToast();

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        audioChunksRef.current.push(event.data);
      };

      mediaRecorder.onstop = () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/wav' });
        const url = URL.createObjectURL(audioBlob);
        setAudioURL(url);
        stream.getTracks().forEach(track => track.stop());
      };

      mediaRecorder.start();
      setIsRecording(true);
      setRecordingTime(0);

      // Start timer
      timerRef.current = setInterval(() => {
        setRecordingTime(prev => prev + 1);
      }, 1000);

    } catch (error) {
      toast({
        title: "Recording Error",
        description: "Could not access microphone. Please check permissions.",
        variant: "destructive",
      });
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
      
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
  };

  const playRecording = () => {
    if (audioURL) {
      const audio = new Audio(audioURL);
      audio.play();
    }
  };

  const sendRecording = () => {
    if (audioChunksRef.current.length > 0) {
      const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/wav' });
      onRecordingComplete(audioBlob);
      clearRecording();
    }
  };

  const clearRecording = () => {
    setAudioURL(null);
    audioChunksRef.current = [];
    setRecordingTime(0);
    
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="bg-gray-50 border-2 border-dashed border-gray-300 rounded-lg p-6">
      <div className="flex flex-col items-center space-y-4">
        <div className="bg-green-500 text-white p-3 rounded-full">
          <Mic className="h-6 w-6" />
        </div>

        {isRecording ? (
          <div className="text-center">
            <div className="text-lg font-semibold text-red-600 mb-2">
              Recording... {formatTime(recordingTime)}
            </div>
            <Button
              onClick={stopRecording}
              className="bg-red-600 hover:bg-red-700"
              disabled={disabled}
            >
              <Square className="h-4 w-4 mr-2" />
              Stop Recording
            </Button>
          </div>
        ) : audioURL ? (
          <div className="text-center space-y-3">
            <div className="text-sm text-gray-600">
              Recording complete ({formatTime(recordingTime)})
            </div>
            <div className="flex space-x-2">
              <Button
                onClick={playRecording}
                variant="outline"
                size="sm"
              >
                <Play className="h-4 w-4 mr-1" />
                Play
              </Button>
              <Button
                onClick={sendRecording}
                className="bg-green-500 hover:bg-green-600"
                size="sm"
                disabled={disabled}
              >
                <Mic className="h-4 w-4 mr-1" />
                Send
              </Button>
              <Button
                onClick={clearRecording}
                variant="outline"
                size="sm"
              >
                <Trash2 className="h-4 w-4 mr-1" />
                Delete
              </Button>
            </div>
          </div>
        ) : (
          <div className="text-center">
            <Button
              onClick={startRecording}
              className="bg-green-500 hover:bg-green-600"
              disabled={disabled}
            >
              <Mic className="h-4 w-4 mr-2" />
              Start Recording
            </Button>
            <p className="text-sm text-gray-600 mt-2">
              Click to record a voice message
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
