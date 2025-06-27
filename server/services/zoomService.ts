import { storage } from "../storage";

const zoomConfig = {
  clientId: process.env.ZOOM_CLIENT_ID || "eFwvmyl2TcSKNM1iyMTlng",
  clientSecret: process.env.ZOOM_CLIENT_SECRET || "FYldVq4AcTDt9IclIp9eEkuTUc1IPff6",
  accountId: process.env.ZOOM_ACCOUNT_ID || "OZWhroVYT0adDjOQOUAZSA"
};

export class ZoomService {
  private async getAccessToken(): Promise<string> {
    // Skip real API call in development
    if (process.env.NODE_ENV === 'development') {
      return 'mock-access-token';
    }

    const credentials = Buffer.from(`${zoomConfig.clientId}:${zoomConfig.clientSecret}`).toString('base64');
    
    const response = await fetch('https://zoom.us/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'account_credentials',
        account_id: zoomConfig.accountId,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to get Zoom access token');
    }

    const data = await response.json();
    return data.access_token;
  }

  async createMeeting(companyId: number, userId: number): Promise<any> {
    try {
      const company = await storage.getCompany(companyId);
      
      if (!company) {
        throw new Error('Company not found');
      }

      // For localhost development, create a mock meeting
      if (process.env.NODE_ENV === 'development') {
        const mockMeetingId = `${Math.floor(Math.random() * 900000000) + 100000000}`; // 9-digit number like real Zoom IDs
        const mockMeetingUrl = `https://zoom.us/j/${mockMeetingId}`;
        const mockPassword = Math.random().toString(36).substring(2, 8);

        await storage.updateCompany(companyId, {
          zoomMeetingId: mockMeetingId,
          zoomMeetingUrl: mockMeetingUrl,
          zoomMeetingPassword: mockPassword,
        });

        return {
          id: mockMeetingId,
          join_url: mockMeetingUrl,
          password: mockPassword,
          topic: `${company.name} - 24/7 Company Meeting`,
        };
      }

      // Production Zoom API integration
      const accessToken = await this.getAccessToken();
      const meetingData = {
        topic: `${company.name} - 24/7 Company Meeting`,
        type: 8, // Recurring meeting with no fixed time
        recurrence: {
          type: 1, // Daily
          repeat_interval: 1,
        },
        settings: {
          host_video: true,
          participant_video: true,
          join_before_host: true,
          mute_upon_entry: false,
          waiting_room: false,
          audio: "both",
          auto_recording: "none",
        },
      };

      const response = await fetch('https://api.zoom.us/v2/users/me/meetings', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(meetingData),
      });

      if (!response.ok) {
        throw new Error('Failed to create Zoom meeting');
      }

      const meeting = await response.json();
      
      // Update company with meeting details
      await storage.updateCompany(companyId, {
        zoomMeetingId: meeting.id.toString(),
        zoomMeetingUrl: meeting.join_url,
        zoomMeetingPassword: meeting.password,
      });

      return meeting;
    } catch (error) {
      console.error('Zoom meeting creation error:', error);
      throw error;
    }
  }

  async getMeetingInfo(meetingId: string): Promise<any> {
    try {
      const accessToken = await this.getAccessToken();
      
      const response = await fetch(`https://api.zoom.us/v2/meetings/${meetingId}`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to get meeting info');
      }

      return await response.json();
    } catch (error) {
      console.error('Get meeting info error:', error);
      throw error;
    }
  }

  async deleteMeeting(meetingId: string): Promise<boolean> {
    try {
      const accessToken = await this.getAccessToken();
      
      const response = await fetch(`https://api.zoom.us/v2/meetings/${meetingId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      return response.ok;
    } catch (error) {
      console.error('Delete meeting error:', error);
      return false;
    }
  }
}

export const zoomService = new ZoomService();
