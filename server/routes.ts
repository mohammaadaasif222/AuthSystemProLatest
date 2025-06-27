import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { setupAuth, hashPassword } from "./auth";
import { zoomService } from "./services/zoomService";
import { insertUserSchema, insertCompanySchema, insertMessageSchema, User } from "@shared/schema";
import { z } from "zod";
import multer from "multer";
import path from "path";
import fs from "fs";

// Ensure uploads directory exists
const uploadsDir = path.join(process.cwd(), "uploads", "voice");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const upload = multer({
  dest: uploadsDir,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['audio/wav', 'audio/mpeg', 'audio/webm', 'audio/ogg'];
    cb(null, allowedTypes.includes(file.mimetype));
  },
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
  },
});

function requireAuth(req: any, res: any, next: any) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
}

function requireRole(roles: string[]) {
  return (req: any, res: any, next: any) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Authentication required" });
    }
    
    const user = req.user as User;
    if (!roles.includes(user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    
    next();
  };
}

export function registerRoutes(app: Express): Server {
  setupAuth(app);

  // User Management Endpoints
  app.post("/api/users/create-company-admin", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const validation = insertUserSchema.extend({
        role: z.literal("company_admin"),
      }).safeParse(req.body);
      
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid user data" });
      }

      const existingUser = await storage.getUserByEmail(validation.data.email);
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists" });
      }

      const user = await storage.createUser({
        ...validation.data,
        password: await hashPassword(validation.data.password),
        createdBy: req.user?.id,
      });

      const { password, ...userWithoutPassword } = user;
      res.status(201).json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/users/create-employee", requireRole(["super_admin", "company_admin"]), async (req, res, next) => {
    try {
      const validation = insertUserSchema.extend({
        role: z.literal("employee"),
      }).safeParse(req.body);
      
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid user data" });
      }

      const currentUser = req.user as User;
      
      // Company admin can only create employees for their company
      if (currentUser.role === "company_admin" && validation.data.companyId !== currentUser.companyId) {
        return res.status(403).json({ message: "Can only create employees for your company" });
      }

      const existingUser = await storage.getUserByEmail(validation.data.email);
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists" });
      }

      const user = await storage.createUser({
        ...validation.data,
        password: await hashPassword(validation.data.password),
        createdBy: req.user?.id,
      });

      const { password, ...userWithoutPassword } = user;
      res.status(201).json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/users", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user as User;
      let users: User[] = [];

      if (currentUser.role === "super_admin") {
        users = await storage.getUsersByRole("company_admin");
        const employees = await storage.getUsersByRole("employee");
        users = [...users, ...employees];
      } else if (currentUser.role === "company_admin" && currentUser.companyId) {
        users = await storage.getUsersByCompany(currentUser.companyId);
      }

      const usersWithoutPasswords = users.map(({ password, ...user }) => ({
        ...user,
        deviceInfo: user.deviceInfo ? JSON.parse(user.deviceInfo) : null
      }));
      res.json(usersWithoutPasswords);
    } catch (error) {
      next(error);
    }
  });

  // Block/Unblock user
  app.patch("/api/users/:id/block", requireRole(["super_admin", "company_admin"]), async (req, res, next) => {
    try {
      const userId = parseInt(req.params.id);
      const { isBlocked } = req.body;
      const currentUser = req.user as User;

      // Company admin can only block users in their company
      if (currentUser.role === "company_admin") {
        const targetUser = await storage.getUser(userId);
        if (!targetUser || targetUser.companyId !== currentUser.companyId) {
          return res.status(403).json({ message: "Can only manage users in your company" });
        }
      }

      const updatedUser = await storage.updateUser(userId, { isBlocked });
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }

      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  });

  // Company Management Endpoints
  app.post("/api/companies", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const validation = insertCompanySchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid company data" });
      }

      const company = await storage.createCompany({
        ...validation.data,
        createdBy: req.user?.id,
      });

      res.status(201).json(company);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/companies", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user as User;
      
      if (currentUser.role === "super_admin") {
        const companies = await storage.getAllCompanies();
        // Auto-initialize meetings for companies without one
        for (const company of companies) {
          if (!company.zoomMeetingId) {
            try {
              await zoomService.createMeeting(company.id, currentUser.id);
            } catch (error) {
              console.log(`Auto-created meeting for company ${company.id}`);
            }
          }
        }
        const updatedCompanies = await storage.getAllCompanies();
        res.json(updatedCompanies);
      } else if (currentUser.companyId) {
        const company = await storage.getCompany(currentUser.companyId);
        if (company && !company.zoomMeetingId) {
          try {
            await zoomService.createMeeting(company.id, currentUser.id);
            const updatedCompany = await storage.getCompany(currentUser.companyId);
            res.json(updatedCompany ? [updatedCompany] : []);
          } catch (error) {
            res.json(company ? [company] : []);
          }
        } else {
          res.json(company ? [company] : []);
        }
      } else {
        res.json([]);
      }
    } catch (error) {
      next(error);
    }
  });

  app.put("/api/companies/:id", requireAuth, async (req, res, next) => {
    try {
      const companyId = parseInt(req.params.id);
      const currentUser = req.user as User;
      
      // Check permissions
      if (currentUser.role !== "super_admin" && currentUser.companyId !== companyId) {
        return res.status(403).json({ message: "Insufficient permissions" });
      }

      const company = await storage.updateCompany(companyId, req.body);
      if (!company) {
        return res.status(404).json({ message: "Company not found" });
      }

      res.json(company);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/companies/:id", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const companyId = parseInt(req.params.id);
      const success = await storage.deleteCompany(companyId);
      
      if (!success) {
        return res.status(404).json({ message: "Company not found" });
      }

      res.sendStatus(204);
    } catch (error) {
      next(error);
    }
  });

  // Zoom Integration Endpoints
  app.post("/api/zoom/create-meeting", requireRole(["company_admin"]), async (req, res, next) => {
    try {
      const currentUser = req.user as User;
      
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }

      const meeting = await zoomService.createMeeting(currentUser.companyId, currentUser.id);
      res.json(meeting);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/zoom/meeting-info", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user as User;
      
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }

      const company = await storage.getCompany(currentUser.companyId);
      if (!company || !company.zoomMeetingId) {
        return res.status(404).json({ message: "No meeting found for this company" });
      }

      const meetingInfo = await zoomService.getMeetingInfo(company.zoomMeetingId);
      res.json(meetingInfo);
    } catch (error) {
      next(error);
    }
  });

  // Messaging Endpoints
  app.post("/api/messages/send", requireRole(["employee"]), async (req, res, next) => {
    try {
      const currentUser = req.user as User;
      
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }

      // Find company admin for this company
      const companyUsers = await storage.getUsersByCompany(currentUser.companyId);
      const companyAdmin = companyUsers.find(user => user.role === "company_admin");
      
      if (!companyAdmin) {
        return res.status(404).json({ message: "No company admin found" });
      }

      const validation = insertMessageSchema.safeParse({
        ...req.body,
        senderId: currentUser.id,
        receiverId: companyAdmin.id,
        companyId: currentUser.companyId,
      });

      if (!validation.success) {
        return res.status(400).json({ message: "Invalid message data" });
      }

      const message = await storage.createMessage(validation.data);
      res.status(201).json(message);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/messages", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user as User;
      let messages: any[] = [];

      if (currentUser.role === "company_admin" && currentUser.companyId) {
        messages = await storage.getCompanyMessages(currentUser.companyId);
      } else if (currentUser.role === "employee") {
        messages = await storage.getMessagesByReceiver(currentUser.id);
      }

      res.json(messages);
    } catch (error) {
      next(error);
    }
  });

  app.put("/api/messages/:id/read", requireAuth, async (req, res, next) => {
    try {
      const messageId = parseInt(req.params.id);
      const success = await storage.markMessageAsRead(messageId);
      
      if (!success) {
        return res.status(404).json({ message: "Message not found" });
      }

      res.sendStatus(200);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/messages/voice", requireRole(["employee"]), upload.single("voice"), async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No voice file uploaded" });
      }

      const currentUser = req.user as User;
      
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }

      // Find company admin
      const companyUsers = await storage.getUsersByCompany(currentUser.companyId);
      const companyAdmin = companyUsers.find(user => user.role === "company_admin");
      
      if (!companyAdmin) {
        return res.status(404).json({ message: "No company admin found" });
      }

      const message = await storage.createMessage({
        senderId: currentUser.id,
        receiverId: companyAdmin.id,
        companyId: currentUser.companyId,
        messageType: "voice",
        content: `/uploads/voice/${req.file.filename}`,
      });

      res.status(201).json(message);
    } catch (error) {
      next(error);
    }
  });

  // Database Query Interface (Development only)
  app.post("/api/database/query", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const { query } = req.body;
      
      if (!query || typeof query !== "string") {
        return res.status(400).json({ message: "Invalid query" });
      }

      // Basic safety check - prevent destructive operations in production
      if (process.env.NODE_ENV === "production") {
        const destructiveKeywords = ["DROP", "DELETE", "TRUNCATE", "ALTER"];
        const upperQuery = query.toUpperCase();
        
        if (destructiveKeywords.some(keyword => upperQuery.includes(keyword))) {
          return res.status(403).json({ message: "Destructive queries not allowed in production" });
        }
      }

      const result = await storage.executeQuery(query);
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Statistics endpoint
  app.get("/api/stats", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const companies = await storage.getAllCompanies();
      const companyAdmins = await storage.getUsersByRole("company_admin");
      const employees = await storage.getUsersByRole("employee");
      
      const activeMeetings = companies.filter(c => c.zoomMeetingId).length;

      res.json({
        companies: companies.length,
        companyAdmins: companyAdmins.length,
        employees: employees.length,
        meetings: activeMeetings,
      });
    } catch (error) {
      next(error);
    }
  });

  const httpServer = createServer(app);

  // WebSocket server for real-time messaging
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  wss.on('connection', (ws: WebSocket) => {
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data.toString());
        
        // Broadcast message to all connected clients
        wss.clients.forEach((client) => {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
          }
        });
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    });
  });

  return httpServer;
}
