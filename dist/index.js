var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express2 from "express";

// server/routes.ts
import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  companies: () => companies,
  companiesRelations: () => companiesRelations,
  insertCompanySchema: () => insertCompanySchema,
  insertMessageSchema: () => insertMessageSchema,
  insertUserSchema: () => insertUserSchema,
  loginSchema: () => loginSchema,
  messages: () => messages,
  messagesRelations: () => messagesRelations,
  users: () => users,
  usersRelations: () => usersRelations
});
import { pgTable, text, serial, integer, boolean, timestamp, varchar, foreignKey } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";
var companies = pgTable("companies", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  isActive: boolean("is_active").default(true),
  zoomMeetingId: varchar("zoom_meeting_id", { length: 255 }),
  zoomMeetingUrl: text("zoom_meeting_url"),
  zoomMeetingPassword: varchar("zoom_meeting_password", { length: 255 }),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  createdBy: integer("created_by")
});
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  password: text("password").notNull(),
  role: varchar("role", { length: 50 }).notNull(),
  companyId: integer("company_id"),
  firstName: varchar("first_name", { length: 100 }).notNull(),
  lastName: varchar("last_name", { length: 100 }).notNull(),
  isActive: boolean("is_active").default(true),
  isBlocked: boolean("is_blocked").default(false),
  lastLoginAt: timestamp("last_login_at"),
  lastIpAddress: varchar("last_ip_address", { length: 45 }),
  deviceInfo: text("device_info"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  createdBy: integer("created_by")
}, (table) => ({
  companyReference: foreignKey({
    columns: [table.companyId],
    foreignColumns: [companies.id]
  }),
  createdByReference: foreignKey({
    columns: [table.createdBy],
    foreignColumns: [table.id]
  })
}));
var messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  senderId: integer("sender_id").notNull(),
  receiverId: integer("receiver_id").notNull(),
  companyId: integer("company_id").notNull(),
  messageType: varchar("message_type", { length: 20 }).notNull(),
  content: text("content").notNull(),
  isRead: boolean("is_read").default(false),
  createdAt: timestamp("created_at").defaultNow()
}, (table) => ({
  senderReference: foreignKey({
    columns: [table.senderId],
    foreignColumns: [users.id]
  }),
  receiverReference: foreignKey({
    columns: [table.receiverId],
    foreignColumns: [users.id]
  }),
  companyReference: foreignKey({
    columns: [table.companyId],
    foreignColumns: [companies.id]
  })
}));
var companiesRelations = relations(companies, ({ many, one }) => ({
  users: many(users),
  messages: many(messages),
  createdByUser: one(users, {
    fields: [companies.createdBy],
    references: [users.id]
  })
}));
var usersRelations = relations(users, ({ many, one }) => ({
  company: one(companies, {
    fields: [users.companyId],
    references: [companies.id]
  }),
  sentMessages: many(messages, { relationName: "sender" }),
  receivedMessages: many(messages, { relationName: "receiver" }),
  createdByUser: one(users, {
    fields: [users.createdBy],
    references: [users.id]
  }),
  createdUsers: many(users, { relationName: "created_users" }),
  createdCompanies: many(companies)
}));
var messagesRelations = relations(messages, ({ one }) => ({
  sender: one(users, {
    fields: [messages.senderId],
    references: [users.id],
    relationName: "sender"
  }),
  receiver: one(users, {
    fields: [messages.receiverId],
    references: [users.id],
    relationName: "receiver"
  }),
  company: one(companies, {
    fields: [messages.companyId],
    references: [companies.id]
  })
}));
var insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var insertCompanySchema = createInsertSchema(companies).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var insertMessageSchema = createInsertSchema(messages).omit({
  id: true,
  createdAt: true
});
var loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
var PostgresSessionStore = connectPg(session);
var DatabaseStorage = class {
  sessionStore;
  constructor() {
    this.sessionStore = new PostgresSessionStore({
      pool,
      createTableIfMissing: true
    });
  }
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || void 0;
  }
  async getUserByEmail(email) {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || void 0;
  }
  async createUser(insertUser) {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }
  async updateUser(id, userUpdate) {
    const [user] = await db.update(users).set({ ...userUpdate, updatedAt: /* @__PURE__ */ new Date() }).where(eq(users.id, id)).returning();
    return user || void 0;
  }
  async deleteUser(id) {
    const result = await db.delete(users).where(eq(users.id, id));
    return result.rowCount > 0;
  }
  async getUsersByCompany(companyId) {
    return await db.select().from(users).where(eq(users.companyId, companyId));
  }
  async getUsersByRole(role) {
    return await db.select().from(users).where(eq(users.role, role));
  }
  async getCompany(id) {
    const [company] = await db.select().from(companies).where(eq(companies.id, id));
    return company || void 0;
  }
  async createCompany(insertCompany) {
    const [company] = await db.insert(companies).values(insertCompany).returning();
    return company;
  }
  async updateCompany(id, companyUpdate) {
    const [company] = await db.update(companies).set({ ...companyUpdate, updatedAt: /* @__PURE__ */ new Date() }).where(eq(companies.id, id)).returning();
    return company || void 0;
  }
  async deleteCompany(id) {
    const result = await db.delete(companies).where(eq(companies.id, id));
    return result.rowCount > 0;
  }
  async getAllCompanies() {
    return await db.select().from(companies);
  }
  async getMessage(id) {
    const [message] = await db.select().from(messages).where(eq(messages.id, id));
    return message || void 0;
  }
  async createMessage(insertMessage) {
    const [message] = await db.insert(messages).values(insertMessage).returning();
    return message;
  }
  async getMessagesByReceiver(receiverId) {
    return await db.select().from(messages).where(eq(messages.receiverId, receiverId));
  }
  async getCompanyMessages(companyId) {
    return await db.select().from(messages).where(eq(messages.companyId, companyId));
  }
  async markMessageAsRead(id) {
    const result = await db.update(messages).set({ isRead: true }).where(eq(messages.id, id));
    return result.rowCount > 0;
  }
  async executeQuery(query) {
    try {
      const result = await pool.query(query);
      return {
        status: "success",
        rows: result.rowCount,
        data: result.rows
      };
    } catch (error) {
      return {
        status: "error",
        message: error instanceof Error ? error.message : "Unknown error"
      };
    }
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "your_session_secret_here",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1e3
      // 24 hours
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const user = await storage.getUserByEmail(email);
          if (!user || !await comparePasswords(password, user.password)) {
            return done(null, false);
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user || false);
    } catch (error) {
      done(error);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const validation = insertUserSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid user data" });
      }
      const existingUser = await storage.getUserByEmail(validation.data.email);
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists" });
      }
      if (req.user) {
        const currentUser = req.user;
        if (validation.data.role === "company_admin" && currentUser.role !== "super_admin") {
          return res.status(403).json({ message: "Only super admin can create company admin accounts" });
        }
        if (validation.data.role === "employee" && !["super_admin", "company_admin"].includes(currentUser.role)) {
          return res.status(403).json({ message: "Insufficient permissions to create employee accounts" });
        }
      }
      const user = await storage.createUser({
        ...validation.data,
        password: await hashPassword(validation.data.password),
        createdBy: req.user?.id
      });
      req.login(user, (err) => {
        if (err) return next(err);
        const { password, ...userWithoutPassword } = user;
        res.status(201).json(userWithoutPassword);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/login", (req, res, next) => {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ message: "Invalid login data" });
    }
    passport.authenticate("local", async (err, user) => {
      if (err) return next(err);
      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }
      if (user.isBlocked) {
        return res.status(403).json({ message: "Account has been blocked. Contact administrator." });
      }
      try {
        const userAgent = req.headers["user-agent"] || "";
        const ipAddress = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || (req.connection.socket ? req.connection.socket.remoteAddress : null) || "unknown";
        const deviceInfo = {
          browser: userAgent.includes("Chrome") ? "Chrome" : userAgent.includes("Firefox") ? "Firefox" : userAgent.includes("Safari") ? "Safari" : "Unknown",
          os: userAgent.includes("Windows") ? "Windows" : userAgent.includes("Mac") ? "macOS" : userAgent.includes("Linux") ? "Linux" : userAgent.includes("Android") ? "Android" : userAgent.includes("iPhone") ? "iOS" : "Unknown",
          device: userAgent.includes("Mobile") ? "Mobile" : "Desktop",
          userAgent
        };
        await storage.updateUser(user.id, {
          lastLoginAt: /* @__PURE__ */ new Date(),
          lastIpAddress: ipAddress,
          deviceInfo: JSON.stringify(deviceInfo)
        });
        req.login(user, (err2) => {
          if (err2) return next(err2);
          const { password, ...userWithoutPassword } = user;
          res.json(userWithoutPassword);
        });
      } catch (error) {
        console.error("Error updating login info:", error);
        req.login(user, (err2) => {
          if (err2) return next(err2);
          const { password, ...userWithoutPassword } = user;
          res.json(userWithoutPassword);
        });
      }
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const { password, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
  });
}

// server/services/zoomService.ts
var zoomConfig = {
  clientId: process.env.ZOOM_CLIENT_ID || "eFwvmyl2TcSKNM1iyMTlng",
  clientSecret: process.env.ZOOM_CLIENT_SECRET || "FYldVq4AcTDt9IclIp9eEkuTUc1IPff6",
  accountId: process.env.ZOOM_ACCOUNT_ID || "OZWhroVYT0adDjOQOUAZSA"
};
var ZoomService = class {
  async getAccessToken() {
    if (process.env.NODE_ENV === "development") {
      return "mock-access-token";
    }
    const credentials = Buffer.from(`${zoomConfig.clientId}:${zoomConfig.clientSecret}`).toString("base64");
    const response = await fetch("https://zoom.us/oauth/token", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${credentials}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "account_credentials",
        account_id: zoomConfig.accountId
      })
    });
    if (!response.ok) {
      throw new Error("Failed to get Zoom access token");
    }
    const data = await response.json();
    return data.access_token;
  }
  async createMeeting(companyId, userId) {
    try {
      const company = await storage.getCompany(companyId);
      if (!company) {
        throw new Error("Company not found");
      }
      if (process.env.NODE_ENV === "development") {
        const mockMeetingId = `${Math.floor(Math.random() * 9e8) + 1e8}`;
        const mockMeetingUrl = `https://zoom.us/j/${mockMeetingId}`;
        const mockPassword = Math.random().toString(36).substring(2, 8);
        await storage.updateCompany(companyId, {
          zoomMeetingId: mockMeetingId,
          zoomMeetingUrl: mockMeetingUrl,
          zoomMeetingPassword: mockPassword
        });
        return {
          id: mockMeetingId,
          join_url: mockMeetingUrl,
          password: mockPassword,
          topic: `${company.name} - 24/7 Company Meeting`
        };
      }
      const accessToken = await this.getAccessToken();
      const meetingData = {
        topic: `${company.name} - 24/7 Company Meeting`,
        type: 8,
        // Recurring meeting with no fixed time
        recurrence: {
          type: 1,
          // Daily
          repeat_interval: 1
        },
        settings: {
          host_video: true,
          participant_video: true,
          join_before_host: true,
          mute_upon_entry: false,
          waiting_room: false,
          audio: "both",
          auto_recording: "none"
        }
      };
      const response = await fetch("https://api.zoom.us/v2/users/me/meetings", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(meetingData)
      });
      if (!response.ok) {
        throw new Error("Failed to create Zoom meeting");
      }
      const meeting = await response.json();
      await storage.updateCompany(companyId, {
        zoomMeetingId: meeting.id.toString(),
        zoomMeetingUrl: meeting.join_url,
        zoomMeetingPassword: meeting.password
      });
      return meeting;
    } catch (error) {
      console.error("Zoom meeting creation error:", error);
      throw error;
    }
  }
  async getMeetingInfo(meetingId) {
    try {
      const accessToken = await this.getAccessToken();
      const response = await fetch(`https://api.zoom.us/v2/meetings/${meetingId}`, {
        headers: {
          "Authorization": `Bearer ${accessToken}`
        }
      });
      if (!response.ok) {
        throw new Error("Failed to get meeting info");
      }
      return await response.json();
    } catch (error) {
      console.error("Get meeting info error:", error);
      throw error;
    }
  }
  async deleteMeeting(meetingId) {
    try {
      const accessToken = await this.getAccessToken();
      const response = await fetch(`https://api.zoom.us/v2/meetings/${meetingId}`, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${accessToken}`
        }
      });
      return response.ok;
    } catch (error) {
      console.error("Delete meeting error:", error);
      return false;
    }
  }
};
var zoomService = new ZoomService();

// server/routes.ts
import { z as z2 } from "zod";
import multer from "multer";
import path from "path";
import fs from "fs";
var uploadsDir = path.join(process.cwd(), "uploads", "voice");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
var upload = multer({
  dest: uploadsDir,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["audio/wav", "audio/mpeg", "audio/webm", "audio/ogg"];
    cb(null, allowedTypes.includes(file.mimetype));
  },
  limits: {
    fileSize: 10 * 1024 * 1024
    // 10MB
  }
});
function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
}
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Authentication required" });
    }
    const user = req.user;
    if (!roles.includes(user.role)) {
      return res.status(403).json({ message: "Insufficient permissions" });
    }
    next();
  };
}
function registerRoutes(app2) {
  setupAuth(app2);
  app2.post("/api/users/create-company-admin", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const validation = insertUserSchema.extend({
        role: z2.literal("company_admin")
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
        createdBy: req.user?.id
      });
      const { password, ...userWithoutPassword } = user;
      res.status(201).json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/users/create-employee", requireRole(["super_admin", "company_admin"]), async (req, res, next) => {
    try {
      const validation = insertUserSchema.extend({
        role: z2.literal("employee")
      }).safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid user data" });
      }
      const currentUser = req.user;
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
        createdBy: req.user?.id
      });
      const { password, ...userWithoutPassword } = user;
      res.status(201).json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/users", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user;
      let users2 = [];
      if (currentUser.role === "super_admin") {
        users2 = await storage.getUsersByRole("company_admin");
        const employees = await storage.getUsersByRole("employee");
        users2 = [...users2, ...employees];
      } else if (currentUser.role === "company_admin" && currentUser.companyId) {
        users2 = await storage.getUsersByCompany(currentUser.companyId);
      }
      const usersWithoutPasswords = users2.map(({ password, ...user }) => ({
        ...user,
        deviceInfo: user.deviceInfo ? JSON.parse(user.deviceInfo) : null
      }));
      res.json(usersWithoutPasswords);
    } catch (error) {
      next(error);
    }
  });
  app2.patch("/api/users/:id/block", requireRole(["super_admin", "company_admin"]), async (req, res, next) => {
    try {
      const userId = parseInt(req.params.id);
      const { isBlocked } = req.body;
      const currentUser = req.user;
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
  app2.post("/api/companies", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const validation = insertCompanySchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid company data" });
      }
      const company = await storage.createCompany({
        ...validation.data,
        createdBy: req.user?.id
      });
      res.status(201).json(company);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/companies", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user;
      if (currentUser.role === "super_admin") {
        const companies2 = await storage.getAllCompanies();
        for (const company of companies2) {
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
  app2.put("/api/companies/:id", requireAuth, async (req, res, next) => {
    try {
      const companyId = parseInt(req.params.id);
      const currentUser = req.user;
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
  app2.delete("/api/companies/:id", requireRole(["super_admin"]), async (req, res, next) => {
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
  app2.post("/api/zoom/create-meeting", requireRole(["company_admin"]), async (req, res, next) => {
    try {
      const currentUser = req.user;
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }
      const meeting = await zoomService.createMeeting(currentUser.companyId, currentUser.id);
      res.json(meeting);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/zoom/meeting-info", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user;
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
  app2.post("/api/messages/send", requireRole(["employee"]), async (req, res, next) => {
    try {
      const currentUser = req.user;
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }
      const companyUsers = await storage.getUsersByCompany(currentUser.companyId);
      const companyAdmin = companyUsers.find((user) => user.role === "company_admin");
      if (!companyAdmin) {
        return res.status(404).json({ message: "No company admin found" });
      }
      const validation = insertMessageSchema.safeParse({
        ...req.body,
        senderId: currentUser.id,
        receiverId: companyAdmin.id,
        companyId: currentUser.companyId
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
  app2.get("/api/messages", requireAuth, async (req, res, next) => {
    try {
      const currentUser = req.user;
      let messages2 = [];
      if (currentUser.role === "company_admin" && currentUser.companyId) {
        messages2 = await storage.getCompanyMessages(currentUser.companyId);
      } else if (currentUser.role === "employee") {
        messages2 = await storage.getMessagesByReceiver(currentUser.id);
      }
      res.json(messages2);
    } catch (error) {
      next(error);
    }
  });
  app2.put("/api/messages/:id/read", requireAuth, async (req, res, next) => {
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
  app2.post("/api/messages/voice", requireRole(["employee"]), upload.single("voice"), async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No voice file uploaded" });
      }
      const currentUser = req.user;
      if (!currentUser.companyId) {
        return res.status(400).json({ message: "No company assigned" });
      }
      const companyUsers = await storage.getUsersByCompany(currentUser.companyId);
      const companyAdmin = companyUsers.find((user) => user.role === "company_admin");
      if (!companyAdmin) {
        return res.status(404).json({ message: "No company admin found" });
      }
      const message = await storage.createMessage({
        senderId: currentUser.id,
        receiverId: companyAdmin.id,
        companyId: currentUser.companyId,
        messageType: "voice",
        content: `/uploads/voice/${req.file.filename}`
      });
      res.status(201).json(message);
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/database/query", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const { query } = req.body;
      if (!query || typeof query !== "string") {
        return res.status(400).json({ message: "Invalid query" });
      }
      if (process.env.NODE_ENV === "production") {
        const destructiveKeywords = ["DROP", "DELETE", "TRUNCATE", "ALTER"];
        const upperQuery = query.toUpperCase();
        if (destructiveKeywords.some((keyword) => upperQuery.includes(keyword))) {
          return res.status(403).json({ message: "Destructive queries not allowed in production" });
        }
      }
      const result = await storage.executeQuery(query);
      res.json(result);
    } catch (error) {
      next(error);
    }
  });
  app2.get("/api/stats", requireRole(["super_admin"]), async (req, res, next) => {
    try {
      const companies2 = await storage.getAllCompanies();
      const companyAdmins = await storage.getUsersByRole("company_admin");
      const employees = await storage.getUsersByRole("employee");
      const activeMeetings = companies2.filter((c) => c.zoomMeetingId).length;
      res.json({
        companies: companies2.length,
        companyAdmins: companyAdmins.length,
        employees: employees.length,
        meetings: activeMeetings
      });
    } catch (error) {
      next(error);
    }
  });
  const httpServer = createServer(app2);
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });
  wss.on("connection", (ws2) => {
    ws2.on("message", (data) => {
      try {
        const message = JSON.parse(data.toString());
        wss.clients.forEach((client) => {
          if (client !== ws2 && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
          }
        });
      } catch (error) {
        console.error("WebSocket message error:", error);
      }
    });
  });
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs2 from "fs";
import path3 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path2 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path2.resolve(import.meta.dirname, "client", "src"),
      "@shared": path2.resolve(import.meta.dirname, "shared"),
      "@assets": path2.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path2.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path2.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path4 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path4.startsWith("/api")) {
      let logLine = `${req.method} ${path4} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = 5e3;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true
  }, () => {
    log(`serving on port ${port}`);
  });
})();
