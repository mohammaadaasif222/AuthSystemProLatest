import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Express } from "express";
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { storage } from "./storage";
import { User as SelectUser, insertUserSchema, loginSchema } from "@shared/schema";

declare global {
  namespace Express {
    interface User extends SelectUser {}
  }
}

const scryptAsync = promisify(scrypt);

async function hashPassword(password: string) {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

async function comparePasswords(supplied: string, stored: string) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

export function setupAuth(app: Express) {
  const sessionSettings: session.SessionOptions = {
    secret: process.env.SESSION_SECRET || "your_session_secret_here",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  };

  app.set("trust proxy", 1);
  app.use(session(sessionSettings));
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const user = await storage.getUserByEmail(email);
          if (!user || !(await comparePasswords(password, user.password))) {
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
  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user || false);
    } catch (error) {
      done(error);
    }
  });

  app.post("/api/register", async (req, res, next) => {
    try {
      const validation = insertUserSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ message: "Invalid user data" });
      }

      const existingUser = await storage.getUserByEmail(validation.data.email);
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Only super_admin can create company_admin accounts
      // Only super_admin and company_admin can create employee accounts
      if (req.user) {
        const currentUser = req.user as SelectUser;
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
        createdBy: req.user?.id,
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

  app.post("/api/login", (req, res, next) => {
    const validation = loginSchema.safeParse(req.body);
    if (!validation.success) {
      return res.status(400).json({ message: "Invalid login data" });
    }

    passport.authenticate("local", async (err: any, user: SelectUser | false) => {
      if (err) return next(err);
      if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Check if user is blocked
      if (user.isBlocked) {
        return res.status(403).json({ message: "Account has been blocked. Contact administrator." });
      }

      try {
        // Get device and IP information
        const userAgent = req.headers['user-agent'] || '';
        const ipAddress = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 
                         (req.connection.socket ? req.connection.socket.remoteAddress : null) || 'unknown';
        
        // Parse device info from user agent
        const deviceInfo = {
          browser: userAgent.includes('Chrome') ? 'Chrome' : userAgent.includes('Firefox') ? 'Firefox' : userAgent.includes('Safari') ? 'Safari' : 'Unknown',
          os: userAgent.includes('Windows') ? 'Windows' : userAgent.includes('Mac') ? 'macOS' : userAgent.includes('Linux') ? 'Linux' : userAgent.includes('Android') ? 'Android' : userAgent.includes('iPhone') ? 'iOS' : 'Unknown',
          device: userAgent.includes('Mobile') ? 'Mobile' : 'Desktop',
          userAgent: userAgent
        };

        // Update user's last login info
        await storage.updateUser(user.id, {
          lastLoginAt: new Date(),
          lastIpAddress: ipAddress,
          deviceInfo: JSON.stringify(deviceInfo)
        });

        req.login(user, (err) => {
          if (err) return next(err);
          const { password, ...userWithoutPassword } = user;
          res.json(userWithoutPassword);
        });
      } catch (error) {
        console.error('Error updating login info:', error);
        req.login(user, (err) => {
          if (err) return next(err);
          const { password, ...userWithoutPassword } = user;
          res.json(userWithoutPassword);
        });
      }
    })(req, res, next);
  });

  app.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });

  app.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const { password, ...userWithoutPassword } = req.user as SelectUser;
    res.json(userWithoutPassword);
  });
}

export { hashPassword, comparePasswords };
