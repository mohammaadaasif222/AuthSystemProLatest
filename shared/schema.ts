import { pgTable, text, serial, integer, boolean, timestamp, varchar, foreignKey } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";

export const companies = pgTable("companies", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  isActive: boolean("is_active").default(true),
  zoomMeetingId: varchar("zoom_meeting_id", { length: 255 }),
  zoomMeetingUrl: text("zoom_meeting_url"),
  zoomMeetingPassword: varchar("zoom_meeting_password", { length: 255 }),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
  createdBy: integer("created_by"),
});

export const users = pgTable("users", {
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
  createdBy: integer("created_by"),
}, (table) => ({
  companyReference: foreignKey({
    columns: [table.companyId],
    foreignColumns: [companies.id],
  }),
  createdByReference: foreignKey({
    columns: [table.createdBy],
    foreignColumns: [table.id],
  }),
}));

export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  senderId: integer("sender_id").notNull(),
  receiverId: integer("receiver_id").notNull(),
  companyId: integer("company_id").notNull(),
  messageType: varchar("message_type", { length: 20 }).notNull(),
  content: text("content").notNull(),
  isRead: boolean("is_read").default(false),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => ({
  senderReference: foreignKey({
    columns: [table.senderId],
    foreignColumns: [users.id],
  }),
  receiverReference: foreignKey({
    columns: [table.receiverId],
    foreignColumns: [users.id],
  }),
  companyReference: foreignKey({
    columns: [table.companyId],
    foreignColumns: [companies.id],
  }),
}));

// Relations
export const companiesRelations = relations(companies, ({ many, one }) => ({
  users: many(users),
  messages: many(messages),
  createdByUser: one(users, {
    fields: [companies.createdBy],
    references: [users.id],
  }),
}));

export const usersRelations = relations(users, ({ many, one }) => ({
  company: one(companies, {
    fields: [users.companyId],
    references: [companies.id],
  }),
  sentMessages: many(messages, { relationName: "sender" }),
  receivedMessages: many(messages, { relationName: "receiver" }),
  createdByUser: one(users, {
    fields: [users.createdBy],
    references: [users.id],
  }),
  createdUsers: many(users, { relationName: "created_users" }),
  createdCompanies: many(companies),
}));

export const messagesRelations = relations(messages, ({ one }) => ({
  sender: one(users, {
    fields: [messages.senderId],
    references: [users.id],
    relationName: "sender",
  }),
  receiver: one(users, {
    fields: [messages.receiverId],
    references: [users.id],
    relationName: "receiver",
  }),
  company: one(companies, {
    fields: [messages.companyId],
    references: [companies.id],
  }),
}));

// Schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertCompanySchema = createInsertSchema(companies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertMessageSchema = createInsertSchema(messages).omit({
  id: true,
  createdAt: true,
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Company = typeof companies.$inferSelect;
export type InsertCompany = z.infer<typeof insertCompanySchema>;
export type Message = typeof messages.$inferSelect;
export type InsertMessage = z.infer<typeof insertMessageSchema>;
export type LoginData = z.infer<typeof loginSchema>;
