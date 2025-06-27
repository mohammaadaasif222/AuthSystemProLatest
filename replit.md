# Company Communication Platform

## Overview

This is a full-stack web application built as a multi-tenant communication platform for companies. The system supports three distinct user roles (Super Admin, Company Admin, and Employee) with role-based access control and features including messaging, voice recording, Zoom integration, and database management capabilities.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript
- **UI Library**: Shadcn/ui components built on Radix UI primitives
- **Styling**: Tailwind CSS with custom CSS variables for theming
- **State Management**: TanStack Query (React Query) for server state
- **Routing**: Wouter for client-side routing
- **Form Handling**: React Hook Form with Zod validation
- **Build Tool**: Vite with custom configuration for monorepo structure

### Backend Architecture
- **Runtime**: Node.js 20 with TypeScript (ESM)
- **Framework**: Express.js with custom middleware
- **Authentication**: Passport.js with local strategy and session-based auth
- **Database**: PostgreSQL with Drizzle ORM
- **Database Provider**: Neon serverless PostgreSQL
- **Session Storage**: PostgreSQL-backed sessions using connect-pg-simple
- **File Upload**: Multer for voice message handling
- **Real-time Communication**: WebSocket support for messaging

### Data Storage Solutions
- **Primary Database**: PostgreSQL via Neon serverless
- **ORM**: Drizzle with type-safe schema definitions
- **Session Storage**: PostgreSQL tables for session persistence
- **File Storage**: Local filesystem for voice recordings (uploads/voice directory)
- **Schema Management**: Drizzle migrations in PostgreSQL dialect

## Key Components

### User Management System
- **Three-tier Role System**: Super Admin, Company Admin, Employee
- **Company-based Multi-tenancy**: Users belong to companies with isolated data
- **Password Security**: Scrypt-based password hashing with salt
- **Session Management**: Secure session handling with configurable expiration

### Communication Features
- **Text Messaging**: Company-wide messaging system with read/unread status
- **Voice Messaging**: Audio recording and upload capabilities with file type validation
- **Real-time Updates**: WebSocket integration for live message delivery
- **Message Types**: Support for both text and voice message formats

### Integration Services
- **Zoom Integration**: Full Zoom API integration for meeting management
  - OAuth 2.0 authentication with Zoom
  - Automatic meeting creation for companies
  - 24/7 persistent meeting rooms
  - Meeting URL and password management

### Administrative Tools
- **Database Query Interface**: Direct SQL query execution for Super Admins
- **Company Management**: CRUD operations for company entities
- **User Management**: User creation, role assignment, and company association
- **Statistics Dashboard**: Real-time metrics and system statistics

## Data Flow

### Authentication Flow
1. User submits credentials via login form
2. Passport.js validates against database using scrypt password verification
3. Session created and stored in PostgreSQL
4. User object attached to request context
5. Role-based route protection enforced

### Message Flow
1. User creates message (text or voice) via frontend interface
2. Message validated and stored in PostgreSQL with sender/receiver metadata
3. WebSocket notification sent to relevant users
4. Real-time UI updates via TanStack Query invalidation
5. Read receipts tracked and updated

### Company Management Flow
1. Super Admin creates company via admin dashboard
2. Company Admin assigned to manage company users
3. Zoom meeting automatically created and configured
4. Company-specific data isolation enforced at database level

## External Dependencies

### Frontend Dependencies
- **UI Components**: Extensive Radix UI component library for accessibility
- **State Management**: TanStack Query for server state synchronization
- **Form Validation**: Zod for runtime type validation
- **Styling**: Tailwind CSS with class-variance-authority for component variants
- **Icons**: Lucide React for consistent iconography

### Backend Dependencies
- **Database**: Neon serverless PostgreSQL with WebSocket constructor
- **Authentication**: Passport.js with express-session
- **File Upload**: Multer with type and size validation
- **Password Security**: Node.js crypto module for scrypt hashing
- **API Integration**: Fetch API for Zoom service communication

### Development Dependencies
- **Build Tools**: Vite with React plugin and custom bundling
- **Type Safety**: TypeScript with strict configuration
- **Development Server**: Hot module replacement and error overlay
- **Database Migration**: Drizzle Kit for schema management

## Deployment Strategy

### Production Build
- **Frontend**: Vite builds optimized React bundle to dist/public
- **Backend**: ESBuild bundles Express server to dist/index.js
- **Static Assets**: Served from built frontend bundle

### Environment Configuration
- **Database**: Requires DATABASE_URL environment variable
- **Sessions**: Configurable SESSION_SECRET for security
- **Zoom Integration**: Requires Zoom OAuth credentials
- **Node Environment**: NODE_ENV controls development/production behavior

### Deployment Target
- **Platform**: Replit Autoscale deployment
- **Port Configuration**: Express server on port 5000, exposed on port 80
- **Process Management**: npm scripts for development and production modes
- **Database Provisioning**: Automated PostgreSQL database setup

### Health Monitoring
- **Request Logging**: Custom middleware for API request tracking
- **Error Handling**: Centralized error handling with status code management
- **Development Tools**: Runtime error modal and source mapping for debugging

## Changelog
- June 27, 2025. Initial setup
- June 27, 2025. Database seeded with demo accounts - authentication system fully functional
- June 27, 2025. Company admin and employee dashboards implemented with meeting management and messaging
- June 27, 2025. Mock Zoom integration for localhost development - company admins can create meetings, employees can join
- June 27, 2025. Real-time messaging system between employees and company admins working correctly

## User Preferences

Preferred communication style: Simple, everyday language.