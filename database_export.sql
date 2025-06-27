-- Complete Database Export for Authentication System
-- Run this script in pgAdmin to recreate the entire database locally

-- Drop existing tables if they exist
DROP TABLE IF EXISTS session CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS companies CASCADE;

-- Create companies table
CREATE TABLE companies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    zoom_meeting_id VARCHAR(255),
    zoom_meeting_url VARCHAR(512),
    zoom_meeting_password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER
);

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('super_admin', 'company_admin', 'employee')),
    company_id INTEGER REFERENCES companies(id),
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    is_blocked BOOLEAN DEFAULT false,
    last_login_at TIMESTAMP,
    last_ip_address VARCHAR(45),
    device_info TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER
);

-- Create messages table
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER NOT NULL REFERENCES users(id),
    company_id INTEGER NOT NULL REFERENCES companies(id),
    message_type VARCHAR(20) DEFAULT 'text' CHECK (message_type IN ('text', 'voice')),
    content TEXT NOT NULL,
    file_path VARCHAR(512),
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create session table for authentication
CREATE TABLE session (
    sid VARCHAR NOT NULL COLLATE "default",
    sess JSON NOT NULL,
    expire TIMESTAMP(6) NOT NULL
) WITH (OIDS=FALSE);

ALTER TABLE session ADD CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE;
CREATE INDEX IDX_session_expire ON session (expire);

-- Insert sample companies data
INSERT INTO companies (id, name, description, is_active, zoom_meeting_id, zoom_meeting_url, zoom_meeting_password, created_at, updated_at, created_by) VALUES
(1, 'Tech Solutions Inc.', 'Technology consulting company', true, '123456789', 'https://zoom.us/j/123456789', 'demo123', '2025-06-27 11:33:15.626', '2025-06-27 11:33:15.626', NULL),
(2, 'Global Enterprises', 'International business solutions', true, NULL, NULL, NULL, '2025-06-27 12:00:00.000', '2025-06-27 12:00:00.000', 1);

-- Insert sample users data (passwords are hashed with scrypt)
-- Passwords: admin123 for super_admin and company_admin, employee123 for employees
INSERT INTO users (id, email, password, role, company_id, first_name, last_name, is_active, is_blocked, last_login_at, last_ip_address, device_info, created_at, updated_at, created_by) VALUES
(1, 'superadmin@system.com', '821f9c3d4b78962b9b130a1c4d5fea63599e68365ab1b129729a8ecc5ffc59308b8dd1c9f2cf5cd63eaaf3f4622ac40aafe94c5e9454a29a135d3079e8950454.ea496c9179641fd8a6d6faf7da5bdc24', 'super_admin', NULL, 'Super', 'Admin', true, false, '2025-06-27 18:00:00.000', '192.168.1.100', '{"browser":"Chrome","os":"Windows","device":"Desktop","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}', '2025-06-27 11:33:29.224', '2025-06-27 11:33:29.224', NULL),
(2, 'admin@techsolutions.com', '821f9c3d4b78962b9b130a1c4d5fea63599e68365ab1b129729a8ecc5ffc59308b8dd1c9f2cf5cd63eaaf3f4622ac40aafe94c5e9454a29a135d3079e8950454.ea496c9179641fd8a6d6faf7da5bdc24', 'company_admin', 1, 'Company', 'Admin', true, false, '2025-06-27 18:07:00.000', '192.168.1.101', '{"browser":"Chrome","os":"macOS","device":"Desktop","userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}', '2025-06-27 11:33:36.276', '2025-06-27 11:33:36.276', 1),
(3, 'john.doe@techsolutions.com', '92b6ad940d59094360aacbf18c2245fb8ead903c2b7b02a7249a473c9b37192cd828405cdfc921ec86c9b6d113ea7494c3a66d6fe285473848f7d561a7e7b05f.689d87a691dc3371c8643d7e1d594703', 'employee', 1, 'John', 'Doe', true, false, '2025-06-27 18:01:00.000', '192.168.1.102', '{"browser":"Firefox","os":"Linux","device":"Desktop","userAgent":"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"}', '2025-06-27 11:33:44.173', '2025-06-27 11:33:44.173', 2),
(4, 'jane.smith@techsolutions.com', '92b6ad940d59094360aacbf18c2245fb8ead903c2b7b02a7249a473c9b37192cd828405cdfc921ec86c9b6d113ea7494c3a66d6fe285473848f7d561a7e7b05f.689d87a691dc3371c8643d7e1d594703', 'employee', 1, 'Jane', 'Smith', true, false, '2025-06-27 17:45:00.000', '192.168.1.103', '{"browser":"Safari","os":"iOS","device":"Mobile","userAgent":"Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15"}', '2025-06-27 11:33:48.619', '2025-06-27 11:33:48.619', 2),
(5, 'admin@globalenterprises.com', '821f9c3d4b78962b9b130a1c4d5fea63599e68365ab1b129729a8ecc5ffc59308b8dd1c9f2cf5cd63eaaf3f4622ac40aafe94c5e9454a29a135d3079e8950454.ea496c9179641fd8a6d6faf7da5bdc24', 'company_admin', 2, 'Global', 'Admin', true, false, NULL, NULL, NULL, '2025-06-27 12:00:00.000', '2025-06-27 12:00:00.000', 1);

-- Insert sample messages data
INSERT INTO messages (id, sender_id, receiver_id, company_id, message_type, content, is_read, created_at) VALUES
(1, 3, 2, 1, 'text', 'Hello from employee John - this is a test message to the company admin', false, '2025-06-27 11:54:47.546'),
(2, 4, 2, 1, 'text', 'Hi, I need assistance with the project deadline. Can we schedule a meeting?', false, '2025-06-27 12:00:15.123'),
(3, 3, 2, 1, 'text', 'The meeting was very productive today. Thank you for organizing it.', true, '2025-06-27 12:00:30.456');

-- Set sequence values to continue from current max IDs
SELECT setval('companies_id_seq', (SELECT MAX(id) FROM companies));
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));
SELECT setval('messages_id_seq', (SELECT MAX(id) FROM messages));

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_company_id ON users(company_id);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_messages_sender_id ON messages(sender_id);
CREATE INDEX idx_messages_receiver_id ON messages(receiver_id);
CREATE INDEX idx_messages_company_id ON messages(company_id);
CREATE INDEX idx_messages_created_at ON messages(created_at);

/*
Demo Accounts for Testing:
- Super Admin: superadmin@system.com / admin123
- Company Admin (Tech Solutions): admin@techsolutions.com / admin123  
- Company Admin (Global Enterprises): admin@globalenterprises.com / admin123
- Employee (Tech Solutions): john.doe@techsolutions.com / employee123
- Employee (Tech Solutions): jane.smith@techsolutions.com / employee123

Features:
- Role-based access control with three user levels
- Company management with multi-tenancy
- Meeting management with mock Zoom integration (Meeting ID: 123456789)
- Real-time messaging between employees and company admins
- Session-based authentication with PostgreSQL storage
*/