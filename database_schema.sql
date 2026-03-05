-- Database Schema for Secure User Registration System
-- This file documents the database structure
-- The actual database (users.db) is created automatically when the app runs

-- Users Table
-- Stores registered user information with secure password hashes
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table Description:
-- id: Unique identifier for each user (auto-incremented)
-- username: Unique username (3-20 characters, alphanumeric + underscore)
-- email: Unique email address (used for OTP verification)
-- password_hash: bcrypt hashed password (never stores plain text)
-- created_at: Timestamp of account creation

-- Security Notes:
-- 1. Passwords are hashed using bcrypt before storage
-- 2. Username uniqueness is enforced at database level
-- 3. Email uniqueness is enforced at database level
-- 4. No sensitive data stored in plain text
-- 5. Database file (users.db) is created automatically on first run
-- 6. Database file should NOT be committed to version control
