-- ============================================================
-- CyberGuard v2.0 — MySQL Database Schema
-- To use MySQL: pip install PyMySQL
-- Change DATABASE_URL in config.py to:
--   mysql+pymysql://root:password@localhost/cyberguard_db
-- Then run: mysql -u root -p < database/cyberguard.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS cyberguard_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cyberguard_db;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(100)  NOT NULL,
    email           VARCHAR(255)  NOT NULL UNIQUE,
    password_hash   VARCHAR(512)  NOT NULL,
    role            ENUM('user','admin') NOT NULL DEFAULT 'user',
    is_verified     TINYINT(1)    NOT NULL DEFAULT 0,
    is_blocked      TINYINT(1)    NOT NULL DEFAULT 0,
    login_attempts  INT           NOT NULL DEFAULT 0,
    locked_until    DATETIME      DEFAULT NULL,
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Login history / audit log
CREATE TABLE IF NOT EXISTS login_history (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT          NOT NULL,
    login_time  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address  VARCHAR(64),
    user_agent  VARCHAR(512),
    status      ENUM('success','failed','blocked') NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- OTP tokens (2FA)
CREATE TABLE IF NOT EXISTS otp_tokens (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT          NOT NULL,
    token       VARCHAR(10)  NOT NULL,
    purpose     VARCHAR(20)  NOT NULL DEFAULT 'login',
    expires_at  DATETIME     NOT NULL,
    used        TINYINT(1)   NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Email tokens (verification + password reset)
CREATE TABLE IF NOT EXISTS email_tokens (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT          NOT NULL,
    token       VARCHAR(128) NOT NULL UNIQUE,
    purpose     ENUM('verify','reset') NOT NULL,
    expires_at  DATETIME     NOT NULL,
    used        TINYINT(1)   NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Blog posts
CREATE TABLE IF NOT EXISTS blog_posts (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    title       VARCHAR(255) NOT NULL,
    slug        VARCHAR(300) NOT NULL UNIQUE,
    content     TEXT         NOT NULL,
    author_id   INT,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ── Indexes for performance ────────────────────────────────────────────────
CREATE INDEX idx_login_history_user ON login_history(user_id);
CREATE INDEX idx_login_history_time ON login_history(login_time);
CREATE INDEX idx_otp_user           ON otp_tokens(user_id);
CREATE INDEX idx_email_token        ON email_tokens(token);
