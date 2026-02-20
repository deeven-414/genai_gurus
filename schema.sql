-- ================================================================
--  CodeReview AI — MySQL Database Schema
--  Run once:  mysql -u root -p < schema.sql
-- ================================================================

CREATE DATABASE IF NOT EXISTS codereview_ai
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE codereview_ai;

-- ── users ──────────────────────────────────────────────────────
-- Stores login credentials (email + bcrypt-hashed password)
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  name          VARCHAR(120)  NOT NULL,
  email         VARCHAR(255)  NOT NULL,
  password_hash VARCHAR(255)  NOT NULL,       -- bcrypt hash, never plain text
  is_active     TINYINT(1)    NOT NULL DEFAULT 1,
  created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
                                        ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE  KEY uq_email  (email),
  INDEX         idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── password_reset_tokens ──────────────────────────────────────
-- Holds time-limited tokens for "Forgot Password" flow
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id         INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED  NOT NULL,
  token      VARCHAR(255)  NOT NULL,
  expires_at DATETIME      NOT NULL,
  used       TINYINT(1)    NOT NULL DEFAULT 0,
  created_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_token (token),
  INDEX      idx_token (token),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── code_reviews ───────────────────────────────────────────────
-- Saves each review result linked to the authenticated user
CREATE TABLE IF NOT EXISTS code_reviews (
  id         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED     NOT NULL,
  language   VARCHAR(50)      NOT NULL,
  code       MEDIUMTEXT       NOT NULL,
  review     MEDIUMTEXT,
  score      TINYINT UNSIGNED,               -- extracted X/10 value
  created_at DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_user    (user_id),
  INDEX idx_created (created_at),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── code_rewrites ──────────────────────────────────────────────
-- Saves each rewrite result linked to the authenticated user
CREATE TABLE IF NOT EXISTS code_rewrites (
  id             INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id        INT UNSIGNED  NOT NULL,
  language       VARCHAR(50)   NOT NULL,
  original_code  MEDIUMTEXT    NOT NULL,
  rewritten_code MEDIUMTEXT,
  created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;