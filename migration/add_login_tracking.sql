-- RBAC users table migration: add login tracking fields
-- Run this on existing databases to add new columns

-- Add registration timestamp (NOT NULL with default for existing rows)
ALTER TABLE users ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '用户注册时间';

-- Add last login timestamp
ALTER TABLE users ADD COLUMN last_login TIMESTAMP NULL DEFAULT NULL COMMENT '最后登录时间';

-- Add consecutive login fail count
ALTER TABLE users ADD COLUMN login_fail_count SMALLINT NOT NULL DEFAULT 0 COMMENT '连续登录失败次数';

-- Add last login failure timestamp
ALTER TABLE users ADD COLUMN last_login_fail TIMESTAMP NULL DEFAULT NULL COMMENT '最后登录失败时间';
