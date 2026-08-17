-- ================================================================
-- RBAC users 表结构对齐（生产执行，幂等可重复跑）
-- 依赖功能：登录审计(login/login_fail) + 账户锁定(5分钟失败窗口计数)
-- 对齐 models/users.json 定义
-- 用法：先 USE 到 users 表所在库（Sage 生产为 sage 库）再执行
-- ================================================================

-- 1) created_at 注册日期（date 可空）
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='created_at');
SET @sql = IF(@col=0,
  'ALTER TABLE users ADD COLUMN created_at date DEFAULT NULL COMMENT ''注册日期''',
  'ALTER TABLE users MODIFY created_at date DEFAULT NULL COMMENT ''注册日期''');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 2) last_login 最后登录时间（timestamp 可空）
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='last_login');
SET @sql = IF(@col=0,
  'ALTER TABLE users ADD COLUMN last_login timestamp NULL DEFAULT NULL COMMENT ''最后登录时间''',
  'ALTER TABLE users MODIFY last_login timestamp NULL DEFAULT NULL COMMENT ''最后登录时间''');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 3) login_fail_count 连续登录失败次数（smallint NOT NULL DEFAULT 0）
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='login_fail_count');
SET @sql = IF(@col=0,
  'ALTER TABLE users ADD COLUMN login_fail_count smallint NOT NULL DEFAULT 0 COMMENT ''连续登录失败次数''',
  'ALTER TABLE users MODIFY login_fail_count smallint NOT NULL DEFAULT 0 COMMENT ''连续登录失败次数''');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 4) last_login_fail 最后登录失败时间（关键修复：必须 NULL 可空）
--    早期手工建表为 NOT NULL DEFAULT current_timestamp()，
--    成功登录时 SET last_login_fail=NULL 会被 MySQL 静默转成当前时间戳，
--    导致 5 分钟失败窗口的 IS NULL 判定永远失效，账户锁定逻辑错误。
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='last_login_fail');
SET @sql = IF(@col=0,
  'ALTER TABLE users ADD COLUMN last_login_fail timestamp NULL DEFAULT NULL COMMENT ''最后登录失败时间''',
  'ALTER TABLE users MODIFY last_login_fail timestamp NULL DEFAULT NULL COMMENT ''最后登录失败时间''');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 5) sync_from 同步应用id（仅补加，已存在则跳过）
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' AND COLUMN_NAME='sync_from');
SET @sql = IF(@col=0,
  'ALTER TABLE users ADD COLUMN sync_from varchar(32) DEFAULT NULL COMMENT ''同步应用id''',
  'SELECT ''sync_from already exists''');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- 验证结果（应显示 5 行，last_login_fail 的 Null 列为 YES）
SHOW COLUMNS FROM users WHERE Field IN ('created_at','last_login','login_fail_count','last_login_fail','sync_from');
