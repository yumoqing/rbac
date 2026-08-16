-- RBAC users 表结构修正：对齐 models/users.json 定义
-- 修复早期手工建表导致的类型/约束错误。
-- 实测 pipeline 库 users 表 last_login_fail 为 NOT NULL DEFAULT current_timestamp()，
-- 导致 up_login.dspy 成功登录时 SET last_login_fail=NULL 被 MySQL 转成当前时间戳。
-- 对齐后：last_login_fail/last_login 可空，NULL=从未失败。

ALTER TABLE users MODIFY created_at date DEFAULT NULL COMMENT '注册日期';
ALTER TABLE users MODIFY last_login timestamp NULL DEFAULT NULL COMMENT '最后登录时间';
ALTER TABLE users MODIFY login_fail_count smallint NOT NULL DEFAULT 0 COMMENT '连续登录失败次数';
ALTER TABLE users MODIFY last_login_fail timestamp NULL DEFAULT NULL COMMENT '最后登录失败时间';

-- sync_from 列幂等补加（MySQL 8.0 无 ADD COLUMN IF NOT EXISTS）
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'sync_from');
SET @sql = IF(@col = 0,
              'ALTER TABLE users ADD COLUMN sync_from varchar(32) DEFAULT NULL COMMENT ''同步应用id''',
              'SELECT ''sync_from already exists''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
