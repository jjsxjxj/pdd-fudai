-- D1 数据库初始化脚本
-- 在 Cloudflare Dashboard 或用 wrangler d1 execute 运行

-- 邀请码表
CREATE TABLE IF NOT EXISTS codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL,              -- 完整邀请码 (8-9位数字)
  code_masked TEXT NOT NULL,       -- 脱敏后的码 (中间两位隐藏)
  ip TEXT NOT NULL,                -- 提交者IP
  status TEXT DEFAULT 'active',    -- active / used
  used_at TEXT,                    -- 被点击跳转的时间
  created_at TEXT NOT NULL,        -- 提交时间
  location TEXT DEFAULT ''         -- 提交者归属地 (如: 嘉兴市 电信)
);

-- IP 黑名单表
CREATE TABLE IF NOT EXISTS blacklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL UNIQUE,         -- 被拉黑的IP
  reason TEXT DEFAULT '',          -- 拉黑原因
  location TEXT DEFAULT '',        -- 归属地 (如: 嘉兴市 电信)
  duration TEXT DEFAULT '24h',     -- 封禁期限: 24h / 1m / 1y / permanent
  expires_at TEXT,                 -- 过期时间 (NULL表示永久)
  created_at TEXT NOT NULL         -- 拉黑时间
);

-- 假码举报表
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL,              -- 被举报的邀请码 (脱敏展示)
  ip TEXT NOT NULL,                -- 举报人IP
  submitter_ip TEXT DEFAULT '',    -- 被举报码的提交者IP (用于自动拉黑判断)
  status TEXT DEFAULT 'pending',   -- pending / handled / dismissed
  created_at TEXT NOT NULL         -- 举报时间
);

-- 提交日志表 (用于速率限制和审计)
CREATE TABLE IF NOT EXISTS submit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  code TEXT,
  action TEXT NOT NULL,            -- submit / use / blocked / ocr_ai / admin_fail
  reason TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

-- 访问统计表（首页每次访问记录一次，供今日访问量/IP 统计）
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 站点设置表 (公告、广告、联系方式等)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,            -- notice / ads / qq_group / qq_owner / smart_enabled ...
  value TEXT,                      -- 内容 (ads 存 JSON 数组)
  updated_at TEXT NOT NULL
);

-- 索引：加速查询
-- 注意：限流/统计类查询都是 (ip, action, created_at) 三条件组合，
-- 单列索引 idx_logs_ip 会先扫出该 IP 的所有历史日志再过滤，量大后明显变慢；
-- 复合索引可直接命中。
CREATE INDEX IF NOT EXISTS idx_codes_status ON codes(status);
CREATE INDEX IF NOT EXISTS idx_codes_created ON codes(created_at);
-- 列表查询：WHERE status=? ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_codes_status_created ON codes(status, created_at);
-- 重复提交检查：WHERE code=? AND status IN (...)
CREATE INDEX IF NOT EXISTS idx_codes_code ON codes(code);
-- used 码 30 秒轮换清理：WHERE status='used' AND used_at < ?
CREATE INDEX IF NOT EXISTS idx_codes_used_at ON codes(used_at);

CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_blacklist_created ON blacklist(created_at);

-- 限流三件套：checkRateLimit / checkDailyLimit / checkActionRateLimit
CREATE INDEX IF NOT EXISTS idx_logs_ip_action_created ON submit_logs(ip, action, created_at);
-- 旧的单列 ip 索引已被上面的复合索引完全覆盖（ip 为最左前缀），保留只会增加写放大
DROP INDEX IF EXISTS idx_logs_ip;
-- 今日统计：WHERE created_at > ? AND action = ?
CREATE INDEX IF NOT EXISTS idx_logs_action_created ON submit_logs(action, created_at);
CREATE INDEX IF NOT EXISTS idx_logs_created ON submit_logs(created_at);

-- visits 限流（WHERE ip=? AND created_at>?）与今日统计
CREATE INDEX IF NOT EXISTS idx_visits_created ON visits(created_at);
CREATE INDEX IF NOT EXISTS idx_visits_ip_created ON visits(ip, created_at);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
-- 举报防刷：WHERE ip=? AND created_at>?
CREATE INDEX IF NOT EXISTS idx_reports_ip_created ON reports(ip, created_at);
-- 自动拉黑判定：WHERE submitter_ip=? AND created_at>?
CREATE INDEX IF NOT EXISTS idx_reports_submitter_created ON reports(submitter_ip, created_at);
