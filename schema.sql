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
  action TEXT NOT NULL,            -- submit / use / blocked
  reason TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

-- 站点设置表 (公告、广告、联系方式等)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,            -- notice / ads / qq_group / qq_owner / smart_enabled ...
  value TEXT,                      -- 内容 (ads 存 JSON 数组)
  updated_at TEXT NOT NULL
);

-- 索引：加速查询
CREATE INDEX IF NOT EXISTS idx_codes_status ON codes(status);
CREATE INDEX IF NOT EXISTS idx_codes_created ON codes(created_at);
CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON submit_logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_created ON submit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
