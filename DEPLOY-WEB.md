# PDD 福袋互助平台 — 网页在线部署教程

> 全程在浏览器里操作，不装任何软件，不开终端，不用命令行。
> 只要会注册账号、会复制粘贴就能部署。
> 预计耗时：**10~15 分钟**

## ⚠️ 开始之前：先确认这本教程适合你

| | 本教程（纯网页部署） | [命令行部署](DEPLOY.md) |
|---|---|---|
| 需要装软件 | 不用 | Node.js + Wrangler |
| 获取源码 | 从 GitHub 网页复制 | `git clone` |
| 提交 / 取码 / 举报 / 黑名单 / 后台管理 | ✅ 全部可用 | ✅ 全部可用 |
| 识别截图（秒出互助码） | ✅ 可用 | ✅ 可用 |
| AI 识图兜底（可选） | ✅ 可用（做第 6.2 步的 AI 绑定即可） | ✅ 可用 |

**两种方式功能完全一致。**
「识别截图」用的是**内联在 `src/index.js` 里的像素匹配算法** —— 它不依赖任何需要额外上传的静态资源（早期版本曾用 tesseract.js，要拖一个 20MB 的模型包，那种方案网页版确实用不了）。所以只靠粘贴一个代码文件的网页版，同样能秒出结果、且图片不出本机。

**唯一可选的一步是 AI 识图兜底**：本地没认出码时，可以把图片再交给 Cloudflare Workers AI 试一次。这需要在第 6.2 步绑定 Workers AI，**不做也不影响识别截图**。

---

## 目录

1. [注册 Cloudflare 账号](#第-1-步注册-cloudflare-账号)
2. [创建 D1 数据库](#第-2-步创建-d1-数据库)
3. [建数据库表](#第-3-步建数据库表)
4. [创建 Worker](#第-4-步创建-worker)
5. [获取代码并粘贴](#第-5-步获取代码并粘贴到编辑器)
6. [绑定数据库与 AI](#第-6-步绑定数据库与-ai)
7. [设置管理密码](#第-7-步设置管理密码)
8. [设置定时清空](#第-8-步设置定时清空)
9. [部署上线](#第-9-步部署上线)
10. [绑定自定义域名（可选）](#第-10-步绑定自定义域名可选)
11. [进入后台管理](#第-11-步进入后台管理)
12. [常见问题](#常见问题)

---

## 第 1 步：注册 Cloudflare 账号

1. 打开浏览器，访问 **https://dash.cloudflare.com/sign-up**
2. 输入你的邮箱和密码
3. 点 **Create Account**
4. 去邮箱收验证邮件，点验证链接
5. 登录成功

> 已有账号的直接登录。

---

## 第 2 步：创建 D1 数据库

D1 是 Cloudflare 的免费数据库，用来存邀请码、黑名单等数据。

1. 登录后，在左侧菜单找到 **Storage & Databases**
2. 点 **D1 SQL Database**
3. 点 **Create Database**（创建数据库）
4. **Database name** 填：`pdd-fudai-db`
5. 点 **Create**

创建完成后，你会看到一个数据库页面。**把这个页面的网址留着**，等下还要回来。

> 记住数据库名称 `pdd-fudai-db`，后面要用。

---

## 第 3 步：建数据库表

1. 在刚才创建的 D1 数据库页面里，点 **Console**（控制台）标签页
2. 你会看到一个 SQL 输入框
3. 把下面的 SQL **全部复制**，粘贴到输入框里：

```sql
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
```

4. 点 **Execute**（执行）按钮
5. 看到绿色 "Success" 就建好了

> **⚠️ 千万别漏掉 `visits` 表和那几条索引。** 首页的「今日访问量」统计会读 `visits` 表，表不存在的话 `/api/config` 接口会直接报错，**打开首页就是白屏**。限流接口也依赖 `idx_logs_ip_action_created`，缺了会退化成全表扫描。
>
> **上面这份 SQL 与仓库里的 [`schema.sql`](https://github.com/jjsxjxj/pdd-fudai/blob/main/schema.sql) 完全一致。** 如果将来代码有更新，判断依据以仓库文件为准——在 GitHub 打开它，点右上角 **Copy raw file** 按钮复制全部内容，再粘贴到这里执行即可（重复执行是安全的，所有语句都带 `IF NOT EXISTS`）。

---

## 第 4 步：创建 Worker

1. 回到 Cloudflare 主页（点左上角 Cloudflare 图标）
2. 左侧菜单点 **Workers & Pages**
3. 点 **Create**（创建）
4. 选 **Create Worker**（创建 Worker）
5. **Name** 填：`pdd-fudai`
6. 点 **Deploy**（部署）

> 先随便部署，下一步会替换代码。

部署后你会看到一个预览页面，先别管它，点 **Edit code**（编辑代码）进入代码编辑器。

---

## 第 5 步：获取代码并粘贴到编辑器

### 5.1 从 GitHub 复制代码（不用装任何软件）

1. 用浏览器打开源码页面：
   **https://github.com/jjsxjxj/pdd-fudai/blob/main/src/index.js**
2. 点代码框右上角的 **Copy raw file**（复制原始文件）按钮 —— 整份代码会复制到剪贴板
3. 如果没看到这个按钮：点右上角的 **Raw**，在新打开的纯文本页面里按 `Ctrl+A` 全选、`Ctrl+C` 复制

> **⚠️ 不要在 GitHub 的代码预览页直接 Ctrl+A 复制。** 预览页每一行开头都带着行号，粘进编辑器后整份代码都会报语法错误。必须用 **Copy raw file** 按钮或 **Raw** 页面。

### 5.2 粘贴并部署

1. 回到 Cloudflare 代码编辑器（左边是代码区，右边是预览区）
2. **把左边代码区里的内容全部删掉**（点进代码区，`Ctrl+A` 全选，再按 `Delete`）
3. `Ctrl+V` 粘贴刚才复制的代码
4. 等代码加载完（文件约 90KB，粘贴后等 2~3 秒）
5. 检查代码：**开头应是 `/**`，结尾应是 `};`**。如果被截断了，说明没复制完整，回到 5.1 重来
6. 点右上角 **Deploy**（部署）

---

## 第 6 步：绑定数据库与 AI

### 6.1 绑定数据库（必须）

Worker 需要连上第 2 步建的数据库才能工作。

1. 在 Worker 页面（不是代码编辑器），点 **Settings**（设置）标签页
2. 找到 **Bindings**（绑定）部分，点 **Add binding**
3. 选 **D1 database**
4. 填写：
   - **Variable name**：`DB`（必须是大写的 DB，不能写错）
   - **D1 database**：下拉选择 `pdd-fudai-db`（第 2 步创建的那个）
5. 点 **Save**（保存）

> **⚠️ 变量名必须填 `DB`**，代码里用的是 `env.DB`，写错就连不上数据库，首页会白屏。

### 6.2 绑定 Workers AI（AI 识图兜底，可选）

**不绑定也能用「识别截图」** —— 本地像素识别内联在页面代码里，不需要任何额外资源。绑定 AI 只是多一层兜底：本地没认出码时，自动把图片再交给 AI 试一次。

不想要这层兜底，可以直接跳过本步。

1. 仍在 **Settings** → **Bindings** 区域，点 **Add binding**
2. 类型选 **Workers AI**
3. **Variable name** 填 `AI`（大写）
4. 点 **Save**（保存）
5. 回到代码编辑器，点一次 **Deploy** 让绑定生效

> **识别方式说明**：识别截图**先**在浏览器里做本地像素识别（不联网、图片不出本机、毫秒级）；只有本地没认出或置信度偏低时，才会走服务端 AI（此时图片会发给 Cloudflare Workers AI 模型处理）。
>
> 想启用这层兜底：登录后台 → **站点设置** → 把 **识别截图模式** 选成 **本地识别 + AI 兜底**。

---

## 第 7 步：设置管理密码

1. 在 Settings 页面，找到 **Variables and Secrets**（变量和密钥）
2. 点 **Add variable**
3. 填写：
   - **Variable name**：`ADMIN_KEY`
   - **Value**：你自己想一个密码（比如 `mySecret123!@#`）
   - **Type**：选 **Secret**（加密存储，更安全）
4. 点 **Save**（保存）

> **⚠️ 请牢记这个密码！** 这是进后台的钥匙，丢了只能重新设。

---

## 第 8 步：设置定时清空

让系统每天 23:59 自动清空互助码，零点开始新一天。

1. 在 Settings 页面，找到 **Triggers**（触发器）部分
2. 找到 **Cron Triggers**
3. 点 **Add Cron Trigger**
4. 填入 Cron 表达式：`59 15 * * *`
5. 点 **Save**

> **为什么是 `59 15`？** Cron 用 UTC 时间，中国时间 = UTC + 8。
> 23:59 中国时间 = 15:59 UTC。

**想改成别的时间？** 对照表：

| 中国时间 | Cron 表达式 |
|---------|------------|
| 23:59 | `59 15 * * *` |
| 00:00 | `0 16 * * *` |
| 06:00 | `0 22 * * *` |
| 12:00 | `0 4 * * *` |

---

## 第 9 步：部署上线

1. 回到 Worker 主页面，点 **Edit code** 进入编辑器
2. 不需要改代码，直接点右上角 **Deploy**（部署）
3. 等待几秒，显示 "Deployed" 就完成了

🎉 **现在可以访问了！**

你的网址是：`https://pdd-fudai.<你的子域名>.workers.dev`

> 在 Worker 主页面顶部能看到这个网址，点一下就能打开。
>
> **中国大陆用户注意**：`workers.dev` 域名在中国大陆可能打不开。
> 如果打不开，请按第 10 步绑定自己的域名。

---

## 第 10 步：绑定自定义域名（可选）

有自己的域名体验更好，网址短好记，全球可访问。

### 10.1 域名接入 Cloudflare

如果你的域名不在 Cloudflare：

1. Cloudflare 主页 → **Add a Site** → 输入域名 → 选 **Free** 计划
2. 按提示去域名注册商改 NS 记录
3. 等待生效

### 10.2 添加自定义域名

1. 进入你的 Worker 页面
2. 点 **Settings** → **Domains & Routes**
3. 点 **Add Custom Domain**
4. 输入你想用的域名，比如 `fudai.yourdomain.com`
5. 点 **Add Domain**
6. Cloudflare 会自动帮你添加 DNS 记录，**不需要手动设置**

> 前提：这个域名必须已经在 Cloudflare 管理（DNS 在 Cloudflare）。

### 10.3 重新部署

绑定域名后，点一次 **Deploy** 让域名生效。

现在可以用 `https://fudai.yourdomain.com` 访问了！

---

## 第 11 步：进入后台管理

### 打开后台

1. 在你的网址后面加上 `/admin`
   - 例如：`https://pdd-fudai.xxx.workers.dev/admin`
   - 或：`https://fudai.yourdomain.com/admin`
2. 输入第 7 步设置的 `ADMIN_KEY` 密码
3. 点 **登录**

### 后台能做什么

| 标签页 | 功能 |
|--------|------|
| **数据统计** | 活跃码数、已使用、黑名单数、今日提交/拦截、待处理举报 |
| **站点设置** | 公告、广告位、QQ群/站长QQ、智能直达开关、刷新间隔（3~30秒） |
| **邀请码管理** | 查看所有码（含完整码）、归属地、状态，可手动删除 |
| **IP 黑名单** | 添加/移除黑名单，支持封禁期限（24h/1月/1年/永久），自动获取归属地 |
| **举报管理** | 处理/驳回/删除假码举报，显示提交者 IP 脱敏 |
| **提交日志** | 分页查看所有提交记录，审计异常行为 |

### 设置公告和广告

进入 **站点设置** 标签页：

- **公告**：首页顶部显示，留空则不显示
- **广告条**：提交框上方显示，留空则不显示
- **QQ 群号**：首页"反馈·申诉"弹窗里显示加群按钮，留空则不显示
- **站长 QQ**：同上
- **智能直达**：开关，开启后首页显示"一键直达"按钮
- **刷新间隔**：列表自动刷新秒数，默认 5 秒
- **识别截图模式**：`local`（仅本地像素识别，默认）/ `ai`（本地识别 + AI 兜底）。**建议保持默认** —— 本地识别秒出、不消耗 AI 额度；想让本地没认出时自动交给 AI，再改成 `ai`（需要第 6.2 步的 AI 绑定）
- **iOS 快捷指令地址**：首页 iOS 按钮指向的快捷指令链接，留空则隐藏该按钮

---

## 常见问题

### Q: 打开网站白屏？

按顺序检查这几项：
1. 代码有没有粘贴完整（开头 `/**`，结尾 `};`）
2. D1 数据库绑定变量名是不是大写的 `DB`
3. **`visits` 表建了没有** —— 首页的「今日访问量」统计要读它，缺了会让 `/api/config` 接口报错，**页面直接白屏**。把第 3 步的 SQL 重新完整执行一遍即可（所有语句都是 `IF NOT EXISTS`，重复执行安全）
4. 数据库表有没有全部建成功（第 3 步）
5. 改完绑定之后，有没有回代码编辑器点过一次 **Deploy**
6. 去 Worker 页面的 **Real-time Logs** 看具体报错

### Q: 点「识别截图」没反应，或提示识别失败？

识别截图的第一道是**本地像素识别**（秒出、不联网），所以先检查图片本身：

1. 确认选的是**拼多多的福袋分享图或手机整屏截图**，码清晰可见、没被裁掉边缘
2. 图片别太大（超过 4MB 会被前端直接拒绝）
3. 本地没认出码时，页面会提示「没识别到邀请码，请手动输入」——直接手输即可；想让系统自动改用 AI 再试一次，需要做第 6.2 步的 **Workers AI** 绑定，并在后台把 **识别截图模式** 设为 **本地识别 + AI 兜底**
4. 弹窗里的识别结果**可以手动改**——码区原图就在上面，对照着改完再点「确认提交」

如果 AI 兜底也失败，多半是调用频率限制（同一 IP 每分钟次数有限），稍等再试。

### Q: `workers.dev` 打不开？

中国大陆网络下 `workers.dev` 可能被屏蔽。解决方案：
- 绑定自己的域名（看第 10 步）
- 或挂梯子访问

### Q: 后台提示密码错误？

重新设置 ADMIN_KEY：
1. Worker → Settings → Variables and Secrets
2. 删掉旧的 `ADMIN_KEY`
3. 重新 Add variable，名称 `ADMIN_KEY`，填新密码，Type 选 Secret
4. 保存后重新 Deploy 一次

### Q: IP 归属地显示英文？

系统会依次尝试百度 API → ip-api.com → Cloudflare 自带数据。显示英文说明前两个超时了，回退到了 Cloudflare 自带数据。不影响功能，只是文字不够美观。

### Q: 提示"提交过于频繁"？

防刷规则：同一 IP 1 分钟最多 5 次，1 天最多 30 次。等一会儿再试。

### Q: 怎么修改网站颜色/文字？

所有代码在 Worker 编辑器里（点 **Edit code**）。搜索关键词找到对应位置修改，保存后点 **Deploy** 即可。

### Q: 怎么更新代码？

1. Worker → **Edit code**
2. 修改代码
3. 点 **Deploy**

几秒就上线了。

### Q: 怎么查看数据库数据？

1. Cloudflare 主页 → Storage & Databases → D1 → `pdd-fudai-db`
2. 点 **Console** 标签页
3. 输入 SQL 查询，例如：
   - 查看所有码：`SELECT * FROM codes`
   - 查看黑名单：`SELECT * FROM blacklist`
   - 清空所有码：`DELETE FROM codes`
4. 点 **Execute**

### Q: 免费够用吗？

- Workers：每天 100,000 次请求（免费）
- D1：5GB 存储（免费）
- Cron Trigger：免费

个人互助平台完全够用。

### Q: 每天几点清空互助码？

每天 23:59（中国时间）自动清空，零点开始新一天。黑名单、举报记录、设置不受影响。

---

## 附录：部署流程一览

```
注册 Cloudflare 账号
       ↓
创建 D1 数据库 (pdd-fudai-db)
       ↓
执行 SQL 建表 (6 张表 + 15 个索引)
       ↓
创建 Worker (pdd-fudai)
       ↓
从 GitHub 复制 src/index.js（Raw / Copy raw file）→ 粘贴 → Deploy
       ↓
Settings → Bindings → 添加 D1 绑定 (变量名: DB)
       ↓
Settings → Bindings → 添加 Workers AI 绑定 (变量名: AI)  ← AI 识图兜底（可选）
       ↓
Settings → Variables → 添加 ADMIN_KEY (Secret)
       ↓
Settings → Triggers → 添加 Cron (59 15 * * *)
       ↓
重新 Deploy → 访问网址 → 🎉上线
       ↓
(可选) 绑定自定义域名
       ↓
/admin → 输入密码 → 后台管理
```

---

> 部署遇到问题？截图发出来，我帮你看。
