# PDD 福袋互助平台 — 网页在线部署教程

> 全程在浏览器里操作，不装任何软件，不开终端，不用命令行。
> 只要会注册账号、会复制粘贴就能部署。
> 预计耗时：**10~15 分钟**

---

## 目录

1. [注册 Cloudflare 账号](#第-1-步注册-cloudflare-账号)
2. [创建 D1 数据库](#第-2-步创建-d1-数据库)
3. [建数据库表](#第-3-步建数据库表)
4. [创建 Worker](#第-4-步创建-worker)
5. [粘贴代码](#第-5-步粘贴代码)
6. [绑定数据库](#第-6-步绑定数据库)
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
  code TEXT NOT NULL,
  code_masked TEXT NOT NULL,
  ip TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  used_at TEXT,
  created_at TEXT NOT NULL,
  location TEXT DEFAULT ''
);

-- IP 黑名单表
CREATE TABLE IF NOT EXISTS blacklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL UNIQUE,
  reason TEXT DEFAULT '',
  location TEXT DEFAULT '',
  duration TEXT DEFAULT '24h',
  expires_at TEXT,
  created_at TEXT NOT NULL
);

-- 假码举报表
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL,
  ip TEXT NOT NULL,
  submitter_ip TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  created_at TEXT NOT NULL
);

-- 提交日志表
CREATE TABLE IF NOT EXISTS submit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  code TEXT,
  action TEXT NOT NULL,
  reason TEXT DEFAULT '',
  created_at TEXT NOT NULL
);

-- 站点设置表
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT NOT NULL
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_codes_status ON codes(status);
CREATE INDEX IF NOT EXISTS idx_codes_created ON codes(created_at);
CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON submit_logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_created ON submit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
```

4. 点 **Execute**（执行）按钮
5. 看到绿色 "Success" 就建好了

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

## 第 5 步：粘贴代码

1. 进入代码编辑器后，你会看到左边是代码区，右边是预览区
2. **把左边代码区里的内容全部删掉**（Ctrl+A 全选，然后 Delete）
3. 打开项目里的 `src/index.js` 文件（用记事本或任何文本编辑器打开）
4. **Ctrl+A 全选 → Ctrl+C 复制**
5. 回到 Cloudflare 编辑器，**Ctrl+V 粘贴**
6. 等代码全部加载完（文件较大，约 89KB，粘贴后等 2~3 秒）
7. 点右上角 **Deploy**（部署）

> **⚠️ 注意**：粘贴后检查一下代码开头是不是 `/**`，结尾是不是 `};`。如果开头或结尾被截断了，说明没粘贴完整，重新来一次。

---

## 第 6 步：绑定数据库

Worker 需要连上第 2 步建的数据库才能工作。

1. 在 Worker 页面（不是代码编辑器），点 **Settings**（设置）标签页
2. 找到 **Bindings**（绑定）部分，点 **Add binding**
3. 选 **D1 database**
4. 填写：
   - **Variable name**：`DB`（必须是大写的 DB，不能写错）
   - **D1 database**：下拉选择 `pdd-fudai-db`（第 2 步创建的那个）
5. 点 **Save**（保存）

> **⚠️ 变量名必须填 `DB`**，代码里用的是 `env.DB`，写错就连不上数据库。

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

---

## 常见问题

### Q: 打开网站白屏？

检查这几项：
1. 代码有没有粘贴完整（开头 `/**`，结尾 `};`）
2. D1 数据库绑定变量名是不是大写的 `DB`
3. 数据库表有没有建成功（第 3 步）
4. 去 Worker 的 **Real-time Logs** 看有没有报错

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
执行 SQL 建表 (5 张表 + 6 个索引)
       ↓
创建 Worker (pdd-fudai)
       ↓
粘贴 src/index.js 全部代码 → Deploy
       ↓
Settings → Bindings → 添加 D1 绑定 (变量名: DB)
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
