# PDD 福袋互助平台 — 手把手部署教程

> 本教程从零开始，带你把 PDD 福袋互助平台部署到 Cloudflare Workers 上。
> 全程免费，不需要服务器，不需要域名也能用（有域名更好）。
> 预计耗时：**15~20 分钟**

---

## 目录

1. [你需要准备什么](#1-你需要准备什么)
2. [注册 Cloudflare 账号](#2-注册-cloudflare-账号)
3. [安装 Node.js 和 Wrangler](#3-安装-nodejs-和-wrangler)
4. [登录 Cloudflare](#4-登录-cloudflare)
5. [创建 D1 数据库](#5-创建-d1-数据库)
6. [初始化数据库表](#6-初始化数据库表)
7. [设置管理密钥](#7-设置管理密钥)
8. [部署到 Cloudflare Workers](#8-部署到-cloudflare-workers)
9. [绑定自定义域名（推荐）](#9-绑定自定义域名推荐)
10. [配置 Cron 定时清空](#10-配置-cron-定时清空)
11. [后台管理使用指南](#11-后台管理使用指南)
12. [常见问题](#12-常见问题)

---

## 1. 你需要准备什么

| 项目 | 是否必须 | 说明 |
|------|---------|------|
| 电脑（Windows / Mac / Linux） | ✅ 必须 | 用来执行命令 |
| Cloudflare 账号 | ✅ 必须 | 免费注册 |
| Node.js 16+ | ✅ 必须 | 运行 Wrangler 工具 |
| 一个域名 | ❌ 可选 | 没有也能用，只是网址长一点 |

> **没有域名？** 部署后会得到一个 `xxx.workers.dev` 的网址，直接用就行。
> 中国大陆可能无法访问 workers.dev，建议有条件的绑一个自己的域名。

---

## 2. 注册 Cloudflare 账号

1. 打开浏览器，访问 **https://dash.cloudflare.com/sign-up**
2. 输入邮箱和密码，点 **Create Account**
3. 去邮箱收验证邮件，点验证链接
4. 登录成功，看到 Cloudflare 控制台首页

> 已经有账号的直接登录就行。

---

## 3. 安装 Node.js 和 Wrangler

### 3.1 安装 Node.js

1. 打开 **https://nodejs.org/**
2. 下载 **LTS（长期支持版）**，一路下一步安装
3. 安装完成后，打开终端验证：

   **Windows**：按 `Win + R`，输入 `cmd`，回车，然后输入：
   ```bash
   node -v
   ```
   应该显示类似 `v20.11.0` 的版本号。

   **Mac**：打开「终端」App，输入同样的命令。

### 3.2 安装 Wrangler

Wrangler 是 Cloudflare 的命令行工具，用来部署代码。

在终端里执行：

```bash
npm install -g wrangler
```

> 如果提示权限错误（Mac / Linux），前面加 `sudo`：
> ```bash
> sudo npm install -g wrangler
> ```

安装完验证：

```bash
wrangler --version
```

应该显示类似 `wrangler 4.0.0` 的版本号。

---

## 4. 登录 Cloudflare

在终端执行：

```bash
wrangler login
```

会自动打开浏览器，显示 Cloudflare 授权页面。

1. 点 **Allow**
2. 看到浏览器显示 "You have granted authorization" 就成功了
3. 回到终端，会显示登录成功

> **如果浏览器没有自动弹出**：终端里会显示一个网址，手动复制到浏览器打开就行。

---

## 5. 创建 D1 数据库

D1 是 Cloudflare 的 SQLite 数据库，免费 5GB，用来存储邀请码、黑名单等数据。

在终端执行：

```bash
wrangler d1 create pdd-fudai-db
```

你会看到类似这样的输出：

```
✅ Successfully created DB 'pdd-fudai-db'
┌───────────────────────────────────────┬───────────────────────────────┐
│ database_id                           │ database_name                 │
├───────────────────────────────────────┼───────────────────────────────┤
│ abcdef12-3456-7890-abcd-ef1234567890  │ pdd-fudai-db                  │
└───────────────────────────────────────┴───────────────────────────────┘
```

**⚠️ 重要！** 把 `database_id`（那一串 UUID）记下来，下一步要用。

---

## 6. 初始化数据库表

进入项目目录，执行建表命令：

```bash
cd pdd-fudai
wrangler d1 execute pdd-fudai-db --remote --file=schema.sql
```

看到类似这样的输出就成功了：

```
✅ Executed 9 queries in 0.12s
```

这会创建 5 张表：

| 表名 | 用途 |
|------|------|
| `codes` | 邀请码（用户提交的互助码） |
| `blacklist` | IP 黑名单 |
| `reports` | 假码举报记录 |
| `submit_logs` | 提交日志（用于防刷统计） |
| `settings` | 站点设置（公告、广告、QQ 等） |

---

## 7. 设置管理密钥

管理密钥是进后台的密码，一定要设一个复杂的。

在终端执行：

```bash
wrangler secret put ADMIN_KEY
```

终端会提示你输入密钥值：

```
🌀 Creating the secret for the Worker "pdd-fudai"
Enter a secret value: 
```

输入一个你自己想好的密码（比如 `mySecretKey123!@#`），回车。

> **⚠️ 请牢记这个密码！** 后台登录、API 管理都需要它。
> 丢失了只能重新设置，旧密码无法找回。

看到 `✅ Success` 就设置成功了。

---

## 8. 部署到 Cloudflare Workers

### 8.1 修改配置文件

先把配置模板复制一份：

```bash
cp wrangler.toml.example wrangler.toml
```

打开 `wrangler.toml`，找到这一行：

```toml
database_id = "abcdef12-3456-7890-abcd-ef1234567890"
```

把引号里的值替换成 **第 5 步你记下来的 database_id**。

### 8.2 执行部署

在终端执行：

```bash
wrangler deploy
```

看到类似这样的输出就成功了：

```
Total Upload: 89.2 KiB / gzip: 22.1 KiB
Uploaded pdd-fudai (1.23 sec)
  Deployed pdd-fudai triggers
    - https://pdd-fudai.<你的子域名>.workers.dev
    - cron: 59 15 * * *
```

### 8.3 打开网站

把输出里的网址复制到浏览器打开，你就能看到首页了！

🎉 **部署成功！**

> **中国大陆用户注意**：`workers.dev` 域名在中国大陆可能打不开。
> 如果遇到这种情况，请按第 9 步绑定自己的域名。

---

## 9. 绑定自定义域名（推荐）

有自己的域名体验会好很多，网址短好记，全球可访问。

### 9.1 域名接入 Cloudflare

如果你的域名不在 Cloudflare 管理：

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 点 **Add a Site**，输入你的域名
3. 选择 **Free（免费）计划**
4. Cloudflare 会给你 2 个 NS 地址
5. 去你的域名注册商（阿里云/腾讯云/GoDaddy 等），把 DNS 的 NS 记录改成 Cloudflare 给的那两个
6. 等待生效（通常几分钟到几小时）

> 如果你的域名已经在 Cloudflare，跳过这一步。

### 9.2 添加 DNS 记录

1. 在 Cloudflare Dashboard 里进入你的域名
2. 点左侧菜单 **DNS** → **Records**
3. 点 **Add record**
4. 填写：
   - **Type**: `A`
   - **Name**: `fudai`（或者你想要的子域名前缀）
   - **IPv4 address**: `192.0.2.1`（占位地址，Workers 会自动接管）
   - **Proxy status**: 🟠 Proxied（橙色云朵，必须开）
5. 点 **Save**

### 9.3 修改配置文件

打开 `wrangler.toml`，找到 `routes` 部分：

```toml
routes = [
  { pattern = "fudai.yourdomain.com/*", zone_id = "YOUR_ZONE_ID" }
]
```

- 把 `fudai.yourdomain.com` 改成你自己的域名
- 把 `zone_id` 改成你的域名的 Zone ID

> **怎么找 Zone ID？**
> Cloudflare Dashboard → 你的域名 → 右侧边栏 Overview 页面最下方，能看到 **Zone ID**，复制它。

### 9.4 重新部署

```bash
wrangler deploy
```

部署成功后，输出里会显示你的自定义域名。打开它试试！

---

## 10. 配置 Cron 定时清空

项目已经内置了每天 23:59 自动清空互助码的 Cron Trigger。

配置在 `wrangler.toml` 里：

```toml
[triggers]
crons = ["59 15 * * *"]
```

> **为什么是 `59 15` 而不是 `59 23`？**
> 因为 Cron 用的是 UTC 时间，中国时间（CST）= UTC + 8。
> 23:59 CST = 15:59 UTC。

**如果你想改成其他时间清空**，修改这个表达式：

| 中国时间 | UTC 时间 | Cron 表达式 |
|---------|---------|------------|
| 23:59 | 15:59 | `59 15 * * *` |
| 00:00 | 16:00 | `0 16 * * *` |
| 06:00 | 22:00 | `0 22 * * *` |
| 12:00 | 04:00 | `0 4 * * *` |

改完后重新 `wrangler deploy` 即可。

> Cron 最多延迟几分钟触发，属于正常现象。即使没触发，用户下次访问时也会触发懒清理兜底。

---

## 11. 后台管理使用指南

### 11.1 进入后台

1. 打开你的网站地址
2. 在网址后面加上 `/admin`，例如：`https://fudai.yourdomain.com/admin`
3. 输入你第 7 步设置的 `ADMIN_KEY` 密码
4. 点 **登录**

### 11.2 站点设置

进入后台后，点 **站点设置** 标签页：

| 设置项 | 说明 | 示例 |
|--------|------|------|
| 公告 | 首页顶部显示的公告文字，留空则不显示 | `欢迎来到福袋互助平台！` |
| 广告条 | 提交框上方的广告文字，留空则不显示 | `加群获取更多福利` |
| 广告弹窗 | 可关闭的弹窗广告内容，留空则不显示 | |
| QQ 群号 | 首页"建议·反馈·申诉"弹窗里显示的加群按钮 | `123456789` |
| 站长 QQ | 同上，显示站长的个人 QQ | `987654321` |
| 智能直达 | 开关，开启后首页显示"一键直达"按钮 | `开` |
| 刷新间隔 | 列表自动刷新间隔（秒），可调 3~30 | `5` |

### 11.3 邀请码管理

点 **邀请码管理** 标签页：

- 查看所有用户提交的邀请码（含完整码、提交者 IP、归属地、状态）
- 可以手动删除某个码
- 已使用的码 30 秒后自动删除

### 11.4 IP 黑名单管理

点 **IP 黑名单** 标签页：

- **添加黑名单**：输入 IP 地址，选择封禁期限（24小时 / 1个月 / 1年 / 永久），系统自动获取归属地
- **查看黑名单**：列表显示 IP（脱敏）、归属地、封禁原因、剩余时间
- **移除黑名单**：点"移除"按钮即可解封

> **自动拉黑规则**：如果某个提交者的 IP 被 2 个以上不同的举报人举报，系统会自动拉黑该 IP（默认 24 小时）。

### 11.5 举报管理

点 **举报管理** 标签页：

- 查看所有用户举报的假码记录
- 显示被举报码、举报人 IP（脱敏）、提交者 IP（脱敏）
- 可以标记为"已处理"或"驳回"
- 可以删除举报记录

### 11.6 提交日志

点 **提交日志** 标签页：

- 分页查看所有提交记录
- 包含 IP（脱敏）、提交的码、操作类型（submit/use/blocked）、时间
- 用于审计异常行为

---

## 12. 常见问题

### Q: 部署后打开网站是白屏？

**A:** 检查终端部署输出有没有报错。常见原因：
- `wrangler.toml` 里的 `database_id` 没改成你自己的
- 数据库表没建（第 6 步漏了）
- 重新执行 `wrangler deploy`

### Q: `workers.dev` 打不开？

**A:** 中国大陆网络环境下 `workers.dev` 域名可能被屏蔽。解决方案：
1. 绑定自己的域名（看第 9 步）
2. 或者挂梯子访问

### Q: 后台进不去，提示密码错误？

**A:** 重新设置管理密钥：

```bash
wrangler secret put ADMIN_KEY
```

输入新密码后重新部署：

```bash
wrangler deploy
```

### Q: IP 归属地显示英文？

**A:** 归属地采用三级获取策略：
1. 百度开放数据 API（全中文）— 首选
2. ip-api.com（中文地名 + 英文 ISP 翻译）— 备用
3. Cloudflare `request.cf`（英文）— 兜底

如果显示英文，说明外部 API 请求超时了，回退到了 Cloudflare 自带数据。不影响使用，只是归属地文字不够美观。

### Q: 提示"提交过于频繁"？

**A:** 防刷规则生效了：
- 同一 IP **1 分钟内最多提交 5 次**
- 同一 IP **1 天最多提交 30 次**

等一会儿再试。管理员可以在 `src/index.js` 顶部的 `CONFIG` 里修改这些限制。

### Q: 邀请码每天什么时候清空？

**A:** 每天 23:59（中国时间）自动清空所有互助码，零点开始新一天。黑名单、举报记录、设置不受影响。

### Q: 怎么修改网站的颜色/文字？

**A:** 所有前端代码都内联在 `src/index.js` 里。搜索关键词找到对应位置修改，然后 `wrangler deploy` 重新部署即可。

### Q: 免费额度够用吗？

**A:** Cloudflare Workers 免费计划：
- 每天 **100,000 次** 请求
- D1 数据库 **5GB** 存储
- Cron Trigger **免费**

对于个人互助平台完全够用。如果流量大了，Workers 付费计划 $5/月，请求不限量。

### Q: 怎么更新代码？

**A:** 修改 `src/index.js` 后，执行：

```bash
wrangler deploy
```

几秒钟就上线了。

### Q: 怎么查看数据库里的数据？

**A:** 执行：

```bash
# 查看所有邀请码
wrangler d1 execute pdd-fudai-db --remote --command "SELECT * FROM codes"

# 查看黑名单
wrangler d1 execute pdd-fudai-db --remote --command "SELECT * FROM blacklist"

# 查看设置
wrangler d1 execute pdd-fudai-db --remote --command "SELECT * FROM settings"

# 清空所有邀请码
wrangler d1 execute pdd-fudai-db --remote --command "DELETE FROM codes"
```

---

## 附录：完整部署命令速查

```bash
# 1. 安装 Wrangler
npm install -g wrangler

# 2. 登录
wrangler login

# 3. 创建数据库
wrangler d1 create pdd-fudai-db

# 4. 建表（记得先 cd 到项目目录）
cd pdd-fudai
wrangler d1 execute pdd-fudai-db --remote --file=schema.sql

# 5. 设置管理密钥
wrangler secret put ADMIN_KEY

# 6. 部署
wrangler deploy

# 7. 更新代码（修改后重新部署）
wrangler deploy
```

---

> 部署遇到问题？把终端报错信息截图发出来，我帮你看。
