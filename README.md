# PDD 福袋互助平台 - Cloudflare Workers 版

基于 Cloudflare Workers + D1 数据库的拼多多福袋邀请码互助平台。

**线上地址**: https://fudai.10087.eu.org

**部署教程**: [Cloudflare Workers 部署指南 - 我的博客](https://813146.xyz/post/deploy-cloudflare-workers-via-dashboard)

**更新日志**: [CHANGELOG.md](./CHANGELOG.md)

## 功能特性

### 核心功能
- 提交 8-9 位拼多多福袋邀请码
- 列表展示（中间两位脱敏隐藏）
- 点击"跳转"直接打开拼多多搜索（使用完整码）
- **跳转前置提醒**：首次点击"跳转"或"智能直达"时弹窗提示必须先手动从拼多多首页进入福袋界面（首页 → 百亿补贴 → 百亿消费券 → 福袋），否则组队失败；同一浏览器只提示一次（`localStorage.pdd_jump_tip_ok`），两个入口共用标记
- **跳转倒计时**：每次跳转前 toast 倒计时约 1.6 秒（"N 秒后跳转拼多多，请确认已在福袋界面"）再打开新标签，让提示可被看清；延迟控制在浏览器 user activation 有效期内，避免被弹窗拦截器阻止
- 使用后 30 秒自动删除，列表轮换刷新（刷新间隔后台可调，默认 5 秒）
- 自己用过的显示"已使用"，别人用过的显示灰色
- 智能直达：一键取最新互助码并直接跳转拼多多（后台可开关）
- 重复提交重新排队点亮
- 邀请码 24 小时自动过期
- **每天 23:59 自动清空所有互助码**，零点开始新一天活动（Cron Trigger）

### 首页统计
- 今日 IP 数、今日访问次数、今日提交次数（实时显示）
- 时间显示附带 IP 归属地（如 `8/18 19:38 · 浙江省舟山市 移动`）

### 假码举报与自动拉黑
- 列表内可对刚使用的码发起"假码举报"（每 IP 每 10 分钟限 1 条）
- **双 IP 举报自动拉黑**：同一提交者 IP 被 ≥ 2 个不同举报人 IP 举报时，自动加入黑名单
- 管理后台"举报管理"标签页处理/驳回/删除举报
- 违规小黑屋公示：公共黑名单 API 返回掩码 IP + 归属地，首页弹窗展示

### IP 黑名单管理
- 管理后台可添加/移除黑名单 IP
- **封禁期限可调**：24 小时 / 1 个月 / 1 年 / 永久（默认 24 小时）
- 过期自动解禁
- 黑名单 IP 提交时直接拦截
- IP 脱敏兼容 IPv4 / IPv6 / IPv4-mapped IPv6

### IP 归属地（中文）
- 提交时同步取 Cloudflare `request.cf` 兜底（零耗时，英文）
- 中文归属地由百度开放数据 API 在后台异步补全（`waitUntil`，不阻塞提交）
- ISP 英文翻译为中文（China Mobile → 移动、China Telecom → 电信 等）
- 提交码时自动获取并存储
- 管理后台手动拉黑时自动填充

### 联系与广告
- 首页"建议·反馈·申诉"弹窗：QQ 群一键加群 + 站长 QQ（后台可配置，留空自动隐藏）
- 广告位：静态广告条 + 可关闭的弹窗广告，显示在提交框上方
- 无广告时全部自动隐藏

### 识图提取（OCR 自动识别互助码）
- 首页上传/截图福袋分享图，一键识别 8-9 位互助码，免去手动输入
- **本地识别优先**：tesseract.js 在浏览器端运行，图片不上传（首次加载约 15 秒，之后缓存秒开）
- OCR 运行时与训练数据**同域自托管**（`public/ocr/`，随 Worker Assets 部署到 `/ocr/`），不依赖任何第三方 CDN，国内加载无障碍
- 本地识别失败时可切换 **AI 识图兜底**（Cloudflare Workers AI `llama-3.2-11b-vision`），后台可配置 `ocr_mode`：`local`（本地优先）/ `ai`（仅 AI）
- AI 识图接口带限流与降级提示

### 提交秒回（异步归属地补全）
- 提交互力码**即时返回**，不再等待归属地查询
- 同步先用 Cloudflare `request.cf` 数据兜底展示（英文归属地，零耗时）
- 中文归属地（百度 API）通过 `ctx.waitUntil` 在后台异步补全，几秒内自动更新

### 防恶意提交（5 层防护）
1. **IP 黑名单检查** - 命中黑名单直接拒绝
2. **速率限制** - 单 IP 每分钟最多提交 5 次
3. **每日限额** - 单 IP 每天最多提交 30 次
4. **蜜罐字段** - 隐藏字段检测机器人提交
5. **输入校验** - 严格校验 8-9 位纯数字格式

### 管理后台
- 数据统计面板（活跃码、已使用、黑名单数、今日提交/拦截、待处理举报）
- 站点设置（公告、广告位、QQ 群/站长 QQ、智能直达开关、刷新间隔）
- 邀请码管理（查看完整码、归属地、删除）
- IP 黑名单管理（添加/移除，支持归属地 + 封禁期限 + 剩余时间显示）
- 举报管理（处理/驳回/删除，显示提交者 IP 脱敏）
- 提交日志审计（分页查看所有提交记录）

### 配色
- 蓝色主题：主色 `#2a71d0`，亮蓝 `#4a9eff`，成功绿 `#07c160`
- 活动入口文字红色 `#E02E24`（拼多多品牌色）

## 技术架构

```
用户浏览器 ──┬── 页面 + 公开 API ──→ Cloudflare Workers ──→ D1 (SQLite)
             │                          ├─ Workers AI（OCR 兜底，可选）
             │                          ├─ ctx.waitUntil（归属地后台补全）
             │                          └─ ASSETS 静态资源（/ocr/，tesseract.js 同域自托管）
             └── OCR 本地识别（tesseract.js WASM，图片不出浏览器）
                                            ↓
                              Cron Trigger 23:59 CST → 清空互助码
```

- **运行时**: Cloudflare Workers
- **数据库**: Cloudflare D1 (SQLite)
- **静态资源**: Worker Assets（`public/` 目录 → 同域 `/ocr/`，无跨域问题）
- **定时任务**: Cron Trigger `59 15 * * *`（23:59 CST）
- **前端**: 内联 HTML/CSS/JS（无需额外静态托管）
- **OCR**: tesseract.js 浏览器端本地识别 + Workers AI 兜底

## 部署步骤

### 1. 安装 Wrangler CLI

```bash
npm install -g wrangler
```

### 2. 登录 Cloudflare

```bash
wrangler login
```

### 3. 复制配置模板

```bash
cp wrangler.toml.example wrangler.toml
```

仓库中的 `wrangler.toml.example` 是脱敏模板；真实的 `wrangler.toml`（含你的 ID）已加入 `.gitignore`，不会被提交。

### 4. 创建 D1 数据库

```bash
wrangler d1 create pdd-fudai-db
```

将输出的 `database_id` 填入 `wrangler.toml`。

### 5. 初始化数据库

```bash
wrangler d1 execute pdd-fudai-db --remote --file=schema.sql
```

### 6. 设置管理密钥

```bash
wrangler secret put ADMIN_KEY
```

> ADMIN_KEY 是管理后台的登录密码，务必设置复杂一些，且**不要**写进任何文件。

### 7. 部署

```bash
wrangler deploy
```

`public/ocr/` 下的 OCR 运行时（约 20MB）会随 Worker Assets 一并部署到同域 `/ocr/`。

### 8. 绑定自定义域名（可选）

在 `wrangler.toml` 中配置 `routes`（替换 pattern 与 zone_id），并在 Cloudflare Dashboard 添加 DNS 记录。详见 [DEPLOY.md](DEPLOY.md)。

## 配置说明

### 代码配置（`src/index.js` 顶部 `CONFIG`）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `CODE_LENGTH_MIN` | 8 | 邀请码最短长度 |
| `CODE_LENGTH_MAX` | 9 | 邀请码最长长度 |
| `MAX_ACTIVE_CODES` | 50 | 列表最大展示条数 |
| `RATE_LIMIT_WINDOW_MS` | 60000 | 速率限制窗口（毫秒） |
| `RATE_LIMIT_MAX` | 5 | 窗口内最大提交次数 |
| `DAILY_LIMIT` | 30 | 每 IP 每日最大提交次数 |
| `CODE_TTL_HOURS` | 24 | 邀请码过期时间（小时） |
| `USED_KEEP_MS` | 30000 | 使用后保留时长（毫秒） |

### Wrangler 配置（`wrangler.toml`，从 `wrangler.toml.example` 复制）

| 字段 | 说明 |
|------|------|
| `routes` | 自定义域名绑定（pattern + zone_id） |
| `[assets]` | 静态资源绑定（`public/` → 同域 `/ocr/`，OCR 运行时自托管） |
| `d1_databases` | D1 数据库绑定（binding = "DB"） |
| `[ai]` | Workers AI 绑定（binding = "AI"，OCR 兜底） |
| `triggers.crons` | Cron 定时任务（`59 15 * * *` = 23:59 CST 清空码） |

## API 接口

### 公开接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/codes` | 获取邀请码列表 |
| GET | `/api/config` | 获取首页配置 + 今日统计 |
| POST | `/api/visit` | 记录访问 |
| POST | `/api/submit` | 提交邀请码（即时返回，归属地后台补全） |
| POST | `/api/ocr` | AI 识图提取互助码（限流，本地识别失败时兜底） |
| POST | `/api/use/:id` | 标记已使用，返回完整码 |
| POST | `/api/quick-use` | 智能直达 |
| GET | `/api/blacklist` | 公共黑名单公示 |
| POST | `/api/report/:id` | 举报假码 |

### 管理接口（需 `X-Admin-Key` 头）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/stats` | 统计数据 |
| GET/POST | `/api/admin/settings` | 站点设置 |
| GET | `/api/admin/codes` | 所有邀请码（含完整码） |
| DELETE | `/api/admin/codes/:id` | 删除指定码 |
| GET/POST/DELETE | `/api/admin/blacklist` | 黑名单管理 |
| GET | `/api/admin/reports` | 举报列表 |
| POST | `/api/admin/reports/:id/status` | 更新举报状态 |
| DELETE | `/api/admin/reports/:id` | 删除举报 |
| GET | `/api/admin/logs` | 提交日志 |

## 项目结构

```
pdd-fudai/
├── src/
│   └── index.js              # Worker 主文件（API + 内联前端 + 内联管理后台）
├── public/
│   └── ocr/                  # OCR 运行时（tesseract.js 主库/worker/core WASM/英文训练数据，约 20MB）
├── scripts/                  # 本地开发工具（不入 git，不上传）
├── schema.sql                # D1 数据库建表脚本
├── wrangler.toml.example     # 部署配置模板（脱敏，复制为 wrangler.toml 使用）
├── package.json              # 项目配置
├── DEPLOY.md                 # 详细部署教程（新手友好）
├── CHANGELOG.md              # 更新日志
└── README.md                 # 本文档
```

## 费用

Cloudflare Workers 免费计划：
- 每天 100,000 次请求
- D1 免费计划：5GB 存储 + 每天无限读取
- Cron Trigger：免费

对于个人互助平台完全够用。
