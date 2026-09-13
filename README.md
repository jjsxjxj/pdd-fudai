# PDD 福袋互助平台 - Cloudflare Workers 版

基于 Cloudflare Workers + D1 数据库的拼多多福袋邀请码互助平台。

**线上地址**: 部署到 Cloudflare 后，用你自己的域名访问即可

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
- 弹窗广告的标题/副标题由后台配置（留空则不渲染标题栏），项目内不含任何硬编码的第三方品牌文案
- 无广告时全部自动隐藏，`/api/config` 也不返回 `ads` / `ad_title` / `ad_sub` 字段

### 识别截图（秒出互助码，不加载模型）
- 点输入框右侧的「识别截图」，选一张福袋分享图或手机整屏截图，自动认出 8-9 位互助码
- **本地像素识别，毫秒级出结果**：拼多多邀请码是固定字体的受控印刷体，不必跑 OCR 模型，直接用「红区定位 → Otsu 行分离 → 列切分 → 间隙聚类 → 6×8 归一化栅格比模板」在浏览器内存里算完 —— **零网络请求、零模型下载、图片不出本机**
- 识别成功后弹「识别结果确认」窗：展示裁出的**码区原图** + 可编辑的码，核对无误再提交，避免认错一位数字
- 低置信度或没识别到时，可选 **AI 识图兜底**（Cloudflare Workers AI `llama-3.2-11b-vision`）。后台 `ocr_mode`：`local`（仅本地，默认）/ `ai`（本地 + AI 兜底）
- AI 识图接口带 IP 限流与降级提示
- 实测：1240×2772 安卓整屏截图约 50ms，缩到 900px 宽约 10~26ms

### 提交秒回（异步归属地补全）
- 提交互力码**即时返回**，不再等待归属地查询
- 同步先用 Cloudflare `request.cf` 数据兜底展示（英文归属地，零耗时）
- 中文归属地（百度 API）通过 `ctx.waitUntil` 在后台异步补全，几秒内自动更新

### 安全防护
写接口统一在 API 入口做黑名单拦截（`/api/submit`、`/api/quick-use`、`/api/use/:id`、`/api/report/:id`、`/api/ocr`），命中直接 403。

提交链路的 5 层防护：
1. **IP 黑名单检查** - 命中黑名单直接拒绝
2. **速率限制** - 单 IP 每分钟最多提交 5 次
3. **每日限额** - 单 IP 每天最多提交 30 次（按 CST 自然日）
4. **蜜罐字段** - 隐藏字段检测机器人提交（返回假成功，不入库）
5. **输入校验** - 严格校验 8-9 位纯数字格式

其他接口与全局加固：
- **访问打点限流** - `/api/visit` 单 IP 每分钟最多 30 次
- **后台鉴权失败限流** - 单 IP 每分钟 10 次失败后转 429，失败均记入审计日志
- **密钥恒时比较** - SHA-256 摘要定长比较，不泄露密钥长度
- **举报防武器化** - 禁止自举报、24 小时时间窗、需 3 个不同 IP 才自动拉黑
- **并发安全** - 领码走原子 UPDATE + `meta.changes` 判定，不存在超发
- **分页收敛** - `pageSize` 上限 200，`page` 最小 1
- **请求体闸门** - `content-length` 超 8MB 直接 413
- **响应缓存策略** - 含互助码的 JSON 一律 `no-store`；`/admin` 额外带 `X-Robots-Tag: noindex`
- **安全响应头** - CSP、`X-Frame-Options: DENY`、`nosniff`、`no-referrer`

### 管理后台
- 数据统计面板（活跃码、已使用、黑名单数、今日提交/拦截、待处理举报）
- 站点设置（公告、广告位、弹窗广告文案、QQ 群/站长 QQ、智能直达开关、iOS 快捷指令地址、刷新间隔、OCR 模式、限流阈值）
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
             │                          ├─ Workers AI（识图兜底，可选）
             │                          └─ ctx.waitUntil（归属地后台补全）
             └── 识别截图（像素模板匹配，算法内联在页面代码里，图片不出浏览器）
                                            ↓
                              Cron Trigger 23:59 CST → 清空互助码
```

- **运行时**: Cloudflare Workers
- **数据库**: Cloudflare D1 (SQLite)
- **定时任务**: Cron Trigger `59 15 * * *`（23:59 CST）
- **前端**: 内联 HTML/CSS/JS（单文件部署，无需静态资源绑定）
- **识别截图**: 浏览器端像素模板匹配（算法内联在页面里）+ Workers AI 兜底

## 部署步骤

本项目提供两套部署教程，按自己的情况任选其一：

| 方式 | 是否需要命令行 | 需要装软件 | 识别截图 | 详细教程 |
|------|--------------|-----------|---------|---------|
| **A. 命令行部署（推荐）** | 需要 | Node.js + Wrangler | ✅ 秒出 | 本文下方步骤 / [DEPLOY.md](DEPLOY.md)（手把手详解） |
| **B. 纯网页部署** | 不需要 | 无，全程浏览器 | ✅ 秒出 | [DEPLOY-WEB.md](DEPLOY-WEB.md) |

> **两种方式功能完全一致**：「识别截图」用的是**内联在 `src/index.js` 里的像素匹配算法**，不需要额外上传任何静态资源，所以只能粘贴单个代码文件的网页版，同样能秒出结果。
>
> 唯一可选的一步是 **AI 识图兜底**——它需要在 Cloudflare 后台绑定 Workers AI（网页版教程第 6.2 步）。不绑定也不影响识别截图，只是本地没认出码时少一层重试。

以下为 **方式 A：命令行部署** 的完整步骤。

### 1. 克隆项目

```bash
git clone https://github.com/jjsxjxj/pdd-fudai.git
cd pdd-fudai
```

> 没装 Git？从 https://git-scm.com/downloads 下载安装，或在 GitHub 页面点 **Code → Download ZIP** 下载解压。

### 2. 安装 Wrangler CLI

> 需要 **Node.js 22 或更高**（最新版 Wrangler 的硬性要求，低于 22 会报 `EBADENGINE`）。

```bash
npm install -g wrangler
```

### 3. 登录 Cloudflare

```bash
wrangler login
```

### 4. 创建 D1 数据库

```bash
wrangler d1 create pdd-fudai-db
```

记下输出中的 `database_id`（一串 UUID），下一步要填进配置文件。

### 5. 复制配置模板

```bash
cp wrangler.toml.example wrangler.toml
```

把上一步的 `database_id` 填入 `wrangler.toml` 的 `d1_databases` 段。

仓库中的 `wrangler.toml.example` 是脱敏模板；真实的 `wrangler.toml`（含你的 ID）已加入 `.gitignore`，不会被提交。

### 6. 初始化数据库

```bash
wrangler d1 execute pdd-fudai-db --remote --file=schema.sql
```

### 7. 部署

```bash
wrangler deploy
```

无需上传任何静态资源 —— 识别截图的算法已经内联在 `src/index.js` 里。

### 8. 设置管理密钥

```bash
wrangler secret put ADMIN_KEY
```

> ADMIN_KEY 是管理后台的登录密码，务必设置复杂一些，且**不要**写进任何文件。
>
> **此步必须在部署之后执行**：`wrangler secret put` 要求目标 Worker 已经存在，未部署时会报 `script_not_found [code: 10007]`。设置成功即自动生成新版本并上线，无需再执行一次 `deploy`。

### 9. 绑定自定义域名（可选）

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
| `VISIT_RATE_LIMIT` | 30 | 每 IP 每分钟访问打点上限 |
| `ADMIN_FAIL_LIMIT` | 10 | 每 IP 每分钟后台鉴权失败上限（超出转 429） |
| `REPORT_AUTO_BAN_THRESHOLD` | 3 | 自动拉黑所需的不同举报人 IP 数 |
| `REPORT_AUTO_BAN_WINDOW_MS` | 86400000 | 举报计票时间窗（24 小时） |
| `LOG_KEEP_DAYS` | 30 | 日志/访问/已处理举报保留天数（Cron 清理） |
| `PAGE_SIZE_MAX` | 200 | 分页接口 `pageSize` 上限 |

### Wrangler 配置（`wrangler.toml`，从 `wrangler.toml.example` 复制）

| 字段 | 说明 |
|------|------|
| `routes` | 自定义域名绑定（pattern + zone_id） |
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
| POST | `/api/ocr` | AI 识图提取互助码（本地识别没认出时的兜底，带 IP 限流） |
| POST | `/api/use/:id` | 标记已使用，返回完整码 |
| POST | `/api/quick-use` | 智能直达 |
| GET | `/api/blacklist` | 公共黑名单公示（分页，`pageSize` 上限 200；自动排除已过期记录） |
| POST | `/api/report/:id` | 举报假码（禁止自举报，24h 内 3 个不同 IP 触发自动拉黑） |
| GET | `/robots.txt` | 禁止收录 `/admin` 与 `/api/` |

### 管理接口（需 `X-Admin-Key` 头）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/stats` | 统计数据 |
| GET/POST | `/api/admin/settings` | 站点设置（`notice` / `ads` / `ad_title` / `ad_sub` / `qq_group` / `qq_owner` / `smart_enabled` / `refresh_interval` / `rate_limit_max` / `daily_limit` / `ocr_mode` / `ios_url`） |
| GET | `/api/admin/codes` | 所有邀请码（含完整码） |
| DELETE | `/api/admin/codes/:id` | 删除指定码 |
| GET/POST/DELETE | `/api/admin/blacklist` | 黑名单管理（GET 响应含服务端计算的 `remaining` 剩余时长） |
| GET | `/api/admin/reports` | 举报列表 |
| POST | `/api/admin/reports/:id/status` | 更新举报状态 |
| DELETE | `/api/admin/reports/:id` | 删除举报 |
| GET | `/api/admin/logs` | 提交日志 |

## 项目结构

```
pdd-fudai/
├── src/
│   └── index.js              # Worker 主文件（API + 内联前端 + 内联管理后台 + 内联识别内核）
├── scripts/                  # 本地开发工具（不入 git，不上传）
├── schema.sql                # D1 数据库建表脚本
├── wrangler.toml.example     # 部署配置模板（脱敏，复制为 wrangler.toml 使用）
├── package.json              # 项目配置
├── DEPLOY.md                 # 详细部署教程 · 命令行版（新手友好）
├── DEPLOY-WEB.md             # 详细部署教程 · 纯网页版（不装任何软件）
├── CHANGELOG.md              # 更新日志
└── README.md                 # 本文档
```

## 费用

Cloudflare Workers 免费计划：
- 每天 100,000 次请求
- D1 免费计划：5GB 存储 + 每天无限读取
- Cron Trigger：免费

对于个人互助平台完全够用。
