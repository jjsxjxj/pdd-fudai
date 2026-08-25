# PDD 福袋互助平台 - Cloudflare Workers 版

基于 Cloudflare Workers + D1 数据库的拼多多福袋邀请码互助平台。

**线上地址**: https://fudai.10087.eu.org

## 功能特性

### 核心功能
- 提交 8-9 位拼多多福袋邀请码
- 列表展示（中间两位脱敏隐藏）
- 点击"跳转"直接打开拼多多搜索（使用完整码）
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
- 三级获取：百度开放数据 API → ip-api.com → Cloudflare request.cf 兜底
- ISP 英文翻译为中文（China Mobile → 移动、China Telecom → 电信 等）
- 提交码时自动获取并存储
- 管理后台手动拉黑时自动填充

### 联系与广告
- 首页"建议·反馈·申诉"弹窗：QQ 群一键加群 + 站长 QQ（后台可配置，留空自动隐藏）
- 广告位：静态广告条 + 可关闭的弹窗广告，显示在提交框上方
- 无广告时全部自动隐藏

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
用户浏览器 → Cloudflare Workers (API + 内联页面) → Cloudflare D1 (SQLite)
                    ↓
          Cron Trigger 23:59 CST → 清空互助码
```

- **运行时**: Cloudflare Workers
- **数据库**: Cloudflare D1 (SQLite)
- **定时任务**: Cron Trigger `59 15 * * *`（23:59 CST）
- **前端**: 内联 HTML/CSS/JS（无需额外静态托管）
- **零外部依赖**: 单文件部署

## 部署步骤

### 1. 安装 Wrangler CLI

```bash
npm install -g wrangler
```

### 2. 登录 Cloudflare

```bash
wrangler login
```

### 3. 创建 D1 数据库

```bash
wrangler d1 create pdd-fudai-db
```

将输出的 `database_id` 复制到 `wrangler.toml`。

### 4. 初始化数据库

```bash
wrangler d1 execute pdd-fudai-db --remote --file=schema.sql
```

### 5. 设置管理密钥

```bash
wrangler secret put ADMIN_KEY
```

### 6. 部署

```bash
wrangler deploy
```

### 7. 绑定自定义域名（可选）

在 `wrangler.toml` 中配置 `routes`，并在 Cloudflare Dashboard 添加 DNS 记录。

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

### Wrangler 配置（`wrangler.toml`）

| 字段 | 说明 |
|------|------|
| `routes` | 自定义域名绑定 |
| `d1_databases` | D1 数据库绑定（binding = "DB"） |
| `triggers.crons` | Cron 定时任务（`59 15 * * *` = 23:59 CST 清空码） |

## API 接口

### 公开接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/codes` | 获取邀请码列表 |
| GET | `/api/config` | 获取首页配置 + 今日统计 |
| POST | `/api/visit` | 记录访问 |
| POST | `/api/submit` | 提交邀请码 |
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
├── scripts/
│   ├── check-inline-js.js    # 内联 JS 语法诊断工具
│   ├── stress_test.py        # 压测脚本（50并发，5分钟）
│   └── stress-test-report.txt # 压测报告
├── schema.sql                # D1 数据库建表脚本
├── wrangler.toml             # Cloudflare Workers 配置
├── package.json              # 项目配置
└── README.md                 # 本文档
```

## 费用

Cloudflare Workers 免费计划：
- 每天 100,000 次请求
- D1 免费计划：5GB 存储 + 每天无限读取
- Cron Trigger：免费

对于个人互助平台完全够用。
