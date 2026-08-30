# 更新日志

本项目所有值得注意的变更记录于此。版本按功能里程碑划分，日期为该批改动完成部署的日期。

## [未发布] - 2026-08-30

### 新增
- **跳转前置一次性提醒弹窗**：首次点击"跳转"或"智能直达"时弹出提示，说明必须先手动从拼多多首页进入福袋界面（首页 → 百亿补贴 → 百亿消费券 → 福袋），否则组队失败。
  - 标记键 `localStorage.pdd_jump_tip_ok`，两个入口共用，同一浏览器只提示一次
  - 仅在用户点"我已进入福袋界面，继续跳转"时写入标记；点取消或点遮罩不写标记且中止跳转，下次仍会提示
  - `localStorage` 读取异常时直接放行，避免隐私模式下功能被阻塞
- **跳转倒计时提示**：新增 `openPddDelayed(code, prefix)`，跳转前用 toast 倒计时约 1.6 秒（"N 秒后跳转拼多多，请确认已在福袋界面"）再打开新标签。延迟刻意控制在浏览器 user activation 有效期（约 5 秒）内，避免 `window.open` 被弹窗拦截器阻止。

### 变更
- `useCode()` 与 `quickUse()` 改为在跳转前先经过提醒拦截；`quickUse()` 在用户取消时恢复按钮可用状态，避免按钮永久禁用
- 两处裸 `window.open()` 统一替换为 `openPddDelayed()`

## [0.5.0] - 2026-08-29

### 安全
- **敏感信息治理**：真实 `wrangler.toml`（含 `zone_id` / `database_id`）退出 git 跟踪并加入 `.gitignore`，仓库仅保留脱敏模板 `wrangler.toml.example`
- `DEPLOY.md` 中的真实域名、zone id、database id 全部替换为占位符

### 文档
- README 补充"识图提取（OCR 自动识别互助码）"与"提交秒回（异步归属地补全）"两节
- 技术架构图重绘，加入 Worker Assets / Workers AI / `ctx.waitUntil` 三条链路
- 部署步骤新增"复制配置模板"一步并重排为 8 步；Wrangler 配置表补充 `[assets]` / `[ai]`；API 表补充 `/api/ocr`

## [0.4.0] - 2026-08-28

### 变更
- **提交秒回**：IP 归属地改为 `ctx.waitUntil` 后台异步补全 —— 先同步取 `request.cf` 作为兜底立即返回，中文归属地由后台调百度 API 后 UPDATE 回写，提交响应不再等待外部接口
- `wrangler.toml` 的 `routes` 移出 `[assets]` 段，消除部署警告

### 修复
- `handleSubmit` 漏传 `ctx` 导致的 500 错误

## [0.3.0] - 2026-08-26 ~ 2026-08-27

### 变更
- **OCR 资源全面自托管**：tesseract.js 主库、worker、core、训练数据全部随 Worker Assets 部署到同域 `/ocr/`，彻底摆脱第三方 CDN 依赖
  - 起因：npmmirror 无 CORS 头、unpkg 不稳定、`corePath` 原先指向了错误的包名（正确包名为 `tesseract.js-core`，无 `@` 作用域）
  - `langPath` / `workerPath` / `corePath` 全部改为同域相对路径，配合 `workerBlobURL: false`
- 公告滚动速度按文本宽度动态计算（90px/s），长短公告观感一致

### 修复
- 新增 `.gitattributes`，保护 OCR 静态资源不被 git 换行符转换损坏

## [0.2.0] - 2026-08-25

### 新增
- **识图提取**：截图 OCR 自动识别互助码
  - 主方案为 tesseract.js 浏览器端本地识别，图片不上传服务器
  - 兜底方案为 Cloudflare Workers AI `@cf/meta/llama-3.2-11b-vision-instruct`，本地识别失败时弹窗让用户选择"AI 识别"或"手动输入"
  - 后台 `ocr_mode` 可切换 `local`（本地优先）/ `ai`（仅 AI）
  - 提取规则：优先取连续 8/9 位数字，兜底取最长数字串
  - AI 通道三个已踩过的坑：base64 转换须按 8192 字节分块（否则栈溢出）、首次调用需在 Cloudflare 面板同意 Meta License、返回的 `response` 字段可能是数字类型需兼容

## [0.1.0] - 2026-08-25

### 新增
- 项目首个可用版本：Cloudflare Workers + D1 单文件部署
- 互助码提交、脱敏列表、跳转拼多多、30 秒后自动删除、24 小时过期
- 智能直达、重复提交重新点亮
- 每天 23:59 Cron 自动清空
- 首页统计（今日 IP 数 / 访问次数 / 提交次数）与 IP 归属地显示
- 假码举报与双 IP 举报自动拉黑、违规小黑屋公示
- IP 黑名单管理（封禁期限可调、过期自动解禁）
- 5 层防恶意提交防护
- 管理后台（`/admin`，`X-Admin-Key` 鉴权）
