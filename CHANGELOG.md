# 更新日志

本项目所有值得注意的变更记录于此。版本按功能里程碑划分，日期为该批改动完成部署的日期。

## [0.9.2] - 2026-09-13

### 修复
- **归属地中文显示与提交变慢（同一根因）**。线上诊断（临时接口读 `request.cf` 与两个归属地库的真实返回）暴露：
  - `getClientIP` 拿到的是 **IPv6**（如 `2409:8a28:...`），而百度 opendata 与 ipwho.is **都是 IPv4-only 库**：前者对 IPv6 返回 `{"data":[]}` 空数组，后者直接 `429 Rate limit exceeded`。于是「后台异步补全」**100% 失败**，页面上只能显示同步兜底的英文 `Shanghai` + 翻译后的「移动」
  - 两个源在 `fillLocationAsync` 里**串行 + 各 5s 超时**，失败路径每次要跑满约 10 秒，白白占用 Worker 并发配额；且**失败结果不缓存**，每次提交都重跑一遍 —— 这正是「先秒提交、后台刷新 IP」却感觉变慢的原因
  - 修法：① 地名中文化改用内置 `CN_CITY` / `CN_REGION` 映射表（Cloudflare 的 `cf.city` / `cf.region` 是固定英文取值集合），**纯本地计算、零网络零耗时**，不再依赖外部 IPv4 接口；② 新增 `isQueryableIP()`，IPv6 与私网/保留地址直接跳过外部查询；③ `fillLocationAsync` 加**负缓存**（成功与失败都写 10 分钟缓存），失败不再反复白跑
- **首页「立即提交」与「🚀 智能直达」两个按钮零间距贴合**。`.btn-row` 的上边距是 `0`，紧接在 `margin-bottom: 0` 的 `.input-area` 之后，两行按钮视觉上粘成一块。改为 `margin:10px 0 18px`，与 `.input-area` 内部 `gap:10px` 的节奏一致

## [0.9.1] - 2026-09-13

### 修复
- **识别成功率提升：修掉两类会把正确印证码整簇否决的误杀**。用 10 张新的 iPhone 整屏截图（1179×2556，微信转发链路）做压力测试时暴露：
  - **数字 `1` 天生窄**：同一张码里 `1` 只有 28px 宽，其他数字 49px 左右。旧的「各块宽度必须接近中位宽」规则（至少 n-2 个块落在中位宽 ±28% 内）在码里出现 3 个 `1` 时直接不成立，整簇被废弃。现改为**逐块宽高比判定**（0.18~0.90）：中文方块字宽高比≈0.96、两个字符合并≈1.5 都会被排除，而窄体的 `1`（实测 0.39）不再误伤
  - **噪点碎片把码撑成 10 块**：码带里的小字与抗锯齿会在数字簇尾部留下 3×5 的碎片，使簇长度变成 10 而被「必须是 8~9 个字形」拦下。新增 `pruneCluster`，按高度（低于簇内中位高 45%）与宽度（低于中位高 15%）剔除不协调块，剔除后重新判定簇长度

### 测试
- **正向**：新增 10 张 iPhone 截图 × 原图/1600/1200/900/700/500 共 30 例 **30/30**；旧 3 张安卓截图 6/6；合成图 27/27
- **JPEG 压测**：10 张截图 × 3 种宽度（原图/900/600）× 4 档质量（q95/80/65/45）共 120 例 **120/120**（模拟微信反复转码）
- **负样本**：非码区裁切、纯中文、红底白字中文、纯色/渐变/噪点/条纹共 196 例 **196/196 零误报**
- **浏览器端实测**：10 张原图在真实页面上全部识别正确，单张 69~181ms，全部带码区预览

## [0.9.0] - 2026-09-11

### 新增
- **识别截图：秒出互助码，不再加载任何模型**。此前的「识图提取」依赖 tesseract.js（约 20MB 运行时 + 英文训练数据，首次使用要等十几秒加载），现改为前端**像素模板匹配**：
  - 算法链路：`红区定位 → Otsu 一维阈值做行分离 → 列切分 → 间隙聚类分出数字簇 → 6×8 面积平均降采样归一化 → 与 10 类字体模板做最近邻`
  - 字体模板为**零样本**生成：取 8 种系统字体（Arial / Arial Black / Arial Bold / Segoe UI Semibold / Segoe UI Bold / 微软雅黑 / Bahnschrift / Trebuchet MS Bold）渲染 0-9 后取平均，对 27 个真机字形 100% 正确；缺失的数字 `6` 由真机 `9` 旋转 180°（`6 = rot180(9)`）交叉印证补全
  - 全程在浏览器内存里完成：**零网络请求、零模型下载、图片不出本机**。实测 1240×2772 安卓整屏截图约 50ms，压到 900px 宽约 10~26ms
  - 双通道定位：先找红底码带（拼多多分享图），失败再走任意底色通道（含深色字压在浅底上时的极性翻转）
- **「识别结果确认」弹窗**：识别到码不再直接提交，而是弹出**裁出的码区原图** + 可编辑的 9 位数字输入框（只收数字、上限 9 位），用户核对后再点「确认提交」，避免认错一位数字
- **提交区改版**（对齐主流互助站布局）：
  - 识别按钮内嵌进输入框右端 —— CSS 绘制的四角取景框 + 扫描线图标，图标在上、文字在下
  - 提交按钮改为**全宽**蓝色大按钮，独占一行
  - 输入行用 `<form>` 包裹，手机键盘按「前往 / Go」即可提交，不必再去点按钮
  - 「智能直达」右端新增 **ⓘ 帮助**，点开说明用法与「必须先手动进福袋界面」的注意事项

### 变更
- **`ocr_mode` 语义调整**：`local`（默认）＝ 只用本地像素识别，没认出就直接提示手动输入；`ai` ＝ 本地识别优先，没认出或置信度偏低时自动调用 `/api/ocr?force=ai` 兜底。此前 `ai` 是「完全不走本地」，现在本地恒为第一优先（免费且更快），AI 只作兜底
- **移除 tesseract.js 全链路**：`public/ocr/`（19.5MB 运行时与训练数据，含 4 份 WASM core）整个删除；`wrangler.toml` 的 `[assets]` 段、`src/index.js` 里的 `/ocr/` 静态路由与 `env.ASSETS` 引用一并移除；`.gitattributes`（唯一规则是禁止 `public/ocr` 换行符转换）随之删除。部署产物从「162KB 代码 + 19.5MB 资源」降到 **162KB（gzip 44KB）**
- **部署方式差异归零**：以前「纯网页部署」因为传不了 `public/ocr/` 而用不了本地识别，现在识别算法内联在页面代码里，网页版与命令行版功能完全一致

### 修复
- `showToast(msg, 'warning')` 没有背景色：CSS 只定义了 `.success` / `.error`，`warning` 类型会落到透明底 + 白字 = 看不见。补上 `.toast.warning{background:#f59e0b}`

### 文档
- **README**：识别截图章节重写；架构图与项目结构去掉 `public/`；部署方式对比表改为「功能完全一致」；Wrangler 配置表删除 `[assets]` 行
- **DEPLOY.md / DEPLOY-WEB.md**：删除「网页版用不了本地识别」整段说明；6.2 的 Workers AI 绑定由「必需」改为「可选兜底」；FAQ 识图排障改写；后台设置项名称由「OCR 模式」更新为「识别截图模式」
- 三份部署文档同步原则不变：改一处必须三处一致

## [0.8.6] - 2026-09-11

### 新增
- **启用 Google Search Console 站点验证**：`CONFIG.SEO_VERIFY_GOOGLE` 填入验证串后，首页 head 输出 `<meta name="google-site-verification">`，供 Google 完成站点归属验证，验证通过即可提交 `sitemap.xml`。
- **启用必应站长平台验证**：新增 `CONFIG.SEO_VERIFY_BING`，填入验证串后首页 head 自动输出 `<meta name="msvalidate.01">`，供 Bing Webmaster Tools 完成站点归属验证。

### 优化
- **移除首页「展开查看详细说明」折叠块**：该块原本列出 4 条规则（邀请码打码规则、跳转后标记「已使用」、未被点击可重新提交入队、活动入口路径），这些内容现已完整包含在页面底部的说明区（「使用步骤」与「常见问题」）中，属重复信息，故整块移除，首页更清爽。
  - 同时清理其专属样式：`details` / `summary` / `.instruction-list` 共 8 行，以及移动端媒体查询里的 2 行适配；另删除一行随之失效的代码注释。全站已无 `details` 元素。
- **改写「常见问题」里的互助引导**：原条目「提交后为什么还要去点别人的码？互助是双向的……」改为「**应该先点别人的码，还是先提交自己的？**有码优先使用，没码的提交。」——原说法是在讲道理（为什么），新说法直接给操作顺序（怎么做），对第一次进站的用户更可执行。

## [0.8.5] - 2026-09-10

### 新增（SEO 优化，面向搜索引擎收录）
- **首页 head 全面补齐**：`description` / `keywords` / `robots` / `canonical` / `theme-color`，以及 Open Graph 与 Twitter Card —— 微信、QQ 转发链接时会显示标题与摘要，不再是一条光秃秃的 URL
- **新增内联 SVG favicon**：搜索结果与浏览器标签页有图标（内联 data URI，不新增文件、不产生额外请求）
- **新增 JSON-LD 结构化数据**：`WebSite` + `FAQPage` 两组，为 Google 富媒体结果提供依据
- **页面语义修正**：首页主标题由 `<h2>` 改为 `<h1>`（此前整站没有 h1），复用原 h2 样式，视觉不变
- **新增服务端渲染的说明文案区**（页面底部）：介绍平台用途、使用步骤、常见问题与合规说明。**可被爬虫读到的正文由 388 字提升到 1104 字**（此前互助码列表由 AJAX 加载，爬虫只能看到「加载中...」）
- **新增 `/sitemap.xml`**：含首页 URL、`lastmod`（取部署日期）、`changefreq`、`priority`
- **`robots.txt` 增强**：显式 `Allow: /` 并声明 `Sitemap:` 地址

### 安全
- **后台页面增加 `noindex,nofollow`**：在 `robots.txt` 之外再上一道保险，防止后台页面被搜索引擎收录

### 运维
- 新增 `CONFIG.SITE_ORIGIN`（站点域名统一引用，换域名只改一处）与 `CONFIG.SEO_VERIFY_BAIDU` / `CONFIG.SEO_VERIFY_GOOGLE` 验证码占位；填入验证串后自动输出对应站长平台的验证 meta
- 修正 `scripts/check-inline-js.cjs`：模板字符串引入 `${CONFIG.xxx}` 插值后，原提取方式的作用域缺少 `CONFIG` 会直接报错，现会把依赖常量一并注入求值上下文

## [0.8.4] - 2026-09-10

### 修复
- **后台登录后刷新页面就掉登录状态**：登录密钥此前只保存在页面内存中（一个 JavaScript 变量），页面一旦重新加载就归零——F5 刷新、手机切到其它 App 后回来（页面被系统回收重载）、从别处重新进入后台，都会退回登录框。
  现改为存入 `sessionStorage`：刷新与页面重载后自动恢复登录，关闭标签页即清除，密钥不会长期停留在浏览器里。
- **登录过期不再静默失败**：此前后台接口返回 401 时前端不作任何提示，表现为「点了没反应」。现在会明确提示「登录已过期，请重新登录」并退回登录框（并发请求只提示一次）。
- 后台导航栏新增「退出登录」按钮，可主动清除本机登录态。

## [文档修复] - 2026-09-10

### 新增
- **README 增加两套部署方式的分流入口**：命令行部署与纯网页部署并列对比（是否需装软件、源码获取方式、OCR 差异），各自指向对应教程，读者不必再猜哪一份适合自己
- **DEPLOY-WEB.md 补齐「获取源码」步骤**：原第 5 步要求「打开项目里的 `src/index.js`」，可纯网页用户手上根本没有这个文件。现改为从 GitHub 网页点 **Copy raw file** / **Raw** 复制，并明确警告不要在代码预览页直接 Ctrl+A（行号会被一起复制，粘进去全是语法错误）
- **DEPLOY-WEB.md 增加 Workers AI 绑定步骤（第 6.2 步）**：网页版无法上传 `public/ocr/`，本地识别必然失败；绑定 AI 后走服务端识别仍可正常识图。另说明可在后台把 OCR 模式改为 `ai`，省去一次失败等待

### 修复
- **DEPLOY-WEB.md 内嵌建表 SQL 与 `schema.sql` 严重脱节**：缺 `visits` 表（首页统计要读它，**缺了 `/api/config` 报错、页面直接白屏**）与 10 个复合索引，还残留已废弃的 `idx_logs_ip`。现按 `schema.sql` 全量同步，90 行逐行一致（已用脚本校验），并注明「以仓库 `schema.sql` 为准」的取用方式
- **部署文档缺失「克隆项目」这一步**：README 与 DEPLOY.md 都从「安装 Wrangler」讲起，DEPLOY.md 更直接写 `cd pdd-fudai`——而读者手上并没有代码，照做必然卡住。两份文档已补上 `git clone`，并给出未装 Git 时改用 GitHub **Code → Download ZIP** 的替代路径
- **部署顺序错误：「设置管理密钥」被排在「部署」之前**：`wrangler secret put` 要求目标 Worker 已存在，未部署时执行会报 `workers.api.error.script_not_found [code: 10007]`——报错信息晦涩，新手几乎无法自行定位。两份文档均调整为「先部署，后设密钥」，并补充说明：设置密钥会自动创建新版本并立即上线，**无需**再执行一次 `deploy`
- **Node.js 版本要求过时**：文档原写「Node.js 16+」、示例版本 `v20.11.0`，而最新版 Wrangler（4.130.0）的 `engines` 要求 `node >= 22.0.0`，按旧文档安装会在 `npm install -g wrangler` 阶段撞上 `EBADENGINE`。已统一改为 **Node.js 22+**，并在安装章节补充该报错的排查提示
- DEPLOY.md 常见问题新增 `script_not_found` 专项问答，并修正「重新设置密钥后需要再执行 `wrangler deploy`」的错误说法
- DEPLOY-WEB.md 白屏排查增加 `visits` 表检查项，并新增「点识图没反应 / 识别失败」专项问答；后台设置项说明补上「OCR 模式」「iOS 快捷指令地址」两项

## [0.8.3] - 2026-09-05

### 变更
- **首页 iOS 快捷指令地址改为后台可配**：站点设置新增「iOS 快捷指令地址」一项，改地址不必重新部署
- 默认地址移到服务端 `CONFIG.IOS_SHORTCUT_URL`，模板里不再写死 `icloud.com` 链接（与 0.8.2 去掉硬编码品牌文案同一思路：展示内容不应写死在代码里）
- 支持三态语义，区分「从未配置」与「已主动关闭」：
  - 从未在后台保存过 → 用默认地址
  - 填了具体 URL → 用该 URL
  - 显式留空 → 首页隐藏该按钮
- 后台回填时展示**当前生效值**（从未配置则回填默认地址），否则管理员看到空框会误以为按钮不显示，也无法分辨「走默认」和「已关闭」
- 抽出 `isHttpUrl()` 统一协议判定：`safeHref()` 用于拼 HTML 字符串（需 `escapeHtml`）、DOM 属性赋值需用原始值，两者上下文不同但协议判断必须共用一份，否则逻辑会漂移

### 安全
- 地址保存时过 `sanitizeUrl()` 协议白名单，防 `javascript:` 伪协议与属性截断注入（如 `https://x/" onmouseover=`）
- **非法地址返回 400 并说明原因，而不是静默清空**：管理员少写协议头（如 `icloud.com/xxx`）时，静默清空会让按钮凭空消失且不留任何痕迹，报错才能当场说清原因（此处与广告 URL 的静默过滤策略不同，是有意为之）
- 前端给 `href` 赋值时再判一次协议，避免历史脏数据绕过

部署版本：`c978ecee-7f23-448c-a5f3-1e4a4c6de5ac`

## [0.8.2] - 2026-08-31

### 修复
- **未配置广告时首页仍出现硬编码品牌文案**：弹窗广告的标题「外卖·打车 每日必领神券」与副标题「美团 · 淘宝闪购 · 京东｜外卖打车全线折上折」是写死在 `INDEX_HTML` 里的，虽然 `.ad-pop` 默认 `display:none`（无广告时不会弹出），但这段文字始终存在于页面 DOM 与 HTML 源码中，浏览器查看源码、搜索引擎抓取、以及任何手动加 `.show` 的场景都会看到，等于站点在未接广告时凭空提及第三方品牌
- 同时广告链接图标写死为「团 / 淘 / 京 / 滴」四个品牌首字，与实际配置的广告无关

### 变更
- 弹窗广告标题栏改为后台可配：站点设置新增「弹窗广告标题」「弹窗广告副标题」两项（限 60 / 120 字），留空则整个标题栏 `display:none` 不渲染
- `GET /api/config` 仅在**已配置广告**且对应文案非空时才返回 `ad_title` / `ad_sub`
- `GET /api/admin/settings` 与 `POST /api/admin/settings` 增加 `ad_title` / `ad_sub` 字段
- 文案通过 `textContent` 注入（而非 `innerHTML` 拼接），天然免疫 XSS
- 广告链接图标由品牌首字改为序号（1/2/3...）

部署版本：`79ad9199-71a4-431b-aa69-77d31af382af`

## [0.8.1] - 2026-08-31

对 0.8.0 的改动做二次复核（防止重构引入回归），发现并修掉 5 处遗漏。

### 修复
- **超大 `page` 参数导致 500**：`parsePaging` 用 `Number.isFinite` 判定，而 `Number.isFinite(1e20)` 为 `true`，`(1e20 - 1) * 50` 已超出安全整数范围，bind 进 D1 会抛异常。改用 `Number.isSafeInteger` 并新增 `PAGE_MAX: 100000` 上限（`page=999999999` 现收敛为 100000，返回空页而非 500）。这是 0.8.0 给路径 id 加了 `parseId` 但漏掉分页参数的同类问题

### 安全
- 补齐 4 处 `innerHTML` 拼接的转义遗漏（均为低危、值域受控，但属同类风险面）：
  - 首页小黑屋公示的 `remaining`（来自服务端 `formatRemaining`）
  - 后台码列表的 `status`、日志列表的 `action`（DB 字段，理论上受控）
  - 后台黑名单的 `duration` 兜底分支（`durMap` 未命中时直出原值）

### 复核方法
本轮新增三项静态扫描（临时脚本，已删除）+ 完整接口回归：
- 内联前端脚本的「未定义标识符调用」扫描：两个模板均无遗漏（`rgba` / `resolve` / `reject` 为误报）
- 「定义但从未被引用的函数」扫描：后端与两个前端模板均为 0
- 所有 `innerHTML` / `outerHTML` 写入点逐行核对转义
- `schema.sql` 本地连续重跑两次均成功（幂等性确认），索引列表确认 `idx_logs_ip` 已不存在、`idx_logs_ip_action_created` 在位

部署版本：`65316b12-3f8c-4603-b9b5-182aabfde683`

## [0.8.0] - 2026-08-31

第三轮全量审查（语法 / 重复代码 / Bug / 安全四个维度逐条过），修掉上两轮遗漏的问题。

### 安全
- **广告 URL 属性截断注入**：`sanitizeUrl` 原来只校验 `https?://` 前缀，`https://x.com/a.png" onmouseover="alert(1)` 能通过。该值会被拼进 `<img src="...">` 与后台输入框 `value="..."`，引号未过滤即可闭合属性注入事件处理器。现在额外拒绝含引号、尖括号、反斜杠、空白的 URL
- **后台广告输入框未转义**：`adRowHTML()` 直接把 `image_url` / `link_url` 拼进 `value="..."`，历史脏数据仍可触发。已补 `escapeHtml`
- **公告详情弹窗未转义**：`showNoticeModal` 把公告原文拼 `innerHTML`（其余位置都转义了，唯独漏了这处）
- **黑名单移除按钮改用 dataset**：原来把 IP 拼进 `onclick="removeBlacklist('...')"` 的字符串字面量里，脏 IP 可闭合引号执行任意 JS
- **自动拉黑不再可封掉全站**：提交者 IP 为空或 `0.0.0.0`（取不到 IP）时跳过拉黑。原逻辑会往 blacklist 塞一条 `0.0.0.0`，而 `getClientIP` 兜底值正是 `0.0.0.0`，等于封禁所有取不到真实 IP 的用户
- **日志字段截断**：`logAction` 的 `code` 截 32 字符、`reason` 截 200。蜜罐分支会把未校验的 `body.code` 原样落库，可用 1MB 字符串反复提交撑爆 D1 存储

### 修复
- **非对象 JSON body 导致 500**：`null` / `"str"` / `123` / `[1,2]` 都是合法 JSON，`request.json()` 不抛异常，但随后 `body.code` 会抛 TypeError 冒泡成 500。新增 `readJsonBody()` 统一要求普通对象，4 个处理器全部改用，实测 5 种畸形 body 全返 400
- **超大路径 id**：`parseInt('99999999999999999999')` 得到 `1e20` 浮点数再 bind 进 SQL，行为依赖驱动。新增 `parseId()` 收敛为安全整数，越界回 404
- **举报状态更新 / 删除举报无论是否命中都报成功**：改按 `meta.changes` 返回 404（其他删除接口上一轮已修，这两个漏了）
- **小黑屋公示展示已过期记录**：过期即自动解禁（`checkBlacklist` 放行），但公示页照旧显示，已解封用户会看到自己还"在小黑屋里"。查询加 `expires_at IS NULL OR expires_at > now`
- **OCR local 模式白解析请求体**：`local` 分支原本在 `formData()` 之后才返回，每个请求都要先把整张图解析完再拒绝。现提前到解析之前；同时给 `formData()` 包 try/catch，非 multipart body 明确回 400 而不是走兜底错误
- `maskCode` 对 `null` 会抛异常（`code.length`），改先 String 化

### 重构（消除重复代码）
- 三处限流查询（`checkRateLimit` / `checkActionRateLimit` / `checkDailyLimit`）的 COUNT 语句完全相同，抽出 `countActions(db, ip, action, since)`
- 三个后台列表接口各复制了一份「数据页 + COUNT」的串行两次往返，抽出 `paginatedList()` 并合并为一次 `db.batch`（每个接口省一个 D1 往返）
- 后台前端的 `formatRemainingAdmin()` 与服务端 `formatRemaining()` 逻辑完全重复，删除前端版本，改由 `/api/admin/blacklist` 直接返回 `remaining` 字段（与公示页同一套逻辑，不会再改一处忘一处）
- 删除从未被调用的 `isExpired()` 与重复的 `checkBlacklist` 注释行

部署版本：`93780898-e0a6-4826-b6c1-5860f4454418`

## [0.7.1] - 2026-08-31

### 修复
- **CSP 拦掉了 Cloudflare Web Analytics 的 beacon 脚本**：`https://static.cloudflareinsights.com/beacon.min.js` 是 Cloudflare 在边缘自动注入进 HTML 的 RUM 统计脚本（不在项目源码里），0.7.0 收紧 CSP 后被 `script-src 'self'` 挡下，浏览器控制台报红且访问统计失效。现在 `script-src` 放行 `https://static.cloudflareinsights.com`，`connect-src` 放行 `https://cloudflareinsights.com`（上报端点）

部署版本：`5bef2eb8-3e9e-4b5e-ae48-4d9593879190`

## [0.7.0] - 2026-08-31

本轮为专项安全加固 + 性能优化，无新功能。

### 安全
- **全局黑名单拦截**：原来只有 `/api/submit` 查黑名单，被封 IP 依然能领码（清空列表）、举报（武器化自动拉黑）、刷 AI 识图额度。现在在 `handleAPI` 入口按 `BLACKLIST_GUARDED` 白名单统一拦截 submit / use / quick-use / report / ocr 全部公开写接口
- **后台密钥暴力破解防护**：`/api/admin/*` 鉴权失败现在按 IP 记 `admin_fail` 审计日志并限流（10 次/分钟，超限 429）。此前 `ADMIN_KEY` 作为唯一凭据可被脚本无限枚举且不留痕
- **密钥比较不再泄露长度**：`verifyAdmin` 原实现先比 `length` 再逐字符比较，等于把真实密钥长度暴露给攻击者。改为双方各自 SHA-256 后比较 32 字节摘要，长度恒定
- **自动拉黑三重加固**（原逻辑可被当武器拉黑正常用户）：举报统计加 24 小时时间窗（原来统计全表历史）、门槛从 2 个不同 IP 提到 3 个、禁止举报自己提交的码
- **CSP 替换废弃头**：移除已被所有现代浏览器废弃的 `X-XSS-Protection`，改为完整 `Content-Security-Policy`（`script-src 'self'` + `frame-ancestors 'none'` + `base-uri 'none'` + `object-src 'none'`），可挡住外部脚本注入
- **敏感响应不再可缓存**：所有 JSON 响应加 `Cache-Control: no-store`。`/api/use`、`/api/quick-use` 的响应体里是完整互助码，被中间代理缓存会导致跨用户泄露
- **后台页防收录**：`/admin` 响应加 `X-Robots-Tag: noindex` + `no-store`，并新增 `/robots.txt` 禁止爬取 `/admin` 与 `/api/`
- **归属地查询全 HTTPS**：兜底服务从明文 `http://ip-api.com` 换为 `https://ipwho.is`，用户 IP 不再在 Workers 与第三方之间裸奔；查询参数补 `encodeURIComponent`
- **公开写接口补限流**：`/api/visit` 此前完全无限流，可被脚本每秒上千次刷爆 D1 写配额与统计数字，现限 30 次/分钟/IP
- **输入校验补齐**：后台分页参数收敛（`pageSize` 上限 200、`page` 最小 1，此前 `pageSize=999999` 可一次拖走整表、`page=0` 会让 OFFSET 变负数报错）；手动拉黑校验 IP 格式与封禁期限白名单；`/api/ocr` 校验上传字段确为文件且 MIME 在图片白名单内；公告长度限 500 字、广告最多 10 条；全部 `request.json()` 包 try/catch
- `.gitignore` 补 `.dev.vars` / `.env`，防本地密钥误入库

### 性能
- **首页轮询不再每次写库**：`/api/codes` 原来每次请求都先跑一条 `DELETE` 做垃圾回收。首页 5 秒轮询下，100 个在线用户即 20 次写/秒。改为 SELECT 直接按截止时间过滤（展示效果一致），DELETE 降级为 10% 抽样的 `waitUntil` 后台清理
- **配置读取从 N 次往返压到 1 次**：新增 `getSettings()` 批量读，`/api/config`（首页必打）由 7 次 `getSetting` + 3 次统计查询共 10 个串行 D1 往返，压缩到 1 次 IN 查询 + 1 次 batch；后台设置读取同理，保存改为单次 batch 提交
- **后台统计合并**：`/api/admin/stats` 的 6 项指标由 6 次串行查询改为一次 `db.batch()`
- **补 8 组复合索引**：限流查询都是 `(ip, action, created_at)` 三条件组合，原来只有单列 `idx_logs_ip`，会先扫出该 IP 全部历史日志再过滤。新增 `idx_logs_ip_action_created`、`idx_logs_action_created`、`idx_codes_status_created`、`idx_codes_code`、`idx_codes_used_at`、`idx_visits_ip_created`、`idx_reports_ip_created`、`idx_reports_submitter_created`

### 修复
- **领码竞态导致同一个码发给两个人**：`/api/use/:id` 与 `/api/quick-use` 原为「先 SELECT 判 active，再 UPDATE」，并发下两个请求都能读到 active。改为带 `status='active'` 条件的原子 UPDATE，用 `meta.changes` 判断是否抢到；quick-use 抢不到时重试下一个码（最多 3 次）。已用 10 并发实测：仅 1 个成功，其余正确返回"已被使用"
- **visits / reports 表只增不减**：每日定时清理扩展为按 30 天保留期清理 `submit_logs`、`visits`、已处理的 `reports`，并顺带删除已过期的黑名单记录；整批改为一次 `db.batch()`
- 删除码/移除黑名单接口原来无论是否命中都返回"已删除"，现按 `meta.changes` 正确返回 404
- Cron 任务包 try/catch，清理失败不再静默抛出

### 变更
- 移除 OCR 已废弃的 `auto` 模式死分支与未使用的 `CONFIG.MAX_CODE_LENGTH`、`setSetting()`
- OCR 的模型名与 prompt 提取为 `OCR_MODEL` / `OCR_PROMPT` 常量，agree-license 重试复用同一 payload（原来整份 prompt 复制两遍，容易改漏）
- 主入口新增 8MB 请求体闸门；API 异常日志带上路径，响应体不回传任何堆栈信息
- 后台设置的三个数值型字段（刷新间隔 / 每分钟上限 / 每日上限）改为表驱动校验
- 删除被复合索引完全覆盖的单列索引 `idx_logs_ip`（`schema.sql` 中改为显式 `DROP INDEX IF EXISTS`），减少 `submit_logs` 的写放大

部署版本：`b1c39d4e-4028-48ec-8ffc-f1e3307ecc9b`

## [0.6.0] - 2026-08-31

### 安全
- **防 IP 伪造**：`getClientIP` 只信任 Cloudflare 注入的 `cf-connecting-ip`，移除可被伪造的 `x-forwarded-for` / `x-real-ip` 回退链，封堵伪造 IP 头绕过黑名单/限流的漏洞
- **管理密钥泄露面收敛**：管理后台鉴权移除 `?key=` URL 查询参数方式（密钥会进浏览器历史/服务器日志），仅保留 `X-Admin-Key` 请求头，并改用恒时比较防时序侧信道
- **AI 额度防盗刷**：`/api/ocr` AI 识别路径新增独立 IP 限流（默认 10 次/分钟）+ 调用前记审计日志（`ocr_ai`），并限制上传图片大小上限 4MB
- **互助码列表防遍历清空**：`/api/use/:id` 与快速使用接口新增 IP 限流（默认 20 次/分钟），防止脚本遍历把列表一次性"用"空
- **移除 CORS 全开**：删除 `Access-Control-Allow-Origin: *`，新增安全响应头（`X-Content-Type-Options: nosniff` / `X-Frame-Options: DENY` / `Referrer-Policy: no-referrer` / `X-XSS-Protection`），API 与页面响应统一注入
- **存储型 XSS 双重防护**：后端新增 `sanitizeUrl()` 协议白名单（仅 http/https）过滤广告链接与图片；前端新增 `escapeHtml()` / `safeHref()`，对所有 `innerHTML` 拼接点（归属地、脱敏码、联系方式、小黑屋公示、广告、管理后台表格）统一转义

### 修复
- **OCR 接口 500**：`handleOcr` 的 `let ocrMode` 原声明在 `try` 块内，`getSetting` 抛异常时 catch 块访问它触发 `ReferenceError`（TDZ），掩盖真实错误冒泡成 500；提前声明并给默认值 `local`，任何异常都能正常兜底返回
- `schema.sql` 缺失 `visits` 表（原先靠代码运行时动态建表，新环境部署后今日访问统计失效），已补表和 `idx_visits_created` 索引

### 变更
- IP 归属地缓存从 Worker 实例级 `Map`（无常驻进程，实际不生效）改为 Cache API（`caches.default`，10 分钟 TTL），减少重复 IP 的归属地查询
- `quick-use` 接口直接返回码 `id`，前端不再用「头3+尾3」模糊匹配定位刚使用的码
- CST 今日 0:00 计算抽取为 `getCSTTodayStartISO()`，三处重复实现统一复用
- 管理后台设置读取的 `smart_enabled` 统一返回 boolean 类型
- 每日定时清理新增 30 天前的 `submit_logs` 审计日志，防止表无限膨胀
- 清理首页 `entry_image` / `entryImg` 死代码与 `ad.title` 无效引用

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
