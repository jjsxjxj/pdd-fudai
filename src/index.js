/**
 * PDD 福袋互助平台 - Cloudflare Workers 后端
 *
 * 功能：
 *  - 提交/查看/标记邀请码
 *  - IP 黑名单管理
 *  - 防恶意提交（速率限制、每日限额、蜜罐、输入校验）
 */

// ============================================================
//  配置
// ============================================================
const CONFIG = {
  CODE_LENGTH_MIN: 8,          // 邀请码最短长度
  CODE_LENGTH_MAX: 9,          // 邀请码最长长度
  MAX_ACTIVE_CODES: 50,        // 列表最多展示条数
  RATE_LIMIT_WINDOW_MS: 60_000, // 速率限制窗口（1分钟）
  RATE_LIMIT_MAX: 5,           // 窗口内最大提交次数
  DAILY_LIMIT: 30,             // 每IP每日最大提交次数
  CODE_TTL_HOURS: 24,          // 邀请码过期时间（小时）
  USED_KEEP_MS: 30_000,        // 使用后保留时长（毫秒），30秒后自动删除轮换
  OCR_AI_RATE_LIMIT: 10,       // 每IP每分钟 AI 识图次数上限（防额度盗刷）
  USE_RATE_LIMIT: 20,          // 每IP每分钟标记使用/智能直达次数上限（防遍历清空列表）
  OCR_MAX_IMG_BYTES: 4 * 1024 * 1024, // 服务端识图图片大小上限（4MB）
  VISIT_RATE_LIMIT: 30,        // 每IP每分钟访问打点上限（防 visits 表被刷爆）
  ADMIN_FAIL_LIMIT: 10,        // 每IP每分钟后台鉴权失败次数上限（防密钥暴力破解）
  REPORT_AUTO_BAN_THRESHOLD: 3,   // 自动拉黑所需的不同举报人IP数
  REPORT_AUTO_BAN_WINDOW_MS: 24 * 3600_000, // 自动拉黑的举报统计时间窗（24小时）
  LOG_KEEP_DAYS: 30,           // submit_logs / visits / reports 保留天数
  PAGE_SIZE_MAX: 200,          // 后台分页每页最大条数
  PAGE_MAX: 100000,            // 后台分页最大页码（防 offset 溢出成非安全整数）
  // iOS 快捷指令默认地址：后台「站点设置」未配置过 ios_url 时首页用这个；
  // 后台显式保存为空则首页不显示该按钮（区分「未配置」与「配置为空」两种语义）
  IOS_SHORTCUT_URL: 'https://www.icloud.com/shortcuts/e5dacaf5c4dc4809bca41848175373c1',
  // 站点正式域名：canonical / og:url / sitemap.xml / robots.txt 统一引用这里，换域名只改一处
  SITE_ORIGIN: 'https://your-domain.example.com',
  // SEO 站长平台验证码：在对应平台添加站点后把验证串填到这里；留空则不输出该 meta 标签。
  // 百度搜索资源平台 ziyuan.baidu.com → HTML 标签验证；Google Search Console → HTML 标记；
  // 必应 Bing Webmaster Tools（bing.com/webmasters）→「HTML Meta 标记」给的 msvalidate.01
  SEO_VERIFY_BAIDU: '',
  SEO_VERIFY_GOOGLE: '',
  SEO_VERIFY_BING: '',
};

/** 需要黑名单拦截的公开写接口（被拉黑的 IP 不仅不能提交，也不能领码/举报/刷 AI 额度） */
const BLACKLIST_GUARDED = [
  { method: 'POST', test: (p) => p === '/api/submit' },
  { method: 'POST', test: (p) => p === '/api/quick-use' },
  { method: 'POST', test: (p) => p === '/api/ocr' },
  { method: 'POST', test: (p) => /^\/api\/use\/\d+$/.test(p) },
  { method: 'POST', test: (p) => /^\/api\/report\/\d+$/.test(p) },
];

// ============================================================
//  工具函数
// ============================================================

/** 获取客户端真实 IP
 *  只信任 Cloudflare 注入的 cf-connecting-ip（用户无法伪造）。
 *  切勿 fallback 到 x-forwarded-for / x-real-ip：这两个头客户端可随意伪造，
 *  非 CF 环境下会被用来绕过黑名单、限流、甚至伪造多个 IP 触发自动拉黑。 */
function getClientIP(request) {
  return request.headers.get('cf-connecting-ip') || '0.0.0.0';
}

/** 脱敏：隐藏中间两位 */
function maskCode(code) {
  const s = String(code == null ? '' : code);
  if (s.length < 4) return '****';
  const mid = Math.floor(s.length / 2);
  return s.slice(0, mid - 1) + '**' + s.slice(mid + 1);
}

/** JSON 响应
 *  首页与 API 同域（fetch 用相对路径），无需 CORS —— 移除 Access-Control-Allow-Origin:*，
 *  避免任意站点跨域携带 X-Admin-Key 调用管理接口。
 *  统一 no-store：/api/use、/api/quick-use 的响应体里是完整互助码，
 *  一旦被中间代理或浏览器缓存，同一 URL 的后续请求可能读到别人的码。 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: securityHeaders({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
    }),
  });
}

/** 安全响应头：防 MIME 嗅探、防点击劫持、防 Referer 泄露
 *  X-XSS-Protection 已被所有现代浏览器移除（且历史上曾引入过漏洞），改用 CSP。
 *  CSP 用 'unsafe-inline'：本项目前端 HTML/CSS/JS 全部内联在 Worker 里，暂不做 nonce 化；
 *  即便如此仍能挡住外部脚本注入（script-src 只允许 self 与下面显式列出的 CF 域）。
 *  static.cloudflareinsights.com：Cloudflare Web Analytics(RUM) 在边缘自动注入的 beacon 脚本，
 *  不加白会被 CSP 拦掉、控制台报红且统计失效。上报端点是同域 /cdn-cgi/rum，
 *  但部分版本会直接打 cloudflareinsights.com，故 connect-src 一并放行。 */
const CF_BEACON_ORIGIN = 'https://static.cloudflareinsights.com';
const CF_RUM_ORIGIN = 'https://cloudflareinsights.com';

function securityHeaders(extra = {}) {
  return Object.assign({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' blob: ${CF_BEACON_ORIGIN}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      `connect-src 'self' blob: data: ${CF_RUM_ORIGIN}`,
      "worker-src 'self' blob:",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "object-src 'none'",
    ].join('; '),
  }, extra);
}

/** 当前时间 ISO 字符串 */
function now() {
  return new Date().toISOString();
}

/** 北京时间（CST, UTC+8）今日 0:00 对应的 UTC ISO 字符串。
 *  Workers 跑 UTC，直接 setHours 会算成 UTC 0:00（=CST 8:00），导致今日统计边界错位。 */
function getCSTTodayStartISO() {
  const cstOfNow = new Date(Date.now() + 8 * 3600_000);
  cstOfNow.setUTCHours(0, 0, 0, 0);
  return new Date(cstOfNow.getTime() - 8 * 3600_000).toISOString();
}

// ============================================================
//  防恶意提交中间件
// ============================================================

/** 检查IP是否在黑名单中（含过期判断） */
async function checkBlacklist(db, ip) {
  const result = await db.prepare('SELECT ip, reason, expires_at FROM blacklist WHERE ip = ?').bind(ip).first();
  if (!result) return null;
  // 有过期时间且已过期 = 自动解禁
  if (result.expires_at) {
    const expires = new Date(result.expires_at).getTime();
    if (Date.now() > expires) {
      // 可选：清理过期记录
      await db.prepare('DELETE FROM blacklist WHERE ip = ?').bind(ip).run();
      return null;
    }
  }
  return result;
}

/** 统计某 IP 在 sinceISO 之后的某类动作条数
 *  原来 checkRateLimit / checkActionRateLimit / checkDailyLimit 三处各写了一遍
 *  完全相同的 COUNT(*) 语句，只有时间窗和 action 不同。 */
async function countActions(db, ip, action, sinceISO) {
  const row = await db
    .prepare('SELECT COUNT(*) as count FROM submit_logs WHERE ip = ? AND created_at > ? AND action = ?')
    .bind(ip, sinceISO, action)
    .first();
  return (row && row.count) || 0;
}

/** 速率限制：检查窗口内提交次数 */
async function checkRateLimit(db, ip, maxPerMin) {
  if (!maxPerMin || maxPerMin < 1) maxPerMin = CONFIG.RATE_LIMIT_MAX;
  const since = new Date(Date.now() - CONFIG.RATE_LIMIT_WINDOW_MS).toISOString();
  return (await countActions(db, ip, 'submit', since)) >= maxPerMin;
}

/** 通用动作限流：某 IP 一分钟内某动作（use/ocr_ai/...）次数是否达上限
 *  用于 use、quick-use、AI 识图等公开接口的防刷（submit 走上面专用限流） */
async function checkActionRateLimit(db, ip, action, maxPerMin) {
  if (!ip || ip === '0.0.0.0' || !maxPerMin || maxPerMin < 1) return false;
  const since = new Date(Date.now() - 60_000).toISOString();
  return (await countActions(db, ip, action, since)) >= maxPerMin;
}

/** 每日限额 */
async function checkDailyLimit(db, ip, dailyMax) {
  if (!dailyMax || dailyMax < 1) dailyMax = CONFIG.DAILY_LIMIT;
  return (await countActions(db, ip, 'submit', getCSTTodayStartISO())) >= dailyMax;
}

/** 记录日志
 *  code / reason 截断：honeypot 分支会把未经校验的 body.code 直接落库，
 *  攻击者可以塞 1MB 字符串（body 上限 8MB）反复提交撑爆 D1 存储。 */
async function logAction(db, ip, code, action, reason = '') {
  await db
    .prepare('INSERT INTO submit_logs (ip, code, action, reason, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(ip, String(code || '').slice(0, 32), action, String(reason || '').slice(0, 200), now())
    .run();
}

/** 解析路径里的自增主键 id
 *  原来各处直接 parseInt(match[1])（无 radix，且不设上限）：
 *  /api/use/99999999999999999999 会被解析成 1e20 这种浮点数再 bind 进 SQL，
 *  行为依赖驱动实现。这里统一收敛为安全整数，越界返回 null 由调用方回 404。 */
function parseId(raw) {
  const n = parseInt(raw, 10);
  if (!Number.isSafeInteger(n) || n < 1) return null;
  return n;
}

/** 校验邀请码格式（8~9 位数字） */
function validateCode(code) {
  if (!code || typeof code !== 'string') return { valid: false, reason: '邀请码不能为空' };
  const trimmed = code.trim();
  if (trimmed.length < CONFIG.CODE_LENGTH_MIN || trimmed.length > CONFIG.CODE_LENGTH_MAX) {
    return { valid: false, reason: `邀请码必须是 ${CONFIG.CODE_LENGTH_MIN}-${CONFIG.CODE_LENGTH_MAX} 位数字` };
  }
  if (!/^\d+$/.test(trimmed)) {
    return { valid: false, reason: '邀请码只能包含数字' };
  }
  return { valid: true, code: trimmed };
}

// ============================================================
//  站点设置工具
// ============================================================

/** 读取站点设置 */
async function getSetting(db, key) {
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? row.value : null;
}

/** 批量读取站点设置，返回 { key: value } 映射
 *  原来 /api/config 与后台设置页各自串行 await 了 7~9 次 getSetting，
 *  等于 7~9 个 D1 往返（每次约 5~20ms）；这里一条 IN 查询搞定。 */
async function getSettings(db, keys) {
  const placeholders = keys.map(() => '?').join(',');
  const res = await db
    .prepare(`SELECT key, value FROM settings WHERE key IN (${placeholders})`)
    .bind(...keys)
    .all();
  const map = {};
  for (const row of res.results || []) map[row.key] = row.value;
  return map;
}

/** URL 协议白名单：只允许 http/https，防 javascript:/data: 等存储型 XSS
 *  额外拒绝引号/尖括号/空白：这些字符会被拼进 HTML 属性（后台广告输入框的 value），
 *  只做协议前缀判断不足以防属性截断注入（如 https://x/" onmouseover="...）。 */
function sanitizeUrl(u) {
  if (!u) return '';
  const t = String(u).trim();
  if (!/^https?:\/\//i.test(t)) return '';
  if (/["'<>\\\s]/.test(t)) return '';
  return t;
}

/** iOS 快捷指令地址的三态解析（settings 里 ios_url 有三种状态，语义各不相同）：
 *   ① DB 无该行（从未在后台保存过）→ 用 CONFIG.IOS_SHORTCUT_URL 默认值
 *   ② 后台显式保存为空       → 返回 ''，首页据此隐藏按钮（这是「主动关掉」，不能回退成默认值）
 *   ③ 有值                   → 再过一遍 sanitizeUrl，防历史脏数据绕过保存时的校验；
 *                              校验不通过按「隐藏」处理（fail closed，比悄悄退回默认值可预期）*/
function resolveIosUrl(raw) {
  if (raw === undefined || raw === null) return CONFIG.IOS_SHORTCUT_URL;
  const t = String(raw).trim();
  if (!t) return '';
  return sanitizeUrl(t);
}

/** 安全读取 JSON 请求体
 *  原来 4 个处理器各自复制一份 try/catch，且都假定解析结果是对象：
 *  body 为 `null` / `"str"` / `123`（都是合法 JSON）时，后续 body.xxx 会抛 TypeError
 *  冒泡成 500。这里统一要求必须是普通对象。 */
async function readJsonBody(request) {
  try {
    const body = await request.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
    return body;
  } catch {
    return null;
  }
}

/** GET /api/config — 获取首页配置（公告/广告/联系方式/开关），空值自动省略
 *  这是首页每次加载都会打的接口，原来 7 次 getSetting + 3 次统计 = 10 个串行 D1 往返；
 *  现在压到 1 次 settings 批量读 + 1 次三指标合并统计。 */
async function handleGetConfig(db) {
  const s = await getSettings(db, ['notice', 'ads', 'ad_title', 'ad_sub', 'qq_group', 'qq_owner', 'smart_enabled', 'refresh_interval', 'ocr_mode', 'ios_url']);
  const notice = s.notice;
  const adsRaw = s.ads;
  const qqGroup = s.qq_group;
  const qqOwner = s.qq_owner;
  const smartRaw = s.smart_enabled;
  const refreshInterval = s.refresh_interval;
  const data = {};

  // 刷新间隔：默认 5 秒，范围 3-30 秒
  const ri = parseInt(refreshInterval, 10);
  data.refresh_interval = (!isNaN(ri) && ri >= 3 && ri <= 30) ? ri : 5;

  // 公告：非空才返回
  if (notice && notice.trim()) {
    data.notice = notice.trim();
  }

  // 广告：解析 JSON 数组，过滤空项
  let ads = [];
  if (adsRaw) {
    try {
      ads = JSON.parse(adsRaw);
      if (!Array.isArray(ads)) ads = [];
    } catch {
      ads = [];
    }
  }
  ads = ads.filter((ad) => ad && ad.image_url && ad.image_url.trim());
  if (ads.length > 0) {
    data.ads = ads.map((ad) => ({
      image_url: ad.image_url.trim(),
      link_url: (ad.link_url && ad.link_url.trim()) || '',
    }));
    // 弹窗广告文案：后台可配，未配则弹窗不显示标题栏（不再硬编码任何品牌名）
    if (s.ad_title && s.ad_title.trim()) data.ad_title = s.ad_title.trim();
    if (s.ad_sub && s.ad_sub.trim()) data.ad_sub = s.ad_sub.trim();
  }

  // 联系方式：非空才返回（首页据此显示按钮/弹窗）
  if (qqGroup && qqGroup.trim()) data.qq_group = qqGroup.trim();
  if (qqOwner && qqOwner.trim()) data.qq_owner = qqOwner.trim();

  // 智能直达开关：默认开启
  data.smart_enabled = smartRaw !== 'off';

  // OCR 模式：local（默认，浏览器本地优先）/ ai（仅服务端 AI），默认 local
  data.ocr_mode = (s.ocr_mode === 'ai') ? 'ai' : 'local';

  // iOS 快捷指令地址：从未配置过 → 用服务端默认值；后台显式留空 → 返回 ''，前端隐藏按钮
  data.ios_url = resolveIosUrl(s.ios_url);

  // 今日统计（按中国时区 CST UTC+8 算今日 0:00，与前端列表展示日期一致）
  // 三个指标合并成一条查询，比原来 3 次串行往返快得多
  const todayISO = getCSTTodayStartISO();
  data.today_submits = 0;
  data.today_visits = 0;
  data.today_ips = 0;
  try {
    const [submits, visits] = await db.batch([
      db.prepare("SELECT COUNT(*) as c FROM submit_logs WHERE created_at > ? AND action = 'submit'").bind(todayISO),
      db.prepare('SELECT COUNT(*) as c, COUNT(DISTINCT ip) as ips FROM visits WHERE created_at > ?').bind(todayISO),
    ]);
    const sRow = submits.results && submits.results[0];
    const vRow = visits.results && visits.results[0];
    if (sRow) data.today_submits = sRow.c || 0;
    if (vRow) {
      data.today_visits = vRow.c || 0;
      data.today_ips = vRow.ips || 0;
    }
  } catch {
    // 统计失败不影响主配置返回
  }

  return json({ success: true, data });
}

/** POST /api/visit — 记录访问（visits 表在 schema.sql 中创建）
 *  加限流：这是完全公开的写接口，不限流可被脚本每秒上千次刷爆 D1 写配额与统计数字。
 *  计数直接查 visits 表（不再额外写一条 submit_logs，省一半写入）。 */
async function handleVisit(db, ip) {
  try {
    if (ip && ip !== '0.0.0.0') {
      const since = new Date(Date.now() - 60_000).toISOString();
      const hit = await db
        .prepare('SELECT COUNT(*) as count FROM visits WHERE ip = ? AND created_at > ?')
        .bind(ip, since)
        .first();
      if (hit && hit.count >= CONFIG.VISIT_RATE_LIMIT) {
        return json({ success: true }); // 静默丢弃，不暴露限流细节
      }
    }
    await db.prepare("INSERT INTO visits (ip, created_at) VALUES (?, ?)").bind(ip, now()).run();
  } catch (e) {
    // 忽略插入错误，不阻塞用户
  }
  return json({ success: true });
}

// ============================================================
//  API 路由处理
// ============================================================

/** GET /api/codes — 获取邀请码列表（未使用在前，30秒内已使用灰色排后面，超时即删轮换）
 *  性能要点：原实现每次请求都先跑一条 DELETE。首页每 5 秒轮询一次，
 *  100 个在线用户就是 20 次写/秒，纯粹为了做垃圾回收，很容易吃满 D1 写配额。
 *  改为：① SELECT 里直接按截止时间过滤，展示效果与立即删除完全一致；
 *        ② DELETE 降级为后台清理，只在约 10% 的请求里通过 waitUntil 异步执行。 */
async function handleGetCodes(db, ctx) {
  const ttlCutoff = new Date(Date.now() - CONFIG.CODE_TTL_HOURS * 3600_000).toISOString();
  const delCutoff = new Date(Date.now() - CONFIG.USED_KEEP_MS).toISOString();

  const result = await db
    .prepare(
      "SELECT id, code_masked, status, used_at, created_at, location FROM codes " +
      "WHERE (status = 'active' AND created_at >= ?) " +
      "   OR (status = 'used' AND used_at IS NOT NULL AND used_at >= ?) " +
      "ORDER BY (status = 'used'), created_at DESC LIMIT ?"
    )
    .bind(ttlCutoff, delCutoff, CONFIG.MAX_ACTIVE_CODES)
    .all();

  // 抽样触发后台清理，避免每次轮询都写库
  if (ctx && ctx.waitUntil && Math.random() < 0.1) {
    ctx.waitUntil(
      db.prepare(
        "DELETE FROM codes WHERE (status = 'active' AND created_at < ?) OR (status = 'used' AND used_at IS NOT NULL AND used_at < ?)"
      ).bind(ttlCutoff, delCutoff).run().catch(() => {})
    );
  }

  return json({ success: true, data: result.results });
}

/** POST /api/submit — 提交邀请码 */
async function handleSubmit(db, request, ip, ctx) {
  const body = await readJsonBody(request);
  if (!body) return json({ success: false, error: '请求格式错误' }, 400);

  // 蜜罐检查：如果隐藏字段被填写，说明是机器人
  const honeypot = body.website || body.url_field || '';
  if (honeypot) {
    await logAction(db, ip, body.code || '', 'blocked', 'honeypot');
    // 返回假成功，不暴露检测逻辑
    return json({ success: true, message: '提交成功' });
  }

  // 校验邀请码
  const validation = validateCode(body.code);
  if (!validation.valid) {
    return json({ success: false, error: validation.reason }, 400);
  }
  const code = validation.code;

  // 黑名单已在 handleAPI 入口统一拦截（BLACKLIST_GUARDED），此处不再重复查一次

  // 读取后台可配置的提交限流参数（一次批量读，读取失败则用 CONFIG 默认值）
  const limitCfg = await getSettings(db, ['rate_limit_max', 'daily_limit']);
  let rateLimitMax = parseInt(limitCfg.rate_limit_max, 10);
  if (isNaN(rateLimitMax) || rateLimitMax < 1) rateLimitMax = CONFIG.RATE_LIMIT_MAX;
  let dailyLimit = parseInt(limitCfg.daily_limit, 10);
  if (isNaN(dailyLimit) || dailyLimit < 1) dailyLimit = CONFIG.DAILY_LIMIT;

  // 速率限制
  const rateLimited = await checkRateLimit(db, ip, rateLimitMax);
  if (rateLimited) {
    await logAction(db, ip, code, 'blocked', 'rate_limit');
    return json({ success: false, error: '提交过于频繁，请稍后再试' }, 429);
  }

  // 每日限额
  const dailyLimited = await checkDailyLimit(db, ip, dailyLimit);
  if (dailyLimited) {
    await logAction(db, ip, code, 'blocked', 'daily_limit');
    return json({ success: false, error: '今日提交次数已达上限' }, 429);
  }

  // 归属地：先用 request.cf 同步取（Cloudflare 自带，零耗时），让提交秒回；
  // 中文高精度归属地由 waitUntil 后台异步补全（原来同步等百度API，慢时卡提交最多10秒）
  const location = getIPLocationSync(request);

  // 检查重复提交：如果该码已存在（活跃或30秒窗口内使用中），重新排队点亮
  const existing = await db
    .prepare("SELECT id FROM codes WHERE code = ? AND status IN ('active','used')")
    .bind(code)
    .first();

  if (existing) {
    // 重新排队：更新时间和归属地
    await db
      .prepare("UPDATE codes SET created_at = ?, status = 'active', used_at = NULL, location = ? WHERE id = ?")
      .bind(now(), location, existing.id)
      .run();
    await logAction(db, ip, code, 'submit', 'reactivate');
    fillLocationAsync(db, ctx, ip, code);
    return json({ success: true, message: '已重新排队' });
  }

  // 插入新码（含归属地）
  await db
    .prepare('INSERT INTO codes (code, code_masked, ip, status, created_at, location) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(code, maskCode(code), ip, 'active', now(), location)
    .run();

  await logAction(db, ip, code, 'submit', 'ok');
  fillLocationAsync(db, ctx, ip, code);
  return json({ success: true, message: '提交成功' });
}

/** 后台异步补全中文归属地：不阻塞提交响应；用 Cloudflare Cache API 缓存（跨 isolate、10分钟 TTL），
 *  避免重复查外部 API（实例级 Map 在 Workers 中几乎无效且无上限） */
function fillLocationAsync(db, ctx, ip, code) {
  if (!ctx || !ctx.waitUntil) return;
  ctx.waitUntil((async () => {
    try {
      const cacheKey = 'https://iploc-cache.local/' + ip;
      let loc = '';
      const hit = await caches.default.match(cacheKey);
      if (hit) {
        loc = await hit.text();
      } else {
        loc = await fetchIPLocation(ip);
        if (loc) {
          await caches.default.put(cacheKey, new Response(loc, {
            headers: { 'Cache-Control': 'public, max-age=600' },
          }));
        }
      }
      if (loc) {
        await db
          .prepare('UPDATE codes SET location = ? WHERE code = ? AND ip = ?')
          .bind(loc, code, ip)
          .run();
      }
    } catch {}
  })());
}

/** POST /api/use/:id — 标记邀请码为已使用，返回完整码供直接跳转 PDD
 *  原实现「先 SELECT 判 active，再 UPDATE」存在竞态：并发两个请求都能读到 active，
 *  于是同一个码被返回给两个人（对福袋助力来说第二个人必定失败）。
 *  这里改成先做带 status='active' 条件的原子 UPDATE，用 meta.changes 判断是否抢到。 */
async function handleUseCode(db, id, ip) {
  // 限流：防恶意脚本遍历 id 瞬间清空列表
  if (await checkActionRateLimit(db, ip, 'use', CONFIG.USE_RATE_LIMIT)) {
    return json({ success: false, error: '操作过于频繁，请稍后再试' }, 429);
  }

  const upd = await db
    .prepare("UPDATE codes SET status = 'used', used_at = ? WHERE id = ? AND status = 'active'")
    .bind(now(), id)
    .run();

  if (!upd.meta || upd.meta.changes === 0) {
    // 没抢到：要么码不存在，要么已被别人用掉
    const exists = await db.prepare('SELECT id FROM codes WHERE id = ?').bind(id).first();
    return exists
      ? json({ success: false, error: '该码已被使用' }, 409)
      : json({ success: false, error: '该码不存在' }, 404);
  }

  const row = await db.prepare('SELECT code FROM codes WHERE id = ?').bind(id).first();
  await logAction(db, ip, '', 'use', `code_id:${id}`);
  return json({ success: true, code: row ? row.code : '', message: '已标记为已使用' });
}

/** POST /api/quick-use — 智能直达：取最新未使用码，标记使用并返回完整码（含 id，供前端本地标记"刚使用"）
 *  同样用原子 UPDATE + 重试规避并发抢同一个码。 */
async function handleQuickUse(db, ip) {
  // 限流：与 use 共用同一计数（动作都是 use）
  if (await checkActionRateLimit(db, ip, 'use', CONFIG.USE_RATE_LIMIT)) {
    return json({ success: false, error: '操作过于频繁，请稍后再试' }, 429);
  }

  // 智能直达开关
  const smartRaw = await getSetting(db, 'smart_enabled');
  if (smartRaw === 'off') {
    return json({ success: false, error: '智能直达已关闭' }, 403);
  }

  // 最多重试 3 次：每次取当前最新的 active 码并原子抢占，被别人抢走就换下一个
  for (let attempt = 0; attempt < 3; attempt++) {
    const row = await db
      .prepare("SELECT id, code FROM codes WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
      .first();
    if (!row) break;

    const upd = await db
      .prepare("UPDATE codes SET status = 'used', used_at = ? WHERE id = ? AND status = 'active'")
      .bind(now(), row.id)
      .run();

    if (upd.meta && upd.meta.changes > 0) {
      await logAction(db, ip, row.code, 'use', `quick_use code_id:${row.id}`);
      return json({ success: true, code: row.code, id: row.id, message: '智能直达成功' });
    }
  }

  return json({ success: false, error: '暂无可用互助码' }, 404);
}

/** POST /api/report/:id — 举报假码
 *  自动拉黑条件（三重加固，防被当武器用来拉黑正常用户）：
 *   1) 只统计 24 小时内的举报（原来统计全表，历史举报会永久累积）
 *   2) 需要 >= 3 个不同举报人 IP（原来 2 个，两台设备即可拉黑任意人）
 *   3) 举报人 10 分钟内只能举报一次，且计票用 COUNT(DISTINCT ip) 去重
 *   4) 提交者 IP 取不到（0.0.0.0）时不拉黑，否则会封掉所有取不到 IP 的用户
 */
async function handleReportCode(db, id, ip) {
  // 查询被举报的码及其提交者IP
  const row = await db.prepare('SELECT code, code_masked, ip, location FROM codes WHERE id = ?').bind(id).first();
  if (!row) return json({ success: false, error: '该码不存在' }, 404);

  // 不允许举报自己提交的码（自举报可用于洗白或制造噪音）
  if (row.ip && row.ip === ip) {
    return json({ success: false, error: '不能举报自己提交的互助码' }, 400);
  }

  // 防刷：同一举报人IP 10分钟内只能举报一次
  const since = new Date(Date.now() - 10 * 60_000).toISOString();
  const dup = await db
    .prepare('SELECT id FROM reports WHERE ip = ? AND created_at > ?')
    .bind(ip, since)
    .first();
  if (dup) return json({ success: false, error: '举报过于频繁，请稍后再试' }, 429);

  // 插入举报记录（含提交者IP）
  await db
    .prepare('INSERT INTO reports (code, ip, submitter_ip, status, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(row.code_masked, ip, row.ip, 'pending', now())
    .run();

  // 24 小时窗口内，该提交者IP被多少个不同IP举报
  const banWindow = new Date(Date.now() - CONFIG.REPORT_AUTO_BAN_WINDOW_MS).toISOString();
  const reportStats = await db
    .prepare('SELECT COUNT(DISTINCT ip) as cnt FROM reports WHERE submitter_ip = ? AND created_at > ?')
    .bind(row.ip, banWindow)
    .first();

  if (reportStats && reportStats.cnt >= CONFIG.REPORT_AUTO_BAN_THRESHOLD) {
    // 提交者 IP 缺失（非 CF 环境的 0.0.0.0 或历史空值）时绝不能拉黑：
    // 那会把 blacklist 里塞进一条命中所有"取不到 IP"用户的规则，等于全站封禁。
    if (!row.ip || row.ip === '0.0.0.0') {
      return json({ success: true, message: '举报已提交，管理员会尽快核实' });
    }
    // 自动拉黑提交者IP（默认24小时）
    const reason = '被多人举报假码（自动拉黑）';
    const location = row.location || '';
    const expiresAt = calcExpiresAt('24h');
    await db
      .prepare('INSERT INTO blacklist (ip, reason, location, duration, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, location = excluded.location, duration = excluded.duration, expires_at = excluded.expires_at, created_at = excluded.created_at')
      .bind(row.ip, reason, location, '24h', expiresAt, now())
      .run();

    // 自动通过所有针对该提交者IP的待处理举报
    await db
      .prepare("UPDATE reports SET status = 'handled' WHERE submitter_ip = ? AND status = 'pending'")
      .bind(row.ip)
      .run();

    return json({ success: true, message: '举报已提交，该提交者已被多人举报，系统已自动拉黑其IP（24小时）' });
  }

  return json({ success: true, message: '举报已提交，管理员会尽快核实' });
}

/** GET /api/blacklist — 小黑屋公示（公开、IP脱敏）
 *  过滤掉已过期的记录：过期即自动解禁（checkBlacklist 会放行），
 *  但公示页原来照旧展示，会让已解封的用户看到自己还"在小黑屋里"。 */
async function handlePublicBlacklist(db) {
  const result = await db
    .prepare('SELECT ip, reason, location, duration, expires_at, created_at FROM blacklist WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC LIMIT 50')
    .bind(now())
    .all();

  const masked = (result.results || []).map((row) => ({
    ip: maskIP(row.ip),
    location: row.location || '',
    reason: row.reason || '',
    remaining: formatRemaining(row.expires_at),
    created_at: row.created_at,
  }));

  return json({ success: true, data: masked });
}

/** IP 脱敏：兼容 IPv4 和 IPv6
 *  IPv4: 1.2.3.4 -> 1.2.3.***
 *  IPv6: 2001:db8:85a3::8a2e:370:7334 -> 2001:db8:85a3:****
 *  IPv4-mapped IPv6: ::ffff:1.2.3.4 -> 1.2.3.***
 */
function maskIP(ip) {
  if (!ip) return '***';
  // 检测 IPv4-mapped IPv6 (::ffff:1.2.3.4)
  const v4mapped = ip.match(/:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4mapped) {
    const parts = v4mapped[1].split('.');
    if (parts.length === 4) return parts[0] + '.' + parts[1] + '.' + parts[2] + '.***';
  }
  // IPv6
  if (ip.includes(':')) {
    const parts = ip.split(':');
    // 至少保留前3组，其余掩码
    const keep = Math.min(3, parts.length);
    return parts.slice(0, keep).join(':') + ':****';
  }
  // IPv4
  const parts = ip.split('.');
  if (parts.length === 4) {
    return parts[0] + '.' + parts[1] + '.' + parts[2] + '.***';
  }
  return '***';
}

/** 根据封禁期限计算过期时间 */
function calcExpiresAt(duration) {
  if (!duration || duration === 'permanent') return null;
  const now = Date.now();
  const ms = {
    '24h': 24 * 60 * 60 * 1000,
    '1m': 30 * 24 * 60 * 60 * 1000,
    '1y': 365 * 24 * 60 * 60 * 1000
  }[duration] || 24 * 60 * 60 * 1000;
  return new Date(now + ms).toISOString();
}

/** 格式化剩余时间 */
function formatRemaining(expiresAt) {
  if (!expiresAt) return '永久';
  const diff = new Date(expiresAt).getTime() - Date.now();
  if (diff <= 0) return '已过期';
  const hours = Math.floor(diff / (3600 * 1000));
  if (hours < 24) return hours + '小时后';
  const days = Math.floor(hours / 24);
  if (days < 30) return days + '天后';
  const months = Math.floor(days / 30);
  if (months < 12) return months + '个月后';
  return Math.floor(months / 12) + '年后';
}

/** ISP 英文名→中文翻译（常见中国运营商） */
function translateISP(isp) {
  if (!isp) return '';
  const s = isp.toLowerCase();
  if (s.includes('china mobile') || s.includes('cmnet') || s.includes('9808')) return '移动';
  if (s.includes('china unicom') || s.includes('unicom') || s.includes('4837')) return '联通';
  if (s.includes('china telecom') || s.includes('chinatelecom') || s.includes('4134')) return '电信';
  if (s.includes('tietong')) return '铁通';
  if (s.includes('china education') || s.includes('cernet')) return '教育网';
  if (s.includes('baidu')) return '百度';
  if (s.includes('alibaba') || s.includes('aliyun')) return '阿里云';
  if (s.includes('tencent')) return '腾讯云';
  if (s.includes('huawei')) return '华为云';
  // 含中文直接返回
  if (/[\u4e00-\u9fa5]/.test(isp)) return isp;
  return '';
}

/** 通过外部开放数据获取IP归属地（中文，全 HTTPS）
 *  返回格式示例："江苏省南京市 电信"、"美国"
 *  注意：ip 必须 encodeURIComponent 后再拼 URL —— 后台手动拉黑时 ip 来自管理员输入，
 *  未编码的特殊字符可篡改 query 结构。 */
async function fetchIPLocation(ip) {
  if (!ip || ip === '0.0.0.0') return '';
  const q = encodeURIComponent(ip);

  // 方案1：百度开放数据 API（HTTPS，中文）
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch('https://opendata.baidu.com/api.php?query=' + q + '&co=&resource_id=6006&oe=utf8', { signal: controller.signal });
    clearTimeout(timeout);
    if (res.ok) {
      const data = await res.json();
      if (data && data.data && data.data[0] && data.data[0].location) {
        return data.data[0].location.trim();
      }
    }
  } catch {}

  // 方案2：ipwho.is（HTTPS 免费，中文地名 + ISP）
  // 原来用的 http://ip-api.com 免费版只支持明文 HTTP，会在 Workers 与第三方之间裸奔传输用户 IP。
  try {
    const controller2 = new AbortController();
    const timeout2 = setTimeout(() => controller2.abort(), 5000);
    const res2 = await fetch('https://ipwho.is/' + q + '?lang=zh-CN&fields=success,country,region,city,connection', { signal: controller2.signal });
    clearTimeout(timeout2);
    if (res2.ok) {
      const d = await res2.json();
      if (d && d.success !== false) {
        const parts = [];
        if (d.country && d.country !== '中国') parts.push(d.country);
        if (d.region) parts.push(d.region);
        if (d.city && d.city !== d.region) parts.push(d.city);
        const ispCn = translateISP((d.connection && (d.connection.isp || d.connection.org)) || '');
        if (ispCn) parts.push(ispCn);
        const loc = parts.join(' ').trim();
        if (loc) return loc;
      }
    }
  } catch {}

  return '';
}

/** 获取IP归属地（中文优先：百度 API 异步，request.cf 同步兜底）
 *  提交接口用同步版（不阻塞响应），后台手动拉黑用异步版
 */
function getIPLocationSync(request) {
  try {
    const cf = request.cf;
    if (!cf) return '';
    const parts = [];
    if (cf.city) parts.push(cf.city);
    else if (cf.region) parts.push(cf.region);
    // ISP 英文→中文翻译
    const ispCn = translateISP(cf.asOrganization || '');
    if (ispCn) parts.push(ispCn);
    else if (cf.asOrganization) parts.push(cf.asOrganization);
    return parts.join(' ').trim();
  } catch {
    return '';
  }
}

// ============================================================
//  管理后台 API
// ============================================================

/** 验证管理员密钥
 *  只接受 X-Admin-Key 请求头（禁止 ?key= 查询参数，避免密钥进访问日志/Referer/浏览器历史）。
 *  先各自 SHA-256 再逐字节比较：摘要长度恒为 32 字节，既不泄露真实密钥长度
 *  （原实现 `length !== length` 提前返回会把长度暴露给攻击者），也保持恒时比较。 */
async function verifyAdmin(request, env) {
  const adminKey = request.headers.get('X-Admin-Key');
  if (!adminKey || !env.ADMIN_KEY) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(adminKey)),
    crypto.subtle.digest('SHA-256', enc.encode(env.ADMIN_KEY)),
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/** 解析并收敛分页参数
 *  原实现直接 parseInt 用户输入且无上限：pageSize=999999 可一次拖走整表，
 *  page=0 / 负数会让 OFFSET 变负数导致 SQL 报错。
 *  page 另需收敛上限：Number.isFinite(1e20) 为 true，但 (1e20-1)*50 已超出安全整数范围，
 *  bind 进 D1 会抛异常冒泡成 500。 */
function parsePaging(request) {
  const url = new URL(request.url);
  let page = parseInt(url.searchParams.get('page') || '1', 10);
  let pageSize = parseInt(url.searchParams.get('pageSize') || '50', 10);
  if (!Number.isSafeInteger(page) || page < 1) page = 1;
  if (page > CONFIG.PAGE_MAX) page = CONFIG.PAGE_MAX;
  if (!Number.isSafeInteger(pageSize) || pageSize < 1) pageSize = 50;
  if (pageSize > CONFIG.PAGE_SIZE_MAX) pageSize = CONFIG.PAGE_SIZE_MAX;
  return { page, pageSize, offset: (page - 1) * pageSize };
}

/** IPv4 / IPv6 格式校验：手动拉黑接口原来接受任意字符串，
 *  会往 blacklist 塞进永不命中的垃圾数据（cf-connecting-ip 永远不会等于它）。 */
function isValidIP(ip) {
  if (!ip || ip.length > 45) return false;
  // IPv4：每段 0-255，且不允许 01 这类前导零写法（与 cf-connecting-ip 的规范格式不一致会永不命中）
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    return ip.split('.').every((p) => {
      const n = Number(p);
      return n >= 0 && n <= 255 && String(n) === p;
    });
  }
  // IPv6（含压缩写法与 IPv4-mapped）
  return ip.includes(':') && /^[0-9a-fA-F:]+(\.\d{1,3}){0,3}$/.test(ip);
}

/** GET /api/admin/blacklist — 获取黑名单列表
 *  remaining 由服务端算：原来后台前端另写了一份 formatRemainingAdmin，
 *  与 formatRemaining 逻辑完全重复（改一处忘另一处就会两边显示不一致）。 */
async function handleAdminGetBlacklist(db) {
  const result = await db.prepare('SELECT id, ip, reason, location, duration, expires_at, created_at FROM blacklist ORDER BY created_at DESC').all();
  const data = (result.results || []).map((row) => ({
    ...row,
    remaining: formatRemaining(row.expires_at),
  }));
  return json({ success: true, data });
}

/** POST /api/admin/blacklist — 添加IP到黑名单 */
async function handleAdminAddBlacklist(db, request) {
  const body = await readJsonBody(request);
  if (!body) return json({ success: false, error: '请求格式错误' }, 400);
  const ip = String(body.ip || '').trim();
  const reason = String(body.reason || '').trim().slice(0, 200) || '手动拉黑';
  let location = String(body.location || '').trim().slice(0, 100);
  const rawDuration = String(body.duration || '').trim();
  // 期限白名单：任意字符串会被 calcExpiresAt 兜成 24h，但 duration 字段会存进脏值并展示到公示页
  const duration = ['24h', '1m', '1y', 'permanent'].includes(rawDuration) ? rawDuration : '24h';

  if (!ip) return json({ success: false, error: 'IP不能为空' }, 400);
  if (!isValidIP(ip)) return json({ success: false, error: 'IP 格式不合法' }, 400);

  // 归属地未填写时自动获取
  if (!location) {
    location = await fetchIPLocation(ip);
  }

  const expiresAt = calcExpiresAt(duration);

  await db
    .prepare('INSERT INTO blacklist (ip, reason, location, duration, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, location = excluded.location, duration = excluded.duration, expires_at = excluded.expires_at, created_at = excluded.created_at')
    .bind(ip, reason, location, duration, expiresAt, now())
    .run();

  return json({ success: true, message: `已拉黑 ${ip}（${duration === 'permanent' ? '永久' : duration}）`, location });
}

/** DELETE /api/admin/blacklist — 从黑名单移除IP */
async function handleAdminRemoveBlacklist(db, request) {
  const url = new URL(request.url);
  const ip = (url.searchParams.get('ip') || '').slice(0, 45);
  if (!ip) return json({ success: false, error: 'IP不能为空' }, 400);

  const res = await db.prepare('DELETE FROM blacklist WHERE ip = ?').bind(ip).run();
  if (!res.meta || res.meta.changes === 0) {
    return json({ success: false, error: `未找到 ${ip}` }, 404);
  }
  return json({ success: true, message: `已移除 ${ip}` });
}

/** 分页列表通用查询：数据页 + 总数一次 batch 取回
 *  三个后台列表接口（logs / codes / reports）原本各自复制了一份
 *  「SELECT ... LIMIT ? OFFSET ?」+「SELECT COUNT(*)」的串行两次往返。
 *  注意：columns / table 只允许传本文件内的字面量常量（SQL 标识符无法参数化），
 *  绝不可把请求参数透传进来，否则就是 SQL 注入入口。 */
async function paginatedList(db, request, columns, table) {
  const { page, pageSize, offset } = parsePaging(request);
  const [rows, cnt] = await db.batch([
    db.prepare(`SELECT ${columns} FROM ${table} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(pageSize, offset),
    db.prepare(`SELECT COUNT(*) as total FROM ${table}`),
  ]);
  const totalRow = cnt.results && cnt.results[0];
  return json({
    success: true,
    data: rows.results || [],
    pagination: { page, pageSize, total: (totalRow && totalRow.total) || 0 },
  });
}

/** GET /api/admin/logs — 查看提交日志 */
function handleAdminGetLogs(db, request) {
  return paginatedList(db, request, 'ip, code, action, reason, created_at', 'submit_logs');
}

/** GET /api/admin/stats — 统计数据（6 项指标一次 batch 取回，原来是 6 次串行 D1 往返） */
async function handleAdminGetStats(db) {
  // 基于北京时间（CST）今日 0:00，避免 Workers UTC 时区导致今日边界错位
  const todayStartISO = getCSTTodayStartISO();
  const rows = await db.batch([
    db.prepare("SELECT COUNT(*) as c FROM codes WHERE status = 'active'"),
    // 已使用：统计 submit_logs 中 action='use' 的累计条数（每次点击"跳转/已使用"都会落日志，
    // 不会被 30 秒清理删除），比 codes WHERE status='used' 实时数准确
    db.prepare("SELECT COUNT(*) as c FROM submit_logs WHERE action = 'use'"),
    db.prepare('SELECT COUNT(*) as c FROM blacklist'),
    db.prepare("SELECT COUNT(*) as c FROM submit_logs WHERE created_at > ? AND action = 'submit'").bind(todayStartISO),
    db.prepare("SELECT COUNT(*) as c FROM submit_logs WHERE created_at > ? AND action = 'blocked'").bind(todayStartISO),
    db.prepare("SELECT COUNT(*) as c FROM reports WHERE status = 'pending'"),
  ]);
  const n = (i) => {
    const r = rows[i] && rows[i].results && rows[i].results[0];
    return r ? (r.c || 0) : 0;
  };

  return json({
    success: true,
    data: {
      activeCodes: n(0),
      usedCodes: n(1),
      blacklistCount: n(2),
      todaySubmits: n(3),
      todayBlocked: n(4),
      pendingReports: n(5),
    },
  });
}

/** GET /api/admin/codes — 管理员查看所有码（含完整码） */
function handleAdminGetAllCodes(db, request) {
  return paginatedList(db, request, 'id, code, code_masked, ip, status, created_at, used_at, location', 'codes');
}

/** DELETE /api/admin/codes/:id — 删除指定码 */
async function handleAdminDeleteCode(db, id) {
  const res = await db.prepare('DELETE FROM codes WHERE id = ?').bind(id).run();
  if (!res.meta || res.meta.changes === 0) {
    return json({ success: false, error: '该码不存在' }, 404);
  }
  return json({ success: true, message: '已删除' });
}

/** GET /api/admin/settings — 读取站点设置 */
async function handleAdminGetSettings(db) {
  const s = await getSettings(db, ['notice', 'ads', 'ad_title', 'ad_sub', 'qq_group', 'qq_owner', 'smart_enabled', 'refresh_interval', 'rate_limit_max', 'daily_limit', 'ocr_mode', 'ios_url']);
  const notice = s.notice || '';
  const adsRaw = s.ads || '[]';
  const adTitle = s.ad_title || '';
  const adSub = s.ad_sub || '';
  // iOS 地址对后台回填要做区分：从未配置过 → 把服务端默认值显示出来（让管理员看到当前生效的是哪个）；
  // 显式保存为空 → 老老实实显示空，代表「已主动关闭」。这里不能直接用 resolveIosUrl，
  // 否则两者都变成同一个值，管理员无法分辨。
  const iosUrl = (s.ios_url === undefined || s.ios_url === null) ? CONFIG.IOS_SHORTCUT_URL : s.ios_url;
  const qqGroup = s.qq_group || '';
  const qqOwner = s.qq_owner || '';
  const smartRaw = s.smart_enabled || 'on';
  const refreshInterval = s.refresh_interval || '5';
  const rateLimitMax = s.rate_limit_max || String(CONFIG.RATE_LIMIT_MAX);
  const dailyLimit = s.daily_limit || String(CONFIG.DAILY_LIMIT);
  const ocrMode = (s.ocr_mode === 'ai') ? 'ai' : 'local';
  let ads = [];
  try {
    ads = JSON.parse(adsRaw);
    if (!Array.isArray(ads)) ads = [];
  } catch {
    ads = [];
  }
  return json({ success: true, data: { notice, ads, ad_title: adTitle, ad_sub: adSub, qq_group: qqGroup, qq_owner: qqOwner, smart_enabled: smartRaw !== 'off', refresh_interval: refreshInterval, rate_limit_max: rateLimitMax, daily_limit: dailyLimit, ocr_mode: ocrMode, ios_url: iosUrl } });
}

/** POST /api/admin/settings — 保存站点设置
 *  原来每个字段各 await 一次 setSetting，一次保存最多 9 个串行写；改为收集后一次 batch 提交。
 *  同时给所有文本字段加长度上限（公告原本无限长，可撑爆首页与 /api/config 响应体）。 */
async function handleAdminSaveSettings(db, request) {
  const body = await readJsonBody(request);
  if (!body) return json({ success: false, error: '请求格式错误' }, 400);

  const pending = {};

  // 公告：文本，去首尾空格（可为空），限 500 字
  if (typeof body.notice === 'string') {
    pending.notice = body.notice.trim().slice(0, 500);
  }

  // 广告：数组，每项 { image_url, link_url }；URL 过协议白名单防 XSS，最多 10 条
  if (Array.isArray(body.ads)) {
    const cleanAds = body.ads
      .slice(0, 10)
      .filter((ad) => ad && typeof ad.image_url === 'string' && sanitizeUrl(ad.image_url))
      .map((ad) => ({
        image_url: sanitizeUrl(ad.image_url).slice(0, 500),
        link_url: sanitizeUrl(ad.link_url).slice(0, 500),
      }));
    pending.ads = JSON.stringify(cleanAds);
  }

  // 弹窗广告文案：留空则首页弹窗不显示标题栏
  if (typeof body.ad_title === 'string') pending.ad_title = body.ad_title.trim().slice(0, 60);
  if (typeof body.ad_sub === 'string') pending.ad_sub = body.ad_sub.trim().slice(0, 120);

  // iOS 快捷指令地址：留空 = 首页隐藏该按钮；非空必须过协议白名单（防 javascript: 伪协议）
  // 这里选择「报错」而不是像广告 URL 那样静默清空：管理员少写协议头（如 icloud.com/...）时，
  // 静默清空会让按钮凭空消失且不留任何痕迹，报错能当场说清原因。
  if (typeof body.ios_url === 'string') {
    const raw = body.ios_url.trim().slice(0, 500);
    if (!raw) {
      pending.ios_url = '';
    } else if (!sanitizeUrl(raw)) {
      return json({ success: false, error: 'iOS 快捷指令地址必须以 http:// 或 https:// 开头' }, 400);
    } else {
      pending.ios_url = sanitizeUrl(raw);
    }
  }

  // 联系方式
  if (typeof body.qq_group === 'string') pending.qq_group = body.qq_group.trim().slice(0, 50);
  if (typeof body.qq_owner === 'string') pending.qq_owner = body.qq_owner.trim().slice(0, 50);

  // 智能直达开关 on/off
  if (body.smart_enabled === 'on' || body.smart_enabled === 'off') {
    pending.smart_enabled = body.smart_enabled;
  }

  // 数值型设置：字段名 -> [最小值, 最大值]
  const numericRanges = {
    refresh_interval: [3, 30],    // 首页刷新间隔（秒）
    rate_limit_max: [1, 60],      // 单IP每分钟提交上限
    daily_limit: [1, 2000],       // 单IP每日提交上限
  };
  for (const [key, [min, max]] of Object.entries(numericRanges)) {
    const raw = body[key];
    if (typeof raw !== 'string' && typeof raw !== 'number') continue;
    const v = parseInt(String(raw), 10);
    if (!isNaN(v) && v >= min && v <= max) pending[key] = String(v);
  }

  // OCR 模式：ai（仅服务端）/ local（浏览器本地优先）
  if (body.ocr_mode === 'ai' || body.ocr_mode === 'local') {
    pending.ocr_mode = body.ocr_mode;
  }

  const keys = Object.keys(pending);
  if (keys.length === 0) return json({ success: true, message: '无需更新' });

  const ts = now();
  await db.batch(keys.map((k) =>
    db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at')
      .bind(k, pending[k], ts)
  ));

  return json({ success: true, message: '设置已保存' });
}

// ---------- 举报管理 ----------

/** GET /api/admin/reports — 举报列表 */
function handleAdminGetReports(db, request) {
  return paginatedList(db, request, 'id, code, ip, submitter_ip, status, created_at', 'reports');
}

/** POST /api/admin/reports/:id/status — 更新举报状态（handled/dismissed） */
async function handleAdminUpdateReport(db, id, request) {
  const body = await readJsonBody(request);
  if (!body) return json({ success: false, error: '请求格式错误' }, 400);
  const status = body.status;
  if (!['handled', 'dismissed', 'pending'].includes(status)) {
    return json({ success: false, error: '状态不合法' }, 400);
  }
  const res = await db.prepare('UPDATE reports SET status = ? WHERE id = ?').bind(status, id).run();
  if (!res.meta || res.meta.changes === 0) {
    return json({ success: false, error: '该举报不存在' }, 404);
  }
  return json({ success: true, message: '已更新' });
}

/** DELETE /api/admin/reports/:id — 删除举报记录 */
async function handleAdminDeleteReport(db, id) {
  const res = await db.prepare('DELETE FROM reports WHERE id = ?').bind(id).run();
  if (!res.meta || res.meta.changes === 0) {
    return json({ success: false, error: '该举报不存在' }, 404);
  }
  return json({ success: true, message: '已删除' });
}

/** POST /api/ocr — 互助码识别接口（AI 路径）
 *  ocr_mode: local(默认, 由前端浏览器本地识别, 后端返回 fallback) / ai(仅服务端AI识别)
 *  前端默认走浏览器本地识别；用户选择「用AI识别」时带 ?force=ai 调用本接口
 */
const OCR_MODEL = '@cf/meta/llama-3.2-11b-vision-instruct';
const OCR_PROMPT = 'Look at this image carefully. It is from Pinduoduo (拼多多). There is an invitation code shown as a string of 8 or 9 digits (like 12345678 or 123456789). What is the invitation code? Reply with ONLY the digits, no other text.';

async function handleOcr(request, env, ip) {
  try {
    // 支持 ?force=ai 强制走 AI（前端「用 AI 识别」按钮）
    let forceAi = false;
    try { forceAi = new URL(request.url).searchParams.get('force') === 'ai'; } catch (e) {}

    // OCR 模式（ai / local），force=ai 时强制为 ai
    const ocrModeRaw = await getSetting(env.DB, 'ocr_mode');
    let ocrMode = (ocrModeRaw === 'ai') ? 'ai' : 'local';
    if (forceAi) ocrMode = 'ai';

    // local 模式：不消耗 AI 额度也不需要读图，尽早返回让前端走浏览器本地识别。
    // 放在 formData() 之前：否则每个 local 模式请求都要先把整个 body 解析一遍才被拒。
    if (ocrMode === 'local') {
      return json({ success: false, fallback: 'local', error: '请使用浏览器本地识别' });
    }

    // 从 FormData 中读取图片（非 multipart body 会抛异常，明确回 400 而不是走兜底错误）
    let formData;
    try {
      formData = await request.formData();
    } catch {
      return json({ success: false, error: '未收到图片' }, 400);
    }
    const file = formData.get('image');
    if (!file || typeof file.arrayBuffer !== 'function') {
      // 非文件（例如脚本传了普通字符串字段）直接拒绝，避免下面 arrayBuffer 抛异常
      return json({ success: false, error: '未收到图片' }, 400);
    }

    // 服务端图片大小限制（前端限制可被脚本绕过）
    if (file.size && file.size > CONFIG.OCR_MAX_IMG_BYTES) {
      return json({ success: false, error: '图片太大，请选小于 4MB 的截图' }, 413);
    }

    // MIME 白名单：只允许常见图片类型，防把任意二进制塞给 AI 模型
    const mimeType = (file.type || 'image/png').toLowerCase().split(';')[0].trim();
    if (!['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/gif', 'image/bmp'].includes(mimeType)) {
      return json({ success: false, error: '仅支持 PNG / JPG / WebP 等图片格式' }, 415);
    }

    // AI 路径限流：防 AI 额度被盗刷（无鉴权公开接口）
    if (await checkActionRateLimit(env.DB, ip, 'ocr_ai', CONFIG.OCR_AI_RATE_LIMIT)) {
      return json({ success: false, error: 'AI 识别调用过于频繁，请稍后再试或手动输入' }, 429);
    }
    // 调用前记日志作为限流计数（失败也消耗额度，一并计数）
    await logAction(env.DB, ip, '', 'ocr_ai', 'ok');

    // 转为 base64 传给 AI 模型（llama-3.2 vision 支持 messages 格式的 image_url）
    const imageBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(imageBuffer);
    // 分块转 base64，避免 String.fromCharCode(...arr) 超出调用栈上限
    let binStr = '';
    const CHUNK = 8192;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binStr += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    const base64 = btoa(binStr);

    // 调用 Cloudflare Workers AI 视觉模型（llama-3.2-11b-vision-instruct）
    // payload 抽出来复用，避免 agree-license 重试时复制粘贴一整份（两份 prompt 容易改漏）
    const aiPayload = {
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: OCR_PROMPT },
            { type: 'image_url', image_url: { url: 'data:' + mimeType + ';base64,' + base64 } },
          ],
        },
      ],
      max_tokens: 20,
      temperature: 0.1,
    };

    let aiResponse;
    try {
      aiResponse = await env.AI.run(OCR_MODEL, aiPayload);
    } catch (e) {
      const errStr = String((e && e.message) || e);
      // 如果需要 agree Meta License，先 agree 再重试
      if (/agree|license|3016|5016/.test(errStr)) {
        try { await env.AI.run(OCR_MODEL, { prompt: 'agree' }); } catch (e2) {}
        aiResponse = await env.AI.run(OCR_MODEL, aiPayload);
      } else {
        throw e;
      }
    }

    // 安全获取 AI 返回文本（不同格式兼容；response 可能是数字类型）
    let rawText = '';
    if (aiResponse) {
      if (typeof aiResponse.response === 'string') {
        rawText = aiResponse.response.trim();
      } else if (typeof aiResponse.response === 'number') {
        rawText = String(aiResponse.response);
      } else if (aiResponse.message && typeof aiResponse.message.content === 'string') {
        rawText = aiResponse.message.content.trim();
      } else if (typeof aiResponse === 'string') {
        rawText = aiResponse.trim();
      }
    }

    // 清理 markdown 符号和空白，只留数字
    const cleaned = rawText.replace(/[^0-9]/g, ' ');

    // 优先提取连续的 8 或 9 位数字（识别逻辑：连续八位或九位数）
    const matches = cleaned.match(/\d{8,9}/g) || [];
    if (matches.length > 0) {
      return json({ success: true, code: matches[0], rawText: rawText.slice(0, 100) });
    }

    // 兜底：无 8/9 位数字时，取最长的数字串（6~12 位才认为可信）
    const allNums = cleaned.match(/\d+/g) || [];
    if (allNums.length > 0) {
      const longest = allNums.sort((a, b) => b.length - a.length)[0];
      if (longest.length >= 6 && longest.length <= 12) {
        return json({ success: true, code: longest, rawText: rawText.slice(0, 100) });
      }
    }

    return json({
      success: false,
      error: '未识别到互助码，请手动输入或换清晰截图',
    });
  } catch(e) {
    console.error('handleOcr error:', e);
    // ai 模式（含 force=ai）：额度受限或出错都友好提示手动输入；
    // local 模式在上面已提前返回，走不到这里，故不再保留 auto 分支（该模式已废弃）。
    return json({ success: false, error: '抱歉，识别出错，请手动输入互助码' });
  }
}

// ============================================================
//  路由分发
// ============================================================

async function handleAPI(request, env, path, ctx) {
  const method = request.method;
  const ip = getClientIP(request);

  // OPTIONS 预检
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204 });
  }

  // ---- 全局黑名单拦截 ----
  // 原来只有 /api/submit 查黑名单，被拉黑的 IP 依然能领码（清空列表）、举报（武器化自动拉黑）、
  // 刷 AI 识图额度。这里统一在入口拦所有公开写接口。
  if (BLACKLIST_GUARDED.some((r) => r.method === method && r.test(path))) {
    const blocked = await checkBlacklist(env.DB, ip);
    if (blocked) {
      await logAction(env.DB, ip, '', 'blocked', `blacklist@${path}: ${blocked.reason || ''}`);
      return json({ success: false, error: '您的IP已被拉黑，如需申诉请联系管理员' }, 403);
    }
  }

  // ---- 公开接口 ----
  if (path === '/api/codes' && method === 'GET') {
    return handleGetCodes(env.DB, ctx);
  }

  if (path === '/api/config' && method === 'GET') {
    return handleGetConfig(env.DB);
  }

  if (path === '/api/visit' && method === 'POST') {
    return handleVisit(env.DB, ip);
  }

  if (path === '/api/submit' && method === 'POST') {
    return handleSubmit(env.DB, request, ip, ctx);
  }

  // 识别截图 · AI 兜底（Cloudflare Workers AI 视觉模型）
  if (path === '/api/ocr' && method === 'POST') {
    return handleOcr(request, env, ip);
  }

  // 智能直达
  if (path === '/api/quick-use' && method === 'POST') {
    return handleQuickUse(env.DB, ip);
  }

  // 小黑屋公示（公开）
  if (path === '/api/blacklist' && method === 'GET') {
    return handlePublicBlacklist(env.DB);
  }

  // 举报假码：/api/report/123
  const reportMatch = path.match(/^\/api\/report\/(\d+)$/);
  if (reportMatch && method === 'POST') {
    const rid = parseId(reportMatch[1]);
    if (rid === null) return json({ success: false, error: '该码不存在' }, 404);
    return handleReportCode(env.DB, rid, ip);
  }

  // 标记使用：/api/use/123
  const useMatch = path.match(/^\/api\/use\/(\d+)$/);
  if (useMatch && method === 'POST') {
    const uid = parseId(useMatch[1]);
    if (uid === null) return json({ success: false, error: '该码不存在' }, 404);
    return handleUseCode(env.DB, uid, ip);
  }

  // ---- 管理后台接口 ----
  if (path.startsWith('/api/admin/')) {
    if (!(await verifyAdmin(request, env))) {
      // 鉴权失败落日志 + 限流：ADMIN_KEY 是唯一凭据，不限流就能被脚本无限枚举
      if (await checkActionRateLimit(env.DB, ip, 'admin_fail', CONFIG.ADMIN_FAIL_LIMIT)) {
        return json({ success: false, error: '尝试过于频繁，请稍后再试' }, 429);
      }
      await logAction(env.DB, ip, '', 'admin_fail', path);
      return json({ success: false, error: '未授权' }, 401);
    }

    if (path === '/api/admin/blacklist' && method === 'GET') {
      return handleAdminGetBlacklist(env.DB);
    }
    if (path === '/api/admin/blacklist' && method === 'POST') {
      return handleAdminAddBlacklist(env.DB, request);
    }
    if (path === '/api/admin/blacklist' && method === 'DELETE') {
      return handleAdminRemoveBlacklist(env.DB, request);
    }
    if (path === '/api/admin/logs' && method === 'GET') {
      return handleAdminGetLogs(env.DB, request);
    }
    if (path === '/api/admin/stats' && method === 'GET') {
      return handleAdminGetStats(env.DB);
    }
    if (path === '/api/admin/codes' && method === 'GET') {
      return handleAdminGetAllCodes(env.DB, request);
    }
    const deleteMatch = path.match(/^\/api\/admin\/codes\/(\d+)$/);
    if (deleteMatch && method === 'DELETE') {
      const cid = parseId(deleteMatch[1]);
      if (cid === null) return json({ success: false, error: '该码不存在' }, 404);
      return handleAdminDeleteCode(env.DB, cid);
    }
    if (path === '/api/admin/settings' && method === 'GET') {
      return handleAdminGetSettings(env.DB);
    }
    if (path === '/api/admin/settings' && method === 'POST') {
      return handleAdminSaveSettings(env.DB, request);
    }
    if (path === '/api/admin/reports' && method === 'GET') {
      return handleAdminGetReports(env.DB, request);
    }
    const reportStatusMatch = path.match(/^\/api\/admin\/reports\/(\d+)\/status$/);
    if (reportStatusMatch && method === 'POST') {
      const rsid = parseId(reportStatusMatch[1]);
      if (rsid === null) return json({ success: false, error: '该举报不存在' }, 404);
      return handleAdminUpdateReport(env.DB, rsid, request);
    }
    const reportDeleteMatch = path.match(/^\/api\/admin\/reports\/(\d+)$/);
    if (reportDeleteMatch && method === 'DELETE') {
      const rdid = parseId(reportDeleteMatch[1]);
      if (rdid === null) return json({ success: false, error: '该举报不存在' }, 404);
      return handleAdminDeleteReport(env.DB, rdid);
    }
  }

  return json({ success: false, error: '接口不存在' }, 404);
}

// ============================================================
//  静态页面
// ============================================================

async function servePage(pageName) {
  const pages = {
    index: INDEX_HTML,
    admin: ADMIN_HTML,
  };
  const html = pages[pageName];
  if (!html) return new Response('Not Found', { status: 404 });
  const extra = { 'Content-Type': 'text/html; charset=utf-8' };
  // 后台页不进搜索引擎索引，也不缓存（避免 /admin 被爬到并暴露入口）
  if (pageName === 'admin') {
    extra['X-Robots-Tag'] = 'noindex, nofollow, noarchive';
    extra['Cache-Control'] = 'no-store';
  } else {
    extra['Cache-Control'] = 'public, max-age=300';
  }
  return new Response(html, { headers: securityHeaders(extra) });
}

// ============================================================
//  每日清空（23:59 CST 定时 + 懒清理兜底）
// ============================================================

/** 获取当前 CST(UTC+8) 日期字符串 YYYY-MM-DD */
function getCSTDate() {
  return new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

/** 每日清空：删除所有互助码，并按保留期清理日志类表（避免 D1 无限膨胀） */
async function dailyCleanup(db) {
  const today = getCSTDate();
  const last = await db.prepare("SELECT value FROM settings WHERE key = 'last_cleanup_date'").first();
  if (last && last.value === today) return false; // 今天已清理

  const cutoff = new Date(Date.now() - CONFIG.LOG_KEEP_DAYS * 24 * 3600_000).toISOString();

  // 清空所有互助码 + 清理各日志表（visits / reports 原来只增不减，会一直吃 D1 行数配额）
  await db.batch([
    db.prepare("DELETE FROM codes"),
    db.prepare("DELETE FROM submit_logs WHERE created_at < ?").bind(cutoff),
    db.prepare("DELETE FROM visits WHERE created_at < ?").bind(cutoff),
    db.prepare("DELETE FROM reports WHERE created_at < ? AND status != 'pending'").bind(cutoff),
    // 顺手清掉已过期的黑名单记录（checkBlacklist 只在命中时才懒清理）
    db.prepare("DELETE FROM blacklist WHERE expires_at IS NOT NULL AND expires_at < ?").bind(now()),
    db.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('last_cleanup_date', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(today, now()),
  ]);
  return true;
}

// ============================================================
//  入口
// ============================================================

// ============================================================
//  主入口
// ============================================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 请求体大小闸门：Workers 本身没有默认上限，超大 body 会白白吃 CPU 时间
    // （/api/ocr 的图片走 formData，单独用 OCR_MAX_IMG_BYTES 判定，此处放宽到 8MB）
    const declaredLen = parseInt(request.headers.get('content-length') || '0', 10);
    if (declaredLen > 8 * 1024 * 1024) {
      return json({ success: false, error: '请求体过大' }, 413);
    }

    // API 路由
    if (path.startsWith('/api/')) {
      try {
        return await handleAPI(request, env, path, ctx);
      } catch (err) {
        // 只在服务端日志留细节，响应体不回传任何堆栈/SQL 信息
        console.error('[api]', path, err);
        return json({ success: false, error: '服务器内部错误' }, 500);
      }
    }

    // 静态页面
    if (path === '/' || path === '/index.html') {
      return servePage('index');
    }
    if (path === '/admin' || path === '/admin/') {
      return servePage('admin');
    }

    // 站点地图：当前只有首页一个可收录 URL
    // ⚠️ lastmod 必须在请求内计算：Workers 全局作用域的 new Date() 会被钉在 1970-01-01
    if (path === '/sitemap.xml') {
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${CONFIG.SITE_ORIGIN}/</loc>
    <lastmod>${new Date().toISOString().slice(0, 10)}</lastmod>
    <changefreq>hourly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`;
      // 不设 Cache-Control：Worker 动态响应默认不进边缘缓存。
      // 这里刻意不缓存 —— lastmod 随日期变化，若被缓存会把过期日期固化住。
      return new Response(xml, {
        headers: { 'Content-Type': 'application/xml; charset=utf-8' },
      });
    }

    // 明确告知爬虫不要收录后台
    if (path === '/robots.txt') {
      return new Response(
        'User-agent: *\n' +
        'Allow: /\n' +
        'Disallow: /admin\n' +
        'Disallow: /api/\n' +
        '\n' +
        'Sitemap: ' + CONFIG.SITE_ORIGIN + '/sitemap.xml\n',
        { headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }

    return new Response('Not Found', { status: 404 });
  },

  // Cron Trigger: 每天 23:59 CST (15:59 UTC) 清空互助码 + 清理历史日志
  async scheduled(event, env, ctx) {
    try {
      await dailyCleanup(env.DB);
    } catch (err) {
      console.error('[cron] dailyCleanup failed:', err);
    }
  },
};

// ============================================================
//  前端页面 HTML（内联，部署后由 Worker 直接返回）
// ============================================================

const INDEX_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PDD福袋邀请码互助 - 拼多多福袋五折互助码免费分享</title>
<meta name="description" content="免费的拼多多福袋邀请码互助平台：提交并分享福袋五折邀请码，实时更新互助码列表，一键跳转拼多多搜索助力。支持截图识别邀请码、违规公示，每日自动清理，无需注册。">
<meta name="keywords" content="拼多多福袋,福袋互助,PDD福袋,拼多多邀请码,福袋五折,百亿补贴福袋,福袋助力,福袋互助码">
<meta name="robots" content="index,follow">
<meta name="theme-color" content="#2563eb">
<link rel="canonical" href="${CONFIG.SITE_ORIGIN}/">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%232563eb'/%3E%3Ctext x='32' y='41' font-size='20' text-anchor='middle' fill='%23ffffff' font-family='sans-serif' font-weight='bold'%3EPDD%3C/text%3E%3C/svg%3E">
${CONFIG.SEO_VERIFY_GOOGLE ? '<meta name="google-site-verification" content="' + CONFIG.SEO_VERIFY_GOOGLE + '">' : ''}
${CONFIG.SEO_VERIFY_BAIDU ? '<meta name="baidu-site-verification" content="' + CONFIG.SEO_VERIFY_BAIDU + '">' : ''}
${CONFIG.SEO_VERIFY_BING ? '<meta name="msvalidate.01" content="' + CONFIG.SEO_VERIFY_BING + '">' : ''}
<meta property="og:type" content="website">
<meta property="og:site_name" content="PDD福袋五折互助">
<meta property="og:title" content="PDD福袋邀请码互助 - 拼多多福袋五折互助码免费分享">
<meta property="og:description" content="免费的拼多多福袋邀请码互助平台：提交并分享福袋五折邀请码，实时更新互助码列表，一键跳转拼多多搜索助力。">
<meta property="og:url" content="${CONFIG.SITE_ORIGIN}/">
<meta property="og:locale" content="zh_CN">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="PDD福袋邀请码互助 - 拼多多福袋五折互助码免费分享">
<meta name="twitter:description" content="免费的拼多多福袋邀请码互助平台：提交并分享福袋五折邀请码，一键跳转拼多多搜索助力。">
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[{"@type":"WebSite","@id":"${CONFIG.SITE_ORIGIN}/#website","url":"${CONFIG.SITE_ORIGIN}/","name":"PDD福袋五折互助","alternateName":"拼多多福袋邀请码互助平台","description":"免费的拼多多福袋邀请码互助平台，实时分享福袋五折邀请码。","inLanguage":"zh-CN"},{"@type":"FAQPage","@id":"${CONFIG.SITE_ORIGIN}/#faq","mainEntity":[{"@type":"Question","name":"使用拼多多福袋互助码需要注册或付费吗？","acceptedAnswer":{"@type":"Answer","text":"不需要。本站不收集手机号、不要求登录，提交与查询完全免费。"}},{"@type":"Question","name":"什么是拼多多福袋互助码？","acceptedAnswer":{"@type":"Answer","text":"拼多多福袋活动需要好友助力才能领取五折券，助力时用到的 8~9 位邀请码就是福袋互助码。"}},{"@type":"Question","name":"为什么邀请码中间两位显示为星号？","acceptedAnswer":{"@type":"Answer","text":"为了防止邀请码被批量抓取和恶意刷单，隐藏中间两位不影响他人正常助力。"}},{"@type":"Question","name":"提交的邀请码会一直显示吗？","acceptedAnswer":{"@type":"Answer","text":"不会。邀请码有有效期，被标记已使用后一段时间会自动轮换下架，重新提交即可重新进入列表。"}}]}]}
</script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f8ff;color:#333;min-height:100vh;padding:20px}
.container{max-width:800px;margin:0 auto}

/* 大白卡 */
.card{background:#fff;padding:20px;border-radius:16px;box-shadow:0 4px 20px rgba(59,130,246,.08);margin-bottom:20px;border:1px solid #e0f2fe}
.card h1,.card h2{text-align:center;color:#2563eb;margin:0 0 15px;font-size:1.4em;font-weight:700}

/* 灰底描述段 */
.desc-text{color:#4b5563;font-size:15px;line-height:1.7;text-align:left;margin:0;background:#f8fafc;padding:12px 16px;border-radius:10px}
.desc-tips{display:inline-block;margin-top:6px;color:#3b82f6;font-size:13px}
.desc-tips b{color:#ef4444;font-size:14px;padding:0 2px}

/* 虚线按钮 */
.feedback-btn{width:100%;background:#eef2ff;color:#3b82f6;border:1px dashed #93c5fd;padding:10px 0;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer;margin-top:12px;transition:all .2s ease;display:flex;align-items:center;justify-content:center;gap:6px}
.feedback-btn:hover{background:#dbeafe;border-color:#60a5fa}
.feedback-btn:active{transform:scale(.98)}
.feedback-btn-red{background:#fef2f2;color:#ef4444;border-color:#fca5a5;margin-top:10px}
.feedback-btn-red:hover{background:#fee2e2}
.feedback-btn-ios{background:#f5f5f7;color:#1d1d1f;border-color:#c7c7cc;margin-top:10px;text-decoration:none}
.feedback-btn-ios:hover{background:#e8e8ed;border-color:#aeaeb2}
.feedback-btn-ios .ios-tag{font-size:11px;background:#1d1d1f;color:#fff;border-radius:4px;padding:1px 5px;font-weight:600}

/* 滚动公告 */
.custom-notice-bar{display:flex;align-items:center;background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.03);border:1px solid #f1f5f9;padding:8px 10px 8px 0;margin-bottom:15px;position:relative;overflow:hidden;height:44px;box-sizing:border-box}
.notice-accent{width:4px;height:18px;background:#3b82f6;border-radius:0 4px 4px 0;margin-right:8px;flex-shrink:0}
.notice-tag{font-size:14px;font-weight:bold;color:#475569;white-space:nowrap;margin-right:10px;flex-shrink:0}
.notice-scroll-wrap{flex:1;overflow:hidden;white-space:nowrap;position:relative;height:100%;display:flex;align-items:center;-webkit-mask-image:linear-gradient(to right,transparent,black 5%,black 95%,transparent);mask-image:linear-gradient(to right,transparent,black 5%,black 95%,transparent)}
.notice-scroll-content{display:inline-block;font-size:13px;color:#64748b;animation:marquee 18s linear infinite;padding-left:100%}
@keyframes marquee{0%{transform:translateX(0)}100%{transform:translateX(-100%)}}
.notice-action{font-size:12px;color:#94a3b8;cursor:pointer;white-space:nowrap;margin:0 10px;user-select:none}
.notice-close{width:26px;height:26px;background:#f1f5f9;border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:#64748b;transition:background .2s;flex-shrink:0;margin-right:6px}
.notice-close:active{background:#e2e8f0}

/* 广告位/福利加 */
.ad-section{margin-bottom:20px}
.ad-banner{display:block;width:100%;border-radius:12px;overflow:hidden;background:#fff;margin-bottom:8px;text-decoration:none;border:1px solid #e2e8f0}
.ad-banner img{display:block;width:100%;height:auto}

/* 统计栏 */
.stats-bar{display:flex;justify-content:space-around;padding:14px 0;background:#f8fafc;border-radius:10px;margin-bottom:18px;border:1px solid #e0f2fe}
.stat-item{text-align:center;flex:1}
.stat-item+.stat-item{border-left:1px solid #e0f2fe}
.stat-num{display:block;font-size:20px;font-weight:700;color:#2563eb}
.stat-label{font-size:11px;color:#64748b;margin-top:3px}

/* 输入区（识别按钮内嵌在输入框右端，提交按钮独占一行） */
.input-area{display:flex;flex-direction:column;gap:10px;margin:10px 0 0}
.input-with-scan{display:flex;align-items:center;height:48px;border:1.5px solid #dbeafe;border-radius:13px;background:#f8fafd;box-sizing:border-box;overflow:hidden;transition:border-color .25s ease,background .25s ease,box-shadow .25s ease}
.input-with-scan:focus-within{border-color:#3b82f6;background:#fff;box-shadow:0 0 0 3px rgba(59,130,246,.10)}
.input-with-scan input{flex:1;min-width:0;width:auto;height:100%;font-size:16px;padding:0 16px;border:none;background:transparent;border-radius:0;box-shadow:none;outline:none;box-sizing:border-box;letter-spacing:2px;-webkit-tap-highlight-color:transparent}
.input-with-scan input::placeholder{letter-spacing:0;color:#9ca3af}
.scan-btn{flex-shrink:0;height:100%;padding:0 12px;border:none;border-left:1.5px solid #dbeafe;background:#f2f7ff;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;outline:none;-webkit-tap-highlight-color:transparent;transition:background .2s ease,border-color .2s ease,transform .12s ease,box-shadow .2s ease}
.scan-btn:hover{background:#e8efff}
.scan-btn:active{transform:scale(.94);background:#dbe7ff;box-shadow:inset 0 1px 3px rgba(59,130,246,.18)}
.scan-btn:focus-visible{box-shadow:inset 0 0 0 2px rgba(59,130,246,.55);background:#ebf3ff}
.scan-btn:disabled{opacity:.6;cursor:not-allowed}
.input-with-scan:focus-within .scan-btn{background:linear-gradient(180deg,#f1f6ff 0%,#e8efff 100%);border-left-color:rgba(59,130,246,.22)}
.scan-text{font-size:10px;color:#3b82f6;line-height:1;font-weight:600;white-space:nowrap}
/* 四角取景框 + 扫描线图标（纯 CSS） */
.scan-icon{position:relative;width:17px;height:17px}
.scan-icon::before,.scan-icon::after,.scan-core::before,.scan-core::after{content:'';position:absolute;width:5.5px;height:5.5px}
.scan-icon::before{top:0;left:0;border-top:2px solid #3b82f6;border-left:2px solid #3b82f6;border-top-left-radius:3px}
.scan-icon::after{bottom:0;right:0;border-bottom:2px solid #3b82f6;border-right:2px solid #3b82f6;border-bottom-right-radius:3px}
.scan-core{position:absolute;left:0;top:0;width:100%;height:100%}
.scan-core::before{top:0;right:0;border-top:2px solid #3b82f6;border-right:2px solid #3b82f6;border-top-right-radius:3px}
.scan-core::after{bottom:0;left:0;border-bottom:2px solid #3b82f6;border-left:2px solid #3b82f6;border-bottom-left-radius:3px}
.scan-line{position:absolute;left:15%;right:15%;top:50%;height:2px;margin-top:-1px;background:#3b82f6;border-radius:1px;animation:scan-move 1.6s ease-in-out infinite}
@keyframes scan-move{0%,100%{opacity:1}50%{opacity:.35}}
.submit-btn{width:100%;height:48px;padding:0 22px;border:none;border-radius:13px;cursor:pointer;font-size:15px;font-weight:800;color:#fff;white-space:nowrap;letter-spacing:1px;background:linear-gradient(135deg,#3b82f6,#60a5fa);box-shadow:0 5px 16px rgba(59,130,246,.32);transition:transform .15s ease,box-shadow .2s ease,opacity .2s ease}
.submit-btn:hover{transform:translateY(-1px)}
.submit-btn:active{transform:scale(.97)}
.submit-btn:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
.btn-row{display:flex;gap:10px;margin:0 0 18px}
.action-btn{flex:1;position:relative;display:inline-flex;align-items:center;justify-content:center;height:48px;border:none;border-radius:13px;cursor:pointer;font-size:14.5px;font-weight:800;color:#fff;letter-spacing:1px;background:linear-gradient(135deg,#8b5cf6,#7c3aed);box-shadow:0 5px 16px rgba(139,92,246,.28);transition:transform .15s ease,box-shadow .2s ease,opacity .2s ease}
.action-btn:hover{transform:translateY(-1px)}
.action-btn:active{transform:scale(.97)}
.action-btn:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
.onekey-help{position:absolute;right:10px;top:50%;transform:translateY(-50%);width:20px;height:20px;border-radius:50%;background:rgba(255,255,255,.28);color:#fff;font-size:12.5px;line-height:20px;text-align:center;cursor:pointer;font-weight:700;font-style:normal;-webkit-user-select:none;user-select:none}
.onekey-help:active{background:rgba(255,255,255,.48)}

/* 识别结果确认弹窗 */
.ocr-modal{max-width:380px}
.ocr-preview{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:10px;padding:8px;margin-bottom:12px;text-align:center}
.ocr-preview img{display:none;max-width:100%;border-radius:6px}
.ocr-code-row input{width:100%;height:48px;font-size:20px;font-weight:700;letter-spacing:3px;text-align:center;border:2px solid #bfdbfe;border-radius:10px;outline:none;box-sizing:border-box;color:#1e40af;background:#f8fafd}
.ocr-code-row input:focus{border-color:#3b82f6;background:#fff}
.ocr-tip{font-size:12.5px;color:#64748b;text-align:center;margin-top:8px;line-height:1.6}
.ocr-tip.warn{color:#d97706}
.ocr-actions{display:flex;gap:10px;margin-top:14px}
.ocr-actions button{flex:1;height:44px;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;transition:transform .15s ease,opacity .2s ease}
.ocr-actions button:active{transform:scale(.97)}
.ocr-actions .btn-ghost{background:#f1f5f9;color:#475569}
.ocr-actions .btn-primary{background:linear-gradient(135deg,#3b82f6,#60a5fa);color:#fff;box-shadow:0 4px 12px rgba(59,130,246,.3)}

/* 蜜罐 */
.honeypot{position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden}

/* 倒计时 */
.countdown-wrap{text-align:center;color:#64748b;font-size:13px;margin-bottom:15px;height:20px;line-height:20px}
.countdown-wrap b{color:#3b82f6}

/* 列表 */
.list{list-style:none;padding:0;margin:0}
.list-item{padding:16px 20px;margin:10px 0;border-radius:10px;font-size:18px;display:flex;justify-content:space-between;align-items:center;background:#eff6ff;border-left:6px solid #3b82f6;transition:background-color .3s ease}
.list-item.used{background:#f8fafc;border-left-color:#cbd5e1;color:#94a3b8}
.list-item .info{flex:1;min-width:0}
.list-item .number{font-weight:bold;letter-spacing:1px;color:#1e40af}
.list-item.used .number{color:#94a3b8;text-decoration:line-through}
.list-item .meta{font-size:13px;color:#94a3b8;margin-top:2px}
.list-item .actions{display:flex;align-items:center;gap:6px;flex-shrink:0}
.jump-btn{background:#3b82f6;color:#fff;border:none;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:15px;text-decoration:none;display:inline-block}
.jump-btn:hover{background:#2563eb}
.jump-btn:active{transform:scale(.96)}
.report-btn{background:none;border:none;color:#94a3b8;font-size:12px;cursor:pointer;padding:4px 8px}
.report-btn:hover{color:#ef4444}
.used-tag{color:#94a3b8;font-weight:bold;font-size:15px;padding:4px 10px;background:#e2e8f0;border-radius:4px}
.empty{text-align:center;padding:40px 20px;color:#94a3b8;font-size:14px}

/* 弹窗 */
.modal-mask{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:100;display:none;align-items:center;justify-content:center;padding:16px}
.modal-mask.show{display:flex}
.modal{background:#fff;border-radius:14px;max-width:480px;width:100%;max-height:85vh;overflow-y:auto;position:relative;padding:20px}
.modal h2{font-size:17px;margin-bottom:14px;text-align:center}
.modal .close-x{position:absolute;top:10px;right:14px;font-size:20px;color:#999;cursor:pointer;background:none;border:none}
.modal .close-x:hover{color:#333}
.contact-item{background:#f8f9fa;border-radius:10px;padding:14px;margin-bottom:10px}
.contact-item strong{display:block;margin-bottom:4px;font-size:14px}
.contact-item p{font-size:13px;color:#666;line-height:1.6}
.contact-actions{display:flex;gap:8px;margin-top:14px}
.contact-actions button{flex:1;padding:10px;border:none;border-radius:8px;font-size:14px;cursor:pointer}
.btn-ghost{background:#f0f0f0;color:#555}
.btn-qq{background:linear-gradient(135deg,#12b7f5,#0f95d0);color:#fff}
.bb-table{width:100%;border-collapse:collapse;font-size:12px}
.bb-table th,.bb-table td{padding:7px 8px;text-align:left;border-bottom:1px solid #f0f0f0}
.bb-table th{background:#fafafa;font-weight:600;color:#555}
.bb-table .ip{font-family:monospace}
.bb-sync{text-align:center;font-size:11px;color:#999;margin-top:10px}
.modal-ok{display:block;width:100%;margin-top:14px;padding:10px;border:none;border-radius:8px;background:#3b82f6;color:#fff;font-size:14px;cursor:pointer}

/* 弹窗广告 */
.ad-pop{position:fixed;z-index:99;top:50%;left:50%;transform:translate(-50%,-50%);width:92%;max-width:360px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.3);display:none}
.ad-pop.show{display:block}
.ad-pop .ad-close{position:absolute;top:8px;right:8px;width:28px;height:28px;border-radius:50%;background:rgba(0,0,0,.45);color:#fff;border:none;font-size:15px;cursor:pointer;z-index:2;line-height:28px;text-align:center;padding:0}
.ad-pop .ad-head{background:linear-gradient(135deg,#3b82f6,#60a5fa);color:#fff;padding:14px 16px}
.ad-pop .ad-head .t{font-size:15px;font-weight:700}
.ad-pop .ad-head .s{font-size:11px;opacity:.9;margin-top:2px}
.ad-pop .ad-links{padding:12px}
.ad-pop .ad-link{display:flex;align-items:center;gap:10px;padding:10px;border-radius:10px;text-decoration:none;color:#333;background:#f8f9fa;margin-bottom:8px}
.ad-pop .ad-link:last-child{margin-bottom:0}
.ad-pop .ad-icon{width:36px;height:36px;border-radius:8px;color:#fff;font-size:17px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.ad-pop .ad-link .txt{font-size:13px}
.ad-pop .ad-link .txt b{display:block;font-size:14px}

.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);padding:12px 24px;border-radius:8px;color:#fff;font-size:14px;z-index:999;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}
.toast.success{background:#07c160}
.toast.error{background:#e53935}
.toast.warning{background:#f59e0b}
.loading{text-align:center;padding:20px;color:#999}

@media (max-width:600px){
body{padding:12px}
.card{padding:16px;border-radius:14px}
.card h1,.card h2{font-size:1.25em}
.desc-text{font-size:14px;padding:11px 14px}
.feedback-btn{font-size:13px;padding:11px 0}
.submit-btn,.action-btn{width:100%}
.list-item{flex-direction:column;gap:10px;align-items:flex-start;font-size:16px;padding:14px 16px}
.list-item .actions{align-self:flex-end}
.jump-btn{padding:8px 16px;font-size:14px}
.stats-bar{padding:10px 0}
.stat-num{font-size:18px}
.stat-label{font-size:10px}
}

/* SEO 文案区（服务端渲染，供搜索引擎索引） */
.seo-block{background:#fff;border:1px solid #e0f2fe;border-radius:16px;padding:20px;margin-bottom:20px;color:#4b5563;font-size:14px;line-height:1.8;text-align:left}
.seo-block h2{color:#2563eb;font-size:1.15em;margin:0 0 10px}
.seo-block h3{color:#374151;font-size:1em;margin:16px 0 6px}
.seo-block p{margin:0 0 10px}
.seo-block ol,.seo-block ul{margin:0 0 10px;padding-left:20px}
.seo-block li{margin-bottom:4px}
.seo-block .seo-note{color:#9ca3af;font-size:12px;margin:14px 0 0;padding-top:10px;border-top:1px dashed #e5e7eb}
</style>
</head>
<body>
<div class="container">

  <!-- ===== 第一张大白卡 ===== -->
  <div class="card">
    <h1>PDD福袋五折互助</h1>
    <p class="desc-text">
      ① 输入8-9位邀请码提交，支持重复提交点亮<br>
      ② 列表点"跳转"自动打开拼多多搜索<br>
      ③ 微信内请手动去拼多多粘贴搜索
      <span class="desc-tips">💡 只能提交 <b>拼多多福袋互助码</b>，请勿提交不相关互助码，将会被系统拉黑！</span>
    </p>

    <button class="feedback-btn" onclick="openContact()">💬 建议 · 反馈 · 申诉 · 加入组织</button>
    <button class="feedback-btn feedback-btn-red" onclick="openBlacklist()">🚫 违规小黑屋公示 (严打乱拉人)</button>
    <!-- iOS 快捷指令：地址由后台「站点设置」配置。未配置过 → 用服务端默认地址；后台显式留空 → 隐藏此按钮。
         链接不写死在模板里，改地址不必重新部署。 -->
    <a class="feedback-btn feedback-btn-ios" id="iosShortcutBtn" style="display:none" target="_blank" rel="noopener">📱 <span>iOS 快捷指令版</span><span class="ios-tag">一键安装</span></a>

  </div>

  <!-- 滚动公告（后台配置则显示） -->
  <div class="custom-notice-bar" id="noticeBar" style="display:none">
    <div class="notice-accent"></div>
    <div class="notice-tag">公告</div>
    <div class="notice-scroll-wrap"><div class="notice-scroll-content" id="noticeText"></div></div>
    <div class="notice-action" onclick="showNoticeModal()">查看 &gt;</div>
    <div class="notice-close" onclick="closeNoticeBar()">
      <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
    </div>
  </div>

  <!-- 广告位（后台配置则显示） -->
  <div class="ad-section" id="adSection" style="display:none"></div>

  <!-- ===== 第二张大白卡 ===== -->
  <div class="card">
    <!-- 统计栏 -->
    <div class="stats-bar" id="statsBar">
      <div class="stat-item"><span class="stat-num" id="statIPs">-</span><span class="stat-label">今日IP</span></div>
      <div class="stat-item"><span class="stat-num" id="statVisits">-</span><span class="stat-label">今日访问</span></div>
      <div class="stat-item"><span class="stat-num" id="statSubmits">-</span><span class="stat-label">今日提交</span></div>
    </div>

    <!-- 输入区：识别按钮内嵌在输入框右端；form 包住输入行，手机键盘按「前往/Go」即可提交 -->
    <form class="input-area" id="codeForm" onsubmit="event.preventDefault(); submitCode();">
      <div class="input-with-scan">
        <input type="tel" id="codeInput" placeholder="输入8-9位邀请码" maxlength="9" inputmode="numeric" pattern="[0-9]*" autocomplete="off" oninput="this.value=this.value.replace(/\\D/g,'')">
        <button type="button" class="scan-btn" id="scanBtn" title="识别截图" onclick="pickCodeImage()">
          <span class="scan-icon"><span class="scan-core"></span><span class="scan-line"></span></span>
          <span class="scan-text">识别截图</span>
        </button>
      </div>
      <input type="text" id="websiteField" style="display:none" tabindex="-1" autocomplete="off">
      <button type="submit" class="submit-btn" id="submitBtn">立即提交</button>
      <input type="file" id="ocrFile" accept="image/*" style="display:none" onchange="handleOcrFile(this)">
    </form>
    <div class="btn-row">
      <button class="action-btn" id="smartBtn" onclick="quickUse()">🚀 智能直达<span class="onekey-help" title="智能直达怎么用" onclick="event.stopPropagation(); showSmartHelp()">i</span></button>
    </div>

    <!-- 蜜罐：机器人会填，正常用户看不到 -->
    <div class="honeypot" aria-hidden="true">
      <label>Website<input type="text" name="website" tabindex="-1" autocomplete="off"></label>
    </div>

    <!-- 倒计时 -->
    <div class="countdown-wrap" id="countdownWrap">列表将在 <b id="countdownSec">3</b> 秒后自动刷新</div>

    <!-- 互助码列表 -->
    <ul id="numberList" class="list"><li class="loading" style="text-align:center;padding:20px;color:#999;list-style:none">加载中...</li></ul>
  </div>

  <!-- ===== SEO 内容区：服务端渲染的静态文案，供搜索引擎索引，同时帮助新用户了解用法 ===== -->
  <footer class="seo-block">
    <h2>关于 PDD 福袋五折互助</h2>
    <p><strong>PDD 福袋五折互助</strong>是一个免费的<strong>拼多多福袋邀请码互助平台</strong>。拼多多「百亿补贴 · 百亿消费券」的福袋活动需要好友助力才能领到五折券，而每个人的好友数量有限。本站把大家手上的福袋邀请码汇集在一起：你提交自己的码，就能同时看到别人提交的码，互相助力，提高五折券的领取成功率。</p>
    <h3>使用步骤</h3>
    <ol>
      <li>在拼多多 App 打开福袋活动（首页 → 百亿补贴 → 百亿消费券 → 福袋），复制你的 8~9 位邀请码；</li>
      <li>回到本站，把邀请码粘贴到输入框，点「立即提交」；</li>
      <li>在下方列表里找别人的码，点「跳转」会自动打开拼多多搜索并完成助力；</li>
      <li>别人助力你的码之后，你就能在拼多多里领取对应的五折券。</li>
    </ol>
    <h3>常见问题</h3>
    <ul>
      <li><strong>需要注册或付费吗？</strong>不需要。本站不收集手机号、不要求登录，提交与查询完全免费。</li>
      <li><strong>为什么邀请码中间两位是隐藏的？</strong>为防止被批量抓取和恶意刷单，隐藏部分不影响正常助力。</li>
      <li><strong>应该先点别人的码，还是先提交自己的？</strong>有码优先使用，没码的提交。</li>
      <li><strong>我的码为什么不见了？</strong>邀请码有有效期，被标记「已使用」后一段时间会自动轮换下架，重新提交即可重新进入队列。</li>
      <li><strong>提交不相关的码会怎样？</strong>会被其他用户举报，达到阈值后自动进入小黑屋公示并限制提交。</li>
    </ul>
    <h3>合规说明</h3>
    <p>本站为爱好者搭建的互助信息展示平台，<strong>与拼多多官方无任何隶属或合作关系</strong>。站内邀请码均由用户自行提交，本站不对其真实性作担保。若你是权利方并认为本站内容不当，可通过站内「联系我们」反馈，我们会及时处理。</p>
    <p class="seo-note">PDD福袋五折互助 · 免费拼多多福袋邀请码互助平台 · 数据每日自动清理</p>
  </footer>

</div>

<!-- 弹窗广告：有广告配置时展示，可关闭。标题/副标题由后台设置注入，未配置则整块不渲染 -->
<div class="ad-pop" id="adPop">
  <button class="ad-close" onclick="closeAdPop()">×</button>
  <div class="ad-head" id="adPopHead" style="display:none">
    <div class="t" id="adPopTitle"></div>
    <div class="s" id="adPopSub"></div>
  </div>
  <div class="ad-links" id="adPopLinks"></div>
</div>

<!-- 联系我们弹窗 -->
<div class="modal-mask" id="contactModal" onclick="if(event.target===this)closeModal('contactModal')">
  <div class="modal">
    <button class="close-x" onclick="closeModal('contactModal')">×</button>
    <h2>👨‍💻 联系我们</h2>
    <div id="contactBody"></div>
    <div class="contact-actions">
      <button class="btn-ghost" onclick="closeModal('contactModal')">下次一定</button>
      <button class="btn-qq" id="qqJoinBtn" onclick="joinQQ()" style="display:none">🚀 一键加入 Q群</button>
    </div>
  </div>
</div>

<!-- 小黑屋公示弹窗 -->
<div class="modal-mask" id="blacklistModal" onclick="if(event.target===this)closeModal('blacklistModal')">
  <div class="modal">
    <button class="close-x" onclick="closeModal('blacklistModal')">×</button>
    <h2>🚫 小黑屋实时公示</h2>
    <div id="blacklistBody"><div class="loading">加载中...</div></div>
  </div>
</div>

<!-- 识别结果确认弹窗：展示裁出的码区原图 + 可编辑的码，确认后才提交 -->
<div class="modal-mask" id="ocrModal" onclick="if(event.target===this)closeOcrModal()">
  <div class="modal ocr-modal">
    <button class="close-x" onclick="closeOcrModal()">×</button>
    <h2>识别结果确认</h2>
    <div class="ocr-preview" id="ocrPreviewWrap"><img id="ocrPreview" alt="识别到的码区"></div>
    <div class="ocr-code-row">
      <input type="tel" id="ocrCodeInput" maxlength="9" inputmode="numeric" pattern="[0-9]*" placeholder="8-9位数字" autocomplete="off" oninput="this.value=this.value.replace(/\\D/g,'')">
    </div>
    <div class="ocr-tip" id="ocrTip"></div>
    <div class="ocr-actions">
      <button type="button" class="btn-ghost" onclick="closeOcrModal()">取消</button>
      <button type="button" class="btn-primary" onclick="confirmOcrCode()">确认提交</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
/* ===== 本地像素识别内核：零依赖、零模型、零网络，纯函数（可直接在 Node 里单测） ===== */
/**
 * PDD 邀请码本地像素识别器（零依赖、零模型、零网络）
 * 算法：红区定位 -> Otsu 行分离 -> 列切分 -> 间隙聚类 -> 6x8 归一化 -> 模板匹配
 * 纯函数，输入 RGBA 像素数组，可在 Node 中直接测试。
 */
(function (root) {
  'use strict';

  var BRIGHT = 168;      // 亮字阈值（G 通道）。实测三张真机图 p50=47 / p99.9=255，余量充足
  var GW = 6, GH = 8;    // 归一化网格（实测 5x7~10x14 均 100%，取中间值）
  var MAX_D1 = 0.95;     // 最高距离阈值（正样本实测 0.447~0.569）
  var MIN_GAP = 0.06;    // 与次优类的最小间隔（正样本实测 0.183~0.294）

  /* 模板：0-9 各一个 6x8 标准化栅格，由 8 种字体渲染结果取平均后导出。
     零样本验证：对 27 个真机字形 100% 正确（含数字 6——由 rot180(真机9) 交叉印证）。 */
  var TPL = {
    '0': [-1.354,0.1352,1.0498,1.1045,0.3609,-1.2811,-0.0523,0.9683,-0.6129,-0.6813,0.9224,0.1182,0.8632,0.3854,-1.3899,-1.4097,0.2816,0.93,1.1976,0.1472,-1.4428,-1.4503,0.0605,1.2017,1.2107,0.1314,-1.4428,-1.454,0.056,1.197,0.9245,0.3481,-1.3944,-1.4159,0.2713,0.8991,0.1181,0.9126,-0.7125,-0.751,0.8921,0.0581,-1.2963,0.3075,1.0669,1.0481,0.267,-1.2937],
    '1': [-1.073,-0.965,-0.6834,0.0509,0.8078,1.0558,-0.1241,0.2381,0.5486,0.8805,1.0574,1.0574,0.1994,-0.0368,-0.3693,0.3197,1.0574,1.0574,-0.8056,-0.9887,-1.0961,0.214,1.0574,1.0574,-1.162,-1.162,-1.1342,0.214,1.0574,1.0574,-1.162,-1.162,-1.1342,0.214,1.0574,1.0574,-1.162,-1.162,-1.1342,0.214,1.0574,1.0574,-1.162,-1.162,-1.1342,0.214,1.0574,1.0574],
    '2': [-0.8523,0.5852,1.1809,1.1951,0.6106,-0.9017,0.1721,0.4647,-0.5164,-0.4128,0.9652,0.6164,-0.8405,-0.7866,-1.2076,-1.134,0.6601,0.8642,-1.2616,-1.2616,-1.2513,-0.255,1.1895,-0.0521,-1.2616,-1.1784,-0.0095,1.2117,0.2365,-1.1868,-1.1197,0.2663,1.0902,-0.1185,-1.2297,-1.2616,0.0351,1.0557,0.1278,-0.627,-0.6442,-0.6453,1.1235,1.2952,1.2677,1.2677,1.2677,1.2666],
    '3': [-0.6579,0.8363,1.3223,1.2953,0.5523,-1.0736,-0.0329,0.2404,-0.6946,-0.2594,1.2594,0.2931,-1.1321,-1.0773,-1.2882,-0.7669,1.1525,0.2775,-1.3009,-0.6441,0.3424,1.1716,0.7932,-1.0796,-1.3009,-0.8683,-0.4209,0.1834,1.261,0.2101,-1.0105,-1.0409,-1.2855,-1.2295,0.5318,1.3986,0.3478,0.1095,-0.7715,-0.5477,0.9951,0.9206,-0.1632,0.9401,1.3012,1.2386,0.605,-0.9327],
    '4': [-1.124,-1.124,-1.0681,0.496,0.9865,-1.0112,-1.124,-1.124,-0.2687,1.2218,0.949,-1.0112,-1.124,-0.8305,1.1162,0.4746,0.949,-1.0112,-1.0711,0.6677,0.4278,-0.2632,1.173,-0.9361,0.1025,1.0425,-0.8943,-0.2167,1.2592,-0.8348,1.36,1.1629,0.9265,1.0134,1.4019,1.0053,-0.2788,-0.2788,-0.2788,0.302,1.3059,-0.1762,-1.124,-1.124,-1.124,-0.2741,1.2592,-0.9073],
    '5': [-0.3651,1.2625,1.2592,1.2592,1.2592,0.1409,-0.0907,1.0485,-0.5777,-0.6898,-0.6898,-0.9821,0.2036,0.9249,-0.661,-0.691,-1.0686,-1.4289,0.5038,1.1889,0.8226,0.8292,0.9005,-0.5367,-1.0079,-0.9071,-1.2039,-0.8686,0.7492,0.9381,-1.1948,-1.2133,-1.4223,-1.358,0.3876,1.2254,0.1516,0.0187,-0.8485,-0.5283,0.9698,0.4837,-0.2641,0.7823,1.1421,1.0534,0.3048,-1.2116],
    '6': [-1.4602,-0.7131,0.4592,1.1071,0.5764,-0.9623,-0.8056,0.6594,0.1673,-0.5785,-0.4211,-0.6063,0.2158,0.6237,-0.8052,-1.1709,-1.3088,-1.4492,0.9045,0.8553,0.8338,1.0377,0.8603,-0.8154,1.1971,0.8649,-0.8655,-1.0653,0.6562,0.847,1.0367,0.3982,-1.3956,-1.466,0.0079,1.2474,0.1433,0.9469,-0.6286,-0.8831,0.7038,0.6232,-1.329,0.2079,1.0464,1.09,0.5251,-1.113],
    '7': [1.4884,1.4896,1.4896,1.4896,1.4964,1.4755,0.0383,-0.0641,-0.2279,-0.0816,1.2892,0.5771,-0.8555,-0.8875,-0.9325,0.4551,1.226,-0.655,-0.9387,-0.9387,-0.4476,1.3105,0.1515,-0.9246,-0.9387,-0.9339,0.5772,1.111,-0.6596,-0.9387,-0.9387,-0.6266,1.2582,0.3583,-0.8798,-0.9387,-0.9387,0.0094,1.3392,-0.2812,-0.9387,-0.9387,-0.8942,0.568,1.1177,-0.6385,-0.9387,-0.9387],
    '8': [-1.5226,0.2712,1.0862,1.0869,0.3517,-1.4525,0.0099,0.9706,-0.9509,-1.0049,0.9029,0.1044,0.0461,0.8404,-1.4537,-1.5225,0.7311,0.1291,-1.469,0.7868,0.9072,0.8667,0.8613,-1.4081,-0.1327,1.0035,-0.4577,-0.4299,0.9581,-0.0544,1.1721,0.0283,-1.7044,-1.7069,-0.1159,1.1982,0.7433,0.643,-1.11,-1.1525,0.5101,0.8106,-1.2727,0.4497,1.0607,1.0652,0.5192,-1.1928],
    '9': [-1.2074,0.4143,1.1226,1.0839,0.2727,-1.3131,0.5324,0.8743,-0.764,-0.6268,0.8799,0.1468,1.2214,0.186,-1.4634,-1.415,0.2469,1.0115,0.8129,0.7505,-1.071,-0.9949,0.7343,1.1922,-0.8769,0.8642,1.0391,0.9118,0.8646,0.9314,-1.4643,-1.3472,-1.095,-0.8424,0.5127,0.309,-0.6229,-0.4156,-0.6587,0.0084,0.6694,-0.6356,-0.9339,0.4768,1.0899,0.5583,-0.5281,-1.4421]
  };

  /* ---------- 基础工具 ---------- */

  function rowGroups(counts, threshold, minLen) {
    var out = [], s = -1, i;
    for (i = 0; i < counts.length; i++) {
      if (counts[i] > threshold) {
        if (s < 0) s = i;
      } else if (s >= 0) {
        if (i - 1 - s + 1 >= minLen) out.push([s, i - 1]);
        s = -1;
      }
    }
    if (s >= 0 && counts.length - 1 - s + 1 >= minLen) out.push([s, counts.length - 1]);
    return out;
  }

  function mergeRegions(regions, gap) {
    var out = [], i;
    for (i = 0; i < regions.length; i++) {
      var r = regions[i];
      if (out.length && r[0] - out[out.length - 1][1] <= gap) {
        out[out.length - 1][1] = r[1];
      } else {
        out.push([r[0], r[1]]);
      }
    }
    return out;
  }

  /** 一维 Otsu：在「有字行 / 无字行」之间自动找分界 */
  function otsu1d(vals) {
    var i, lo = Infinity, hi = -Infinity;
    for (i = 0; i < vals.length; i++) {
      if (vals[i] < lo) lo = vals[i];
      if (vals[i] > hi) hi = vals[i];
    }
    if (!(hi - lo >= 10)) return null;
    var BINS = 64, hist = new Float64Array(BINS), span = hi - lo;
    for (i = 0; i < vals.length; i++) {
      var b = Math.floor((vals[i] - lo) / span * BINS);
      if (b < 0) b = 0; if (b >= BINS) b = BINS - 1;
      hist[b]++;
    }
    var centers = new Float64Array(BINS);
    for (i = 0; i < BINS; i++) centers[i] = lo + span * (i + 0.5) / BINS;
    var total = 0, sumAll = 0;
    for (i = 0; i < BINS; i++) { total += hist[i]; sumAll += hist[i] * centers[i]; }
    var wB = 0, sumB = 0, best = -1, bestT = null;
    for (i = 0; i < BINS; i++) {
      wB += hist[i];
      if (wB === 0) continue;
      var wF = total - wB;
      if (wF === 0) break;
      sumB += hist[i] * centers[i];
      var mB = sumB / wB, mF = (sumAll - sumB) / wF;
      var v = wB * wF * (mB - mF) * (mB - mF);
      if (v > best) { best = v; bestT = centers[i]; }
    }
    return bestT;
  }

  /** 6x8 面积平均降采样 + 标准化（与生成模板时完全同一算法） */
  function glyphFeature(bright, W, x0, x1, ya, yb) {
    var w = x1 - x0 + 1, h = yb - ya + 1;
    var v = new Float64Array(GW * GH);
    var gy, gx, yy, xx;
    for (gy = 0; gy < GH; gy++) {
      var ry0 = ya + Math.floor(gy * h / GH);
      var ry1 = ya + Math.floor((gy + 1) * h / GH);
      if (ry1 <= ry0) ry1 = ry0 + 1;
      for (gx = 0; gx < GW; gx++) {
        var rx0 = x0 + Math.floor(gx * w / GW);
        var rx1 = x0 + Math.floor((gx + 1) * w / GW);
        if (rx1 <= rx0) rx1 = rx0 + 1;
        var sum = 0, cnt = 0;
        for (yy = ry0; yy < ry1; yy++) {
          var off = yy * W;
          for (xx = rx0; xx < rx1; xx++) { sum += bright[off + xx]; cnt++; }
        }
        v[gy * GW + gx] = cnt ? sum / cnt : 0;
      }
    }
    var i, m = 0;
    for (i = 0; i < v.length; i++) m += v[i];
    m /= v.length;
    var s = 0;
    for (i = 0; i < v.length; i++) s += (v[i] - m) * (v[i] - m);
    s = Math.sqrt(s / v.length);
    if (s < 1e-6) s = 1e-6;
    for (i = 0; i < v.length; i++) v[i] = (v[i] - m) / s;
    return v;
  }

  /** 剔除簇内明显不成比例的噪点块（码带小字、抗锯齿碎片），避免把 9 位码撑成 10 块 */
  function pruneCluster(cl) {
    if (cl.length < 4) return cl;
    var i, mh = 0;
    for (i = 0; i < cl.length; i++) mh += cl[i].h;
    mh /= cl.length;
    var out = [];
    for (i = 0; i < cl.length; i++) {
      if (cl[i].h < mh * 0.45) continue;      // 高度远低于同伴 → 噪点
      if (cl[i].w < mh * 0.15) continue;      // 宽度远低于同伴 → 碎片
      out.push(cl[i]);
    }
    return out.length >= 2 ? out : cl;
  }

  /** 8~9 丛簇评分：邀请码必然是 8~9 个等高、窄体的字形 */
  function scoreCluster(cl) {
    var n = cl.length;
    if (n !== 8 && n !== 9) return null;
    var i, hs = 0;
    for (i = 0; i < n; i++) hs += cl[i].h;
    var mh = hs / n;
    if (mh < 6) return null;
    var hMin = Infinity, hMax = -Infinity;
    for (i = 0; i < n; i++) { if (cl[i].h < hMin) hMin = cl[i].h; if (cl[i].h > hMax) hMax = cl[i].h; }
    if (hMax - hMin > 0.25 * mh) return null;      // 必须等高
    var ws = [];
    for (i = 0; i < n; i++) {
      var ar = cl[i].w / cl[i].h;
      // 逐块宽高比：中文方块字≈0.96 会被排除；两个字符合并≈1.5 也会被排除；
      // 数字 1 天生窄（实测 0.39），因此不再要求各块宽度彼此接近
      if (ar < 0.18 || ar > 0.90) return null;
      ws.push(cl[i].w);
    }
    var wm = 0; for (i = 0; i < n; i++) wm += ws[i]; wm /= n;
    var wv = 0, hv = 0;
    for (i = 0; i < n; i++) { wv += (ws[i] - wm) * (ws[i] - wm); hv += (cl[i].h - mh) * (cl[i].h - mh); }
    return 100 - 100 * Math.sqrt(wv / n) / wm - 100 * Math.sqrt(hv / n) / mh;
  }

  function segCols(counts) {
    var out = [], s = -1, i;
    for (i = 0; i < counts.length; i++) {
      if (counts[i] > 1) { if (s < 0) s = i; }
      else if (s >= 0) { out.push([s, i - 1]); s = -1; }
    }
    if (s >= 0) out.push([s, counts.length - 1]);
    return out;
  }

  function clusterByGap(items, gap) {
    var out = [], cur = [items[0]], i;
    for (i = 1; i < items.length; i++) {
      if (items[i].x0 - cur[cur.length - 1].x1 > gap) { out.push(cur); cur = [items[i]]; }
      else cur.push(items[i]);
    }
    out.push(cur);
    return out;
  }

  /* ---------- 主流程 ---------- */

  /**
   * @param {Uint8ClampedArray|Uint8Array} data RGBA
   * @param {number} W @param {number} H
   * @returns {null|{code:string,d1:number,gap:number,box:number[],n:number}}
   */
  function recognize(data, W, H) {
    var n = W * H, i, p;
    var bright = new Uint8Array(n);
    for (i = 0, p = 0; i < n; i++, p += 4) {
      if (data[p + 1] > BRIGHT) bright[i] = 1;
    }

    // ---- 通道 1：红底码带（拼多多分享图）----
    var warmRow = new Int32Array(H), y, x;
    for (y = 0; y < H; y++) {
      var c = 0, off = y * W;
      for (x = 0; x < W; x++) {
        p = (off + x) * 4;
        var r = data[p], g = data[p + 1];
        if (r - g > 60 && r > 150) c++;
      }
      warmRow[y] = c;
    }
    var gate = new Int32Array(H);
    for (y = 0; y < H; y++) gate[y] = warmRow[y];
    var res = scanRegions(bright, W, H, gate, W * 0.40, Math.max(10, Math.floor(H * 0.02)));
    if (res) return res;

    // ---- 通道 2：兜底，任意底色（裁到只剩数字、黑字白底等）----
    var inkRow = new Int32Array(H);
    for (y = 0; y < H; y++) {
      var c2 = 0, off2 = y * W;
      for (x = 0; x < W; x++) c2 += bright[off2 + x];
      inkRow[y] = c2;
    }
    // 亮字占比极低时，翻转极性再试（深色字压在浅底上）
    var darkRow = new Int32Array(H);
    var dark = new Uint8Array(n);
    for (i = 0, p = 0; i < n; i++, p += 4) {
      var lum = (data[p] * 299 + data[p + 1] * 587 + data[p + 2] * 114) / 1000;
      if (lum < 110) { dark[i] = 1; darkRow[i / W | 0]++; }
    }
    var anyInk = 0;
    for (y = 0; y < H; y++) anyInk += inkRow[y];
    if (anyInk < n * 0.0005) {
      var res2 = scanRegions(dark, W, H, darkRow, 0, Math.max(10, Math.floor(H * 0.02)), true);
      if (res2) return res2;
    }
    return null;
  }

  function scanRegions(bright, W, H, gate, gateThr, mergeGap, wholeBand) {
    var regions = rowGroups(gate, gateThr, 10);
    regions = mergeRegions(regions, mergeGap);
    var best = null, i, y;
    for (i = 0; i < regions.length; i++) {
      var y0 = regions[i][0], y1 = regions[i][1];
      var rowb = new Float64Array(y1 - y0 + 1);
      for (y = y0; y <= y1; y++) {
        var c = 0, off = y * W;
        for (var x = 0; x < W; x++) c += bright[off + x];
        rowb[y - y0] = c;
      }
      var t = otsu1d(rowb);
      var subs;
      if (t === null) {
        subs = wholeBand ? [[0, rowb.length - 1]] : [];
      } else {
        subs = rowGroups(rowb, t, 6);
      }
      for (var k = 0; k < subs.length; k++) {
        var sy0 = y0 + subs[k][0], sy1 = y0 + subs[k][1];
        if (sy1 - sy0 < 6) continue;
        var cols = new Int32Array(W);
        for (y = sy0; y <= sy1; y++) {
          var o3 = y * W;
          for (var xx = 0; xx < W; xx++) cols[xx] += bright[o3 + xx];
        }
        var segs = segCols(cols), info = [], j;
        for (j = 0; j < segs.length; j++) {
          var x0 = segs[j][0], x1 = segs[j][1];
          if (x1 - x0 + 1 < 3) continue;
          var ya = -1, yb = -1;
          for (y = sy0; y <= sy1; y++) {
            var o4 = y * W, hit = 0;
            for (var x2 = x0; x2 <= x1; x2++) if (bright[o4 + x2]) { hit = 1; break; }
            if (hit) { if (ya < 0) ya = y; yb = y; }
          }
          if (ya < 0) continue;
          info.push({ x0: x0, x1: x1, ya: ya, yb: yb, h: yb - ya + 1, w: x1 - x0 + 1 });
        }
        if (info.length < 2) continue;
        info.sort(function (a, b) { return a.x0 - b.x0; });
        var gaps = [];
        for (j = 1; j < info.length; j++) gaps.push(info[j].x0 - info[j - 1].x1);
        var gs = gaps.slice().sort(function (a, b) { return a - b; });
        var med = gs[Math.floor(gs.length / 2)];
        var clusters = clusterByGap(info, Math.max(med * 3, 6));
        for (var m = 0; m < clusters.length; m++) {
          var cpr = pruneCluster(clusters[m]);
          var sc = scoreCluster(cpr);
          if (sc === null) continue;
          if (!best || sc > best.score) {
            best = { score: sc, cl: cpr, y: [sy0, sy1], bright: bright, W: W };
          }
        }
      }
    }
    if (!best) return null;

    // ---- 逐个字形分类 ----
    var digits = '', d1max = 0, gapMin = Infinity;
    var cl = best.cl;
    for (i = 0; i < cl.length; i++) {
      var f = glyphFeature(bright, W, cl[i].x0, cl[i].x1, cl[i].ya, cl[i].yb);
      var bestCh = null, bd = Infinity, sd = Infinity;
      for (var d = 0; d < 10; d++) {
        var ch = String(d), tpl = TPL[ch];
        if (!tpl || !tpl.length) continue;
        var acc = 0;
        for (var q = 0; q < f.length; q++) { var diff = f[q] - tpl[q]; acc += diff * diff; }
        var dist = Math.sqrt(acc / f.length);
        if (dist < bd) { sd = bd; bd = dist; bestCh = ch; }
        else if (dist < sd) { sd = dist; }
      }
      digits += bestCh;
      if (bd > d1max) d1max = bd;
      var gp = sd - bd;
      if (gp < gapMin) gapMin = gp;
    }
    var box = [cl[0].x0, Math.min.apply(null, cl.map(function (g) { return g.ya; })),
               cl[cl.length - 1].x1, Math.max.apply(null, cl.map(function (g) { return g.yb; }))];
    return { code: digits, d1: d1max, gap: gapMin, box: box, n: cl.length,
             confident: (d1max < MAX_D1 && gapMin > MIN_GAP) };
  }

  root.PddOcrCore = { recognize: recognize, TPL: TPL, BRIGHT: BRIGHT, GW: GW, GH: GH,
                      MAX_D1: MAX_D1, MIN_GAP: MIN_GAP };
})(typeof window !== 'undefined' ? window : globalThis);
</script>

<script>
function showToast(msg, type) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (type || 'success');
  setTimeout(function(){ t.className = 'toast'; }, 2500);
}

/** HTML 转义：所有拼进 innerHTML 的动态值（归属地、联系方式、公告等）必须先转义，防存储型 XSS */
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
    return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
  });
}

/** 是否 http(s) 链接。协议判定只留这一份，避免两处判断逻辑漂移。 */
function isHttpUrl(u) {
  var s = String(u || '').trim();
  return s.indexOf('http://') === 0 || s.indexOf('https://') === 0;
}

/** 链接协议白名单：只允许 http/https，拒绝 javascript:/data: 等（配合后端 sanitizeUrl 双保险） */
function safeHref(u) {
  var s = String(u || '').trim();
  return isHttpUrl(s) ? escapeHtml(s) : 'javascript:void(0)';
}

async function submitCode() {
  var input = document.getElementById('codeInput');
  var btn = document.getElementById('submitBtn');
  var code = input.value.trim();

  if (!code) { showToast('请输入邀请码', 'error'); return; }
  if (code.length < 8 || code.length > 9 || !/^\\d+$/.test(code)) {
    showToast('邀请码必须是8-9位数字', 'error');
    return;
  }

  btn.disabled = true;
  btn.textContent = '提交中...';

  try {
    // 蜜罐：读取隐藏字段值
    var honeypot = document.querySelector('.honeypot input[name="website"]')?.value || '';

    var res = await fetch('/api/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code, website: honeypot })
    });
    var data = await res.json();

    if (data.success) {
      showToast(data.message || '提交成功', 'success');
      input.value = '';
      loadCodes();
    } else {
      showToast(data.error || '提交失败', 'error');
    }
  } catch(e) {
    showToast('网络错误', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '立即提交';
  }
}

/** 读取自己用过的码 id（localStorage，用于区分"我用的"和"别人用的"） */
function getMyUsed() {
  try { return JSON.parse(localStorage.getItem('pdd_my_used') || '[]'); } catch(e) { return []; }
}

/* ============ 识别截图：本地像素识别（毫秒级） + 服务端 AI 兜底 ============
   拼多多分享图里的邀请码是固定字体的受控印刷体（红底金字/青字），不必加载 OCR 模型：
   直接「定位红区 → Otsu 行分离 → 列切分 → 间隙聚类找数字簇 → 6x8 归一化栅格比模板」，
   全程在浏览器内存里完成，零网络、零模型、零等待。内核见上方 window.PddOcrCore。 */

var _ocrBusy = false;

/** 触发选图（内嵌识别按钮） */
function pickCodeImage() {
  if (_ocrBusy) return;
  document.getElementById('ocrFile').click();
}

/** 识别按钮忙碌态 */
function setScanBusy(busy) {
  _ocrBusy = busy;
  var btn = document.getElementById('scanBtn');
  if (!btn) return;
  btn.disabled = busy;
  var txt = btn.querySelector('.scan-text');
  if (txt) txt.textContent = busy ? '识别中' : '识别截图';
}

/** 图片文件 → HTMLImageElement */
function loadImageFile(file) {
  return new Promise(function(resolve, reject) {
    var url = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function() { resolve({ img: img, url: url }); };
    img.onerror = function() { URL.revokeObjectURL(url); reject(new Error('图片加载失败')); };
    img.src = url;
  });
}

/** 本地像素识别：返回 {code,d1,gap,confident,preview} 或 null */
function recognizeCodeLocally(img) {
  if (!window.PddOcrCore) return null;
  // 长边压到 1600 以内：保留字形细节，同时把取像素 + 识别的耗时控制在几十毫秒
  var MAXW = 1600;
  var scale = img.naturalWidth > MAXW ? MAXW / img.naturalWidth : 1;
  var w = Math.max(1, Math.round(img.naturalWidth * scale));
  var h = Math.max(1, Math.round(img.naturalHeight * scale));
  var canvas = document.createElement('canvas');
  canvas.width = w; canvas.height = h;
  var ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(img, 0, 0, w, h);
  var hit = window.PddOcrCore.recognize(ctx.getImageData(0, 0, w, h).data, w, h);
  if (!hit || !hit.code) return null;
  hit.preview = cropPreview(ctx, hit.box, w, h);
  return hit;
}

/** 裁出码区做成预览图（上下留 60% 余量，便于肉眼核对） */
function cropPreview(ctx, box, W, H) {
  try {
    var x0 = box[0], y0 = box[1], x1 = box[2], y1 = box[3];
    var padY = Math.round((y1 - y0 + 1) * 0.6) + 4;
    var padX = 10;
    var sx = Math.max(0, x0 - padX), sy = Math.max(0, y0 - padY);
    var ex = Math.min(W, x1 + 1 + padX), ey = Math.min(H, y1 + 1 + padY);
    var cw = ex - sx, ch = ey - sy;
    if (cw <= 0 || ch <= 0) return null;
    var c = document.createElement('canvas');
    c.width = cw; c.height = ch;
    c.getContext('2d').drawImage(ctx.canvas, sx, sy, cw, ch, 0, 0, cw, ch);
    return c.toDataURL('image/png');
  } catch(e) { return null; }
}

/** 选图后：本地识别优先；低置信度或没识别到时，按后台模式决定是否走 AI 兜底 */
async function handleOcrFile(fileEl) {
  var file = fileEl.files && fileEl.files[0];
  fileEl.value = '';   // 允许重复选择同一张图
  if (!file) return;
  if (file.size > 4 * 1024 * 1024) { showToast('图片太大，请选小于 4MB 的截图', 'error'); return; }

  setScanBusy(true);
  var url = null, hit = null;
  try {
    var loaded = await loadImageFile(file);
    url = loaded.url;

    var t0 = Date.now();
    hit = recognizeCodeLocally(loaded.img);
    var ms = Date.now() - t0;

    if (hit && hit.code && hit.confident) {
      openOcrModal(hit.code, hit.preview, '本地识别完成 · ' + ms + 'ms', true);
      return;
    }
    // 本地没拿到或置信度偏低：只有后台开了 AI 模式才调服务端识图（省额度）
    if ((window._ocrMode || 'local') === 'ai') {
      var aiCode = await aiOcr(file);
      if (aiCode) { openOcrModal(aiCode, hit ? hit.preview : null, 'AI 识别完成', true); return; }
    }
    if (hit && hit.code) {   // 本地有结果但不够确定，交给用户人工核对
      openOcrModal(hit.code, hit.preview, '本地识别置信度偏低，请核对后提交', false);
      return;
    }
    showToast('没识别到邀请码，请手动输入', 'error');
    document.getElementById('codeInput').focus();
  } catch(e) {
    console.error('识别失败:', e);
    showToast('识别出错，请手动输入邀请码', 'error');
  } finally {
    if (url) URL.revokeObjectURL(url);
    setScanBusy(false);
  }
}

/** 服务端 AI 识图（/api/ocr?force=ai），成功返回码，失败返回 null */
async function aiOcr(file) {
  try {
    var formData = new FormData();
    formData.append('image', file);
    var res = await fetch('/api/ocr?force=ai', { method: 'POST', body: formData });
    var data = await res.json();
    if (data.success && data.code) return data.code;
    if (data.fallback === 'local') showToast('AI 识图未开启，请手动输入', 'error');
    else showToast(data.error || 'AI 识别失败，请手动输入', 'error');
    return null;
  } catch(e) {
    showToast('AI 识别请求失败，请手动输入', 'error');
    return null;
  }
}

/* ---------- 识别结果确认弹窗 ---------- */

/** 打开确认弹窗：展示裁出的码区原图 + 可编辑的码 */
function openOcrModal(code, preview, tip, confident) {
  var img = document.getElementById('ocrPreview');
  if (preview) { img.src = preview; img.style.display = 'block'; }
  else { img.removeAttribute('src'); img.style.display = 'none'; }
  document.getElementById('ocrCodeInput').value = code || '';
  var tipEl = document.getElementById('ocrTip');
  tipEl.textContent = tip || '';
  tipEl.className = 'ocr-tip' + (confident ? '' : ' warn');
  openModal('ocrModal');
  var inp = document.getElementById('ocrCodeInput');
  setTimeout(function() { inp.focus(); inp.select(); }, 60);
}

function closeOcrModal() { closeModal('ocrModal'); }

/** 弹窗里点「确认提交」：校验后写入主输入框并提交 */
function confirmOcrCode() {
  var code = (document.getElementById('ocrCodeInput').value || '').trim();
  if (!/^[0-9]{8,9}$/.test(code)) { showToast('请输入 8-9 位数字邀请码', 'error'); return; }
  closeOcrModal();
  document.getElementById('codeInput').value = code;
  submitCode();
}

/** 「智能直达」右端 ⓘ 帮助 */
function showSmartHelp() {
  var overlay = document.createElement('div');
  overlay.className = 'modal-mask show';
  overlay.innerHTML = '<div class="modal">' +
    '<button class="close-x" onclick="this.parentNode.parentNode.remove()">×</button>' +
    '<h2>🚀 智能直达 怎么用</h2>' +
    '<p style="font-size:14px;line-height:1.85;color:#374151;margin:0 0 10px">' +
    '点一下「智能直达」，系统会自动挑一个<b>还没被用过的最新互助码</b>并打开拼多多的搜索页完成助力，不用自己在列表里翻、也不用手动复制粘贴。' +
    '</p>' +
    '<p style="font-size:14px;line-height:1.85;color:#374151;margin:0 0 10px">' +
    '<b>注意：</b>跳转前请先手动从拼多多首页进入福袋活动界面（首页 → 百亿补贴 → 百亿消费券 → 福袋），否则组队会失败。' +
    '</p>' +
    '<p style="font-size:13px;line-height:1.8;color:#6b7280;margin:0 0 14px">' +
    '另外：互助码如果在截图里，直接点输入框右侧的「识别截图」即可，不用手打。' +
    '</p>' +
    '<button class="modal-ok" onclick="this.parentNode.parentNode.remove()">知道了</button>' +
    '</div>';
  document.body.appendChild(overlay);
  overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
}

/** 记录自己用过的码 id */
function addMyUsed(id) {
  var list = getMyUsed();
  if (list.indexOf(id) === -1) list.push(id);
  try { localStorage.setItem('pdd_my_used', JSON.stringify(list)); } catch(e) {}
}
/** 智能直达用过的码 id（显示"刚使用"+举报） */
function getQuickUsed() {
  try { return JSON.parse(localStorage.getItem('pdd_quick_used') || '[]'); } catch(e) { return []; }
}
function addQuickUsed(id) {
  var list = getQuickUsed();
  if (list.indexOf(id) === -1) list.push(id);
  try { localStorage.setItem('pdd_quick_used', JSON.stringify(list)); } catch(e) {}
}

var lastCodeIds = []; // 上一次列表的 id 集合，用于刷新提示

async function loadCodes(fromAutoRefresh) {
  try {
    var res = await fetch('/api/codes');
    var data = await res.json();
    var listEl = document.getElementById('numberList');

    if (data.success && data.data.length > 0) {
      var myUsed = getMyUsed().filter(function(id) {
        return data.data.some(function(x) { return x.id === id; });
      });
      try { localStorage.setItem('pdd_my_used', JSON.stringify(myUsed)); } catch(e) {}
      var quickUsed = getQuickUsed().filter(function(id) {
        return data.data.some(function(x) { return x.id === id; });
      });
      try { localStorage.setItem('pdd_quick_used', JSON.stringify(quickUsed)); } catch(e) {}

      var currentIds = data.data.map(function(x){ return x.id; });
      var freshCount = currentIds.filter(function(id){
        return lastCodeIds.indexOf(id) === -1 && data.data.some(function(x){ return x.id === id && x.status === 'active'; });
      }).length;

      listEl.innerHTML = data.data.map(function(item) {
        var time = new Date(item.created_at);
        var timeStr = (time.getMonth()+1) + '/' + time.getDate() + ' ' +
          String(time.getHours()).padStart(2,'0') + ':' + String(time.getMinutes()).padStart(2,'0');
        var loc = item.location || '';
        var locShort = escapeHtml(loc.substring(0, 12));
        var metaStr = locShort ? timeStr + ' · ' + locShort : timeStr;
        var actionsHtml, usedCls = '';
        if (item.status === 'active') {
          actionsHtml = '<a class="jump-btn" href="javascript:void(0)" onclick="useCode(' + item.id + ', this)">跳转</a>';
        } else {
          usedCls = ' used';
          var isSelf = myUsed.indexOf(item.id) !== -1;
          var isQuick = quickUsed.indexOf(item.id) !== -1;
          if (isQuick) {
            actionsHtml = '<span class="used-tag" style="background:#8b5cf6;color:#fff">刚使用</span>' +
              '<button class="report-btn" onclick="reportCode(' + item.id + ')">假码举报</button>';
          } else {
            actionsHtml = '<span class="used-tag">已使用</span>';
          }
        }
        return '<li class="list-item' + usedCls + '">' +
          '<div class="info"><span class="number">' + escapeHtml(item.code_masked) + '</span>' +
          '<div class="meta">' + metaStr + '</div></div>' +
          '<div class="actions">' + actionsHtml + '</div>' +
        '</li>';
      }).join('');

      if (fromAutoRefresh && lastCodeIds.length > 0 && freshCount > 0) {
        showToast('✨ 已自动刷新，获取到 ' + freshCount + ' 条新码！', 'success');
      }
      lastCodeIds = currentIds;
    } else {
      listEl.innerHTML = '<li class="empty" style="list-style:none">暂无互助码，快来提交第一个吧！</li>';
      lastCodeIds = [];
    }
  } catch(e) {
    document.getElementById('numberList').innerHTML = '<li class="empty" style="list-style:none">加载失败</li>';
  }
}

/** 首次跳转前的提醒弹窗：必须先从拼多多首页进福袋界面，否则组队失败。
 *  同一用户（浏览器）只提示一次，"跳转"和"智能直达"共用同一标记。
 *  返回 Promise<boolean>：true=继续跳转，false=用户取消 */
function ensureJumpTip() {
  return new Promise(function(resolve) {
    var KEY = 'pdd_jump_tip_ok';
    try { if (localStorage.getItem(KEY) === '1') return resolve(true); } catch(e) { return resolve(true); }

    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:9999;padding:16px;';
    var box = document.createElement('div');
    box.style.cssText = 'background:#fff;border-radius:12px;padding:22px 20px;max-width:340px;width:100%;box-shadow:0 8px 30px rgba(0,0,0,.2);';
    var title = document.createElement('div');
    title.style.cssText = 'font-size:16px;font-weight:600;margin-bottom:10px;text-align:center;color:#E02E24;';
    title.textContent = '⚠️ 重要：请先进入福袋界面';
    var sub = document.createElement('div');
    sub.style.cssText = 'font-size:13.5px;color:#444;line-height:1.75;margin-bottom:8px;';
    sub.innerHTML = '助力前请先<b>手动从拼多多首页进入福袋活动界面</b>：<br>' +
      '<span style="color:#E02E24">拼多多首页 → 百亿补贴 → 百亿消费券 → 福袋</span><br>' +
      '否则直接跳转搜索，<b>组队会失败</b>。';
    var tipFoot = document.createElement('div');
    tipFoot.style.cssText = 'font-size:12px;color:#999;margin-bottom:16px;text-align:center;';
    tipFoot.textContent = '此提示仅显示一次，确定后将正常跳转';
    var okBtn = document.createElement('button');
    okBtn.textContent = '我已进入福袋界面，继续跳转';
    okBtn.style.cssText = 'display:block;width:100%;padding:11px;margin-bottom:10px;border:none;border-radius:8px;background:#E02E24;color:#fff;font-size:14px;font-weight:600;cursor:pointer;';
    var cancelBtn = document.createElement('button');
    cancelBtn.textContent = '先去拼多多，稍后再来';
    cancelBtn.style.cssText = 'display:block;width:100%;padding:11px;border:1px solid #ddd;border-radius:8px;background:#fff;color:#666;font-size:14px;cursor:pointer;';

    function done(ok) {
      if (overlay.parentNode) document.body.removeChild(overlay);
      if (ok) { try { localStorage.setItem(KEY, '1'); } catch(e) {} }
      resolve(ok);
    }
    okBtn.onclick = function() { done(true); };
    cancelBtn.onclick = function() { done(false); };
    overlay.addEventListener('click', function(e) { if (e.target === overlay) done(false); });

    box.appendChild(title); box.appendChild(sub); box.appendChild(tipFoot);
    box.appendChild(okBtn); box.appendChild(cancelBtn);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
  });
}

/** 延迟打开拼多多：先弹一个带倒计时的提示，让用户看清"要先在福袋界面"再跳。
 *  延迟 1.6s —— 在浏览器 user activation 有效期（约 5s）内，window.open 不会被拦截。 */
function openPddDelayed(code, prefix) {
  var url = 'https://mobile.yangkeduo.com/search_result.html?search_key=' + code;
  var t = document.getElementById('toast');
  var left = 2;
  function paint() {
    t.textContent = (prefix ? prefix + '，' : '') + left + ' 秒后跳转拼多多，请确认已在福袋界面';
    t.className = 'toast show success';
  }
  paint();
  var timer = setInterval(function() {
    left--;
    if (left > 0) { paint(); return; }
    clearInterval(timer);
    t.className = 'toast';
    window.open(url, '_blank');
  }, 800);
}

async function useCode(id, btn) {
  if (!(await ensureJumpTip())) return;
  try {
    var res = await fetch('/api/use/' + id, { method: 'POST' });
    var data = await res.json();
    if (data.success) {
      // 记录到自己名下：当前用户显示"已使用"，别人看是灰色
      addMyUsed(id);
      var item = btn.closest('.list-item');
      btn.outerHTML = '<span class="used-tag">已使用</span>';
      // 延迟 1.6 秒再打开拼多多，先让用户看清提示
      openPddDelayed(data.code, '');
      // 立即刷新，让 30 秒倒计时接管
      setTimeout(loadCodes, 800);
    } else {
      showToast(data.error || '操作失败', 'error');
      loadCodes(); // 状态已变化，刷新同步
    }
  } catch(e) {
    showToast('操作失败', 'error');
  }
}

/** 智能直达：一键使用最新的未使用码并打开拼多多 */
async function quickUse() {
  var btn = document.getElementById('smartBtn');
  btn.disabled = true;
  if (!(await ensureJumpTip())) { btn.disabled = false; return; }
  try {
    var res = await fetch('/api/quick-use', { method: 'POST' });
    var data = await res.json();
    if (data.success) {
      // 后端直接返回 id，本地标记"刚使用"（无需再模糊匹配）
      addQuickUsed(data.id);
      openPddDelayed(data.code, '智能直达成功');
      setTimeout(loadCodes, 600);
    } else {
      showToast(data.error || '暂无可用互助码', 'error');
    }
  } catch(e) {
    showToast('网络错误', 'error');
  } finally {
    setTimeout(function(){ btn.disabled = false; }, 1500);
  }
}

/** 举报假码 */
async function reportCode(id) {
  if (!confirm('确定举报该码为假码吗？恶意举报会被记录！')) return;
  try {
    var res = await fetch('/api/report/' + id, { method: 'POST' });
    var data = await res.json();
    showToast(data.message || data.error || '操作完成', data.success ? 'success' : 'error');
  } catch(e) {
    showToast('网络错误', 'error');
  }
}

/** 弹窗通用开关 */
function openModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }
function closeNoticeBar() { document.getElementById('noticeBar').style.display = 'none'; try { localStorage.setItem('pdd_notice_closed','1'); } catch(e){} }
function showNoticeModal() {
  var txt = document.getElementById('noticeText').textContent;
  var modal = document.createElement('div');
  modal.className = 'modal-mask show';
  // txt 来自后台公告（textContent 读出的原文），拼进 innerHTML 前必须转义
  modal.innerHTML = '<div class="modal"><button class="close-x" onclick="this.parentNode.parentNode.remove()">×</button><h2>📢 公告详情</h2><p style="white-space:pre-line;font-size:15px;line-height:1.8;color:#333">' + escapeHtml(txt) + '</p></div>';
  document.body.appendChild(modal);
  modal.addEventListener('click', function(e){ if (e.target === modal) modal.remove(); });
}

/** 联系我们 */
function openContact() {
  var body = document.getElementById('contactBody');
  var qqGroup = window._cfg && window._cfg.qq_group;
  var qqOwner = window._cfg && window._cfg.qq_owner;
  var html = '';
  if (qqGroup) {
    html += '<div class="contact-item"><strong>🚀 官方交流互助群</strong><p>群号：' + escapeHtml(qqGroup) + ' (进群不迷路，第一时间获取系统升级信息和福袋活动开放消息)</p></div>';
    document.getElementById('qqJoinBtn').style.display = 'block';
  } else {
    document.getElementById('qqJoinBtn').style.display = 'none';
  }
  if (qqOwner) {
    html += '<div class="contact-item"><strong>🛡️ 站长 QQ</strong><p>QQ号：' + escapeHtml(qqOwner) + ' (如遇被封禁申诉、或功能建议反馈，请联系我，也可以进群联系群主)</p></div>';
  }
  if (!html) { showToast('暂未配置联系方式', 'error'); return; }
  body.innerHTML = html;
  openModal('contactModal');
}

/** 一键加群 */
function joinQQ() {
  var qqGroup = window._cfg && window._cfg.qq_group;
  if (!qqGroup) return;
  window.open('https://qm.qq.com/q/group?key=' + qqGroup, '_blank');
}

/** 小黑屋公示 */
async function openBlacklist() {
  openModal('blacklistModal');
  var body = document.getElementById('blacklistBody');
  body.innerHTML = '<div class="loading">加载中...</div>';
  try {
    var res = await fetch('/api/blacklist');
    var data = await res.json();
    var rows = data.data || [];
    if (rows.length === 0) {
      body.innerHTML = '<div class="empty" style="padding:24px">暂无违规记录，环境良好 🎉</div>';
    } else {
      var rowsHtml = rows.map(function(r) {
        var t = new Date(r.created_at);
        var ts = String(t.getMonth()+1).padStart(2,'0') + '-' + String(t.getDate()).padStart(2,'0') + ' ' +
          String(t.getHours()).padStart(2,'0') + ':' + String(t.getMinutes()).padStart(2,'0');
        var remaining = escapeHtml(r.remaining || '永久');
        return '<tr><td>' + ts + '</td><td class="ip">' + escapeHtml(r.ip) + '</td><td>' + (escapeHtml(r.location) || '未知') + '</td><td>' + remaining + '</td></tr>';
      }).join('');
      body.innerHTML = '<table class="bb-table"><thead><tr><th>时间</th><th>违规 IP</th><th>归属地</th><th>剩余封禁</th></tr></thead><tbody>' +
        rowsHtml + '</tbody></table>' +
        '<div class="bb-sync">系统每10分钟自动同步公示名单</div>' +
        '<button class="modal-ok" onclick="closeModal(\\'blacklistModal\\')">我知道了</button>';
    }
  } catch(e) {
    body.innerHTML = '<div class="empty" style="padding:24px">加载失败</div>';
  }
}

/** 弹窗广告关闭 */
function closeAdPop() {
  document.getElementById('adPop').classList.remove('show');
  try { sessionStorage.setItem('pdd_ad_closed', '1'); } catch(e) {}
}

/** 弹窗广告：展示（有广告且本次会话未关闭） */
function showAdPop(ads, title, sub) {
  try { if (sessionStorage.getItem('pdd_ad_closed')) return; } catch(e) {}
  var head = document.getElementById('adPopHead');
  if (title || sub) {
    document.getElementById('adPopTitle').textContent = title || '';
    document.getElementById('adPopSub').textContent = sub || '';
    head.style.display = 'block';
  } else {
    head.style.display = 'none';
  }
  var links = document.getElementById('adPopLinks');
  var colors = ['#4a9eff', '#ff9500', '#2a71d0', '#0f95d0'];
  links.innerHTML = ads.map(function(ad, i) {
    var href = safeHref(ad.link_url);
    var target = (href !== 'javascript:void(0)') ? 'target="_blank" rel="noopener"' : '';
    var bg = colors[i % colors.length];
    return '<a class="ad-link" href="' + href + '" ' + target + '>' +
      '<span class="ad-icon" style="background:' + bg + '">' + (i + 1) + '</span>' +
      '<span class="txt">点击查看</span>' +
    '</a>';
  }).join('');
  document.getElementById('adPop').classList.add('show');
}

/** 加载首页配置：公告 + 广告 + 联系方式 + 开关 */
async function loadConfig() {
  // 先记录本次访问
  try { await fetch('/api/visit', { method: 'POST' }); } catch(e) {}
  try {
    var res = await fetch('/api/config');
    var data = await res.json();
    if (!data.success) return;
    var cfg = data.data;
    window._cfg = cfg;

    // 显示今日统计
    document.getElementById('statIPs').textContent = cfg.today_ips != null ? cfg.today_ips : '-';
    document.getElementById('statVisits').textContent = cfg.today_visits != null ? cfg.today_visits : '-';
    document.getElementById('statSubmits').textContent = cfg.today_submits != null ? cfg.today_submits : '-';

    // 滚动公告（只在配置了公告时显示）
    var noticeBar = document.getElementById('noticeBar');
    if (cfg.notice) {
      var nt = document.getElementById('noticeText');
      nt.textContent = cfg.notice;
      noticeBar.style.display = 'flex';
      // 动态计算滚动时长：速度恒定（约 90px/秒），文字越长滚动越慢，避免长公告飞快
      try {
        var w = nt.offsetWidth || nt.scrollWidth || 0;
        var dur = Math.max(15, w / 90);
        nt.style.animationDuration = dur.toFixed(1) + 's';
      } catch (e) {}
    } else {
      noticeBar.style.display = 'none';
    }

    // 广告：弹窗（可关闭）+ 静态位（无广告都不显示）
    var adSection = document.getElementById('adSection');
    if (cfg.ads && cfg.ads.length > 0) {
      adSection.innerHTML = cfg.ads.map(function(ad) {
        var href = safeHref(ad.link_url);
        var target = (href !== 'javascript:void(0)') ? 'target="_blank" rel="noopener"' : '';
        return '<a class="ad-banner" href="' + href + '" ' + target + '>' +
          '<img src="' + escapeHtml(ad.image_url) + '" alt="广告" loading="lazy">' +
        '</a>';
      }).join('');
      adSection.style.display = 'block';
      // 弹窗广告（延迟1.2秒展示，不打扰首次加载）
      setTimeout(function() { showAdPop(cfg.ads, cfg.ad_title, cfg.ad_sub); }, 1200);
    } else {
      adSection.innerHTML = '';
      adSection.style.display = 'none';
    }

    // 刷新间隔
    window._refreshInterval = (cfg.refresh_interval && cfg.refresh_interval >= 3 && cfg.refresh_interval <= 30) ? cfg.refresh_interval : 5;

    // 智能直达开关
    if (cfg.smart_enabled === false) {
      document.getElementById('smartBtn').style.display = 'none';
    }

    // iOS 快捷指令按钮：地址来自后台配置，留空则隐藏按钮
    // 赋值给 DOM 属性要用原始值（safeHref 是给 HTML 拼接用的，会转义）；
    // 协议再判一次，防止 href 被设成 javascript: 伪协议
    var iosBtn = document.getElementById('iosShortcutBtn');
    if (cfg.ios_url && isHttpUrl(cfg.ios_url)) {
      iosBtn.href = String(cfg.ios_url);
      iosBtn.style.display = '';   // 清空内联样式，回落到 CSS 里的默认 display
    } else {
      iosBtn.style.display = 'none';
    }

    // 识图模式：存全局，本地识别没成功时决定是否自动走服务端 AI 兜底
    window._ocrMode = (cfg.ocr_mode === 'ai') ? 'ai' : 'local';
  } catch(e) {
    // 配置加载失败静默处理，不影响主功能
  }
}

// 回车提交
document.getElementById('codeInput').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') submitCode();
});

// 初始加载
loadCodes();
loadConfig().then(function() {
  // 配置加载完成后再启动倒计时，确保读取到刷新间隔
  startCountdown();
});
var countdown = 5;
var resultShown = false;
var resultTimer = null;
var countdownTimer = null;

function startCountdown() {
  var interval = (window._refreshInterval && window._refreshInterval >= 3 && window._refreshInterval <= 30) ? window._refreshInterval : 5;
  countdown = interval;
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(function() {
    countdown--;
    if (countdown <= 0) {
      var newInterval = (window._refreshInterval && window._refreshInterval >= 3 && window._refreshInterval <= 30) ? window._refreshInterval : 5;
      countdown = newInterval;
      loadCodes(true);
    } else {
      var secEl = document.getElementById('countdownSec');
      if (secEl) secEl.textContent = countdown;
    }
  }, 1000);
}

// 启动倒计时（等 config 加载后再启动，确保间隔正确）
setTimeout(startCountdown, 800);
</script>
</body>
</html>`;

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理后台 - PDD福袋互助</title>
<meta name="robots" content="noindex,nofollow">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;color:#333}
.login-box{max-width:400px;margin:80px auto;padding:30px;background:#fff;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,.08)}
.login-box h2{text-align:center;margin-bottom:20px}
.login-box input{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;margin-bottom:12px;font-size:15px}
.login-box button{width:100%;padding:12px;background:#2a71d0;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer}
.admin{max-width:900px;margin:0 auto;padding:16px}
.nav{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.nav button{padding:8px 16px;border:none;border-radius:8px;background:#fff;cursor:pointer;font-size:14px}
.nav button.active{background:#2a71d0;color:#fff}
.card{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px}
.card h3{margin-bottom:12px;font-size:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}
.stat-box{background:#f8f9fa;border-radius:8px;padding:16px;text-align:center}
.stat-box .num{font-size:28px;font-weight:700;color:#2a71d0}
.stat-box .label{font-size:12px;color:#666;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #f0f0f0}
th{background:#fafafa;font-weight:600}
tr:hover{background:#fafafa}
.btn-sm{padding:4px 10px;border:none;border-radius:4px;font-size:12px;cursor:pointer;color:#fff}
.btn-danger{background:#e53935}
.btn-success{background:#07c160}
.input-row{display:flex;gap:8px;margin-bottom:12px}
.input-row input{flex:1;padding:8px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px}
.input-row button{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:14px;color:#fff;background:#2a71d0}
.page-nav{display:flex;gap:8px;justify-content:center;margin-top:12px}
.page-nav button{padding:6px 12px;border:1px solid #ddd;border-radius:4px;background:#fff;cursor:pointer}
.page-nav button.active{background:#2a71d0;color:#fff;border-color:#2a71d0}
.mono{font-family:monospace}
.hidden{display:none}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;font-weight:600;color:#444;margin-bottom:6px}
.form-group .hint{font-size:12px;color:#999;margin-top:4px}
.form-group textarea{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px;font-family:inherit;resize:vertical;min-height:80px}
.form-group textarea:focus,.form-group input:focus{outline:none;border-color:#2a71d0}
.form-group input[type="text"]{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px}
.save-btn{padding:10px 32px;background:#2a71d0;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.save-btn:active{transform:scale(.97)}
.ad-row{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.ad-row input{flex:1;padding:8px 12px;border:1px solid #ddd;border-radius:6px;font-size:13px}
.ad-row .rm-btn{padding:6px 12px;background:#e53935;color:#fff;border:none;border-radius:6px;font-size:12px;cursor:pointer;white-space:nowrap}
.add-ad-btn{padding:8px 16px;background:#fff;border:1px dashed #2a71d0;color:#2a71d0;border-radius:8px;font-size:13px;cursor:pointer}
.add-ad-btn:hover{background:#fdf2f2}
.ad-preview{max-width:260px;margin:8px 0;border-radius:8px;overflow:hidden;border:1px solid #eee;display:none}
.ad-preview img{display:block;width:100%}
</style>
</head>
<body>

<!-- 登录页 -->
<div class="login-box" id="loginBox">
  <h2>管理后台登录</h2>
  <input type="password" id="adminKeyInput" placeholder="输入管理密钥" onkeypress="if(event.key==='Enter')doLogin()">
  <button onclick="doLogin()">登录</button>
</div>

<!-- 管理面板 -->
<div class="admin hidden" id="adminPanel">
  <div class="nav">
    <button class="active" onclick="switchTab('stats',this)">统计</button>
    <button onclick="switchTab('settings',this)">站点设置</button>
    <button onclick="switchTab('codes',this)">邀请码管理</button>
    <button onclick="switchTab('blacklist',this)">IP黑名单</button>
    <button onclick="switchTab('reports',this)">举报管理</button>
    <button onclick="switchTab('logs',this)">提交日志</button>
    <button style="margin-left:auto;background:#fff;color:#999" onclick="doLogout()">退出登录</button>
  </div>

  <!-- 统计 -->
  <div id="tab-stats" class="tab-content">
    <div class="card">
      <h3>数据统计</h3>
      <div class="stats" id="statsGrid">
        <div class="stat-box"><div class="num" id="statActive">-</div><div class="label">活跃邀请码</div></div>
        <div class="stat-box"><div class="num" id="statUsed">-</div><div class="label">已使用</div></div>
        <div class="stat-box"><div class="num" id="statBlacklist">-</div><div class="label">黑名单IP</div></div>
        <div class="stat-box"><div class="num" id="statTodaySubmits">-</div><div class="label">今日提交</div></div>
        <div class="stat-box"><div class="num" id="statTodayBlocked">-</div><div class="label">今日拦截</div></div>
        <div class="stat-box"><div class="num" id="statPendingReports">-</div><div class="label">待处理举报</div></div>
      </div>
    </div>
  </div>

  <!-- 站点设置 -->
  <div id="tab-settings" class="tab-content hidden">
    <div class="card">
      <h3>首页公告</h3>
      <div class="form-group">
        <textarea id="noticeInput" placeholder="输入公告内容，支持换行。留空则首页不显示公告"></textarea>
        <div class="hint">公告显示在首页规则下方；留空保存后首页不显示公告。</div>
      </div>
    </div>
    <div class="card">
      <h3>广告位</h3>
      <div id="adsContainer"></div>
      <button class="add-ad-btn" onclick="addAdRow()">+ 添加广告</button>
      <div class="hint" style="margin-top:8px">广告显示在提交框上方；不添加任何广告则首页不显示广告位。图片地址支持 http/https。</div>
      <div class="form-group" style="margin-top:14px">
        <label>弹窗广告标题</label>
        <input type="text" id="adTitleInput" placeholder="留空则弹窗不显示标题栏">
      </div>
      <div class="form-group">
        <label>弹窗广告副标题</label>
        <input type="text" id="adSubInput" placeholder="留空则弹窗不显示标题栏">
      </div>
      <div class="hint">弹窗广告仅在配置了至少一条广告时出现；标题与副标题两者都留空则只显示广告链接列表。</div>
    </div>
    <div class="card">
      <h3>联系与智能功能</h3>
      <div class="form-group">
        <label>QQ 群号</label>
        <input type="text" id="qqGroupInput" placeholder="如 947577635，留空则首页联系弹窗不显示加群入口">
      </div>
      <div class="form-group">
        <label>站长 QQ</label>
        <input type="text" id="qqOwnerInput" placeholder="如 641448480，留空则首页联系弹窗不显示站长 QQ">
      </div>
      <div class="form-group">
        <label>智能直达按钮</label>
        <select id="smartEnabledInput" style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px">
          <option value="on">开启（首页显示「🚀 智能直达」按钮）</option>
          <option value="off">关闭</option>
        </select>
        <div class="hint">开启后首页一键取最新互助码并直接跳转拼多多。</div>
      </div>
      <div class="form-group">
        <label>iOS 快捷指令地址</label>
        <input type="text" id="iosUrlInput" placeholder="留空则首页隐藏「iOS 快捷指令版」按钮">
        <div class="hint">首页「📱 iOS 快捷指令版」按钮的跳转地址，须以 http:// 或 https:// 开头；留空则首页不显示该按钮。</div>
      </div>
      <div class="form-group">
        <label>列表刷新间隔（秒）</label>
        <input type="number" id="refreshIntervalInput" min="3" max="30" placeholder="5" style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px">
        <div class="hint">首页互助码列表自动刷新间隔，范围 3-30 秒，默认 5 秒。</div>
      </div>
      <div class="form-group">
        <label>单IP每分钟提交上限</label>
        <input type="number" id="rateLimitMaxInput" min="1" max="60" placeholder="5" style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px">
        <div class="hint">限制同一 IP 每分钟最多提交次数，范围 1-60，默认 5。</div>
      </div>
      <div class="form-group">
        <label>单IP每日提交上限</label>
        <input type="number" id="dailyLimitInput" min="1" max="2000" placeholder="30" style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px">
        <div class="hint">限制同一 IP 每天最多提交次数，范围 1-2000，默认 30。</div>
      </div>
      <div class="form-group">
        <label>识别截图模式</label>
        <select id="ocrModeInput" style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px">
          <option value="local">仅本地识别（默认，秒出、不消耗 AI 额度）</option>
          <option value="ai">本地识别 + AI 兜底（本地没识别到时自动调服务端 AI）</option>
        </select>
        <div class="hint">识别截图不加载任何模型：选图后先在浏览器里做像素模板匹配（毫秒级、零网络）。选「本地识别 + AI 兜底」时，本地没识别到或置信度偏低会自动调用服务端 AI 识图（消耗 Workers AI 额度，每 IP 每分钟限 10 次）。</div>
      </div>
    </div>
    <div style="margin-bottom:20px">
      <button class="save-btn" onclick="saveSettings()">保存设置</button>
    </div>
  </div>

  <!-- 邀请码管理 -->
  <div id="tab-codes" class="tab-content hidden">
    <div class="card">
      <h3>邀请码列表（含完整码）</h3>
      <table>
        <thead><tr><th>ID</th><th>完整码</th><th>提交IP</th><th>归属地</th><th>状态</th><th>时间</th><th>操作</th></tr></thead>
        <tbody id="codesTableBody"></tbody>
      </table>
      <div class="page-nav" id="codesPageNav"></div>
    </div>
  </div>

  <!-- IP黑名单 -->
  <div id="tab-blacklist" class="tab-content hidden">
    <div class="card">
      <h3>添加IP到黑名单</h3>
      <div class="input-row">
        <input type="text" id="blacklistIP" placeholder="输入IP地址，如 1.2.3.4">
        <input type="text" id="blacklistLocation" placeholder="归属地（可选）" style="max-width:140px">
        <input type="text" id="blacklistReason" placeholder="原因（可选）" style="max-width:160px">
        <select id="blacklistDuration" style="max-width:110px;padding:8px 10px;border:1px solid #ddd;border-radius:6px;font-size:14px">
          <option value="24h">24小时</option>
          <option value="1m">1个月</option>
          <option value="1y">1年</option>
          <option value="permanent">永久</option>
        </select>
        <button onclick="addBlacklist()">拉黑</button>
      </div>
    </div>
    <div class="card">
      <h3>黑名单列表</h3>
      <table>
        <thead><tr><th>IP</th><th>归属地</th><th>原因</th><th>期限</th><th>时间</th><th>操作</th></tr></thead>
        <tbody id="blacklistTableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- 举报管理 -->
  <div id="tab-reports" class="tab-content hidden">
    <div class="card">
      <h3>假码举报列表</h3>
      <table>
        <thead><tr><th>ID</th><th>被举报码</th><th>举报IP</th><th>提交者IP</th><th>状态</th><th>时间</th><th>操作</th></tr></thead>
        <tbody id="reportsTableBody"></tbody>
      </table>
      <div class="page-nav" id="reportsPageNav"></div>
      <div class="hint" style="margin-top:8px">同一提交者IP被2个不同用户举报后系统自动拉黑并自动通过举报。处理 = 确认无效；驳回 = 举报不成立；删除 = 移除记录。</div>
    </div>
  </div>

  <!-- 提交日志 -->
  <div id="tab-logs" class="tab-content hidden">
    <div class="card">
      <h3>提交日志</h3>
      <table>
        <thead><tr><th>IP</th><th>邀请码</th><th>动作</th><th>原因</th><th>时间</th></tr></thead>
        <tbody id="logsTableBody"></tbody>
      </table>
      <div class="page-nav" id="logsPageNav"></div>
    </div>
  </div>
</div>

<script>
var adminKey = '';
var codesPage = 1, logsPage = 1, reportsPage = 1;

/**
 * 登录态存储：sessionStorage
 * 刷新 / 页面重载（含手机切后台被系统回收）后自动恢复；关闭标签页即清除，
 * 密钥不会长期留在浏览器里。
 */
var KEY_STORE = 'pddAdminKey';
var authNotified = false;

function readStoredKey() {
  try { return sessionStorage.getItem(KEY_STORE) || ''; } catch (e) { return ''; }
}

function writeStoredKey(k) {
  try {
    if (k) sessionStorage.setItem(KEY_STORE, k);
    else sessionStorage.removeItem(KEY_STORE);
  } catch (e) {}
}

/** 进入后台面板 */
function showPanel() {
  document.getElementById('loginBox').classList.add('hidden');
  document.getElementById('adminPanel').classList.remove('hidden');
}

/** 清掉登录态并回到登录框 */
function showLogin(msg) {
  adminKey = '';
  writeStoredKey('');
  var ap = document.getElementById('adminPanel');
  if (ap) ap.classList.add('hidden');
  var lb = document.getElementById('loginBox');
  if (lb) lb.classList.remove('hidden');
  var inp = document.getElementById('adminKeyInput');
  if (inp) inp.value = '';
  if (msg) alert(msg);
}

/** 主动退出登录 */
function doLogout() {
  showLogin();
}

/** HTML 转义：管理后台所有动态值（归属地/原因/码等）拼 innerHTML 前先转义 */
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
    return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
  });
}

/** IP脱敏（前端版，兼容IPv4/IPv6） */
function maskIPAdmin(ip) {
  if (!ip) return '***';
  var v4mapped = ip.match(/:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4mapped) {
    var p = v4mapped[1].split('.');
    if (p.length === 4) return p[0] + '.' + p[1] + '.' + p[2] + '.***';
  }
  if (ip.indexOf(':') !== -1) {
    var parts = ip.split(':');
    return parts.slice(0, 3).join(':') + ':****';
  }
  var parts = ip.split('.');
  if (parts.length === 4) return parts[0] + '.' + parts[1] + '.' + parts[2] + '.***';
  return '***';
}

function api(path, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (adminKey) opts.headers['X-Admin-Key'] = adminKey;
  return fetch(path, opts).then(function(r) {
    // 密钥失效：清掉本地登录态并回到登录框（并发请求只提示一次）
    if (r.status === 401) {
      if (!authNotified) {
        authNotified = true;
        showLogin('登录已过期，请重新登录');
        setTimeout(function(){ authNotified = false; }, 1500);
      }
      return { success: false };
    }
    return r.json();
  });
}

function doLogin() {
  var v = document.getElementById('adminKeyInput').value.trim();
  if (!v) return;
  // 不走 api()：登录失败时不该被当成「登录已过期」
  fetch('/api/admin/stats', { headers: { 'X-Admin-Key': v } })
    .then(function(r) {
      if (r.status === 401) { alert('密钥错误'); return null; }
      return r.json();
    })
    .then(function(data) {
      if (!data) return;
      if (data.success) {
        adminKey = v;
        writeStoredKey(v);
        showPanel();
        loadStats();
      } else {
        alert('密钥错误');
      }
    })
    .catch(function(){ alert('登录失败'); });
}

function switchTab(tab, btn) {
  document.querySelectorAll('.nav button').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(function(c){ c.classList.add('hidden'); });
  document.getElementById('tab-' + tab).classList.remove('hidden');
  if (tab === 'stats') loadStats();
  if (tab === 'settings') loadSettings();
  if (tab === 'codes') loadCodes(1);
  if (tab === 'blacklist') loadBlacklist();
  if (tab === 'reports') loadReports(1);
  if (tab === 'logs') loadLogs(1);
}

// ---- 站点设置 ----

var adSeq = 0;

function adRowHTML(image_url, link_url) {
  adSeq++;
  // value 必须转义：广告 URL 来自 settings，若历史脏数据含引号会截断属性造成注入
  return '<div class="ad-row" id="adRow-' + adSeq + '">' +
    '<input type="text" class="ad-img" placeholder="广告图片URL (必填)" value="' + escapeHtml(image_url || '') + '">' +
    '<input type="text" class="ad-link" placeholder="跳转链接URL (可选)" value="' + escapeHtml(link_url || '') + '" style="flex:0.8">' +
    '<button class="rm-btn" onclick="removeAdRow(\\'adRow-' + adSeq + '\\')">删除</button>' +
  '</div>';
}

function loadSettings() {
  api('/api/admin/settings').then(function(data) {
    if (!data.success) return;
    document.getElementById('noticeInput').value = data.data.notice || '';
    document.getElementById('qqGroupInput').value = data.data.qq_group || '';
    document.getElementById('qqOwnerInput').value = data.data.qq_owner || '';
    document.getElementById('smartEnabledInput').value = data.data.smart_enabled === false ? 'off' : 'on';
    document.getElementById('refreshIntervalInput').value = data.data.refresh_interval || '5';
    document.getElementById('rateLimitMaxInput').value = data.data.rate_limit_max || '5';
    document.getElementById('dailyLimitInput').value = data.data.daily_limit || '30';
    document.getElementById('ocrModeInput').value = (data.data.ocr_mode === 'ai') ? 'ai' : 'local';
    document.getElementById('adTitleInput').value = data.data.ad_title || '';
    document.getElementById('adSubInput').value = data.data.ad_sub || '';
    document.getElementById('iosUrlInput').value = data.data.ios_url || '';
    var ads = data.data.ads || [];
    var container = document.getElementById('adsContainer');
    container.innerHTML = '';
    if (ads.length === 0) {
      container.innerHTML = '<div style="color:#999;font-size:13px;margin-bottom:10px">暂无广告</div>';
    } else {
      ads.forEach(function(ad) { container.innerHTML += adRowHTML(ad.image_url, ad.link_url); });
    }
  });
}

function addAdRow() {
  var container = document.getElementById('adsContainer');
  var empty = container.querySelector('[style*="暂无广告"]');
  if (empty) container.innerHTML = '';
  container.innerHTML += adRowHTML('', '');
}

function removeAdRow(id) {
  var el = document.getElementById(id);
  if (el) el.remove();
}

function saveSettings() {
  var notice = document.getElementById('noticeInput').value;
  var qqGroup = document.getElementById('qqGroupInput').value;
  var qqOwner = document.getElementById('qqOwnerInput').value;
  var smartEnabled = document.getElementById('smartEnabledInput').value;
  var refreshInterval = document.getElementById('refreshIntervalInput').value;
  var rateLimitMax = document.getElementById('rateLimitMaxInput').value;
  var dailyLimit = document.getElementById('dailyLimitInput').value;
  var ocrMode = document.getElementById('ocrModeInput').value;
  var adTitle = document.getElementById('adTitleInput').value;
  var adSub = document.getElementById('adSubInput').value;
  var iosUrl = document.getElementById('iosUrlInput').value;
  var ads = [];
  document.querySelectorAll('#adsContainer .ad-row').forEach(function(row) {
    var img = row.querySelector('.ad-img').value.trim();
    var link = row.querySelector('.ad-link').value.trim();
    if (img) ads.push({ image_url: img, link_url: link });
  });

  api('/api/admin/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notice: notice, ads: ads, ad_title: adTitle, ad_sub: adSub, qq_group: qqGroup, qq_owner: qqOwner, smart_enabled: smartEnabled, refresh_interval: refreshInterval, rate_limit_max: rateLimitMax, daily_limit: dailyLimit, ocr_mode: ocrMode, ios_url: iosUrl })
  }).then(function(data) {
    if (data.success) {
      alert('设置已保存');
    } else {
      alert(data.error || '保存失败');
    }
  }).catch(function(){ alert('网络错误'); });
}

function loadStats() {
  api('/api/admin/stats').then(function(data) {
    if (data.success) {
      document.getElementById('statActive').textContent = data.data.activeCodes;
      document.getElementById('statUsed').textContent = data.data.usedCodes;
      document.getElementById('statBlacklist').textContent = data.data.blacklistCount;
      document.getElementById('statTodaySubmits').textContent = data.data.todaySubmits;
      document.getElementById('statTodayBlocked').textContent = data.data.todayBlocked;
      document.getElementById('statPendingReports').textContent = data.data.pendingReports;
    }
  });
}

function loadCodes(page) {
  codesPage = page;
  api('/api/admin/codes?page=' + page).then(function(data) {
    if (data.success) {
      var tbody = document.getElementById('codesTableBody');
      tbody.innerHTML = data.data.map(function(c) {
        var time = new Date(c.created_at).toLocaleString('zh-CN');
        var statusColor = c.status === 'active' ? '#07c160' : c.status === 'used' ? '#f39c12' : '#999';
        return '<tr><td>' + c.id + '</td><td class="mono">' + escapeHtml(c.code) + '</td><td class="mono">' + escapeHtml(c.ip) + '</td>' +
          '<td style="font-size:12px;color:#666">' + (escapeHtml(c.location) || '-') + '</td>' +
          '<td style="color:' + statusColor + '">' + escapeHtml(c.status) + '</td><td>' + time + '</td>' +
          '<td><button class="btn-sm btn-danger" onclick="deleteCode(' + c.id + ')">删除</button></td></tr>';
      }).join('');
      renderPageNav('codesPageNav', data.pagination, loadCodes);
    }
  });
}

function deleteCode(id) {
  if (!confirm('确认删除？')) return;
  api('/api/admin/codes/' + id, { method: 'DELETE' }).then(function(data) {
    if (data.success) loadCodes(codesPage);
  });
}

function loadBlacklist() {
  api('/api/admin/blacklist').then(function(data) {
    if (data.success) {
      var tbody = document.getElementById('blacklistTableBody');
      if (data.data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#999">暂无黑名单</td></tr>';
        return;
      }
      var durMap = { '24h': '24小时', '1m': '1个月', '1y': '1年', permanent: '永久' };
      tbody.innerHTML = data.data.map(function(b) {
        var time = new Date(b.created_at).toLocaleString('zh-CN');
        // remaining 由后端统一计算（与公示页同一套逻辑），前端不再重复实现
        var remaining = b.remaining || '';
        var durLabel = durMap[b.duration] || escapeHtml(b.duration) || '-';
        var durHtml = remaining ? durLabel + '<br><span style="color:#e53935;font-size:11px">' + escapeHtml(remaining) + '</span>' : durLabel;
        return '<tr><td class="mono">' + escapeHtml(b.ip) + '</td><td>' + (escapeHtml(b.location) || '-') + '</td><td>' + (escapeHtml(b.reason) || '-') + '</td><td>' + durHtml + '</td><td>' + time + '</td>' +
          '<td><button class="btn-sm btn-success" data-ip="' + escapeHtml(b.ip) + '" onclick="removeBlacklist(this.dataset.ip)">移除</button></td></tr>';
      }).join('');
    }
  });
}

function addBlacklist() {
  var ip = document.getElementById('blacklistIP').value.trim();
  var reason = document.getElementById('blacklistReason').value.trim();
  var location = document.getElementById('blacklistLocation').value.trim();
  var duration = document.getElementById('blacklistDuration').value;
  if (!ip) { alert('请输入IP'); return; }
  api('/api/admin/blacklist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, reason: reason, location: location, duration: duration })
  }).then(function(data) {
    if (data.success) {
      document.getElementById('blacklistIP').value = '';
      document.getElementById('blacklistReason').value = '';
      document.getElementById('blacklistLocation').value = '';
      loadBlacklist();
    } else {
      alert(data.error || '操作失败');
    }
  });
}

function removeBlacklist(ip) {
  api('/api/admin/blacklist?ip=' + encodeURIComponent(ip), { method: 'DELETE' }).then(function(data) {
    if (data.success) loadBlacklist();
  });
}

function loadReports(page) {
  reportsPage = page;
  api('/api/admin/reports?page=' + page).then(function(data) {
    if (data.success) {
      var tbody = document.getElementById('reportsTableBody');
      if (data.data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#999">暂无举报</td></tr>';
        return;
      }
      var statusMap = { pending: ['待处理', '#2a71d0'], handled: ['已处理', '#07c160'], dismissed: ['已驳回', '#999'] };
      tbody.innerHTML = data.data.map(function(r) {
        var time = new Date(r.created_at).toLocaleString('zh-CN');
        var st = statusMap[r.status] || [r.status, '#333'];
        var submitterIP = r.submitter_ip ? maskIPAdmin(r.submitter_ip) : '-';
        var actions = '';
        if (r.status === 'pending') {
          actions += '<button class="btn-sm btn-success" onclick="updateReport(' + r.id + ',\\'handled\\')">处理</button> ';
          actions += '<button class="btn-sm" style="background:#f39c12" onclick="updateReport(' + r.id + ',\\'dismissed\\')">驳回</button> ';
        } else if (r.status === 'handled') {
          actions += '<button class="btn-sm" style="background:#f39c12" onclick="updateReport(' + r.id + ',\\'pending\\')">恢复待处理</button> ';
        }
        actions += '<button class="btn-sm btn-danger" onclick="deleteReport(' + r.id + ')">删除</button>';
        return '<tr><td>' + r.id + '</td><td class="mono">' + (escapeHtml(r.code) || '-') + '</td><td class="mono">' + escapeHtml(r.ip) + '</td>' +
          '<td class="mono">' + escapeHtml(submitterIP) + '</td>' +
          '<td style="color:' + st[1] + '">' + escapeHtml(st[0]) + '</td><td>' + time + '</td><td>' + actions + '</td></tr>';
      }).join('');
      renderPageNav('reportsPageNav', data.pagination, loadReports);
    }
  });
}

function updateReport(id, status) {
  api('/api/admin/reports/' + id + '/status', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: status })
  }).then(function(data) {
    if (data.success) loadReports(reportsPage);
    else alert(data.error || '操作失败');
  });
}

function deleteReport(id) {
  if (!confirm('确认删除该举报记录？')) return;
  api('/api/admin/reports/' + id, { method: 'DELETE' }).then(function(data) {
    if (data.success) loadReports(reportsPage);
  });
}

function loadLogs(page) {
  logsPage = page;
  api('/api/admin/logs?page=' + page).then(function(data) {
    if (data.success) {
      var tbody = document.getElementById('logsTableBody');
      tbody.innerHTML = data.data.map(function(l) {
        var time = new Date(l.created_at).toLocaleString('zh-CN');
        var actionColor = { submit: '#07c160', blocked: '#e53935', use: '#2a71d0' }[l.action] || '#333';
        return '<tr><td class="mono">' + escapeHtml(l.ip) + '</td><td class="mono">' + (escapeHtml(l.code) || '-') + '</td>' +
          '<td style="color:' + actionColor + '">' + escapeHtml(l.action) + '</td><td>' + (escapeHtml(l.reason) || '-') + '</td><td>' + time + '</td></tr>';
      }).join('');
      renderPageNav('logsPageNav', data.pagination, loadLogs);
    }
  });
}

function renderPageNav(elId, pagination, loadFn) {
  var el = document.getElementById(elId);
  var totalPages = Math.ceil(pagination.total / pagination.pageSize);
  if (totalPages <= 1) { el.innerHTML = ''; return; }
  var html = '';
  if (pagination.page > 1) html += '<button onclick="' + loadFn.name + '(' + (pagination.page-1) + ')">上一页</button>';
  html += '<button class="active">' + pagination.page + '/' + totalPages + '</button>';
  if (pagination.page < totalPages) html += '<button onclick="' + loadFn.name + '(' + (pagination.page+1) + ')">下一页</button>';
  el.innerHTML = html;
}

// 页面加载时自动恢复登录态（sessionStorage）
(function restoreSession() {
  var k = readStoredKey();
  if (!k) return;
  adminKey = k;
  fetch('/api/admin/stats', { headers: { 'X-Admin-Key': k } })
    .then(function(r) {
      if (r.status === 401) { adminKey = ''; writeStoredKey(''); return null; }
      return r.json();
    })
    .then(function(data) {
      if (data && data.success) { showPanel(); loadStats(); }
      else { adminKey = ''; writeStoredKey(''); }
    })
    .catch(function() { adminKey = ''; });
})();
</script>
</body>
</html>`;
