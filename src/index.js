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
  MAX_CODE_LENGTH: 20,         // 防止超长输入
};

// ============================================================
//  工具函数
// ============================================================

/** 获取客户端真实 IP（穿透 Cloudflare 代理） */
function getClientIP(request) {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    '0.0.0.0'
  );
}

/** 脱敏：隐藏中间两位 */
function maskCode(code) {
  if (code.length < 4) return '****';
  const mid = Math.floor(code.length / 2);
  return code.slice(0, mid - 1) + '**' + code.slice(mid + 1);
}

/** JSON 响应 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
    },
  });
}

/** 当前时间 ISO 字符串 */
function now() {
  return new Date().toISOString();
}

/** 检查是否过期 */
function isExpired(isoTime, hours) {
  const diff = Date.now() - new Date(isoTime).getTime();
  return diff > hours * 3600_000;
}

// ============================================================
//  防恶意提交中间件
// ============================================================

/** 检查 IP 是否在黑名单中 */
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

/** 速率限制：检查窗口内提交次数 */
async function checkRateLimit(db, ip, maxPerMin) {
  if (!maxPerMin || maxPerMin < 1) maxPerMin = CONFIG.RATE_LIMIT_MAX;
  const since = new Date(Date.now() - CONFIG.RATE_LIMIT_WINDOW_MS).toISOString();
  const result = await db
    .prepare('SELECT COUNT(*) as count FROM submit_logs WHERE ip = ? AND created_at > ? AND action = ?')
    .bind(ip, since, 'submit')
    .first();
  return result.count >= maxPerMin;
}

/** 每日限额 */
async function checkDailyLimit(db, ip, dailyMax) {
  if (!dailyMax || dailyMax < 1) dailyMax = CONFIG.DAILY_LIMIT;
  // 基于北京时间（CST）今日 0:00，避免 Workers UTC 时区导致的边界错位
  const cstOfNow = new Date(Date.now() + 8 * 3600_000);
  cstOfNow.setUTCHours(0, 0, 0, 0);
  const todayStartMs = cstOfNow.getTime() - 8 * 3600_000;
  const result = await db
    .prepare('SELECT COUNT(*) as count FROM submit_logs WHERE ip = ? AND created_at > ? AND action = ?')
    .bind(ip, new Date(todayStartMs).toISOString(), 'submit')
    .first();
  return result.count >= dailyMax;
}

/** 记录日志 */
async function logAction(db, ip, code, action, reason = '') {
  await db
    .prepare('INSERT INTO submit_logs (ip, code, action, reason, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(ip, code || '', action, reason, now())
    .run();
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

/** 保存站点设置 */
async function setSetting(db, key, value) {
  await db
    .prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at')
    .bind(key, value, now())
    .run();
}

/** GET /api/config — 获取首页配置（公告/广告/联系方式/开关），空值自动省略 */
async function handleGetConfig(db) {
  const notice = await getSetting(db, 'notice');
  const adsRaw = await getSetting(db, 'ads');
  const qqGroup = await getSetting(db, 'qq_group');
  const qqOwner = await getSetting(db, 'qq_owner');
  const smartRaw = await getSetting(db, 'smart_enabled');
  const refreshInterval = await getSetting(db, 'refresh_interval');
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
  }

  // 联系方式：非空才返回（首页据此显示按钮/弹窗）
  if (qqGroup && qqGroup.trim()) data.qq_group = qqGroup.trim();
  if (qqOwner && qqOwner.trim()) data.qq_owner = qqOwner.trim();

  // 智能直达开关：默认开启
  data.smart_enabled = smartRaw !== 'off';

  // OCR 模式：auto（AI优先，被限自动切本地）/ ai（仅服务端）/ local（仅浏览器本地），默认 auto
  const ocrModeRaw = await getSetting(db, 'ocr_mode');
  data.ocr_mode = (ocrModeRaw === 'ai' || ocrModeRaw === 'local') ? ocrModeRaw : 'auto';

  // 今日统计（按中国时区 CST UTC+8 算今日 0:00，与前端列表展示日期一致）
  // Cloudflare Workers 的 Date 是 UTC 直接 setHours 会算成 UTC 0:00（=CST 8:00），
  // 导致 0:00~8:00 (CST) 之间提交的码按日期显示算"今日"但 stats 不算，体验割裂。
  const nowMs = Date.now();
  const cstShiftMs = 8 * 3600_000;
  const cstOfNow = new Date(nowMs + cstShiftMs);
  cstOfNow.setUTCHours(0, 0, 0, 0);                          // CST 今日 0:00
  const todayStartMs = cstOfNow.getTime() - cstShiftMs;      // 换回 UTC ms
  const todayISO = new Date(todayStartMs).toISOString();
  const todaySubmits = await db.prepare("SELECT COUNT(*) as count FROM submit_logs WHERE created_at > ? AND action = 'submit'").bind(todayISO).first();
  data.today_submits = todaySubmits ? (todaySubmits.count || 0) : 0;
  try {
    const todayVisits = await db.prepare("SELECT COUNT(*) as count FROM visits WHERE created_at > ?").bind(todayISO).first();
    const todayUniqueIPs = await db.prepare("SELECT COUNT(DISTINCT ip) as count FROM visits WHERE created_at > ?").bind(todayISO).first();
    data.today_visits = todayVisits ? (todayVisits.count || 0) : 0;
    data.today_ips = todayUniqueIPs ? (todayUniqueIPs.count || 0) : 0;
  } catch {
    data.today_visits = 0;
    data.today_ips = 0;
  }

  return json({ success: true, data });
}

/** POST /api/visit — 记录访问 */
async function handleVisit(db, ip) {
  try {
    await db.prepare("CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, created_at TEXT NOT NULL)").run();
    await db.prepare("INSERT INTO visits (ip, created_at) VALUES (?, ?)").bind(ip, now()).run();
  } catch (e) {
    // 忽略建表/插入错误，不阻塞用户
  }
  return json({ success: true });
}

// ============================================================
//  API 路由处理
// ============================================================

/** GET /api/codes — 获取邀请码列表（未使用在前，30秒内已使用灰色排后面，超时即删轮换） */
async function handleGetCodes(db) {
  // 1) 清理过期码：超过 TTL 的 active 码 和 超过 USED_KEEP_MS 的 used 码
  const ttlCutoff = new Date(Date.now() - CONFIG.CODE_TTL_HOURS * 3600_000).toISOString();
  const delCutoff = new Date(Date.now() - CONFIG.USED_KEEP_MS).toISOString();
  await db.prepare(
    "DELETE FROM codes WHERE (status = 'active' AND created_at < ?) OR (status = 'used' AND used_at IS NOT NULL AND used_at < ?)"
  ).bind(ttlCutoff, delCutoff).run();

  // 2) 返回：未使用的在前（可跳转），30秒内的已使用排后面（灰色）
  const result = await db
    .prepare("SELECT id, code_masked, status, used_at, created_at, location FROM codes WHERE status IN ('active','used') ORDER BY (status = 'used'), created_at DESC LIMIT ?")
    .bind(CONFIG.MAX_ACTIVE_CODES)
    .all();

  return json({ success: true, data: result.results });
}

/** POST /api/submit — 提交邀请码 */
async function handleSubmit(db, request, ip) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: '请求格式错误' }, 400);
  }

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

  // 检查黑名单
  const blocked = await checkBlacklist(db, ip);
  if (blocked) {
    await logAction(db, ip, code, 'blocked', `blacklist: ${blocked.reason}`);
    return json({ success: false, error: '您的IP已被拉黑，如需申诉请联系管理员' }, 403);
  }

  // 读取后台可配置的提交限流参数（读取失败则用 CONFIG 默认值）
  let rateLimitMax = parseInt(await getSetting(db, 'rate_limit_max'), 10);
  if (isNaN(rateLimitMax) || rateLimitMax < 1) rateLimitMax = CONFIG.RATE_LIMIT_MAX;
  let dailyLimit = parseInt(await getSetting(db, 'daily_limit'), 10);
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

  // 自动获取归属地（中文，百度API + ip-api.com 双保险，不赶时间）
  const location = await getIPLocation(request, ip);

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
    return json({ success: true, message: '已重新排队' });
  }

  // 插入新码（含归属地）
  await db
    .prepare('INSERT INTO codes (code, code_masked, ip, status, created_at, location) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(code, maskCode(code), ip, 'active', now(), location)
    .run();

  await logAction(db, ip, code, 'submit', 'ok');
  return json({ success: true, message: '提交成功' });
}

/** POST /api/use/:id — 标记邀请码为已使用，返回完整码供直接跳转 PDD */
async function handleUseCode(db, id, ip) {
  const row = await db.prepare('SELECT code, status FROM codes WHERE id = ?').bind(id).first();
  if (!row) return json({ success: false, error: '该码不存在' }, 404);
  if (row.status !== 'active') return json({ success: false, error: '该码已被使用' }, 409);

  await db
    .prepare("UPDATE codes SET status = 'used', used_at = ? WHERE id = ? AND status = 'active'")
    .bind(now(), id)
    .run();

  await logAction(db, ip, '', 'use', `code_id:${id}`);
  return json({ success: true, code: row.code, message: '已标记为已使用' });
}

/** POST /api/quick-use — 智能直达：取最新未使用码，标记使用并返回完整码 */
async function handleQuickUse(db, ip) {
  // 智能直达开关
  const smartRaw = await getSetting(db, 'smart_enabled');
  if (smartRaw === 'off') {
    return json({ success: false, error: '智能直达已关闭' }, 403);
  }

  // 取最新的未使用码
  const row = await db
    .prepare("SELECT id, code FROM codes WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
    .first();

  if (!row) {
    return json({ success: false, error: '暂无可用互助码' }, 404);
  }

  // 标记为已使用
  await db
    .prepare("UPDATE codes SET status = 'used', used_at = ? WHERE id = ? AND status = 'active'")
    .bind(now(), row.id)
    .run();

  await logAction(db, ip, row.code, 'use', `quick_use code_id:${row.id}`);
  return json({ success: true, code: row.code, message: '智能直达成功' });
}

/** POST /api/report/:id — 举报假码
 *  优化流程：同一提交者IP被2个不同IP举报 → 自动拉黑 + 举报自动通过
 */
async function handleReportCode(db, id, ip, request) {
  // 查询被举报的码及其提交者IP
  const row = await db.prepare('SELECT code, code_masked, ip, location FROM codes WHERE id = ?').bind(id).first();
  if (!row) return json({ success: false, error: '该码不存在' }, 404);

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

  // 检查该提交者IP是否被 >= 2 个不同IP举报
  const reportStats = await db
    .prepare('SELECT COUNT(DISTINCT ip) as cnt FROM reports WHERE submitter_ip = ?')
    .bind(row.ip)
    .first();

  if (reportStats && reportStats.cnt >= 2) {
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

/** GET /api/blacklist — 小黑屋公示（公开、IP脱敏） */
async function handlePublicBlacklist(db) {
  const result = await db
    .prepare('SELECT ip, reason, location, duration, expires_at, created_at FROM blacklist ORDER BY created_at DESC LIMIT 50')
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

/** 通过百度开放数据获取IP归属地（中文，HTTPS，高精度）
 *  返回格式示例："江苏省南京市 电信"、"美国"
 */
async function fetchIPLocation(ip) {
  if (!ip || ip === '0.0.0.0') return '';

  // 方案1：百度开放数据 API（HTTPS，中文）
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch('https://opendata.baidu.com/api.php?query=' + ip + '&co=&resource_id=6006&oe=utf8', { signal: controller.signal });
    clearTimeout(timeout);
    if (res.ok) {
      const data = await res.json();
      if (data && data.data && data.data[0] && data.data[0].location) {
        return data.data[0].location.trim();
      }
    }
  } catch {}

  // 方案2：ip-api.com（HTTP，中文地名+英文ISP→翻译）
  try {
    const controller2 = new AbortController();
    const timeout2 = setTimeout(() => controller2.abort(), 5000);
    const res2 = await fetch('http://ip-api.com/json/' + ip + '?lang=zh-CN&fields=country,regionName,city,isp', { signal: controller2.signal });
    clearTimeout(timeout2);
    if (res2.ok) {
      const data2 = await res2.json();
      const parts = [];
      if (data2.country && data2.country !== '中国') parts.push(data2.country);
      if (data2.regionName) parts.push(data2.regionName);
      if (data2.city && data2.city !== data2.regionName) parts.push(data2.city);
      // ISP 英文→中文翻译
      const ispCn = translateISP(data2.isp || '');
      if (ispCn) parts.push(ispCn);
      const loc = parts.join(' ').trim();
      if (loc) return loc;
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

async function getIPLocation(request, ip) {
  // 先尝试百度 API（中文，但可能超时）
  const loc = await fetchIPLocation(ip);
  if (loc) return loc;

  // 兜底：使用 Cloudflare request.cf（英文）
  return getIPLocationSync(request);
}

// ============================================================
//  管理后台 API
// ============================================================

/** 验证管理员密钥 */
function verifyAdmin(request, env) {
  const adminKey = request.headers.get('X-Admin-Key') || new URL(request.url).searchParams.get('key');
  return adminKey && adminKey === env.ADMIN_KEY;
}

/** GET /api/admin/blacklist — 获取黑名单列表 */
async function handleAdminGetBlacklist(db) {
  const result = await db.prepare('SELECT id, ip, reason, location, duration, expires_at, created_at FROM blacklist ORDER BY created_at DESC').all();
  return json({ success: true, data: result.results });
}

/** POST /api/admin/blacklist — 添加IP到黑名单 */
async function handleAdminAddBlacklist(db, request) {
  const body = await request.json();
  const ip = body.ip?.trim();
  const reason = body.reason?.trim() || '手动拉黑';
  let location = body.location?.trim() || '';
  const duration = body.duration?.trim() || '24h'; // 默认24小时

  if (!ip) return json({ success: false, error: 'IP不能为空' }, 400);

  // 归属地未填写时自动获取
  if (!location) {
    location = await fetchIPLocation(ip);
  }

  const expiresAt = calcExpiresAt(duration);

  // 支持 CIDR 前缀匹配（简单实现：检查前缀）
  await db
    .prepare('INSERT OR REPLACE INTO blacklist (ip, reason, location, duration, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(ip, reason, location, duration, expiresAt, now())
    .run();

  return json({ success: true, message: `已拉黑 ${ip}（${duration === 'permanent' ? '永久' : duration}）`, location });
}

/** DELETE /api/admin/blacklist — 从黑名单移除IP */
async function handleAdminRemoveBlacklist(db, request) {
  const url = new URL(request.url);
  const ip = url.searchParams.get('ip');
  if (!ip) return json({ success: false, error: 'IP不能为空' }, 400);

  await db.prepare('DELETE FROM blacklist WHERE ip = ?').bind(ip).run();
  return json({ success: true, message: `已移除 ${ip}` });
}

/** GET /api/admin/logs — 查看提交日志 */
async function handleAdminGetLogs(db, request) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('pageSize') || '50');
  const offset = (page - 1) * pageSize;

  const result = await db
    .prepare('SELECT ip, code, action, reason, created_at FROM submit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?')
    .bind(pageSize, offset)
    .all();

  const countResult = await db.prepare('SELECT COUNT(*) as total FROM submit_logs').first();

  return json({
    success: true,
    data: result.results,
    pagination: { page, pageSize, total: countResult.total },
  });
}

/** GET /api/admin/stats — 统计数据 */
async function handleAdminGetStats(db) {
  const activeCount = await db.prepare("SELECT COUNT(*) as count FROM codes WHERE status = 'active'").first();
  // 已使用：统计 submit_logs 中 action='use' 的累计条数（每次点击"跳转/已使用"都会落日志，不会被 30 秒清理删除），比 codes WHERE status='used' 实时数准确
  const usedCount = await db.prepare("SELECT COUNT(*) as count FROM submit_logs WHERE action = 'use'").first();
  const blacklistCount = await db.prepare('SELECT COUNT(*) as count FROM blacklist').first();
  // 基于北京时间（CST）今日 0:00，避免 Workers UTC 时区导致今日边界错位
  const cstOfNow = new Date(Date.now() + 8 * 3600_000);
  cstOfNow.setUTCHours(0, 0, 0, 0);
  const todayStartMs = cstOfNow.getTime() - 8 * 3600_000;
  const todayStartISO = new Date(todayStartMs).toISOString();
  const todaySubmits = await db
    .prepare("SELECT COUNT(*) as count FROM submit_logs WHERE created_at > ? AND action = 'submit'")
    .bind(todayStartISO)
    .first();
  const todayBlocked = await db
    .prepare("SELECT COUNT(*) as count FROM submit_logs WHERE created_at > ? AND action = 'blocked'")
    .bind(todayStartISO)
    .first();
  const pendingReports = await db
    .prepare("SELECT COUNT(*) as count FROM reports WHERE status = 'pending'")
    .first();

  return json({
    success: true,
    data: {
      activeCodes: activeCount.count,
      usedCodes: usedCount.count,
      blacklistCount: blacklistCount.count,
      todaySubmits: todaySubmits.count,
      todayBlocked: todayBlocked.count,
      pendingReports: pendingReports.count,
    },
  });
}

/** GET /api/admin/codes — 管理员查看所有码（含完整码） */
async function handleAdminGetAllCodes(db, request) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('pageSize') || '50');
  const offset = (page - 1) * pageSize;

  const result = await db
    .prepare('SELECT id, code, code_masked, ip, status, created_at, used_at, location FROM codes ORDER BY created_at DESC LIMIT ? OFFSET ?')
    .bind(pageSize, offset)
    .all();

  const countResult = await db.prepare('SELECT COUNT(*) as total FROM codes').first();

  return json({
    success: true,
    data: result.results,
    pagination: { page, pageSize, total: countResult.total },
  });
}

/** DELETE /api/admin/codes/:id — 删除指定码 */
async function handleAdminDeleteCode(db, id) {
  await db.prepare('DELETE FROM codes WHERE id = ?').bind(id).run();
  return json({ success: true, message: '已删除' });
}

/** GET /api/admin/settings — 读取站点设置 */
async function handleAdminGetSettings(db) {
  const notice = (await getSetting(db, 'notice')) || '';
  const adsRaw = (await getSetting(db, 'ads')) || '[]';
  const qqGroup = (await getSetting(db, 'qq_group')) || '';
  const qqOwner = (await getSetting(db, 'qq_owner')) || '';
  const smartRaw = (await getSetting(db, 'smart_enabled')) || 'on';
  const refreshInterval = (await getSetting(db, 'refresh_interval')) || '5';
  const rateLimitMax = (await getSetting(db, 'rate_limit_max')) || String(CONFIG.RATE_LIMIT_MAX);
  const dailyLimit = (await getSetting(db, 'daily_limit')) || String(CONFIG.DAILY_LIMIT);
  const ocrModeRaw = (await getSetting(db, 'ocr_mode')) || 'auto';
  const ocrMode = (ocrModeRaw === 'ai' || ocrModeRaw === 'local') ? ocrModeRaw : 'auto';
  let ads = [];
  try {
    ads = JSON.parse(adsRaw);
    if (!Array.isArray(ads)) ads = [];
  } catch {
    ads = [];
  }
  return json({ success: true, data: { notice, ads, qq_group: qqGroup, qq_owner: qqOwner, smart_enabled: smartRaw, refresh_interval: refreshInterval, rate_limit_max: rateLimitMax, daily_limit: dailyLimit, ocr_mode: ocrMode } });
}

/** POST /api/admin/settings — 保存站点设置 */
async function handleAdminSaveSettings(db, request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: '请求格式错误' }, 400);
  }

  // 公告：文本，去首尾空格（可为空）
  if (typeof body.notice === 'string') {
    await setSetting(db, 'notice', body.notice.trim());
  }

  // 广告：数组，每项 { image_url, link_url }
  if (Array.isArray(body.ads)) {
    const cleanAds = body.ads
      .filter((ad) => ad && typeof ad.image_url === 'string' && ad.image_url.trim())
      .map((ad) => ({
        image_url: ad.image_url.trim().slice(0, 500),
        link_url: (ad.link_url && ad.link_url.trim().slice(0, 500)) || '',
      }));
    await setSetting(db, 'ads', JSON.stringify(cleanAds));
  }

  // 联系方式
  if (typeof body.qq_group === 'string') {
    await setSetting(db, 'qq_group', body.qq_group.trim().slice(0, 50));
  }
  if (typeof body.qq_owner === 'string') {
    await setSetting(db, 'qq_owner', body.qq_owner.trim().slice(0, 50));
  }
  // 智能直达开关 on/off
  if (body.smart_enabled === 'on' || body.smart_enabled === 'off') {
    await setSetting(db, 'smart_enabled', body.smart_enabled);
  }

  // 刷新间隔：3-30 秒
  if (typeof body.refresh_interval === 'string' || typeof body.refresh_interval === 'number') {
    const ri = parseInt(String(body.refresh_interval), 10);
    if (!isNaN(ri) && ri >= 3 && ri <= 30) {
      await setSetting(db, 'refresh_interval', String(ri));
    }
  }

  // 单IP每分钟提交上限：1-60
  if (typeof body.rate_limit_max === 'string' || typeof body.rate_limit_max === 'number') {
    const rlm = parseInt(String(body.rate_limit_max), 10);
    if (!isNaN(rlm) && rlm >= 1 && rlm <= 60) {
      await setSetting(db, 'rate_limit_max', String(rlm));
    }
  }

  // 单IP每日提交上限：1-2000
  if (typeof body.daily_limit === 'string' || typeof body.daily_limit === 'number') {
    const dl = parseInt(String(body.daily_limit), 10);
    if (!isNaN(dl) && dl >= 1 && dl <= 2000) {
      await setSetting(db, 'daily_limit', String(dl));
    }
  }

  // OCR 模式：auto / ai / local
  if (body.ocr_mode === 'ai' || body.ocr_mode === 'local' || body.ocr_mode === 'auto') {
    await setSetting(db, 'ocr_mode', body.ocr_mode);
  }

  return json({ success: true, message: '设置已保存' });
}

// ---------- 举报管理 ----------

/** GET /api/admin/reports — 举报列表 */
async function handleAdminGetReports(db, request) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page') || '1');
  const pageSize = parseInt(url.searchParams.get('pageSize') || '50');
  const offset = (page - 1) * pageSize;

  const result = await db
    .prepare('SELECT id, code, ip, submitter_ip, status, created_at FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?')
    .bind(pageSize, offset)
    .all();
  const countResult = await db.prepare('SELECT COUNT(*) as total FROM reports').first();

  return json({
    success: true,
    data: result.results,
    pagination: { page, pageSize, total: countResult.total },
  });
}

/** POST /api/admin/reports/:id/status — 更新举报状态（handled/dismissed） */
async function handleAdminUpdateReport(db, id, request) {
  const body = await request.json();
  const status = body.status;
  if (!['handled', 'dismissed', 'pending'].includes(status)) {
    return json({ success: false, error: '状态不合法' }, 400);
  }
  await db.prepare('UPDATE reports SET status = ? WHERE id = ?').bind(status, id).run();
  return json({ success: true, message: '已更新' });
}

/** DELETE /api/admin/reports/:id — 删除举报记录 */
async function handleAdminDeleteReport(db, id) {
  await db.prepare('DELETE FROM reports WHERE id = ?').bind(id).run();
  return json({ success: true, message: '已删除' });
}

/** POST /api/ocr — 上传图片，用 Cloudflare Workers AI 视觉模型提取互助码
 *  ocr_mode: auto(默认, AI优先, 被限自动切本地) / ai(仅服务端) / local(仅浏览器本地)
 */
async function handleOcr(request, env) {
  const ip = getClientIP(request);
  let ocrMode = 'auto';
  try {
    // 从 FormData 中读取图片
    const formData = await request.formData();
    const file = formData.get('image');
    if (!file) {
      return json({ success: false, error: '未收到图片' }, 400);
    }

    // OCR 模式（auto / ai / local）
    const ocrModeRaw = await getSetting(env.DB, 'ocr_mode');
    ocrMode = (ocrModeRaw === 'ai' || ocrModeRaw === 'local') ? ocrModeRaw : 'auto';

    // local 模式：不消耗 AI 额度，直接让前端用浏览器本地识别
    if (ocrMode === 'local') {
      return json({ success: false, fallback: 'local', error: '请使用浏览器本地识别' });
    }

    // 限流：每 IP 每天最多 10 次 AI 识别（防刷，避免一人耗光全站每日额度）
    const OCR_DAILY = 10;
    const cstShift = 8 * 3600_000;
    const cstOfNow = new Date(Date.now() + cstShift);
    cstOfNow.setUTCHours(0, 0, 0, 0);                       // CST 今日 0:00
    const todayISO = new Date(cstOfNow.getTime() - cstShift).toISOString();
    const used = await env.DB.prepare("SELECT COUNT(*) as c FROM submit_logs WHERE ip = ? AND action = 'ocr' AND created_at > ?").bind(ip, todayISO).first();
    console.error('OCR LIMIT DEBUG ip=', ip, 'todayISO=', todayISO, 'used=', JSON.stringify(used), 'OCR_DAILY=', OCR_DAILY);
    if (used && used.c >= OCR_DAILY) {
      return json({ success: false, error: '今日识别次数已达上限，请手动输入互助码' }, 429);
    }
    await env.DB.prepare("INSERT INTO submit_logs (ip, code, action, created_at) VALUES (?, ?, 'ocr', ?)").bind(ip, null, now()).run();

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
    const mimeType = file.type || 'image/png';

    // 调用 Cloudflare Workers AI 视觉模型（llama-3.2-11b-vision-instruct）
    // 使用 messages 格式，content 数组中包含 text 和 image_url
    let aiResponse;
    try {
      aiResponse = await env.AI.run('@cf/meta/llama-3.2-11b-vision-instruct', {
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'Look at this image carefully. It is from Pinduoduo (拼多多). There is an invitation code shown as a string of 8 or 9 digits (like 12345678 or 123456789). What is the invitation code? Reply with ONLY the digits, no other text.' },
              { type: 'image_url', image_url: { url: 'data:' + mimeType + ';base64,' + base64 } }
            ]
          }
        ],
        max_tokens: 20,
        temperature: 0.1,
      });
    } catch(e) {
      var errStr = String(e.message || e);
      // 如果需要 agree Meta License，先 agree 再重试
      if (errStr.includes('agree') || errStr.includes('license') || errStr.includes('3016') || errStr.includes('5016')) {
        try { await env.AI.run('@cf/meta/llama-3.2-11b-vision-instruct', { prompt: 'agree' }); } catch(e2) {}
        aiResponse = await env.AI.run('@cf/meta/llama-3.2-11b-vision-instruct', {
          messages: [
            {
              role: 'user',
              content: [
                { type: 'text', text: 'Look at this image carefully. It is from Pinduoduo (拼多多). There is an invitation code shown as a string of 8 or 9 digits (like 12345678 or 123456789). What is the invitation code? Reply with ONLY the digits, no other text.' },
                { type: 'image_url', image_url: { url: 'data:' + mimeType + ';base64,' + base64 } }
              ]
            }
          ],
          max_tokens: 20,
          temperature: 0.1,
        });
      } else {
        throw e;
      }
    }

    // 安全获取 AI 返回文本（不同格式兼容；response 可能是数字类型）
    var rawText = '';
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
    var cleaned = rawText.replace(/[^0-9]/g, ' ');

    // 优先提取连续的 8 或 9 位数字（用户要求：识别逻辑为连续八位或九位数）
    var matches = cleaned.match(/\d{8,9}/g) || [];
    // 排除超过 9 位的（如从更长数字串中切出来的），并去重
    var valid = matches.filter(function(s) { return s.length === 8 || s.length === 9; });
    if (valid.length > 0) {
      var code = valid[0];
      return json({
        success: true,
        code: code,
        rawText: rawText.slice(0, 100),
      });
    }

    // 兜底：无 8/9 位数字时，取最长的数字串（至少 6 位才认为可信）
    var allNums = cleaned.match(/\d+/g) || [];
    if (allNums.length > 0) {
      var longest = allNums.sort(function(a, b) { return b.length - a.length; })[0];
      if (longest.length >= 6 && longest.length <= 12) {
        return json({
          success: true,
          code: longest,
          rawText: rawText.slice(0, 100),
        });
      }
    }

    return json({
      success: false,
      error: '未识别到互助码，请手动输入或换清晰截图',
    });
  } catch(e) {
    console.error('handleOcr error:', e);
    const msg = String(e && e.message ? e.message : e);
    // 额度/限流类错误（429 / quota / neuron / rate limit / capacity 等）
    const isQuota = /429|quota|rate.?limit|exceed|neuron|too many|capacity|rest/i.test(msg);
    if (isQuota && ocrMode === 'auto') {
      return json({ success: false, fallback: 'local', error: 'AI 识别额度已用完，请用浏览器本地识别或手动输入互助码' });
    }
    if (isQuota) {
      return json({ success: false, error: '识别额度已用完，请手动输入互助码' });
    }
    return json({ success: false, error: '识别出错，请手动输入互助码' });
  }
}

// ============================================================
//  路由分发
// ============================================================

async function handleAPI(request, env, path) {
  const method = request.method;
  const ip = getClientIP(request);

  // OPTIONS 预检
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204 });
  }

  // ---- 公开接口 ----
  if (path === '/api/codes' && method === 'GET') {
    return handleGetCodes(env.DB);
  }

  if (path === '/api/config' && method === 'GET') {
    return handleGetConfig(env.DB);
  }

  if (path === '/api/visit' && method === 'POST') {
    return handleVisit(env.DB, ip);
  }

  if (path === '/api/submit' && method === 'POST') {
    return handleSubmit(env.DB, request, ip);
  }

  // 识图提取（Cloudflare Workers AI 视觉模型）
  if (path === '/api/ocr' && method === 'POST') {
    return handleOcr(request, env);
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
    return handleReportCode(env.DB, parseInt(reportMatch[1]), ip, request);
  }

  // 标记使用：/api/use/123
  const useMatch = path.match(/^\/api\/use\/(\d+)$/);
  if (useMatch && method === 'POST') {
    return handleUseCode(env.DB, parseInt(useMatch[1]), ip);
  }

  // ---- 管理后台接口 ----
  if (path.startsWith('/api/admin/')) {
    if (!verifyAdmin(request, env)) {
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
      return handleAdminDeleteCode(env.DB, parseInt(deleteMatch[1]));
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
      return handleAdminUpdateReport(env.DB, parseInt(reportStatusMatch[1]), request);
    }
    const reportDeleteMatch = path.match(/^\/api\/admin\/reports\/(\d+)$/);
    if (reportDeleteMatch && method === 'DELETE') {
      return handleAdminDeleteReport(env.DB, parseInt(reportDeleteMatch[1]));
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
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ============================================================
//  每日清空（23:59 CST 定时 + 懒清理兜底）
// ============================================================

/** 获取当前 CST(UTC+8) 日期字符串 YYYY-MM-DD */
function getCSTDate() {
  return new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

/** 每日清空：删除所有互助码，记录清理日期 */
async function dailyCleanup(db) {
  const today = getCSTDate();
  const last = await db.prepare("SELECT value FROM settings WHERE key = 'last_cleanup_date'").first();
  if (last && last.value === today) return false; // 今天已清理

  // 清空所有互助码
  await db.prepare("DELETE FROM codes").run();
  // 更新清理日期
  await db.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('last_cleanup_date', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").bind(today, now()).run();
  console.log('[dailyCleanup] 已清空所有互助码，日期:', today);
  return true;
}

// ============================================================
//  入口
// ============================================================

// ============================================================
//  主入口
// ============================================================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // API 路由
    if (path.startsWith('/api/')) {
      try {
        return await handleAPI(request, env, path);
      } catch (err) {
        console.error(err);
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

    return new Response('Not Found', { status: 404 });
  },

  // Cron Trigger: 每天 23:59 CST (15:59 UTC) 清空互助码
  async scheduled(event, env) {
    const db = env.DB;
    await dailyCleanup(db);
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
<title>PDD福袋五折互助</title>
<script src="https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f8ff;color:#333;min-height:100vh;padding:20px}
.container{max-width:800px;margin:0 auto}

/* 大白卡 */
.card{background:#fff;padding:20px;border-radius:16px;box-shadow:0 4px 20px rgba(59,130,246,.08);margin-bottom:20px;border:1px solid #e0f2fe}
.card h2{text-align:center;color:#2563eb;margin:0 0 15px;font-size:1.4em;font-weight:700}

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

/* 折叠 */
details{margin-top:15px}
summary{cursor:pointer;color:#3b82f6;font-weight:bold;font-size:15px;outline:none;padding:5px 0;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸ ";margin-right:4px}
details[open] summary::before{content:"▾ "}
.instruction-list{line-height:1.8;color:#4b5563;margin:10px 0 0 20px;padding:0;font-size:14px}
.entry-img{display:block;width:100%;max-width:400px;height:auto;border-radius:12px;box-shadow:0 6px 16px rgba(0,0,0,.1);margin:15px auto 0}

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

/* 输入区 */
.input-area{text-align:center;margin:10px 0 25px;display:flex;justify-content:center;gap:12px;align-items:center}
.input-area input{width:240px;height:44px;font-size:16px;padding:0 16px;border:2px solid #bfdbfe;border-radius:8px;outline:none;box-sizing:border-box;text-align:center;letter-spacing:2px}
.input-area input:focus{border-color:#3b82f6}
.submit-btn{background:linear-gradient(135deg,#3b82f6,#60a5fa);color:#fff;border:none;height:44px;padding:0 24px;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer;box-shadow:0 4px 12px rgba(59,130,246,.3);transition:all .2s ease;display:inline-flex;align-items:center;justify-content:center;min-width:120px;box-sizing:border-box}
.submit-btn:hover{transform:translateY(-2px)}
.submit-btn:active{transform:scale(.96)}
.submit-btn:disabled{opacity:.5;cursor:not-allowed}
.action-btn{display:inline-flex;align-items:center;justify-content:center;height:44px;padding:0 24px;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer;color:#fff;background:linear-gradient(135deg,#8b5cf6,#7c3aed);transition:all .2s ease;white-space:nowrap;position:relative;box-sizing:border-box;min-width:120px;box-shadow:0 4px 12px rgba(139,92,246,.3)}
.action-btn:hover{transform:translateY(-2px)}
.action-btn:active{transform:scale(.96)}
.action-btn:disabled{opacity:.5;cursor:not-allowed}

/* 识图提取 */
.ocr-btn{display:inline-flex;align-items:center;justify-content:center;height:44px;padding:0 24px;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer;color:#fff;background:linear-gradient(135deg,#10b981,#059669);transition:all .2s ease;white-space:nowrap;box-sizing:border-box;min-width:120px;box-shadow:0 4px 12px rgba(16,185,129,.3)}
.ocr-btn:hover{transform:translateY(-2px)}
.ocr-btn:active{transform:scale(.96)}
.ocr-btn:disabled{opacity:.5;cursor:not-allowed}

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
.loading{text-align:center;padding:20px;color:#999}

@media (max-width:600px){
body{padding:12px}
.card{padding:16px;border-radius:14px}
.card h2{font-size:1.25em}
.desc-text{font-size:14px;padding:11px 14px}
.feedback-btn{font-size:13px;padding:11px 0}
summary{font-size:14px}
.instruction-list{font-size:13px}
.input-area{flex-direction:column;align-items:stretch}
.input-area input{width:100%;margin-bottom:10px}
.submit-btn,.action-btn,.ocr-btn{width:100%;margin-bottom:10px;min-width:unset}
.list-item{flex-direction:column;gap:10px;align-items:flex-start;font-size:16px;padding:14px 16px}
.list-item .actions{align-self:flex-end}
.jump-btn{padding:8px 16px;font-size:14px}
.stats-bar{padding:10px 0}
.stat-num{font-size:18px}
.stat-label{font-size:10px}
}
</style>
</head>
<body>
<div class="container">

  <!-- ===== 第一张大白卡 ===== -->
  <div class="card">
    <h2>PDD福袋五折互助</h2>
    <p class="desc-text">
      ① 输入8-9位邀请码提交，支持重复提交点亮<br>
      ② 列表点"跳转"自动打开拼多多搜索<br>
      ③ 微信内请手动去拼多多粘贴搜索
      <span class="desc-tips">💡 只能提交 <b>拼多多福袋互助码</b>，请勿提交不相关互助码，将会被系统拉黑！</span>
    </p>

    <button class="feedback-btn" onclick="openContact()">💬 建议 · 反馈 · 申诉 · 加入组织</button>
    <button class="feedback-btn feedback-btn-red" onclick="openBlacklist()">🚫 违规小黑屋公示 (严打乱拉人)</button>
    <a class="feedback-btn feedback-btn-ios" href="https://www.icloud.com/shortcuts/e5dacaf5c4dc4809bca41848175373c1" target="_blank" rel="noopener">📱 <span>iOS 快捷指令版</span><span class="ios-tag">一键安装</span></a>

    <details>
      <summary>展开查看详细说明</summary>
      <ul class="instruction-list">
        <li>邀请码中间两位会隐藏显示（**）。</li>
        <li>点击"跳转"后会标记为"已使用"。</li>
        <li>如果码没被点，再次提交该码即可重新进入队列。</li>
        <li>活动入口：拼多多首页 - 百亿补贴 - 百亿消费券 - 福袋</li>
      </ul>
      <img class="entry-img" id="entryImg" src="" alt="活动入口" loading="lazy" style="display:none">
    </details>

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

    <!-- 输入区 -->
    <div class="input-area">
      <input type="tel" id="codeInput" placeholder="输入8-9位邀请码" maxlength="9" inputmode="numeric" pattern="[0-9]*" oninput="this.value=this.value.replace(/\D/g,'')">
      <input type="text" id="websiteField" style="display:none" tabindex="-1" autocomplete="off">
      <button class="submit-btn" id="submitBtn" onclick="submitCode()">立即提交</button>
      <button class="ocr-btn" id="ocrBtn" onclick="document.getElementById('ocrFile').click()">📷 识图提取</button>
      <input type="file" id="ocrFile" accept="image/*" style="display:none" onchange="handleOcrFile(this)">
      <button class="action-btn" id="smartBtn" onclick="quickUse()">🚀 智能直达</button>
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

</div>

<!-- 弹窗广告：有广告配置时展示，可关闭 -->
<div class="ad-pop" id="adPop">
  <button class="ad-close" onclick="closeAdPop()">×</button>
  <div class="ad-head">
    <div class="t">外卖·打车 每日必领神券</div>
    <div class="s">美团 · 淘宝闪购 · 京东｜外卖打车全线折上折</div>
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

<div class="toast" id="toast"></div>

<script>
function showToast(msg, type) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (type || 'success');
  setTimeout(function(){ t.className = 'toast'; }, 2500);
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
    btn.textContent = '提交';
  }
}

/** 读取自己用过的码 id（localStorage，用于区分"我用的"和"别人用的"） */
function getMyUsed() {
  try { return JSON.parse(localStorage.getItem('pdd_my_used') || '[]'); } catch(e) { return []; }
}

/* ============ 识图提取（Cloudflare Workers AI 视觉模型，服务端识别） ============ */

/** 选择图片后识别互助码（AI 或浏览器本地，按后台模式） */
async function handleOcrFile(fileEl) {
  var file = fileEl.files && fileEl.files[0];
  fileEl.value = ''; // 允许重复选择同一张图
  if (!file) return;

  // 限制图片大小（4MB）
  if (file.size > 4 * 1024 * 1024) {
    showToast('图片太大，请选小于 4MB 的截图', 'error');
    return;
  }

  var btn = document.getElementById('ocrBtn');
  var input = document.getElementById('codeInput');
  var oldText = btn.textContent;
  btn.disabled = true;

  // 模式：local 直接用浏览器本地；auto/ai 先走后端 AI
  var mode = window._ocrMode || 'auto';
  try {
    if (mode === 'local') {
      return await localOcr(file, btn, input);
    }
    btn.textContent = 'AI 识别中...';
    var formData = new FormData();
    formData.append('image', file);
    var res = await fetch('/api/ocr', { method: 'POST', body: formData });
    var data = await res.json();
    if (data.success && data.code) {
      fillOcrResult(input, data.code);
    } else if (data.fallback === 'local') {
      // 后端说 AI 额度用完，前端切本地识别
      return await localOcr(file, btn, input);
    } else {
      showToast(data.error || '未识别到互助码，请手动输入', 'error');
    }
  } catch(e) {
    showToast('识别出错，请手动输入互助码', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

/** 把识别结果填入输入框并提示 */
function fillOcrResult(input, code) {
  input.value = code;
  if (code.length >= 8 && code.length <= 9) {
    showToast('识别成功：' + code + '，请确认后提交', 'success');
  } else {
    showToast('识别到 ' + code + '（长度' + code.length + '位），请核对后提交', 'warning');
  }
  input.focus();
}

/** 浏览器本地 OCR（tesseract.js + 红底白字预处理，纯前端不消耗 AI 额度） */
var _ocrWorker = null;
async function localOcr(file, btn, input) {
  if (!window.Tesseract) {
    showToast('本地识别组件未加载，请手动输入互助码', 'error');
    return;
  }
  btn.textContent = '本地识别中...';
  try {
    var canvas = await preprocessImageForOcr(file);
    if (!_ocrWorker) {
      btn.textContent = '加载识别模型...';
      _ocrWorker = await Tesseract.createWorker('eng');
      await _ocrWorker.setParameters({ tessedit_char_whitelist: '0123456789' });
    }
    btn.textContent = '本地识别中...';
    var result = await _ocrWorker.recognize(canvas);
    var code = extractCodeFromText(result.data.text || '');
    if (code) {
      fillOcrResult(input, code);
    } else {
      // 本地未识别到：友好提示手动输入（本地模式不弹额度提示）
      showToast('本地未识别到互助码，请手动输入', 'error');
    }
  } catch(e) {
    showToast('本地识别出错，请手动输入互助码', 'error');
  }
}

/** 红底白字 → 黑字白底预处理（拼多多分享图），提升数字识别率 */
function preprocessImageForOcr(file) {
  return new Promise(function(resolve, reject) {
    var img = new Image();
    img.onload = function() {
      try {
        var scale = 2;
        var w = img.naturalWidth * scale, h = img.naturalHeight * scale;
        if (w > 3000) { var r = 3000 / w; w = Math.round(3000); h = Math.round(h * r); }
        var canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, w, h);
        var imgData = ctx.getImageData(0, 0, w, h);
        var d = imgData.data;
        for (var i = 0; i < d.length; i += 4) {
          var r = d[i], g = d[i + 1], b = d[i + 2];
          var isRed = r > 150 && (r - g) > 40 && (r - b) > 40;
          var isWhite = r > 200 && g > 200 && b > 200;
          var v;
          if (isRed) v = 255;
          else if (isWhite) v = 0;
          else {
            var lum = 0.299 * r + 0.587 * g + 0.114 * b;
            v = lum > 180 ? 0 : 255;
          }
          d[i] = d[i + 1] = d[i + 2] = v; d[i + 3] = 255;
        }
        ctx.putImageData(imgData, 0, 0);
        resolve(canvas);
      } catch (err) { reject(err); }
    };
    img.onerror = function() { reject(new Error('图片加载失败')); };
    img.src = URL.createObjectURL(file);
  });
}

/** 从文本中提取连续 8/9 位数字（兜底取最长 6-12 位） */
function extractCodeFromText(text) {
  var nums = (text.match(/\d+/g) || []);
  var valid = nums.filter(function(n) { return n.length === 8 || n.length === 9; });
  if (valid.length) return valid[0];
  if (nums.length) {
    var longest = nums.reduce(function(a, b) { return b.length > a.length ? b : a; });
    if (longest.length >= 6 && longest.length <= 12) return longest;
  }
  return null;
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
        var locShort = loc ? loc.substring(0, 12) : '';
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
          '<div class="info"><span class="number">' + item.code_masked + '</span>' +
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

async function useCode(id, btn) {
  try {
    var res = await fetch('/api/use/' + id, { method: 'POST' });
    var data = await res.json();
    if (data.success) {
      // 记录到自己名下：当前用户显示"已使用"，别人看是灰色
      addMyUsed(id);
      var item = btn.closest('.list-item');
      btn.outerHTML = '<span class="used-tag">已使用</span>';
      // 直接打开拼多多搜索（用返回的完整码）
      window.open('https://mobile.yangkeduo.com/search_result.html?search_key=' + data.code, '_blank');
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
  try {
    var res = await fetch('/api/quick-use', { method: 'POST' });
    var data = await res.json();
    if (data.success) {
      addQuickUsedFromResponse(data);
      // 标记为"刚使用"（需要拿到 id —— 智能直达接口返回完整码，前端从列表匹配）
      showToast('智能直达成功，已自动打开拼多多', 'success');
      window.open('https://mobile.yangkeduo.com/search_result.html?search_key=' + data.code, '_blank');
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

/** 智能直达成功后：把对应列表项的 id 记入"刚使用"集合 */
async function addQuickUsedFromResponse(data) {
  try {
    var res = await fetch('/api/codes');
    var list = await res.json();
    var codes = list.data || [];
    var match = codes.find(function(x){ return x.status === 'used'; });
    // 用完整码前3位+后3位模糊匹配（列表只有脱敏码）
    var head = data.code.slice(0, 3), tail = data.code.slice(-3);
    var found = codes.find(function(x){
      var m = x.code_masked.replace(/\\*/g, '');
      return x.code_masked.startsWith(head) && x.code_masked.endsWith(tail) && m.length === head.length + tail.length;
    });
    if (found) addQuickUsed(found.id);
  } catch(e) {}
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

// 使用 HTML5 <details>，无需 toggleFold 函数

/** 弹窗通用开关 */
function openModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }
function closeNoticeBar() { document.getElementById('noticeBar').style.display = 'none'; try { localStorage.setItem('pdd_notice_closed','1'); } catch(e){} }
function showNoticeModal() {
  var txt = document.getElementById('noticeText').textContent;
  var modal = document.createElement('div');
  modal.className = 'modal-mask show';
  modal.innerHTML = '<div class="modal"><button class="close-x" onclick="this.parentNode.parentNode.remove()">×</button><h2>📢 公告详情</h2><p style="white-space:pre-line;font-size:15px;line-height:1.8;color:#333">' + txt + '</p></div>';
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
    html += '<div class="contact-item"><strong>🚀 官方交流互助群</strong><p>群号：' + qqGroup + ' (进群不迷路，第一时间获取系统升级信息和福袋活动开放消息)</p></div>';
    document.getElementById('qqJoinBtn').style.display = 'block';
  } else {
    document.getElementById('qqJoinBtn').style.display = 'none';
  }
  if (qqOwner) {
    html += '<div class="contact-item"><strong>🛡️ 站长 QQ</strong><p>QQ号：' + qqOwner + ' (如遇被封禁申诉、或功能建议反馈，请联系我，也可以进群联系群主)</p></div>';
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
        var remaining = r.remaining || '永久';
        return '<tr><td>' + ts + '</td><td class="ip">' + r.ip + '</td><td>' + (r.location || '未知') + '</td><td>' + remaining + '</td></tr>';
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
function showAdPop(ads) {
  try { if (sessionStorage.getItem('pdd_ad_closed')) return; } catch(e) {}
  var links = document.getElementById('adPopLinks');
  var icons = ['#4a9eff', '#ff9500', '#2a71d0', '#0f95d0'];
  var initials = ['团', '淘', '京', '滴'];
  links.innerHTML = ads.map(function(ad, i) {
    var href = ad.link_url || 'javascript:void(0)';
    var target = ad.link_url ? 'target="_blank" rel="noopener"' : '';
    var ic = i < 4 ? initials[i] : '荐';
    var bg = icons[i % icons.length];
    return '<a class="ad-link" href="' + href + '" ' + target + '>' +
      '<span class="ad-icon" style="background:' + bg + '">' + ic + '</span>' +
      '<span class="txt">' + (ad.title || '点击查看') + '</span>' +
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
      document.getElementById('noticeText').textContent = cfg.notice;
      noticeBar.style.display = 'flex';
    } else {
      noticeBar.style.display = 'none';
    }

    // 活动入口图片（如果后台配置）
    if (cfg.entry_image) {
      var img = document.getElementById('entryImg');
      img.src = cfg.entry_image;
      img.style.display = 'block';
    }

    // 广告：弹窗（可关闭）+ 静态位（无广告都不显示）
    var adSection = document.getElementById('adSection');
    if (cfg.ads && cfg.ads.length > 0) {
      adSection.innerHTML = cfg.ads.map(function(ad) {
        var href = ad.link_url ? ad.link_url : 'javascript:void(0)';
        var target = ad.link_url ? 'target="_blank" rel="noopener"' : '';
        return '<a class="ad-banner" href="' + href + '" ' + target + '>' +
          '<img src="' + ad.image_url + '" alt="广告" loading="lazy">' +
        '</a>';
      }).join('');
      adSection.style.display = 'block';
      // 弹窗广告（延迟1.2秒展示，不打扰首次加载）
      setTimeout(function() { showAdPop(cfg.ads); }, 1200);
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

    // OCR 模式：存全局，识图时决定用 AI 还是浏览器本地
    window._ocrMode = (cfg.ocr_mode === 'ai' || cfg.ocr_mode === 'local') ? cfg.ocr_mode : 'auto';
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
        <label>识图提取模式</label>
        <select id="ocrModeInput" style="width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px">
          <option value="auto">自动（AI优先，额度用完自动切浏览器本地）</option>
          <option value="ai">仅服务端 AI（额度用完提示手动输入）</option>
          <option value="local">仅浏览器本地（不消耗 AI 额度）</option>
        </select>
        <div class="hint">自动模式：默认用 AI 识别，遇到额度限制自动改用浏览器本地识别。本地模式不消耗每日约 347 次的 AI 额度，但首次需下载识别组件（约 10MB）。</div>
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

/** 格式化后台剩余时间 */
function formatRemainingAdmin(expiresAt) {
  if (!expiresAt) return '永久';
  var diff = new Date(expiresAt).getTime() - Date.now();
  if (diff <= 0) return '已过期';
  var hours = Math.floor(diff / (3600 * 1000));
  if (hours < 24) return hours + '小时后';
  var days = Math.floor(hours / 24);
  if (days < 30) return days + '天后';
  var months = Math.floor(days / 30);
  if (months < 12) return months + '个月后';
  return Math.floor(months / 12) + '年后';
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
  opts.headers['X-Admin-Key'] = adminKey;
  return fetch(path, opts).then(function(r){ return r.json(); });
}

function doLogin() {
  adminKey = document.getElementById('adminKeyInput').value.trim();
  if (!adminKey) return;
  api('/api/admin/stats').then(function(data) {
    if (data.success) {
      document.getElementById('loginBox').classList.add('hidden');
      document.getElementById('adminPanel').classList.remove('hidden');
      loadStats();
    } else {
      alert('密钥错误');
    }
  }).catch(function(){ alert('登录失败'); });
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
  return '<div class="ad-row" id="adRow-' + adSeq + '">' +
    '<input type="text" class="ad-img" placeholder="广告图片URL (必填)" value="' + (image_url || '') + '">' +
    '<input type="text" class="ad-link" placeholder="跳转链接URL (可选)" value="' + (link_url || '') + '" style="flex:0.8">' +
    '<button class="rm-btn" onclick="removeAdRow(\\'adRow-' + adSeq + '\\')">删除</button>' +
  '</div>';
}

function loadSettings() {
  api('/api/admin/settings').then(function(data) {
    if (!data.success) return;
    document.getElementById('noticeInput').value = data.data.notice || '';
    document.getElementById('qqGroupInput').value = data.data.qq_group || '';
    document.getElementById('qqOwnerInput').value = data.data.qq_owner || '';
    document.getElementById('smartEnabledInput').value = data.data.smart_enabled === 'off' ? 'off' : 'on';
    document.getElementById('refreshIntervalInput').value = data.data.refresh_interval || '5';
    document.getElementById('rateLimitMaxInput').value = data.data.rate_limit_max || '5';
    document.getElementById('dailyLimitInput').value = data.data.daily_limit || '30';
    document.getElementById('ocrModeInput').value = (data.data.ocr_mode === 'ai' || data.data.ocr_mode === 'local') ? data.data.ocr_mode : 'auto';
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
  var ads = [];
  document.querySelectorAll('#adsContainer .ad-row').forEach(function(row) {
    var img = row.querySelector('.ad-img').value.trim();
    var link = row.querySelector('.ad-link').value.trim();
    if (img) ads.push({ image_url: img, link_url: link });
  });

  api('/api/admin/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notice: notice, ads: ads, qq_group: qqGroup, qq_owner: qqOwner, smart_enabled: smartEnabled, refresh_interval: refreshInterval, rate_limit_max: rateLimitMax, daily_limit: dailyLimit, ocr_mode: ocrMode })
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
        return '<tr><td>' + c.id + '</td><td class="mono">' + c.code + '</td><td class="mono">' + c.ip + '</td>' +
          '<td style="font-size:12px;color:#666">' + (c.location || '-') + '</td>' +
          '<td style="color:' + statusColor + '">' + c.status + '</td><td>' + time + '</td>' +
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
        var remaining = b.expires_at ? formatRemainingAdmin(b.expires_at) : (b.duration === 'permanent' ? '永久' : '');
        var durLabel = durMap[b.duration] || b.duration || '-';
        var durHtml = remaining ? durLabel + '<br><span style="color:#e53935;font-size:11px">' + remaining + '</span>' : durLabel;
        return '<tr><td class="mono">' + b.ip + '</td><td>' + (b.location || '-') + '</td><td>' + (b.reason || '-') + '</td><td>' + durHtml + '</td><td>' + time + '</td>' +
          '<td><button class="btn-sm btn-success" onclick="removeBlacklist(\\'' + b.ip + '\\')">移除</button></td></tr>';
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
        return '<tr><td>' + r.id + '</td><td class="mono">' + (r.code || '-') + '</td><td class="mono">' + r.ip + '</td>' +
          '<td class="mono">' + submitterIP + '</td>' +
          '<td style="color:' + st[1] + '">' + st[0] + '</td><td>' + time + '</td><td>' + actions + '</td></tr>';
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
        return '<tr><td class="mono">' + l.ip + '</td><td class="mono">' + (l.code || '-') + '</td>' +
          '<td style="color:' + actionColor + '">' + l.action + '</td><td>' + (l.reason || '-') + '</td><td>' + time + '</td></tr>';
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
</script>
</body>
</html>`;
