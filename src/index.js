const SESSION_TTL = 60 * 60 * 24 * 7;
const SESSION_TTL_MS = SESSION_TTL * 1000;

const LOGIN_WINDOW_MS = 60_000;
const LOGIN_MAX_ATTEMPTS = 5;

const JSON_MAX_BYTES = 1_000_000;
const MAX_MESSAGES = 300;
const MAX_CONV_NAME = 80;
const MAX_MSG_NAME = 255;
const GET_CONCURRENCY = 20;
const PAGE_SIZE = 50;                 // 懒加载每页条数
const MAX_TS = 9999999999999;         // 13 位数字上限，用于反向时间戳

const SAFE_INLINE_TYPES = new Set([
  'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
  'image/webp', 'image/avif', 'image/bmp',
  'application/pdf',
]);

const encoder = new TextEncoder();

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });

async function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [ah, bh] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  const A = new Uint8Array(ah), B = new Uint8Array(bh);
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}

function parseTs(v, fallback = 0) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function isExpired(meta) {
  if (!meta || !meta.e) return false;
  const exp = parseTs(meta.e, 0);
  return exp > 0 && Date.now() > exp;
}

function safeMime(raw) {
  if (typeof raw !== 'string') return 'application/octet-stream';
  const clean = raw.toLowerCase().replace(/[\r\n\t]/g, '').trim();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(clean)) {
    return 'application/octet-stream';
  }
  if (clean.length > 100) return 'application/octet-stream';
  return clean;
}

function safeDecode(s) {
  if (typeof s !== 'string') return '';
  try { return decodeURIComponent(s); } catch { return ''; }
}

async function safeJsonBody(request, maxBytes = JSON_MAX_BYTES) {
  const len = request.headers.get('Content-Length');
  if (len) {
    const n = parseInt(len, 10);
    if (Number.isFinite(n) && n > maxBytes) {
      throw new Response('payload too large', { status: 413 });
    }
  }
  try {
    const txt = await request.text();
    if (txt.length > maxBytes) {
      throw new Response('payload too large', { status: 413 });
    }
    return txt ? JSON.parse(txt) : {};
  } catch (e) {
    if (e instanceof Response) throw e;
    throw new Response('bad json', { status: 400 });
  }
}

function parseCookie(header, name) {
  if (!header) return null;
  const re = new RegExp('(?:^|;\\s*)' + name + '=([^;]*)');
  const m = header.match(re);
  return m ? m[1] : null;
}

const setCookie = (sid, maxAge) =>
  `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;

/* ============================================================
 * 多租户：密码 → 租户 ID
 * ============================================================ */
function sanitizeTenant(id) {
  return String(id).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 32);
}

async function resolveTenant(env, password) {
  if (env.ACCESS_TOKENS) {
    let map;
    try { map = JSON.parse(env.ACCESS_TOKENS); }
    catch { return null; }
    if (!map || typeof map !== 'object') return null;

    let found = null;
    for (const [pw, tenant] of Object.entries(map)) {
      if (typeof pw !== 'string' || typeof tenant !== 'string') continue;
      if (!tenant) continue;
      const ok = await timingSafeEqual(password, pw);
      if (ok && found === null) {
        found = sanitizeTenant(tenant);
      }
    }
    return found;
  }

  if (env.ACCESS_TOKEN) {
    if (await timingSafeEqual(password, env.ACCESS_TOKEN)) return 'default';
  }
  return null;
}

/* ============================================================
 * 会话
 * ============================================================ */
async function getSession(env, request) {
  const sid = parseCookie(request.headers.get('Cookie'), 'sid');
  if (!sid || !/^[a-f0-9]{64}$/.test(sid)) return null;
  const key = 'session/' + sid;
  const obj = await env.BUCKET.head(key);
  if (!obj) return null;
  const exp = parseTs(obj.customMetadata?.exp, 0);
  const tenant = obj.customMetadata?.t;
  if (exp <= 0 || Date.now() > exp || !tenant) {
    await env.BUCKET.delete(key);
    return null;
  }
  return { sid, key, exp, tenant };
}

async function maybeRenew(env, sess) {
  if (!sess) return null;
  const remain = sess.exp - Date.now();
  if (remain >= SESSION_TTL_MS * 0.5) return null;
  const newExp = Date.now() + SESSION_TTL_MS;
  try {
    await env.BUCKET.put(sess.key, '1', {
      customMetadata: { exp: String(newExp), t: sess.tenant },
    });
    return setCookie(sess.sid, SESSION_TTL);
  } catch {
    return null;
  }
}

function clientIp(request) {
  return (
    request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() ||
    'unknown'
  );
}

/* ============================================================
 * 登录限流
 * ============================================================ */
async function loginRateLimit(env, ip) {
  const key = 'ratelimit/login/' + ip.replace(/[^a-fA-F0-9:.]/g, '_');
  const now = Date.now();
  let data = null;
  try {
    const obj = await env.BUCKET.get(key);
    if (obj) data = JSON.parse(await obj.text());
  } catch {}
  if (!data || typeof data !== 'object' || !Number.isFinite(data.r) || now > data.r) {
    data = { c: 0, r: now + LOGIN_WINDOW_MS };
  }
  data.c = (Number.isFinite(data.c) ? data.c : 0) + 1;
  if (data.c > LOGIN_MAX_ATTEMPTS) {
    const retryAfter = Math.max(1, Math.ceil((data.r - now) / 1000));
    return { blocked: true, retryAfter, key, data };
  }
  return { blocked: false, key, data };
}

async function recordAttempt(env, key, data) {
  await env.BUCKET.put(key, JSON.stringify(data), {
    customMetadata: { exp: String(data.r + 60_000) },
  });
}

/* ============================================================
 * 分页列举
 * ============================================================ */
async function* listAll(bucket, opts = {}) {
  let cursor;
  let pages = 0;
  do {
    const page = await bucket.list({
      ...opts,
      cursor,
      limit: 1000,
      include: ['customMetadata'],
    });
    for (const o of page.objects) yield o;
    cursor = page.truncated ? page.cursor : undefined;
    pages++;
    if (pages > 100) break;
  } while (cursor);
}

/* ---------- ID 校验 ---------- */
function isValidConvId(id) {
  return typeof id === 'string' && /^[a-f0-9]{16,32}$/.test(id);
}
function isValidMsgId(id) {
  return typeof id === 'string' && /^\d{10,16}-[a-f0-9]{8}$/.test(id);
}
function isValidFileUuid(id) {
  return typeof id === 'string' && /^[a-f0-9-]{36}$/.test(id);
}

/* ---------- 路径构造函数 ---------- */
const convMetaKey  = (t, cid) => `${t}/conv/${cid}/meta`;
const convMsgKey   = (t, cid, mid) => `${t}/conv/${cid}/msg/${mid}`;
const convMsgPrefix= (t, cid) => `${t}/conv/${cid}/msg/`;
const convPrefix   = (t) => `${t}/conv/`;
const fileKey      = (t, uuid) => `${t}/file/${uuid}`;

/* ============================================================
 * 同步信号广播
 * ============================================================ */
async function broadcastSignal(env, tenant, payload) {
  try {
    if (!env.SYNC_HUB) return;
    const id = env.SYNC_HUB.idFromName(tenant);
    const stub = env.SYNC_HUB.get(id);
    await stub.fetch('https://do/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch {
    // 静默失败
  }
}

/* ============================================================
 * 对话
 * ============================================================ */
async function listConversations(env, tenant) {
  const list = [];
  const gets = [];
  const prefix = convPrefix(tenant);

  for await (const o of listAll(env.BUCKET, { prefix })) {
    if (!o.key.endsWith('/meta')) continue;
    gets.push((async () => {
      const obj = await env.BUCKET.get(o.key);
      if (!obj) return;
      try { list.push(JSON.parse(await obj.text())); } catch {}
    })());
  }
  await Promise.all(gets);
  list.sort((a, b) => {
    const ap = a.pinned ? 1 : 0;
    const bp = b.pinned ? 1 : 0;
    if (ap !== bp) return bp - ap;
    return (b.updated || 0) - (a.updated || 0);
  });
  return json({ conversations: list });
}

async function createConversation(env, request, tenant) {
  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  const rawName = typeof body.name === 'string' ? body.name : '';
  const name = (rawName.trim() || '新对话').slice(0, MAX_CONV_NAME);
  const now = Date.now();
  const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const conv = { id, name, created: now, updated: now, pinned: false };

  await env.BUCKET.put(convMetaKey(tenant, id), JSON.stringify(conv));

  await broadcastSignal(env, tenant, { type: 'sync-conv', ts: now });

  return json({ conversation: conv });
}

async function updateConversation(env, request, convId, tenant) {
  const key = convMetaKey(tenant, convId);
  const obj = await env.BUCKET.get(key);
  if (!obj) return json({ error: 'not found' }, 404);

  let data;
  try { data = JSON.parse(await obj.text()); }
  catch { return json({ error: 'invalid conversation data' }, 500); }

  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  let changed = false;

  if (typeof body.name === 'string') {
    const name = body.name.trim().replace(/[\r\n\t]/g, ' ').slice(0, MAX_CONV_NAME);
    if (!name) return json({ error: 'invalid name' }, 400);
    data.name = name;
    changed = true;
  }
  if (typeof body.pinned === 'boolean') {
    data.pinned = body.pinned;
    changed = true;
  }
  if (!changed) return json({ error: 'nothing to update' }, 400);

  await env.BUCKET.put(key, JSON.stringify(data));

  await broadcastSignal(env, tenant, { type: 'sync-conv', ts: Date.now() });

  return json({ conversation: data });
}

async function updateConvUpdated(env, tenant, convId, ts) {
  const key = convMetaKey(tenant, convId);
  const obj = await env.BUCKET.get(key);
  if (!obj) return;
  try {
    const data = JSON.parse(await obj.text());
    data.updated = ts;
    await env.BUCKET.put(key, JSON.stringify(data));
  } catch {}
}

async function deleteConversation(env, convId, tenant) {
  const fileUuids = [];
  const deletes = [];
  const prefix = `${tenant}/conv/${convId}/`;

  for await (const o of listAll(env.BUCKET, { prefix })) {
    if (o.key.includes('/msg/')) {
      const meta = o.customMetadata || {};
      if (meta.t === 'file' && meta.k) fileUuids.push(meta.k);
    }
    deletes.push(env.BUCKET.delete(o.key));
  }
  await Promise.all(deletes);

  if (fileUuids.length) {
    await Promise.all(
      fileUuids.map(u => env.BUCKET.delete(fileKey(tenant, u)).catch(() => {}))
    );
  }

  await broadcastSignal(env, tenant, { type: 'sync-conv', ts: Date.now() });

  return json({ ok: true, deletedFiles: fileUuids.length });
}

/* ============================================================
 * 消息
 * ============================================================
 * 消息 key 格式：{tenant}/conv/{cid}/msg/{reverse_ts}-{uuid8}
 *   reverse_ts = MAX_TS - 真实毫秒时间戳
 *   R2 list() 升序 → 最新消息排最前
 *
 * listMessages 支持分页：
 *   - 无 before：返回最新 PAGE_SIZE 条
 *   - before=xxx：返回严格早于 xxx 的 PAGE_SIZE 条
 *   返回按时间顺序（最旧 → 最新），与旧版本一致
 */
async function listMessages(env, convId, tenant, before) {
  const prefix = convMsgPrefix(tenant, convId);
  const startAfter = before ? `${prefix}${before}` : undefined;

  // 多拿一条判断是否还有更多
  const page = await env.BUCKET.list({
    prefix,
    startAfter,
    limit: PAGE_SIZE + 1,
    include: ['customMetadata'],
  });

  const hasMore = page.objects.length > PAGE_SIZE;
  const objects = page.objects.slice(0, PAGE_SIZE);

  // 反转为时间顺序（最旧 → 最新），和旧版一致
  const ordered = objects.slice().reverse();

  const result = new Array(ordered.length);
  const textTasks = [];

  for (let i = 0; i < ordered.length; i++) {
    const o = ordered[i];
    const meta = o.customMetadata || {};
    const id = o.key.slice(prefix.length);

    // 优先用 meta.ts，兜底从反向 id 反推
    let ts = parseTs(meta.ts, 0);
    if (!ts) {
      const reverseTs = parseTs(id.split('-')[0], 0);
      if (reverseTs > 0) ts = MAX_TS - reverseTs;
    }

    if (meta.t === 'file') {
      result[i] = {
        id, t: 'file', ts,
        k: meta.k || '',
        n: meta.n || '',
        s: parseTs(meta.s, 0),
        m: meta.m || '',
        e: parseTs(meta.e, 0),
      };
    } else {
      textTasks.push({ idx: i, key: o.key, id, ts });
    }
  }

  // 文本消息分批并发 get
  for (let i = 0; i < textTasks.length; i += GET_CONCURRENCY) {
    const batch = textTasks.slice(i, i + GET_CONCURRENCY);
    await Promise.all(batch.map(async ({ idx, key, id, ts }) => {
      try {
        const obj = await env.BUCKET.get(key);
        const v = obj ? await obj.text() : '';
        result[idx] = { id, t: 'text', ts, v };
      } catch {
        result[idx] = { id, t: 'text', ts, v: '' };
      }
    }));
  }

  const messages = result.filter(Boolean);
  return json({ messages, hasMore });
}

async function createMessage(env, request, convId, tenant) {
  const metaObj = await env.BUCKET.head(convMetaKey(tenant, convId));
  if (!metaObj) return json({ error: 'conversation not found' }, 404);

  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  const now = Date.now();
  const reverseTs = MAX_TS - now;   // 反转时间戳：越小表示越新
  const msgId = `${reverseTs}-${crypto.randomUUID().replace(/-/g, '').slice(0, 8)}`;
  const key = convMsgKey(tenant, convId, msgId);

  if (body.t === 'text') {
    const v = typeof body.v === 'string' ? body.v : '';
    if (!v) return json({ error: 'empty message' }, 400);
    if (v.length > 200_000) return json({ error: 'too long' }, 400);

    await env.BUCKET.put(key, v, {
      customMetadata: { t: 'text', ts: String(now) },
    });
  } else if (body.t === 'file') {
    const k = typeof body.k === 'string' ? body.k : '';
    if (!isValidFileUuid(k)) return json({ error: 'bad file key' }, 400);

    const r2Key = fileKey(tenant, k);
    const fileObj = await env.BUCKET.head(r2Key);
    if (!fileObj) return json({ error: 'file not found' }, 404);

    const rawName = typeof body.n === 'string' ? body.n : '';
    const name = (rawName.trim() || 'file').slice(0, MAX_MSG_NAME)
      .replace(/[\r\n\t]/g, ' ');
    const size = parseTs(body.s, fileObj.size || 0);
    const mime = safeMime(body.m);
    const exp = parseTs(body.e, 0);

    const meta = {
      t: 'file',
      ts: String(now),
      k,
      n: name,
      s: String(size),
      m: mime,
    };
    if (exp > 0) meta.e = String(exp);

    await env.BUCKET.put(key, '', { customMetadata: meta });
  } else {
    return json({ error: 'bad type' }, 400);
  }

  await updateConvUpdated(env, tenant, convId, now).catch(() => {});
  await trimMessages(env, tenant, convId).catch(() => {});

  await broadcastSignal(env, tenant, { type: 'sync', convId, ts: now });

  return json({ ok: true, id: msgId, ts: now });
}

async function trimMessages(env, tenant, convId) {
  const arr = [];
  const prefix = convMsgPrefix(tenant, convId);
  for await (const o of listAll(env.BUCKET, { prefix })) {
    arr.push(o);
  }
  if (arr.length <= MAX_MESSAGES) return;

  // 反向时间戳下，升序 = 最新在前，所以要删的是后面（最旧的）
  arr.sort((a, b) => a.key.localeCompare(b.key));
  const toDelete = arr.slice(MAX_MESSAGES);

  for (const o of toDelete) {
    const meta = o.customMetadata || {};
    if (meta.t === 'file' && meta.k) {
      await env.BUCKET.delete(fileKey(tenant, meta.k)).catch(() => {});
    }
    await env.BUCKET.delete(o.key).catch(() => {});
  }
}

async function deleteMessage(env, convId, msgId, tenant) {
  const key = convMsgKey(tenant, convId, msgId);
  const obj = await env.BUCKET.head(key);
  if (!obj) return json({ error: 'not found' }, 404);
  const meta = obj.customMetadata || {};
  if (meta.t === 'file' && meta.k) {
    await env.BUCKET.delete(fileKey(tenant, meta.k)).catch(() => {});
  }
  await env.BUCKET.delete(key);

  await broadcastSignal(env, tenant, { type: 'sync', convId, ts: Date.now() });

  return json({ ok: true });
}

async function patchMessage(env, request, convId, msgId, tenant) {
  const key = convMsgKey(tenant, convId, msgId);
  const obj = await env.BUCKET.head(key);
  if (!obj) return json({ error: 'not found' }, 404);
  const meta = obj.customMetadata || {};
  if (meta.t !== 'file') {
    return json({ error: 'only file messages can be renamed' }, 400);
  }

  let body;
  try { body = await safeJsonBody(request); }
  catch (e) { return e instanceof Response ? e : json({ error: 'bad request' }, 400); }

  const rawName = body.n;
  if (typeof rawName !== 'string' || !rawName.trim() || rawName.length > MAX_MSG_NAME) {
    return json({ error: 'invalid name' }, 400);
  }
  const name = rawName.trim().replace(/[\r\n\t]/g, ' ');

  const newMeta = { ...meta, n: name };
  await env.BUCKET.put(key, '', { customMetadata: newMeta });

  if (meta.k && isValidFileUuid(meta.k)) {
    try {
      const r2Key = fileKey(tenant, meta.k);
      const fobj = await env.BUCKET.get(r2Key);
      if (fobj) {
        const fmeta = { ...(fobj.customMetadata || {}), n: name };
        await env.BUCKET.put(r2Key, fobj.body, {
          customMetadata: fmeta,
          httpMetadata: fobj.httpMetadata,
        });
      }
    } catch {}
  }

  await broadcastSignal(env, tenant, { type: 'sync', convId, ts: Date.now() });

  return json({ ok: true, n: name });
}

/* ============================================================
 * Durable Object：WebSocket 同步中枢
 * ============================================================ */
export class SyncHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/broadcast' && request.method === 'POST') {
      let payload = null;
      try { payload = await request.json(); } catch {}
      const sent = this.broadcast(payload);
      return new Response(JSON.stringify({ ok: true, sent }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const upgrade = request.headers.get('Upgrade');
    if (upgrade !== 'websocket') {
      return new Response('expected websocket', { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    this.state.acceptWebSocket(server);

    try {
      server.send(JSON.stringify({ type: 'hello', ts: Date.now() }));
    } catch {}

    return new Response(null, { status: 101, webSocket: client });
  }

  broadcast(payload) {
    if (!payload) return 0;
    let data;
    try { data = JSON.stringify(payload); } catch { return 0; }
    let sent = 0;
    for (const ws of this.state.getWebSockets()) {
      try { ws.send(data); sent++; } catch {}
    }
    return sent;
  }

  async webSocketMessage(ws, msg) {
    if (msg === 'ping') {
      try { ws.send('pong'); } catch {}
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
    try { ws.close(code, reason); } catch {}
  }

  async webSocketError(ws, error) {
    try { ws.close(1011, 'error'); } catch {}
  }
}

/* ============================================================
 * 主入口
 * ============================================================ */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    /* ---------- 静态资源 ---------- */
    if (!path.startsWith('/api/')) {
      const res = await env.ASSETS.fetch(request);
      const headers = new Headers(res.headers);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Referrer-Policy', 'no-referrer');
      headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      headers.set('X-Frame-Options', 'DENY');
      headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
      headers.set('Content-Security-Policy', [
        "default-src 'self'",
        "img-src 'self' data: blob:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self' 'unsafe-inline'",
        "connect-src 'self'",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; '));
      return new Response(res.body, {
        status: res.status,
        statusText: res.statusText,
        headers,
      });
    }

    /* ---------- 登录 ---------- */
    if (path === '/api/login' && request.method === 'POST') {
      const ip = clientIp(request);
      const rl = await loginRateLimit(env, ip);
      if (rl.blocked) {
        return json(
          { error: 'too many attempts', retryAfter: rl.retryAfter },
          429,
          { 'Retry-After': String(rl.retryAfter) }
        );
      }

      let body;
      try { body = await safeJsonBody(request); }
      catch (e) {
        await recordAttempt(env, rl.key, rl.data);
        return e instanceof Response ? e : json({ error: 'bad request' }, 400);
      }

      const { password } = body;
      if (!password || typeof password !== 'string' || password.length > 256) {
        await recordAttempt(env, rl.key, rl.data);
        return json({ error: 'unauthorized' }, 401);
      }

      const tenant = await resolveTenant(env, password);
      if (!tenant) {
        await recordAttempt(env, rl.key, rl.data);
        return json({ error: 'unauthorized' }, 401);
      }

      await env.BUCKET.delete(rl.key).catch(() => {});

      const sid =
        crypto.randomUUID().replace(/-/g, '') +
        crypto.randomUUID().replace(/-/g, '');

      await env.BUCKET.put('session/' + sid, '1', {
        customMetadata: {
          exp: String(Date.now() + SESSION_TTL_MS),
          t: tenant,
        },
      });

      return json({ ok: true }, 200, { 'Set-Cookie': setCookie(sid, SESSION_TTL) });
    }

    if (path === '/api/logout' && request.method === 'POST') {
      const sess = await getSession(env, request);
      if (sess) await env.BUCKET.delete(sess.key);
      return json({ ok: true }, 200, { 'Set-Cookie': setCookie('', 0) });
    }

    if (path === '/api/logout-all' && request.method === 'POST') {
      const sess = await getSession(env, request);
      if (!sess) return json({ error: 'unauthorized' }, 401);
      let count = 0;
      for await (const o of listAll(env.BUCKET, { prefix: 'session/' })) {
        if (o.customMetadata?.t === sess.tenant) {
          await env.BUCKET.delete(o.key);
          count++;
        }
      }
      return json({ ok: true, revoked: count }, 200, {
        'Set-Cookie': setCookie('', 0),
      });
    }

    if (path === '/api/session' && request.method === 'GET') {
      const sess = await getSession(env, request);
      if (!sess) return json({ ok: false });
      const newCookie = await maybeRenew(env, sess);
      const headers = {};
      if (newCookie) headers['Set-Cookie'] = newCookie;
      return json({ ok: true }, 200, headers);
    }

    /* ---------- 认证 ---------- */
    const sess = await getSession(env, request);
    if (!sess) return json({ error: 'unauthorized' }, 401);
    const tenant = sess.tenant;

    /* ---------- WebSocket 同步通道 ---------- */
    if (path === '/api/ws') {
      if (request.headers.get('Upgrade') !== 'websocket') {
        return json({ error: 'expected websocket' }, 426);
      }
      if (!env.SYNC_HUB) {
        return json({ error: 'sync hub not configured' }, 503);
      }
      const id = env.SYNC_HUB.idFromName(tenant);
      const stub = env.SYNC_HUB.get(id);
      return stub.fetch(request);
    }

    const renewCookie = await maybeRenew(env, sess);

    const respond = (resp) => {
      if (!renewCookie) return resp;
      const headers = new Headers(resp.headers);
      headers.append('Set-Cookie', renewCookie);
      return new Response(resp.body, {
        status: resp.status,
        statusText: resp.statusText,
        headers,
      });
    };

    /* ---------- 对话 ---------- */
    if (path === '/api/conversations') {
      if (request.method === 'GET')  return respond(await listConversations(env, tenant));
      if (request.method === 'POST') return respond(await createConversation(env, request, tenant));
      return json({ error: 'method not allowed' }, 405);
    }

    const convMatch = path.match(/^\/api\/conversations\/([^\/]+)$/);
    if (convMatch) {
      const convId = safeDecode(convMatch[1]);
      if (!isValidConvId(convId)) return json({ error: 'bad id' }, 400);
      if (request.method === 'DELETE') return respond(await deleteConversation(env, convId, tenant));
      if (request.method === 'PATCH')  return respond(await updateConversation(env, request, convId, tenant));
      return json({ error: 'method not allowed' }, 405);
    }

    /* ---------- 消息集合 ---------- */
    const msgsMatch = path.match(/^\/api\/conversations\/([^\/]+)\/messages$/);
    if (msgsMatch) {
      const convId = safeDecode(msgsMatch[1]);
      if (!isValidConvId(convId)) return json({ error: 'bad id' }, 400);

      if (request.method === 'GET') {
        // 分页游标：客户端传最旧消息的 id
        const before = url.searchParams.get('before') || '';
        if (before && !isValidMsgId(before)) {
          return json({ error: 'bad before' }, 400);
        }
        return respond(await listMessages(env, convId, tenant, before));
      }
      if (request.method === 'POST') return respond(await createMessage(env, request, convId, tenant));
      return json({ error: 'method not allowed' }, 405);
    }

    /* ---------- 单条消息 ---------- */
    const msgMatch = path.match(/^\/api\/conversations\/([^\/]+)\/messages\/([^\/]+)$/);
    if (msgMatch) {
      const convId = safeDecode(msgMatch[1]);
      const msgId  = safeDecode(msgMatch[2]);
      if (!isValidConvId(convId) || !isValidMsgId(msgId)) {
        return json({ error: 'bad id' }, 400);
      }
      if (request.method === 'DELETE') return respond(await deleteMessage(env, convId, msgId, tenant));
      if (request.method === 'PATCH')  return respond(await patchMessage(env, request, convId, msgId, tenant));
      return json({ error: 'method not allowed' }, 405);
    }

    /* ---------- 文件上传 ---------- */
    if (path === '/api/files' && request.method === 'POST') {
      if (!request.body) return json({ error: 'no body' }, 400);

      const uuid = crypto.randomUUID();
      const r2Key = fileKey(tenant, uuid);

      const rawName = request.headers.get('X-File-Name') || '';
      const name = safeDecode(rawName).slice(0, MAX_MSG_NAME).replace(/[\r\n\t]/g, ' ');
      const rawType = request.headers.get('X-File-Type') || '';
      const type = safeMime(rawType);
      const expiresSec = parseTs(request.headers.get('X-Expires'), 0);

      const meta = { n: name || 'unnamed', t: type };
      if (expiresSec > 0 && expiresSec <= 60 * 60 * 24 * 365) {
        meta.e = String(Date.now() + expiresSec * 1000);
      }

      await env.BUCKET.put(r2Key, request.body, {
        customMetadata: meta,
        httpMetadata: { contentType: type },
      });

      return respond(json({ key: uuid, name: meta.n, exp: meta.e ? parseTs(meta.e, 0) : 0 }));
    }

    /* ---------- 文件下载 ---------- */
    if (path.startsWith('/api/files/') && request.method === 'GET') {
      const uuid = safeDecode(path.slice('/api/files/'.length));
      if (!isValidFileUuid(uuid)) return json({ error: 'bad key' }, 400);

      const r2Key = fileKey(tenant, uuid);
      const obj = await env.BUCKET.get(r2Key);
      if (!obj) return json({ error: 'not found' }, 404);
      if (isExpired(obj.customMetadata)) {
        await env.BUCKET.delete(r2Key);
        return json({ error: 'expired' }, 410);
      }

      const name = obj.customMetadata?.n || uuid;
      const type = safeMime(obj.customMetadata?.t);

      const wantInline = url.searchParams.get('inline') === '1';
      const inline = wantInline && SAFE_INLINE_TYPES.has(type);

      const headers = {
        'Content-Type': inline
          ? type
          : (SAFE_INLINE_TYPES.has(type) ? type : 'application/octet-stream'),
        'Content-Length': String(obj.size),
        'Cache-Control': 'private, max-age=300',
        'X-Content-Type-Options': 'nosniff',
        'Cross-Origin-Resource-Policy': 'same-origin',
      };
      if (!inline) {
        headers['Content-Disposition'] =
          `attachment; filename*=UTF-8''${encodeURIComponent(name)}`;
      }

      return respond(new Response(obj.body, { headers }));
    }

    return json({ error: 'not found' }, 404);
  },

  /* ---------- 定时清理 ---------- */
  async scheduled(event, env, ctx) {
    const now = Date.now();
    const dead = [];

    for await (const o of listAll(env.BUCKET, {})) {
      if (o.key.startsWith('session/') || o.key.startsWith('ratelimit/')) {
        const exp = parseTs(o.customMetadata?.exp, 0);
        if (exp <= 0 || now > exp) dead.push(env.BUCKET.delete(o.key));
        continue;
      }

      if (isExpired(o.customMetadata)) {
        dead.push(env.BUCKET.delete(o.key));
      }
    }
    if (dead.length) await Promise.all(dead);
  },
};