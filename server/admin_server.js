'use strict';

/**
 * Web 管理面（默认 :9090，端口/密码在 server/.env 配置）：
 * - REST API：status / connections / history / traffic / logs / config / close
 * - SSE 实时推送：status（5s 快照）、conn / log（实时事件）
 * - SPA 静态托管：server/web-admin/dist 构建产物（非 /api/ 路径回 index.html）
 * - 鉴权：POST /api/login 换内存 token（24h 过期）；SSE 因 EventSource 限制用 ?token=
 *
 * 安全提示：管理面监听 0.0.0.0 时等于公网暴露，务必设置强 ADMIN_PASSWORD，
 * 并在云防火墙对该端口做 IP 白名单。
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const metrics = require('./metrics');
const log = require('./lib/log');

// ---------- .env 加载（统一走 lib/env，server.js 已最先加载，此处幂等） ----------
require('./lib/env').load();

let ADMIN_PASSWORD;
let ADMIN_PORT;
let ADMIN_HOST;
const TOKEN_TTL_MS = 24 * 3600 * 1000;
const LOGIN_MAX_PER_MIN = 10;

const DIST_DIR = path.join(__dirname, 'web-admin', 'dist');
const PKG_VERSION = require('./package.json').version;

const tokens = new Map();            // token -> expiresAt
const loginAttempts = new Map();     // ip -> { windowStart, count }

let opts = { closeConn: null };
let server = null;
let cleanupTimer = null;
const streams = new Set();

// ---------- 基础 helpers ----------
function json(res, code, obj) {
  if (res.destroyed || res.writableEnded) return;
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let settled = false;
    const fail = (code) => {
      if (settled) return;
      settled = true;
      const error = new Error('invalid request body');
      error.statusCode = code;
      reject(error);
    };
    req.on('data', (d) => {
      bytes += d.length;
      if (bytes > 8192) { fail(413); return; }
      if (!settled) chunks.push(d);
    });
    req.on('end', () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks).toString('utf8')); } });
    req.on('error', () => fail(400));
    req.on('aborted', () => fail(400));
  });
}

function isAuthed(req) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return false;
  const exp = tokens.get(t);
  if (!exp) return false;
  if (exp <= Date.now()) { tokens.delete(t); return false; }
  return true;
}

function checkLoginRate(ip) {
  if (!loginAttempts.has(ip) && loginAttempts.size >= 10000) {
    prune();
    if (loginAttempts.size >= 10000) return false;
  }
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.windowStart > 60000) {
    loginAttempts.set(ip, { windowStart: now, count: 1 });
    return true;
  }
  rec.count += 1;
  return rec.count <= LOGIN_MAX_PER_MIN;
}

// ---------- API 实现 ----------
function apiStatus() {
  const s = metrics.snapshot();
  let todayConns = 0;
  try {
    todayConns = db.get().prepare('SELECT COUNT(*) c FROM connections WHERE started_at >= ?').get(s.dayStart).c
      + metrics.activeList().filter(c => c.startedAt >= s.dayStart).length;
  } catch (_) {}
  return {
    ...s,
    todayConns,
    server: {
      version: PKG_VERSION,
      node: process.version,
      pid: process.pid,
      pm2: process.env.name || null,
    },
  };
}

function apiTraffic(range) {
  const buckets = { '1h': 60000, '24h': 3600000, '7d': 3600000 };
  const bucketMs = buckets[range] || buckets['1h'];
  const keep = { '1h': 3600 * 1000, '24h': 24 * 3600 * 1000, '7d': 7 * 24 * 3600 * 1000 };
  const from = Date.now() - (keep[range] || keep['1h']);
  try {
    const rows = db.get().prepare(
      `SELECT (ts / ?) * ? AS bucket, SUM(bytes_up) AS up, SUM(bytes_down) AS down, MAX(active) AS active
       FROM samples WHERE ts >= ? GROUP BY bucket ORDER BY bucket`
    ).all(bucketMs, bucketMs, from);
    return rows.map((r) => ({ ts: r.bucket, up: r.up, down: r.down, active: r.active }));
  } catch (_) { return []; }
}

function apiHistory(q) {
  const limit = Math.max(1, Math.min(parseInt(q.get('limit') || '100', 10) || 100, 500));
  const from = parseInt(q.get('from') || '0', 10) || 0;
  const to = parseInt(q.get('to') || String(Date.now()), 10) || Date.now();
  const proto = q.get('proto');
  try {
    const sql = proto
      ? 'SELECT * FROM connections WHERE started_at >= ? AND started_at <= ? AND proto = ? ORDER BY id DESC LIMIT ?'
      : 'SELECT * FROM connections WHERE started_at >= ? AND started_at <= ? ORDER BY id DESC LIMIT ?';
    const rows = proto
      ? db.get().prepare(sql).all(from, to, proto, limit)
      : db.get().prepare(sql).all(from, to, limit);
    return rows.map((r) => ({
      id: r.id, client_id: r.client_id, proto: r.proto, target: r.target, host: r.host, port: r.port,
      ip: r.ip, startedAt: r.started_at, endedAt: r.ended_at,
      bytesUp: r.bytes_up, bytesDown: r.bytes_down, status: r.status,
    }));
  } catch (_) { return []; }
}

function apiConfig() {
  const config = opts.config;
  const pwdSet = ADMIN_PASSWORD !== 'admin';
  return {
    forward: {
      port: config.port,
      host: config.host,
      idleTimeoutSec: config.idleTimeoutMs / 1000,
      tokenSet: !!(config.secret && config.secret !== 'z-proxy-dev'),
    },
    admin: {
      port: ADMIN_PORT,
      host: ADMIN_HOST,
      passwordSet: pwdSet,
      tokenTtlHours: TOKEN_TTL_MS / 3600000,
    },
    db: { path: db.DB_PATH, journal: 'WAL' },
    node: process.version,
  };
}

// ---------- 路由 ----------
async function onRequest(req, res) {
  let url;
  try { url = new URL(req.url, 'http://x'); } catch (_) { json(res, 400, { error: 'Bad Request' }); return; }
  const p = url.pathname;

  if (p === '/api/login') return await handleLogin(req, res, url);
  if (p === '/api/stream') return handleStream(req, res, url);
  if (p.startsWith('/api/')) return handleApi(req, res, p, url);
  return serveStatic(req, res, p);
}

async function handleLogin(req, res, url) {
  const ip = req.socket.remoteAddress || 'unknown';
  if (!checkLoginRate(ip)) { json(res, 429, { error: 'Too many attempts' }); return; }
  if (req.method !== 'POST') { json(res, 405, { error: 'Method Not Allowed' }); return; }
  let body = {};
  try { body = JSON.parse(await readBody(req) || '{}'); }
  catch (error) { json(res, error.statusCode || 400, { error: 'Bad JSON or oversized body' }); return; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    json(res, 400, { error: 'Expected a JSON object' }); return;
  }
  const pwd = typeof body.password === 'string' ? body.password : '';
  const a = Buffer.from(pwd);
  const b = Buffer.from(ADMIN_PASSWORD);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) { json(res, 401, { error: 'Wrong password' }); return; }
  prune();
  if (tokens.size >= 1024) { json(res, 503, { error: 'Session limit reached' }); return; }
  const token = crypto.randomBytes(32).toString('hex');
  tokens.set(token, Date.now() + TOKEN_TTL_MS);
  json(res, 200, { token, expiresIn: TOKEN_TTL_MS / 1000 });
}

function handleApi(req, res, p, url) {
  if (!isAuthed(req)) { json(res, 401, { error: 'Unauthorized' }); return; }
  if (req.method === 'POST' && p === '/api/logout') {
    tokens.delete(req.headers.authorization.slice(7));
    for (const stream of streams) if (!tokens.has(stream.token)) stream.close();
    return json(res, 200, { ok: true });
  }
  if (req.method === 'GET' && p === '/api/status') return json(res, 200, apiStatus());
  if (req.method === 'GET' && p === '/api/connections') return json(res, 200, { connections: metrics.activeList() });
  if (req.method === 'GET' && p === '/api/connections/history') return json(res, 200, { connections: apiHistory(url.searchParams) });
  if (req.method === 'GET' && p === '/api/traffic') return json(res, 200, { points: apiTraffic(url.searchParams.get('range')) });
  if (req.method === 'GET' && p === '/api/logs') return handleLogs(req, res, url);
  if (req.method === 'GET' && p === '/api/config') return json(res, 200, apiConfig());
  if (req.method === 'POST' && p.startsWith('/api/connections/') && p.endsWith('/close')) {
    const id = parseInt(p.slice('/api/connections/'.length, -'/close'.length), 10);
    if (!id) { json(res, 400, { error: 'Bad id' }); return; }
    if (typeof opts.closeConn !== 'function') { json(res, 501, { error: 'close not wired' }); return; }
    const done = opts.closeConn(id);
    json(res, done ? 200 : 404, done ? { ok: true } : { error: 'connection not found' });
    return;
  }
  json(res, 404, { error: 'Not Found' });
}

function handleLogs(req, res, url) {
  const limit = Math.max(1, Math.min(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 2000));
  const level = url.searchParams.get('level');
  const afterId = parseInt(url.searchParams.get('afterId') || '0', 10) || 0;
  let rows;
  try {
    const d = db.get();
    if (afterId > 0) {
      rows = level
        ? d.prepare('SELECT * FROM logs WHERE level = ? AND id > ? ORDER BY id ASC LIMIT ?').all(level, afterId, limit)
        : d.prepare('SELECT * FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?').all(afterId, limit);
    } else {
      rows = level
        ? d.prepare('SELECT * FROM logs WHERE level = ? ORDER BY id DESC LIMIT ?').all(level, limit)
        : d.prepare('SELECT * FROM logs ORDER BY id DESC LIMIT ?').all(limit);
      rows.reverse(); // 倒序取最新，再翻回时间正序
    }
    rows = rows.map((r) => ({ id: r.id, ts: r.ts, level: r.level, msg: r.msg }));
  } catch (_) { rows = []; }
  json(res, 200, { logs: rows });
}

// ---------- SSE ----------
function handleStream(req, res, url) {
  const token = url.searchParams.get('token');
  if (!token || !tokens.has(token) || tokens.get(token) <= Date.now()) {
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    res.end('Unauthorized');
    return;
  }
  if (streams.size >= 32) { json(res, 503, { error: 'Stream limit reached' }); return; }
  req.socket.setTimeout(0); // SSE has its own heartbeat and lifetime checks.
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-store',
    'Connection': 'keep-alive',
  });
  const send = (event, data) => {
    if (res.destroyed || res.writableEnded) return;
    if (!tokens.has(token) || tokens.get(token) <= Date.now()) { stream.close(); return; }
    try {
      // Disconnect slow consumers rather than buffering an unbounded queue.
      if (!res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)) res.destroy();
    } catch (_) { res.destroy(); }
  };

  const pushStatus = () => send('status', apiStatus());
  const onConn = (d) => send('conn', d);
  const onLog = (d) => send('log', d);
  const heartbeat = setInterval(() => {
    if (res.destroyed || res.writableEnded) return;
    if (!tokens.has(token) || tokens.get(token) <= Date.now()) { stream.close(); return; }
    try { if (!res.write(': ping\n\n')) res.destroy(); }
    catch (_) { res.destroy(); }
  }, 30000);
  const timer = setInterval(pushStatus, 5000);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    streams.delete(stream);
    clearInterval(timer);
    clearInterval(heartbeat);
    metrics.bus.removeListener('conn', onConn);
    log.bus.removeListener('log', onLog);
  };
  const stream = { res, token, close() {
    release();
    res.end();
    const linger = setTimeout(() => res.destroy(), 1000);
    linger.unref();
    res.once('close', () => clearTimeout(linger));
  } };
  streams.add(stream);

  metrics.bus.on('conn', onConn);
  log.bus.on('log', onLog);
  res.on('close', release);
  pushStatus();
}

// ---------- 静态托管（SPA） ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.map': 'application/json',
};

function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { json(res, 405, { error: 'Method Not Allowed' }); return; }
  if (!fs.existsSync(DIST_DIR)) { json(res, 404, { error: 'frontend not built (run: cd web-admin && npm run build)' }); return; }
  let rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  let file = path.normalize(path.join(DIST_DIR, rel));
  const relative = path.relative(DIST_DIR, file);
  if (relative.startsWith('..') || path.isAbsolute(relative)) { json(res, 403, { error: 'Forbidden' }); return; }
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    file = path.join(DIST_DIR, 'index.html'); // SPA history 回退
    if (!fs.existsSync(file)) { json(res, 404, { error: 'Not Found' }); return; }
  }
  const ext = path.extname(file).toLowerCase();
  const isHtml = ext === '.html';
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Cache-Control': isHtml ? 'no-cache' : 'public, max-age=3600',
  });
  if (req.method === 'HEAD') { res.end(); return; }
  const input = fs.createReadStream(file);
  input.on('error', () => res.destroy());
  input.pipe(res);
}

// ---------- 启动 ----------
function start(_opts) {
  if (_opts) opts = { ...opts, ..._opts };
  if (server) return server;
  const config = opts.config || require('./lib/config').readConfig();
  opts.config = config;
  ADMIN_PASSWORD = config.adminPassword;
  ADMIN_PORT = config.adminPort;
  ADMIN_HOST = config.adminHost;
  server = http.createServer((req, res) => {
    Promise.resolve(onRequest(req, res)).catch(() => {
      if (res.headersSent) res.destroy();
      else json(res, 500, { error: 'Internal Server Error' });
    });
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.setTimeout(30000, socket => socket.destroy());
  server.on('error', (error) => {
    // Management failures must not terminate forwarding.
    console.error(`[admin] unavailable: ${error.message}`);
  });
  cleanupTimer = setInterval(prune, 60000);
  cleanupTimer.unref();
  server.listen(ADMIN_PORT, ADMIN_HOST, () => {
    console.log(`[admin] web admin listening on ${ADMIN_HOST}:${ADMIN_PORT} (password=${ADMIN_PASSWORD === 'admin' ? 'DEFAULT-CHANGE-ME' : 'set'})`);
  });
  return server;
}

function prune() {
  const now = Date.now();
  for (const [token, expiry] of tokens) if (expiry <= now) tokens.delete(token);
  for (const [ip, rec] of loginAttempts) if (now - rec.windowStart > 60000) loginAttempts.delete(ip);
  for (const stream of streams) if (!tokens.has(stream.token)) stream.close();
}

async function stop() {
  if (cleanupTimer) clearInterval(cleanupTimer);
  cleanupTimer = null;
  for (const stream of streams) stream.res.destroy();
  streams.clear();
  tokens.clear();
  loginAttempts.clear();
  if (!server) return;
  const current = server;
  server = null;
  await new Promise(resolve => {
    current.close(resolve);
    if (current.closeAllConnections) current.closeAllConnections();
  });
}

module.exports = { start, stop };
