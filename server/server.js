'use strict';

// Only the first control frame is encrypted. Payload traffic is not wrapped
// in TLS by this transport; never describe this as a fully encrypted tunnel.
const net = require('net');
const http = require('http');
const { readConfig } = require('./lib/config');
const { MAGIC, MAX_PAYLOAD, HEADER_LEN, TAG_LEN, keyFor, encryptFrame, decryptFrame } = require('./lib/frame');
const metrics = require('./metrics');
const admin = require('./admin_server');
const { resolveAddresses, grace } = require('./lib/resolve');

function parseTarget(target) {
  if (typeof target !== 'string' || !target || /[\s/@?#\\]/.test(target)) throw new Error('invalid target');
  let host;
  let port = 443;
  if (target.startsWith('[')) {
    const match = /^\[([^\]]+)\](?::(\d+))?$/.exec(target);
    if (!match || net.isIP(match[1]) !== 6) throw new Error('invalid IPv6 target');
    host = match[1];
    if (match[2]) port = Number(match[2]);
  } else {
    const match = /^([^:]+)(?::(\d+))?$/.exec(target);
    if (!match) throw new Error('invalid target');
    host = match[1];
    if (match[2]) port = Number(match[2]);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535 || host.length > 253) throw new Error('invalid target port/host');
  return { host, port };
}

const HOP_HEADERS = new Set(['connection', 'proxy-connection', 'proxy-authorization',
  'proxy-authenticate', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
function hopHeaders(headers) {
  const names = new Set(HOP_HEADERS);
  for (const name of String(headers.connection || '').split(',')) if (name.trim()) names.add(name.trim().toLowerCase());
  return names;
}

function prepareHttp(info) {
  if (typeof info.r !== 'string' || /[\r\n]/.test(info.r)) throw new Error('invalid request line');
  const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+) (\S+) HTTP\/1\.[01]$/.exec(info.r);
  if (!match) throw new Error('invalid request line');
  const target = new URL(match[2]);
  if (target.protocol !== 'http:' || target.username || target.password || target.hash) throw new Error('invalid HTTP URL');
  if (!info.h || typeof info.h !== 'object' || Array.isArray(info.h)) throw new Error('invalid headers');
  const headers = Object.create(null);
  for (const [name, value] of Object.entries(info.h)) {
    if (typeof value !== 'string' || /[\r\n]/.test(value)) throw new Error('invalid header value');
    http.validateHeaderName(name);
    http.validateHeaderValue(name, value);
    const lower = name.toLowerCase();
    if (Object.hasOwn(headers, lower)) throw new Error('duplicate header name');
    headers[lower] = value;
  }
  const cl = headers['content-length'];
  const te = headers['transfer-encoding'];
  if (cl !== undefined && (!/^\d+$/.test(cl) || !Number.isSafeInteger(Number(cl)))) throw new Error('invalid content-length');
  if (te !== undefined && (te.trim().toLowerCase() !== 'chunked' || cl !== undefined)) throw new Error('unsupported framing');
  if (headers.upgrade || headers.expect) throw new Error('upgrade/expect not supported in HTTP mode');
  // Reconstruct framing once, then let Node's HTTP parser decode chunked/CL.
  // Remove connection-nominated headers, but never remove framing metadata.
  const remove = hopHeaders(headers);
  remove.delete('content-length');
  remove.delete('transfer-encoding');
  const lines = [`${match[1]} ${target.pathname + target.search} HTTP/1.1`, `Host: ${target.host}`, 'Connection: close'];
  for (const [name, value] of Object.entries(headers)) {
    if (name !== 'host' && !remove.has(name)) lines.push(`${name}: ${value}`);
  }
  return { target, head: Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1') };
}

function createProxyServer(config = readConfig(), deps = {}) {
  const key = keyFor(config.secret);
  const registry = new Map();
  const accepted = new Set();
  const connect = deps.connect || net.connect;
  function reject(socket, code, message) {
    metrics.deny(code);
    if (socket.destroyed) return;
    socket.end(encryptFrame(Buffer.from(JSON.stringify({ m: message, c: code })), key));
    const timer = setTimeout(() => socket.destroy(), 1000);
    timer.unref();
    socket.once('close', () => clearTimeout(timer));
  }
  function session(socket, id) {
    let resource = null;
    let closed = false;
    let status = 'closed';
    const timers = new Set();
    const cleanups = new Set();
    const finish = () => {
      if (closed) return;
      closed = true;
      for (const timer of timers) clearTimeout(timer);
      for (const cleanup of cleanups) cleanup();
      cleanups.clear();
      if (resource) resource.destroy();
      registry.delete(id);
      metrics.connClose(id, status);
    };
    socket.once('close', finish);
    socket.once('error', () => { status = 'error'; finish(); });
    const ctx = {
      get dead() { return closed || socket.destroyed; },
      attach(value) {
        if (ctx.dead) { value.destroy(); return false; }
        resource = value;
        registry.set(id, { client: socket, target: value });
        return true;
      },
      timer(fn, ms) {
        const t = setTimeout(() => { timers.delete(t); if (!ctx.dead) fn(); }, ms);
        timers.add(t);
        t.unref();
        return t;
      },
      clear(t) { clearTimeout(t); timers.delete(t); },
      cleanup(fn) {
        if (ctx.dead) { fn(); return; }
        cleanups.add(fn);
      },
      fail(code, msg) {
        status = 'error';
        finish();
        reject(socket, code, msg);
      },
      abort() { status = 'error'; socket.destroy(); finish(); },
    };
    registry.set(id, { client: socket, target: null });
    return ctx;
  }

  // Node's requestTimeout is an absolute request-body deadline. Disable it:
  // upload inactivity and response first-byte deadlines are managed below.
  const httpParser = http.createServer({ maxHeaderSize: MAX_PAYLOAD, requestTimeout: 0 }, (req, res) => {
    const socket = req.socket;
    const ctx = socket._proxyContext;
    const id = socket._proxyId;
    if (!ctx || ctx.dead || socket._proxyRequestSeen) { res.writeHead(400); res.end(); return; }
    socket._proxyRequestSeen = true;
    const target = socket._proxyHttpTarget;
    const remove = hopHeaders(req.headers);
    const headers = Object.create(null);
    for (const [name, value] of Object.entries(req.headers)) {
      if (!remove.has(name)) headers[name] = value;
    }
    headers.host = target.host;
    headers.connection = 'close';
    // Node does not automatically choose chunked framing for GET/DELETE.
    // IncomingMessage is decoded, so explicitly request fresh body framing.
    if (req.headers['transfer-encoding']) headers['transfer-encoding'] = 'chunked';
    if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'];
    let responseStarted = false;
    let upstreamSocket;
    let responseTimer;
    const timedOut = () => {
      upstream.destroy();
      if (!responseStarted && !res.headersSent) {
        res.writeHead(504);
        res.end('Gateway Timeout');
      } else ctx.abort();
    };
    const resetResponseTimer = () => {
      ctx.clear(responseTimer);
      if (!responseStarted) responseTimer = ctx.timer(timedOut, config.httpTimeoutMs);
    };
    // Uploads have an inactivity budget, not a total duration cap. After the
    // request ends, this same timer measures the response first-byte deadline.
    resetResponseTimer();
    const lookup = deps.lookup || ((host, options, callback) => {
      const query = resolveAddresses(host, config.dnsTimeoutMs, deps.dns);
      ctx.cleanup(() => query.cancel());
      query.balanced().then((ips) => {
        query.cancel();
        if (ctx.dead) { callback(new Error('request cancelled')); return; }
        if (options.all) callback(null, ips.map(address => ({ address, family: net.isIP(address) })));
        else callback(null, ips[0], net.isIP(ips[0]));
      }, () => callback(new Error('DNS failed or timed out')));
    });
    const upstream = http.request({
      hostname: target.hostname.replace(/^\[|\]$/g, ''),
      port: target.port || 80, method: req.method,
      path: target.pathname + target.search, headers, lookup, agent: false,
    }, (response) => {
      responseStarted = true;
      ctx.clear(responseTimer);
      if (config.idleTimeoutMs) {
        socket.setTimeout(config.idleTimeoutMs, () => ctx.abort());
        if (upstreamSocket) upstreamSocket.setTimeout(config.idleTimeoutMs, () => ctx.abort());
      }
      // rawHeaders preserves repeated Set-Cookie. Node writes fresh response
      // framing because IncomingMessage has already decoded chunk boundaries.
      const drop = hopHeaders(response.headers);
      const out = [];
      for (let i = 0; i < response.rawHeaders.length; i += 2) {
        const name = response.rawHeaders[i];
        if (!drop.has(name.toLowerCase())) out.push(name, response.rawHeaders[i + 1]);
      }
      out.push('Connection', 'close');
      res.writeHead(response.statusCode, response.statusMessage, out);
      response.on('data', d => metrics.connBytes(id, 0, d.length));
      response.on('error', () => ctx.abort());
      response.once('aborted', () => ctx.abort());
      response.pipe(res);
    });
    if (!ctx.attach(upstream)) return;
    upstream.on('socket', s => {
      upstreamSocket = s;
      const connectTimer = ctx.timer(() => upstream.destroy(new Error('Connect timeout')), config.connectTimeoutMs);
      s.once('connect', () => {
        ctx.clear(connectTimer);
        metrics.connUpgraded(id, s.remoteAddress);
      });
      s.once('close', () => ctx.clear(connectTimer));
    });
    upstream.on('error', () => {
      if (res.writableEnded) return;
      if (!ctx.dead && !responseStarted && !res.headersSent) { res.writeHead(502); res.end('Bad Gateway'); }
      else socket.destroy();
    });
    req.once('aborted', () => ctx.abort());
    req.once('error', () => ctx.abort());
    res.once('finish', () => ctx.clear(responseTimer));
    res.once('error', () => ctx.abort());
    req.on('data', d => {
      metrics.connBytes(id, d.length, 0);
      resetResponseTimer();
    });
    req.once('end', resetResponseTimer);
    req.pipe(upstream); // Built-in parser handles CL, chunked, and backpressure.
  });
  httpParser.httpAllowHalfOpen = true;
  httpParser.maxRequestsPerSocket = 1;
  httpParser.on('clientError', (_err, socket) => {
    if (!socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  httpParser.on('connect', (_req, socket) => socket.destroy());
  httpParser.on('upgrade', (_req, socket) => socket.destroy());

  async function handleConnect(socket, target, leftover, clientId) {
    const { host, port } = parseTarget(target);
    const id = metrics.connOpen({ client_id: clientId, proto: 'CONNECT', target, host, port });
    const ctx = session(socket, id);
    const setup = ctx.timer(() => ctx.fail(502, 'Setup timeout'), config.setupTimeoutMs);
    const query = resolveAddresses(host, config.dnsTimeoutMs, deps.dns);
    ctx.cleanup(() => query.cancel());
    let ips;
    let firstIndex;
    try {
      const first = await query.first;
      ips = first.ips;
      firstIndex = first.index;
    } catch (_) { ips = []; }
    if (ctx.dead) return;
    if (!ips.length) { ctx.fail(502, 'DNS failed'); return; }
    // Begin with the fast family; if it cannot connect, use the other family
    // once it resolves (its independent timeout caps this wait).
    const attempts = async function* () {
      const firstQueue = ips.slice();
      if (query.tasks.length < 2) { yield* firstQueue; return; }
      let otherQueue = null;
      const waiting = query.tasks[1 - firstIndex].then(value => { otherQueue = value.slice(); return value; });
      if (firstQueue.length) yield firstQueue.shift();
      await grace(waiting);
      while (firstQueue.length || (otherQueue && otherQueue.length)) {
        // Do not exhaust a whole failing family before trying its peer.
        if (otherQueue && otherQueue.length) yield otherQueue.shift();
        if (firstQueue.length) yield firstQueue.shift();
      }
      if (otherQueue === null) yield* await waiting;
    };
    for await (const ip of attempts()) {
      if (ctx.dead) return;
      let targetSocket;
      const connected = await new Promise(resolve => {
        let settled = false;
        let attempt;
        const done = ok => {
          if (settled) return;
          settled = true;
          ctx.clear(attempt);
          resolve(ok);
        };
        try {
          targetSocket = connect({ host: ip, port, allowHalfOpen: true });
          if (!ctx.attach(targetSocket)) { done(false); return; }
          attempt = ctx.timer(() => { targetSocket.destroy(); done(false); }, config.connectTimeoutMs);
          targetSocket.once('connect', () => done(true));
          targetSocket.once('error', () => done(false));
          targetSocket.once('close', () => done(false));
        } catch (_) { done(false); }
      });
      if (ctx.dead) return;
      if (!connected) { if (targetSocket) targetSocket.destroy(); continue; }
      ctx.clear(setup);
      query.cancel();
      metrics.connUpgraded(id, ip);
      targetSocket.on('error', () => ctx.abort());
      targetSocket.on('close', () => {
        if (socket.destroyed) return;
        if (!targetSocket.readableEnded) socket.destroy();
        else if (!socket.writableEnded) socket.end();
      });
      if (config.idleTimeoutMs) {
        socket.setTimeout(config.idleTimeoutMs, () => ctx.abort());
        targetSocket.setTimeout(config.idleTimeoutMs, () => ctx.abort());
      }
      socket.write(encryptFrame(Buffer.from(JSON.stringify({ m: 'Connection Established', c: 200 })), key));
      if (leftover.length) {
        metrics.connBytes(id, leftover.length, 0);
        if (!targetSocket.write(leftover)) await new Promise(resolve => {
          targetSocket.once('drain', resolve);
          targetSocket.once('close', resolve);
        });
      }
      if (ctx.dead) return;
      socket.on('data', d => metrics.connBytes(id, d.length, 0));
      targetSocket.on('data', d => metrics.connBytes(id, 0, d.length));
      socket.pipe(targetSocket);
      targetSocket.pipe(socket);
      socket.resume();
      return;
    }
    if (!ctx.dead) ctx.fail(502, 'Upstream unreachable');
  }

  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    if (accepted.size >= config.maxConnections) { socket.destroy(); return; }
    accepted.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => accepted.delete(socket));
    const timer = setTimeout(() => socket.destroy(), config.handshakeTimeoutMs);
    timer.unref();
    socket.once('close', () => clearTimeout(timer));
    let buf = Buffer.alloc(0);
    socket.once('end', () => { if (buf !== null) socket.destroy(); });
    const onData = chunk => {
      buf = Buffer.concat([buf, chunk]);
      if (buf[0] !== MAGIC) { socket.destroy(); return; }
      if (buf.length < 5) return;
      const n = buf.readUInt32BE(1);
      if (n > MAX_PAYLOAD) { socket.destroy(); return; }
      const total = HEADER_LEN + n + TAG_LEN;
      if (buf.length < total) return;
      clearTimeout(timer);
      socket.pause(); // Preserve bytes arriving while DNS/connect runs.
      socket.removeListener('data', onData);
      const pt = decryptFrame(buf.subarray(0, total), key);
      const leftover = buf.subarray(total);
      buf = null;
      if (!pt) { reject(socket, 407, 'Authentication failed'); return; }
      let info;
      try {
        info = JSON.parse(pt.toString('utf8'));
        if (!info || typeof info !== 'object' || Array.isArray(info)) throw new Error('invalid object');
        const clientId = typeof info.c === 'string' && info.c.length <= 64 ? info.c : null;
        if (info.m === 'CONNECT') {
          parseTarget(info.t);
          handleConnect(socket, info.t, leftover, clientId).catch(() => socket.destroy());
        } else if (info.m === 'HTTP') {
          const { target, head } = prepareHttp(info);
          const id = metrics.connOpen({ client_id: clientId, proto: 'HTTP', target: target.href,
            host: target.hostname, port: Number(target.port || 80) });
          socket._proxyId = id;
          socket._proxyContext = session(socket, id);
          socket._proxyHttpTarget = target;
          // Upload inactivity / first-byte deadlines are managed by the HTTP
          // handler. A competing socket timer could destroy a pending 504.
          socket.setTimeout(0);
          socket.unshift(Buffer.concat([head, leftover]));
          httpParser.emit('connection', socket);
          socket.resume();
        } else throw new Error('unsupported method');
      } catch (_) { reject(socket, 400, 'Bad Request'); }
    };
    socket.on('data', onData);
  });
  server.closeConn = id => {
    const pair = registry.get(id);
    if (!pair) return false;
    pair.client.destroy();
    if (pair.target) pair.target.destroy();
    return true;
  };
  server.shutdown = () => {
    for (const socket of accepted) socket.destroy();
    return new Promise(resolve => server.close(resolve));
  };
  return server;
}

if (require.main === module) {
  let config;
  try { config = readConfig(); }
  catch (error) { console.error(`[config] ${error.message}`); process.exit(1); }
  require('./lib/log').install();
  const server = createProxyServer(config);
  server.on('error', error => { console.error(`[server] ${error.message}`); process.exitCode = 1; });
  server.listen(config.port, config.host, () => {
    console.log(`[server] listening on ${config.host}:${config.port}`);
    if (config.development) console.warn('[server] INSECURE development mode: loopback only');
    metrics.start();
    if (config.adminEnabled) admin.start({ closeConn: server.closeConn, config });
  });
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await Promise.all([server.shutdown(), admin.stop()]);
    metrics.stop();
    require('./lib/log').flush();
    require('./db').close();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

module.exports = { createProxyServer, parseTarget, prepareHttp };
