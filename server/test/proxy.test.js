'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { once } = require('node:events');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'z-proxy-tests-'));
process.env.DB_PATH = path.join(temp, 'test.db');
const { readConfig } = require('../lib/config');
const { encryptFrame, decryptFrame, keyFor } = require('../lib/frame');
const { createProxyServer, parseTarget, prepareHttp } = require('../server');
const admin = require('../admin_server');
const metrics = require('../metrics');
const db = require('../db');
const key = keyFor('test-secret-with-at-least-24-characters');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const config = extra => ({ ...readConfig({
  PROXY_TOKEN: 'test-secret-with-at-least-24-characters',
  ADMIN_PASSWORD: 'test-admin-password', HOST: '127.0.0.1',
}), ...extra });
async function proxy(t, overrides, deps) {
  const server = createProxyServer(config(overrides), deps);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.shutdown());
  return server;
}
async function origin(t, handler) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.close(resolve);
    server.closeAllConnections();
  }));
  return server;
}
function frame(info) { return encryptFrame(Buffer.from(JSON.stringify(info)), key); }
async function socketAt(server) {
  const socket = net.connect(server.address().port, '127.0.0.1');
  await once(socket, 'connect');
  return socket;
}
function response(socket) {
  return new Promise((resolve, reject) => {
    const parts = [];
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('response timed out')); }, 4000);
    socket.on('data', d => parts.push(d));
    socket.on('error', () => {});
    socket.on('close', () => { clearTimeout(timer); resolve(Buffer.concat(parts)); });
  });
}
async function httpExchange(server, info, body = Buffer.alloc(0), split = false) {
  const socket = await socketAt(server);
  const result = response(socket);
  if (split) {
    socket.write(frame(info));
    await delay(10);
    socket.write(body);
  } else socket.write(Buffer.concat([frame(info), body]));
  return (await result).toString('latin1');
}
test.after(() => { metrics.stop(); db.close(); fs.rmSync(temp, { recursive: true, force: true }); });

test('configuration rejects missing/weak secrets, bad ports and public insecure mode', () => {
  assert.throws(() => readConfig({}), /PROXY_TOKEN/);
  assert.throws(() => readConfig({ PROXY_TOKEN: 'change-me' }), /PROXY_TOKEN/);
  assert.throws(() => configFrom({ PORT: '123junk' }), /PORT/);
  assert.throws(() => readConfig({ ALLOW_INSECURE_DEV: '1', HOST: '0.0.0.0' }), /loopback/);
  assert.equal(readConfig({ ALLOW_INSECURE_DEV: '1' }).adminHost, '127.0.0.1');
  assert.doesNotThrow(() => readConfig({ PROXY_TOKEN: 'long-secret-with-24-characters', ADMIN_ENABLED: '0' }));
});
function configFrom(extra) { return readConfig({
  PROXY_TOKEN: 'long-secret-with-24-characters', ADMIN_PASSWORD: 'long-admin-password', ...extra,
}); }

test('CONNECT target and HTTP metadata validate types/framing', () => {
  assert.deepEqual(parseTarget('[::1]:443'), { host: '::1', port: 443 });
  for (const invalid of [null, 5, '', 'host:0', 'host:99999', 'host:12bad', '::1:443', 'host/path']) {
    assert.throws(() => parseTarget(invalid));
  }
  for (const headers of [{ 'content-length': '3', 'transfer-encoding': 'chunked' },
    { 'content-length': '-1' }, { upgrade: 'websocket' }, { x: 'bad\r\ninjection' }]) {
    assert.throws(() => prepareHttp({ r: 'GET http://localhost/ HTTP/1.1', h: headers }));
  }
});

test('encrypted frame roundtrip and tampering reject', () => {
  const input = Buffer.from('hello');
  const encoded = encryptFrame(input, key);
  assert.deepEqual(decryptFrame(encoded, key), input);
  encoded[24] ^= 1;
  assert.equal(decryptFrame(encoded, key), null);
});

test('admin null/array/scalar JSON returns 400 and server remains alive', async t => {
  const adminServer = admin.start({ config: config({ adminPort: 0 }) });
  await once(adminServer, 'listening');
  t.after(() => admin.stop());
  const url = `http://127.0.0.1:${adminServer.address().port}/api/login`;
  for (const body of ['null', '[]', '1', '"text"', 'true', '{']) {
    const res = await fetch(url, { method: 'POST', body });
    assert.equal(res.status, 400);
    await res.arrayBuffer();
  }
  const login = await fetch(url, { method: 'POST', body: '{"password":"test-admin-password"}' });
  assert.equal(login.status, 200);
  const { token } = await login.json();
  const base = url.replace('/login', '');
  const loggedOut = await fetch(base + '/logout', { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
  assert.equal(loggedOut.status, 200);
  await loggedOut.arrayBuffer();
  const res = await fetch(base + '/status', { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(res.status, 401);
  await res.arrayBuffer();
});

test('admin request-body size is bounded', async t => {
  const server = admin.start({ config: config({ adminPort: 0 }) });
  await once(server, 'listening');
  t.after(() => admin.stop());
  const res = await fetch(`http://127.0.0.1:${server.address().port}/api/login`, { method: 'POST', body: 'x'.repeat(9000) });
  assert.equal(res.status, 413);
  await res.arrayBuffer();
});

test('admin bind failure does not terminate forwarding', async t => {
  const p = await proxy(t);
  const management = admin.start({ config: config({ adminPort: p.address().port }) });
  const [err] = await once(management, 'error');
  assert.equal(err.code, 'EADDRINUSE');
  t.after(() => admin.stop());
  assert.equal(p.listening, true);
});

test('authenticated invalid JSON types and targets return 400, not crash', async t => {
  const p = await proxy(t);
  for (const value of [null, [], 7, { m: 'CONNECT' }, { m: 'CONNECT', t: 8 }, { m: 'CONNECT', t: 'host:0' }]) {
    const s = await socketAt(p);
    const result = response(s);
    s.write(frame(value));
    const encoded = await result;
    assert.equal(JSON.parse(decryptFrame(encoded, key)).c, 400);
  }
  assert.equal(p.listening, true);
});

test('invalid magic/oversized declaration closes immediately; slow handshake expires', async t => {
  const p = await proxy(t, { handshakeTimeoutMs: 80 });
  for (const data of [Buffer.from([0]), Buffer.from([0x5a, 0, 1, 0, 1])]) {
    const s = await socketAt(p);
    const result = response(s);
    s.write(data);
    assert.equal((await result).length, 0);
  }
  const s = await socketAt(p);
  const result = response(s);
  assert.equal((await result).length, 0);
});

test('HTTP status, duplicate cookies, query, and chunked response survive', async t => {
  let seen;
  const target = await origin(t, (req, res) => {
    seen = req.url;
    res.writeHead(418, { 'Set-Cookie': ['a=1', 'b=2'], 'X-Test': 'yes' });
    res.write('hello');
    res.end('world');
  });
  const p = await proxy(t);
  const text = await httpExchange(p, {
    m: 'HTTP', r: `GET http://127.0.0.1:${target.address().port}/search?q=1 HTTP/1.1`, h: {},
  });
  assert.match(text, /^HTTP\/1.1 418 /);
  assert.equal(seen, '/search?q=1');
  assert.equal((text.match(/set-cookie:/gi) || []).length, 2);
  assert.match(text, /hello/);
  assert.match(text, /world/);
  assert.match(text, /transfer-encoding: chunked/i);
});

test('HTTP fixed-length body handles frame-leftover and subsequent chunks; metrics include body', async t => {
  let seen;
  const target = await origin(t, (req, res) => {
    const data = [];
    req.on('data', d => data.push(d));
    req.on('end', () => { seen = Buffer.concat(data).toString(); res.end('ok'); });
  });
  const p = await proxy(t);
  const baseline = metrics.snapshot().totalBytesUp;
  for (const split of [false, true]) {
    const text = await httpExchange(p, { m: 'HTTP',
      r: `POST http://127.0.0.1:${target.address().port}/ HTTP/1.1`,
      h: { 'content-length': '5' } }, Buffer.from('hello'), split);
    assert.match(text, /^HTTP\/1.1 200 /);
    assert.equal(seen, 'hello');
  }
  assert.equal(metrics.snapshot().totalBytesUp - baseline, 10);
});

test('HTTP chunked request is decoded once and completes without client closing socket', async t => {
  let seen;
  const target = await origin(t, (req, res) => {
    const data = [];
    req.on('data', d => data.push(d));
    req.on('end', () => { seen = Buffer.concat(data).toString(); res.end('ok'); });
  });
  const p = await proxy(t);
  const text = await httpExchange(p, { m: 'HTTP',
    r: `POST http://127.0.0.1:${target.address().port}/ HTTP/1.1`,
    h: { 'transfer-encoding': 'chunked' } }, Buffer.from('5\r\nhello\r\n0\r\n\r\n'));
  assert.match(text, /^HTTP\/1.1 200 /);
  assert.equal(seen, 'hello');
});

test('GET/DELETE/OPTIONS chunked bodies remain framed for the origin', async t => {
  const observed = [];
  const target = await origin(t, (req, res) => {
    const data = [];
    req.on('data', d => data.push(d));
    req.on('end', () => {
      observed.push({ method: req.method, body: Buffer.concat(data).toString(), te: req.headers['transfer-encoding'] });
      res.end('ok');
    });
  });
  const p = await proxy(t);
  for (const method of ['GET', 'DELETE', 'OPTIONS']) {
    const text = await httpExchange(p, { m: 'HTTP',
      r: `${method} http://127.0.0.1:${target.address().port}/ HTTP/1.1`,
      h: { 'transfer-encoding': 'chunked' } }, Buffer.from('5\r\nhello\r\n0\r\n\r\n'));
    assert.match(text, /^HTTP\/1.1 200 /);
  }
  assert.deepEqual(observed.map(r => r.body), ['hello', 'hello', 'hello']);
  assert.ok(observed.every(r => r.te === 'chunked'));
});

test('HTTP client FIN after request does not truncate response', async t => {
  const target = await origin(t, (_req, res) => setTimeout(() => res.end('complete-response'), 20));
  const p = await proxy(t);
  const s = await socketAt(p);
  const result = response(s);
  s.end(frame({ m: 'HTTP', r: `GET http://127.0.0.1:${target.address().port}/ HTTP/1.1`, h: {} }));
  const text = (await result).toString();
  assert.match(text, /^HTTP\/1.1 200 /);
  assert.match(text, /complete-response/);
});

test('streaming response can outlive first-byte deadline when it is active', async t => {
  const target = await origin(t, (_req, res) => {
    res.write('first');
    const timer = setInterval(() => res.write('next'), 20);
    setTimeout(() => { clearInterval(timer); res.end('last'); }, 180);
    res.on('close', () => clearInterval(timer));
  });
  const p = await proxy(t, { httpTimeoutMs: 60, idleTimeoutMs: 100 });
  const text = await httpExchange(p, { m: 'HTTP',
    r: `GET http://127.0.0.1:${target.address().port}/ HTTP/1.1`, h: {} });
  assert.match(text, /first/);
  assert.match(text, /last/);
  assert.ok(text.endsWith('0\r\n\r\n'));
});

test('HEAD and 204 responses have no body', async t => {
  const target = await origin(t, (req, res) => {
    if (req.url === '/none') { res.writeHead(204); res.end(); }
    else { res.writeHead(200, { 'Content-Length': '5' }); res.end('hello'); }
  });
  const p = await proxy(t);
  for (const [method, url, code] of [['HEAD', '/', 200], ['GET', '/none', 204]]) {
    const text = await httpExchange(p, { m: 'HTTP',
      r: `${method} http://127.0.0.1:${target.address().port}${url} HTTP/1.1`, h: {} });
    assert.match(text, new RegExp(`^HTTP/1.1 ${code}`));
    assert.equal(text.split('\r\n\r\n')[1], '');
  }
});

test('HTTP upstream unavailable returns valid 502', async t => {
  const target = await origin(t, (_req, res) => res.end());
  const port = target.address().port;
  await new Promise(resolve => target.close(resolve));
  const p = await proxy(t);
  const text = await httpExchange(p, { m: 'HTTP', r: `GET http://127.0.0.1:${port}/ HTTP/1.1`, h: {} });
  assert.match(text, /^HTTP\/1.1 502 /);
});

test('silent HTTP origin produces a complete 504 response', async t => {
  const target = await origin(t, () => {});
  const p = await proxy(t, { httpTimeoutMs: 80 });
  const text = await httpExchange(p, { m: 'HTTP',
    r: `GET http://127.0.0.1:${target.address().port}/ HTTP/1.1`, h: {} });
  assert.match(text, /^HTTP\/1.1 504 /);
  assert.match(text, /Gateway Timeout/);
});

test('HTTP large chunked body has backpressure-safe framing and exact byte count', async t => {
  let bytes = 0;
  const target = await origin(t, (req, res) => {
    req.on('data', d => { bytes += d.length; });
    req.on('end', () => res.end(String(bytes)));
  });
  const p = await proxy(t);
  const payload = Buffer.alloc(512 * 1024, 'a');
  const encoded = Buffer.concat([Buffer.from(payload.length.toString(16) + '\r\n'),
    payload, Buffer.from('\r\n0\r\n\r\n')]);
  const text = await httpExchange(p, { m: 'HTTP',
    r: `POST http://127.0.0.1:${target.address().port}/ HTTP/1.1`,
    h: { 'transfer-encoding': 'chunked' } }, encoded);
  assert.match(text, /^HTTP\/1.1 200 /);
  assert.equal(bytes, payload.length);
});

test('CONNECT frame can be split bytewise and early payload retained during DNS wait', async t => {
  let seen = Buffer.alloc(0);
  const upstream = net.createServer(s => s.on('data', d => { seen = Buffer.concat([seen, d]); s.write(d); }));
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => new Promise(resolve => upstream.close(resolve)));
  const p = await proxy(t, {}, { dns: {
    resolve4: async () => { await delay(80); return ['127.0.0.1']; },
    resolve6: async () => [],
  } });
  const s = await socketAt(p);
  t.after(() => s.destroy());
  const received = [];
  s.on('data', d => received.push(d));
  const control = frame({ m: 'CONNECT', t: `test.local:${upstream.address().port}` });
  for (const byte of control) { s.write(Buffer.from([byte])); await delay(1); }
  s.write('early');
  await delay(150);
  assert.equal(seen.toString(), 'early');
  const all = Buffer.concat(received);
  const n = all.readUInt32BE(1);
  const total = 21 + n + 32;
  assert.equal(JSON.parse(decryptFrame(all.subarray(0, total), key)).c, 200);
  assert.equal(all.subarray(total).toString(), 'early');
  s.destroy();
  await delay(20);
});

test('late DNS result after timeout cannot resurrect upstream connection', async t => {
  let calls = 0;
  const p = await proxy(t, { dnsTimeoutMs: 50 }, {
    dns: { resolve4: async () => { await delay(150); return ['127.0.0.1']; }, resolve6: async () => [] },
    connect: options => { calls++; return net.connect(options); },
  });
  const s = await socketAt(p);
  const result = response(s);
  s.write(frame({ m: 'CONNECT', t: 'test.local:443' }));
  assert.equal(JSON.parse(decryptFrame(await result, key)).c, 502);
  await delay(180);
  assert.equal(calls, 0);
});

test('fast A record connects without waiting for hung AAAA', async t => {
  const target = net.createServer(s => s.end('greeting'));
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise(resolve => target.close(resolve)));
  const p = await proxy(t, { dnsTimeoutMs: 80 }, { dns: {
    resolve4: async () => ['127.0.0.1'],
    resolve6: () => new Promise(() => {}),
  } });
  const s = await socketAt(p);
  const received = [];
  s.on('data', d => received.push(d));
  s.write(frame({ m: 'CONNECT', t: `fast.test:${target.address().port}` }));
  await delay(120);
  const bytes = Buffer.concat(received);
  const total = 21 + bytes.readUInt32BE(1) + 32;
  assert.equal(JSON.parse(decryptFrame(bytes.subarray(0, total), key)).c, 200);
  assert.equal(bytes.subarray(total).toString(), 'greeting');
  s.destroy();
  await delay(20);
});

test('HTTP DNS deadline uses bounded resolver and does not call getaddrinfo', async t => {
  const p = await proxy(t, { dnsTimeoutMs: 50 }, { dns: {
    resolve4: () => new Promise(() => {}),
    resolve6: () => new Promise(() => {}),
  } });
  const text = await httpExchange(p, { m: 'HTTP', r: 'GET http://hung.test/ HTTP/1.1', h: {} });
  assert.match(text, /^HTTP\/1.1 502 /);
});

test('HTTP considers reachable delayed A when fast AAAA cannot connect', async t => {
  const target = await origin(t, (_req, res) => res.end('dual-stack-ok'));
  const p = await proxy(t, {}, { dns: {
    resolve6: async () => ['::1'],
    resolve4: async () => { await delay(30); return ['127.0.0.1']; },
  } });
  const text = await httpExchange(p, { m: 'HTTP',
    r: `GET http://dual.test:${target.address().port}/ HTTP/1.1`, h: {} });
  assert.match(text, /^HTTP\/1.1 200 /);
  assert.match(text, /dual-stack-ok/);
});

test('CONNECT switches families before exhausting multiple failing addresses', async t => {
  const { Duplex } = require('node:stream');
  const target = net.createServer(s => s.end('alternate-family-ok'));
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  t.after(() => new Promise(resolve => target.close(resolve)));
  const attempted = [];
  const p = await proxy(t, { connectTimeoutMs: 100, setupTimeoutMs: 250 }, {
    dns: { resolve6: async () => ['::1', '::2', '::3'],
      resolve4: async () => { await delay(20); return ['127.0.0.1']; } },
    connect: options => {
      attempted.push(options.host);
      if (options.host.includes(':')) {
        // Controlled pending socket: avoids dependence on external blackholes.
        return new Duplex({ read() {}, write(_d, _enc, callback) { callback(); } });
      }
      return net.connect(options);
    },
  });
  const s = await socketAt(p);
  const received = [];
  s.on('data', d => received.push(d));
  s.write(frame({ m: 'CONNECT', t: `dual.test:${target.address().port}` }));
  await delay(180);
  const bytes = Buffer.concat(received);
  const total = 21 + bytes.readUInt32BE(1) + 32;
  assert.equal(JSON.parse(decryptFrame(bytes.subarray(0, total), key)).c, 200);
  assert.deepEqual(attempted, ['::1', '127.0.0.1']);
  s.destroy();
  await delay(20);
});

test('active upload may exceed first-byte timeout; timer starts after body ends', async t => {
  let observed = 0;
  const target = await origin(t, (req, res) => {
    req.on('data', d => { observed += d.length; });
    req.on('end', () => res.end('upload-complete'));
  });
  const p = await proxy(t, { httpTimeoutMs: 80 });
  const s = await socketAt(p);
  const result = response(s);
  s.write(frame({ m: 'HTTP', r: `POST http://127.0.0.1:${target.address().port}/ HTTP/1.1`,
    h: { 'content-length': '8' } }));
  for (let i = 0; i < 8; i++) { await delay(30); s.write('a'); }
  const text = (await result).toString();
  assert.match(text, /^HTTP\/1.1 200 /);
  assert.match(text, /upload-complete/);
  assert.equal(observed, 8);
});

test('connection limit includes unauthenticated sockets and is released on close', async t => {
  const p = await proxy(t, { maxConnections: 1 });
  const first = await socketAt(p);
  const second = await socketAt(p);
  assert.equal((await response(second)).length, 0);
  first.destroy();
  await delay(20);
  const next = await socketAt(p);
  const result = response(next);
  next.write(frame(null));
  assert.equal(JSON.parse(decryptFrame(await result, key)).c, 400);
});

test('short-connection samples include closed traffic, no double counting', () => {
  metrics.onSample();
  const start = db.get().prepare('SELECT COALESCE(SUM(bytes_up), 0) up FROM samples').get().up;
  const id = metrics.connOpen({ proto: 'CONNECT', target: 'test:443', host: 'test', port: 443 });
  metrics.connBytes(id, 1000, 2000);
  metrics.connClose(id, 'closed');
  // Ensure distinct primary-key timestamps for rapid deterministic samples.
  const oldNow = Date.now;
  Date.now = () => oldNow() + 100;
  try { metrics.onSample(); } finally { Date.now = oldNow; }
  assert.equal(db.get().prepare('SELECT SUM(bytes_up) up FROM samples').get().up - start, 1000);
  Date.now = () => oldNow() + 200;
  try { metrics.onSample(); } finally { Date.now = oldNow; }
  assert.equal(db.get().prepare('SELECT SUM(bytes_up) up FROM samples').get().up - start, 1000);
});
