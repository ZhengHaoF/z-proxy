'use strict';

/**
 * Traffic-forward server (Node.js 22, no external deps).
 *
 * 加密帧协议（客户端↔服务端）：
 *   每条连接以「一个加密帧」开始（目标域名、请求头都加密，链路上看不到任何域名）：
 *     magic(0x5A) | len(4B BE) | nonce(16B) | ciphertext(len) | tag(32B)
 *   加密：密钥流 = HMAC-SHA256(enc_key, nonce || counter32)；ciphertext = payload XOR 密钥流
 *   鉴权：tag = HMAC-SHA256(enc_key, nonce || ciphertext)，验 tag 即验 token
 *   密钥：enc_key = HMAC-SHA256(PROXY_TOKEN, "zhihu-proxy:enc:v1")
 *   载荷为 JSON：
 *     {m:"CONNECT", t:"host:port"}                  → HTTPS 隧道（服务端 DNS+直连，ACK 后透传）
 *     {m:"HTTP", r:"GET http://.. HTTP/1.1", h:{}}  → 普通 HTTP 转发（服务端 http.request）
 *   应答帧（仅 CONNECT 模式）：{m:"OK/错误信息", c:200|407|502|400}
 *
 * Usage:
 *   PORT=8443 PROXY_TOKEN=your-secret node server.js
 */

const net = require('net');
const dns = require('dns').promises;
const http = require('http');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8443', 10);
const HOST = process.env.HOST || '0.0.0.0';
const SECRET = process.env.PROXY_TOKEN || 'zhihu-proxy-dev';
const IDLE_TIMEOUT = parseInt(process.env.IDLE_TIMEOUT || '0', 10); // seconds, 0 = off
const DNS_TIMEOUT_MS = 5000;
const MAGIC = 0x5a;
const ENC_CTX = 'zhihu-proxy:enc:v1';

function encKey() {
  return crypto.createHmac('sha256', SECRET).update(ENC_CTX).digest();
}

function keystream(key, nonce, length) {
  const chunks = [];
  let produced = 0;
  let counter = 0;
  while (produced < length) {
    const ctr = Buffer.from([
      (counter >>> 24) & 0xff, (counter >>> 16) & 0xff,
      (counter >>> 8) & 0xff, counter & 0xff,
    ]);
    chunks.push(crypto.createHmac('sha256', key).update(Buffer.concat([nonce, ctr])).digest());
    produced += 32;
    counter += 1;
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function encryptFrame(payload) {
  const key = encKey();
  const nonce = crypto.randomBytes(16);
  const ks = keystream(key, nonce, payload.length);
  const ct = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) ct[i] = payload[i] ^ ks[i];
  const tag = crypto.createHmac('sha256', key).update(Buffer.concat([nonce, ct])).digest();
  const head = Buffer.alloc(21);
  head[0] = MAGIC;
  head.writeUInt32BE(ct.length, 1);
  nonce.copy(head, 5);
  return Buffer.concat([head, ct, tag]);
}

/** Returns plaintext Buffer, or null if malformed / bad tag (i.e. auth failed). */
function decryptFrame(frame) {
  if (!frame || frame.length < 21 || frame[0] !== MAGIC) return null;
  const n = frame.readUInt32BE(1);
  if (n > 65536 || frame.length !== 21 + n + 32) return null;
  const nonce = frame.subarray(5, 21);
  const ct = frame.subarray(21, 21 + n);
  const tag = frame.subarray(21 + n);
  const key = encKey();
  const expect = crypto.createHmac('sha256', key).update(Buffer.concat([nonce, ct])).digest();
  if (tag.length !== expect.length || !crypto.timingSafeEqual(tag, expect)) return null;
  const ks = keystream(key, nonce, ct.length);
  const pt = Buffer.alloc(ct.length);
  for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
  return pt;
}

function sendAck(socket, code, msg) {
  try {
    socket.write(encryptFrame(Buffer.from(JSON.stringify({ m: msg, c: code }))));
  } catch (_) {}
}

function deny(socket, code, msg) {
  sendAck(socket, code, msg);
  socket.destroy();
}

// ---- 连接处理：每连接一个加密帧 + 后续原始双向流 ----
const server = net.createServer((clientSocket) => {
  clientSocket.on('error', () => {});

  let buf = Buffer.alloc(0);
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > 21 + 65536 + 32) {
      // 迟迟等不到合法帧：直接掐掉
      clientSocket.destroy();
      return;
    }
    if (buf.length < 21) return;
    const n = buf.readUInt32BE(1);
    if (n > 65536 || buf.length < 21 + n + 32) return;
    clientSocket.removeListener('data', onData);
    const frame = buf.subarray(0, 21 + n + 32);
    const leftover = buf.subarray(21 + n + 32);
    buf = null;

    const pt = decryptFrame(frame);
    if (!pt) {
      console.warn('[auth] rejected: bad magic/tag');
      deny(clientSocket, 407, 'Proxy Authentication Required');
      return;
    }
    let info;
    try { info = JSON.parse(pt.toString('utf8')); } catch (_) {
      deny(clientSocket, 400, 'Bad Request');
      return;
    }
    if (info.m === 'CONNECT') handleConnect(clientSocket, info.t, leftover);
    else if (info.m === 'HTTP') handleHttp(clientSocket, info, leftover);
    else deny(clientSocket, 400, 'Bad Request');
  };
  clientSocket.on('data', onData);
});

// ---- HTTPS 隧道（CONNECT）----
function handleConnect(clientSocket, target, leftover) {
  console.log(`[recv] CONNECT ${target}`);
  const idx = (target || '').lastIndexOf(':');
  const host = idx > 0 ? target.slice(0, idx) : target;
  let port = idx > 0 ? parseInt(target.slice(idx + 1), 10) : 443;
  if (!port) port = 443;

  clientSocket.on('error', (e) => {
    console.warn(`[connect] client socket error for ${target}: ${e.message}`);
  });

  // c-ares 的 resolve4/resolve6（getaddrinfo 会对超大 AAAA 集合的域名永久挂起，
  // 例如 www.zhihu.com —— 那是上一版隧道的病根）
  const resolveHost = async () => {
    try {
      const v4 = await dns.resolve4(host);
      if (v4 && v4.length) return v4;
    } catch (_) { /* fall through to AAAA */ }
    try {
      const v6 = await dns.resolve6(host);
      if (v6 && v6.length) return v6;
    } catch (_) { /* fall through */ }
    throw new Error('no address resolved');
  };

  const dnsTimer = setTimeout(() => {
    console.warn(`[connect] DNS timeout for ${host}:${port} (>${DNS_TIMEOUT_MS}ms) — giving up`);
    deny(clientSocket, 502, 'Bad Gateway (DNS timeout)');
  }, DNS_TIMEOUT_MS);

  resolveHost().then((ips) => {
    clearTimeout(dnsTimer);
    let tried = 0;
    let clientDead = false;
    const tryNext = () => {
      if (clientDead) return;
      if (tried >= ips.length) {
        console.warn(`[connect] all upstream IPs failed for ${host}:${port} (tried ${ips.join(',')})`);
        deny(clientSocket, 502, 'Bad Gateway (upstream unreachable)');
        return;
      }
      const ip = ips[tried++];
      let settled = false;
      const targetSocket = net.connect(port, ip, () => {
        settled = true;
        sendAck(clientSocket, 200, 'Connection Established');
        if (leftover && leftover.length) targetSocket.write(leftover);
        clientSocket.pipe(targetSocket);
        targetSocket.pipe(clientSocket);
        if (IDLE_TIMEOUT) {
          clientSocket.setTimeout(IDLE_TIMEOUT * 1000, () => { clientSocket.destroy(); targetSocket.destroy(); });
        }
        console.log(`[connect] ${host}:${port} -> ${ip}`);
      });
      targetSocket.on('error', (e) => {
        if (settled) return; // error after pipe was established — ignore
        settled = true;
        console.warn(`[connect] upstream connect failed ${host}:${port} (${ip}): ${e.message}`);
        try { targetSocket.destroy(); } catch (_) {}
        tryNext();
      });
      clientSocket.on('error', () => {
        clientDead = true;
        try { targetSocket.destroy(); } catch (_) {}
        if (!settled) {
          settled = true;
          console.warn(`[connect] client closed during connect to ${host}:${port} (${ip})`);
        }
      });
    };
    tryNext();
  }).catch((e) => {
    clearTimeout(dnsTimer);
    console.warn(`[connect] DNS failed for ${host}: ${e.message}`);
    deny(clientSocket, 502, 'Bad Gateway (DNS)');
  });
}

// ---- 普通 HTTP 转发（http:// 目标）----
function handleHttp(clientSocket, info, leftover) {
  const r = (info.r || '').toString();
  const h = info.h || {};
  console.log(`[recv] HTTP ${r.split(' ')[1] || ''}`);
  const parts = r.split(' ');
  if (parts.length < 2) { deny(clientSocket, 400, 'Bad Request'); return; }
  let target;
  try { target = new URL(parts[1]); } catch (_) { deny(clientSocket, 400, 'Bad Request'); return; }
  if (target.protocol !== 'http:') { deny(clientSocket, 400, 'Bad Request'); return; }

  const headers = {};
  for (const [k, v] of Object.entries(h)) {
    if (['proxy-authorization', 'proxy-connection', 'proxy-authenticate', 'connection'].includes(k.toLowerCase())) continue;
    headers[k] = v;
  }
  headers['connection'] = 'close';

  const opts = {
    hostname: target.hostname,
    port: target.port || 80,
    method: parts[0],
    path: target.pathname + target.search,
    headers,
  };

  const pReq = http.request(opts, (pRes) => {
    pRes.pipe(clientSocket);
  });
  pReq.on('error', (e) => {
    console.warn(`[http] upstream request failed for ${target.hostname}: ${e.message}`);
    try { clientSocket.destroy(); } catch (_) {}
  });

  // 转发请求体：帧之后的字节都是 body（含 leftover 与后续流）。
  // 按 Content-Length 计数结束请求；无 body 立即结束；chunked 退化为 socket 关闭时结束。
  const chunked = /chunked/i.test(headers['transfer-encoding'] || '');
  const cl = parseInt(headers['content-length'] || '', 10);
  if (chunked) {
    console.warn(`[http] chunked body from ${target.hostname} — relying on socket end`);
    const fwd = (d) => { try { pReq.write(d); } catch (_) {} };
    clientSocket.on('data', fwd);
    clientSocket.on('end', () => { try { pReq.end(); } catch (_) {} });
    if (leftover && leftover.length) pReq.write(leftover);
  } else if (Number.isFinite(cl) && cl > 0) {
    let sent = leftover ? leftover.length : 0;
    const finish = () => {
      clientSocket.removeListener('data', forward);
      try { pReq.end(); } catch (_) {}
    };
    const forward = (d) => {
      try { pReq.write(d); } catch (_) {}
      sent += d.length;
      if (sent >= cl) finish();
    };
    if (leftover && leftover.length) pReq.write(leftover);
    if (sent >= cl) finish();
    else {
      clientSocket.on('data', forward);
      clientSocket.on('end', () => { try { pReq.end(); } catch (_) {} });
    }
  } else {
    // 无请求体（GET/HEAD/CL=0 等）：写完 leftover 立即结束请求
    if (leftover && leftover.length) pReq.write(leftover);
    try { pReq.end(); } catch (_) {}
  }
}

server.listen(PORT, HOST, () => {
  console.log(`[server] encrypted forward proxy listening on ${HOST}:${PORT}`);
  console.log(`[server] auth: encrypted frame (secret=${SECRET ? 'set' : 'off'})`);
});
