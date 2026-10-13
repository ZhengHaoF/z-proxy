'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const { once } = require('node:events');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'z-proxy-interop-'));
process.env.DB_PATH = path.join(temp, 'test.db');
const { createProxyServer } = require('../server');
const { readConfig } = require('../lib/config');
const { encryptFrame, decryptFrame, keyFor } = require('../lib/frame');
const pcPath = path.join(__dirname, '../../client');
const secret = 'isolated-cross-language-test-secret';
const python = process.env.PYTHON || 'python3';
const available = spawnSync(python, ['--version']).status === 0;
test.after(() => {
  require('../db').close();
  fs.rmSync(temp, { recursive: true, force: true });
});

test('Python and Node keep the same frame key and wire encoding', { skip: !available }, () => {
  const run = spawnSync(python, ['-c', `
import sys, os, base64, json
sys.path.insert(0, os.environ['PC_PATH'])
import proxy_client as pc
key = pc._key_for(os.environ['TEST_TOKEN'])
print(base64.b64encode(pc.encrypt_frame(b'{"m":"CONNECT","t":"example.com:443"}', key)).decode())
print(pc.decrypt_frame(base64.b64decode(os.environ['NODE_FRAME']), key).decode())
`], { encoding: 'utf8', env: { ...process.env, PC_PATH: pcPath, TEST_TOKEN: secret,
    NODE_FRAME: encryptFrame(Buffer.from('{"c":200}'), keyFor(secret)).toString('base64') } });
  assert.equal(run.status, 0, run.stderr);
  const [encoded, decoded] = run.stdout.trim().split('\n');
  assert.equal(decryptFrame(Buffer.from(encoded, 'base64'), keyFor(secret)).toString(),
    '{"m":"CONNECT","t":"example.com:443"}');
  assert.equal(decoded, '{"c":200}');
});

test('real Python desktop proxy -> Node proxy -> HTTP origin: POST, query and headers', { skip: !available }, async t => {
  let observed;
  const origin = http.createServer((req, res) => {
    const parts = [];
    req.on('data', d => parts.push(d));
    req.on('end', () => {
      observed = { url: req.url, body: Buffer.concat(parts).toString() };
      res.writeHead(201, { 'Set-Cookie': ['a=1', 'b=2'], 'Content-Length': '2' });
      res.end('ok');
    });
  });
  origin.listen(0, '127.0.0.1');
  await once(origin, 'listening');
  t.after(() => new Promise(resolve => { origin.close(resolve); origin.closeAllConnections(); }));
  const proxy = createProxyServer(readConfig({
    PROXY_TOKEN: secret, ADMIN_ENABLED: '0', HOST: '127.0.0.1',
  }), { lookup: (_host, options, callback) => {
    if (options.all) callback(null, [{ address: '127.0.0.1', family: 4 }]);
    else callback(null, '127.0.0.1', 4);
  } });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  t.after(() => proxy.shutdown());
  const child = spawn(python, ['-u', '-c', `
import asyncio, os, sys
sys.path.insert(0, os.environ['PC_PATH'])
import proxy_client as pc
pc.SERVER_HOST = '127.0.0.1'
pc.SERVER_PORT = int(os.environ['TEST_PORT'])
pc.SECRET = os.environ['TEST_TOKEN']
pc.MODE = 'matched'
pc.BYPASS = []
pc.load_rules = lambda: ['review.example']
async def main():
    server = await asyncio.start_server(pc.handle, '127.0.0.1', 0)
    print(server.sockets[0].getsockname()[1], flush=True)
    async with server:
        await server.serve_forever()
asyncio.run(main())
`], { env: { ...process.env, PC_PATH: pcPath, TEST_PORT: String(proxy.address().port), TEST_TOKEN: secret } });
  let stderr = '';
  child.stderr.on('data', d => { stderr += d; });
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      await once(child, 'exit');
    }
  });
  const port = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('desktop readiness timeout: ' + stderr)), 5000);
    child.once('error', reject);
    child.once('exit', code => { clearTimeout(timer); reject(new Error('desktop exited: ' + code + stderr)); });
    child.stdout.on('data', d => {
      output += d.toString();
      if (/^\d+\n/.test(output)) { clearTimeout(timer); resolve(Number(output.split('\n')[0])); }
    });
  });
  async function request(host) {
    const socket = net.connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const chunks = [];
    const result = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('desktop exchange timeout')); }, 5000);
      socket.on('data', d => chunks.push(d));
      socket.on('error', reject);
      socket.on('close', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
    });
    socket.write(`POST http://${host}:${origin.address().port}/search?q=test HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 5\r\n\r\nhello`);
    return await result;
  }
  const before = require('../metrics').snapshot().totalConns;
  const remote = await request('review.example');
  assert.match(remote, /^HTTP\/1.1 201 /);
  assert.equal((remote.match(/set-cookie:/gi) || []).length, 2);
  assert.deepEqual(observed, { url: '/search?q=test', body: 'hello' });
  assert.equal(require('../metrics').snapshot().totalConns, before + 1,
    'matched route must actually traverse Node, not silently bypass');
  const direct = await request('127.0.0.1');
  assert.match(direct, /^HTTP\/1.1 201 /);
  assert.deepEqual(observed, { url: '/search?q=test', body: 'hello' });
  assert.equal(require('../metrics').snapshot().totalConns, before + 1);
});
