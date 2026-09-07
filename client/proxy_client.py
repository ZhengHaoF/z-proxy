#!/usr/bin/env python3
"""Traffic-forward client.

Local HTTP forward proxy. Domains that match rules.json are tunneled to the
remote server (which does the DNS resolution + TCP connect to the real target).
Domains that do NOT match are connected to directly. A PAC file is served from
this proxy so the OS/browser only routes matched domains through it.

Run headless:  python proxy_client.py
Run with GUI:  python gui.py
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import struct
import sys
from urllib.parse import urlparse

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules.json')

DEFAULTS = {
    'client_port': 8787,
    'server_host': '127.0.0.1',
    'server_port': 8443,
    'token': 'z-proxy-dev',
    'mode': 'matched',
    'bypass': ['localhost', '127.0.0.1', '::1'],
}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    for k in ('client_port', 'server_port'):
        if os.environ.get(k.upper()):
            cfg[k] = int(os.environ[k.upper()])
    for k in ('server_host', 'token'):
        if os.environ.get(k.upper()):
            cfg[k] = os.environ[k.upper()]
    return cfg


CFG = load_config()
CLIENT_PORT = CFG['client_port']
SERVER_HOST = CFG['server_host']
SERVER_PORT = CFG['server_port']
SECRET = CFG['token']
MODE = CFG.get('mode', 'matched')
BYPASS = CFG.get('bypass', ['localhost', '127.0.0.1', '::1'])

# ---- 加密帧协议（客户端↔服务端）----
# 帧格式: magic(0x5A) | len(4B BE) | nonce(16B) | ciphertext(len) | tag(32B)
# 加密: 密钥流 = HMAC-SHA256(enc_key, nonce || counter32)，ciphertext = payload XOR 密钥流
# 鉴权: tag = HMAC-SHA256(enc_key, nonce || ciphertext)，服务端验 tag 即验 token
# 密钥: enc_key = HMAC-SHA256(token, "z-proxy:enc:v1")
MAGIC = b'\x5A'
ENC_CTX = 'z-proxy:enc:v1'

_server = None  # set inside serve()

# Optional per-request logger, set by the GUI (or headless runner). Signature: fn(tag, target)
request_logger = None


def set_request_logger(fn):
    global request_logger
    request_logger = fn


def _log_req(tag, target):
    if request_logger:
        try:
            request_logger(tag, target)
        except Exception:
            pass


def load_rules():
    try:
        with open(RULES_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data.get('rules', [])
    except Exception:
        return []


def domain_matches(host, rules):
    if not host:
        return False
    host = host.lower()
    for rule in rules:
        r = rule.strip().lower()
        if not r:
            continue
        if r.startswith('*.'):
            base = r[2:]
            if host == base or host.endswith('.' + base):
                return True
        elif r.startswith('.'):
            if host == r[1:] or host.endswith(r):
                return True
        else:
            if host == r or host.endswith('.' + r):
                return True
    return False


def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip.is_multicast


def is_bypass(host):
    """True if the host must connect directly (never via the upstream server)."""
    if not host:
        return False
    h = host.lower().strip()
    if _is_private_ip(h):
        return True
    for b in BYPASS:
        r = b.strip().lower()
        if not r:
            continue
        if r.startswith('*.'):
            base = r[2:]
            if h == base or h.endswith('.' + base):
                return True
        elif r.startswith('.'):
            if h == r[1:] or h.endswith(r):
                return True
        else:
            if h == r or h.endswith('.' + r):
                return True
    return False


def _use_server(host, rules):
    """Whether a request should be tunneled to the upstream server."""
    if MODE == 'all':
        return not is_bypass(host)
    return domain_matches(host, rules)


def build_pac(rules):
    if MODE == 'all':
        # Everything through the proxy, except localhost / private ranges / custom bypass.
        lines = [
            '  if (isPlainHostName(host) || host == "localhost" || dnsDomainIs(host, ".local") || shExpMatch(host, "*.local")) return "DIRECT";',
            '  if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";',
            '  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";',
            '  if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";',
            '  if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";',
            '  if (isInNet(host, "169.254.0.0", "255.255.0.0")) return "DIRECT";',
        ]
        for b in BYPASS:
            r = b.strip()
            if not r or r in ('localhost', '127.0.0.1', '::1'):
                continue
            if r.startswith('*.'):
                lines.append(f'  if (shExpMatch(host, "*{r[1:]}")) return "DIRECT";')
            elif r.startswith('.'):
                lines.append(f'  if (shExpMatch(host, "*{r}")) return "DIRECT";')
            else:
                lines.append(f'  if (host == "{r}" || shExpMatch(host, "*.{r}")) return "DIRECT";')
        lines.append(f'  return "PROXY 127.0.0.1:{CLIENT_PORT}";')
        body = '\n'.join(lines)
        return (
            'function FindProxyForURL(url, host) {\n'
            f'{body}\n'
            '}\n'
        )
    # matched mode (default): only rules go through the proxy.
    lines = []
    for rule in rules:
        r = rule.strip()
        if not r:
            continue
        if r.startswith('*.'):
            pat = r[1:]  # ".example.com"
            lines.append(f'  if (shExpMatch(host, "*{pat}")) return "PROXY 127.0.0.1:{CLIENT_PORT}";')
        elif r.startswith('.'):
            lines.append(f'  if (shExpMatch(host, "*{r}")) return "PROXY 127.0.0.1:{CLIENT_PORT}";')
        else:
            lines.append(f'  if (host == "{r}" || shExpMatch(host, "*.{r}")) return "PROXY 127.0.0.1:{CLIENT_PORT}";')
    body = '\n'.join(lines)
    return (
        'function FindProxyForURL(url, host) {\n'
        f'{body}\n'
        '  return "DIRECT";\n'
        '}\n'
    )


def _key_for(token):
    return hmac.new((token or '').encode(), ENC_CTX.encode(), hashlib.sha256).digest()


def _default_key():
    return _key_for(SECRET)


def _keystream(key, nonce, length):
    """PRF 密钥流（CTR 式）：HMAC-SHA256(key, nonce || counter32)，截取 length 字节."""
    out = b''
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + struct.pack('>I', counter), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def encrypt_frame(payload, key=None):
    """加密 + 加标签成帧。key=None → 用全局 SECRET 派生."""
    key = _default_key() if key is None else key
    nonce = os.urandom(16)
    ks = _keystream(key, nonce, len(payload))
    ct = bytes(a ^ b for a, b in zip(payload, ks))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return MAGIC + struct.pack('>I', len(ct)) + nonce + ct + tag


def decrypt_frame(frame, key=None):
    """验 tag + 解密。返回明文 bytes；格式错/tag 不对返回 None."""
    key = _default_key() if key is None else key
    if len(frame) < 21 or frame[0:1] != MAGIC:
        return None
    n = struct.unpack('>I', frame[1:5])[0]
    if n > 65536 or len(frame) != 21 + n + 32:
        return None
    nonce, ct, tag = frame[5:21], frame[21:21 + n], frame[21 + n:]
    expect = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        return None
    ks = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


async def read_exact(reader, n):
    buf = b''
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


async def read_frame(reader, key=None):
    """从流里读一帧。EOF/格式错/tag 错 → None."""
    head = await read_exact(reader, 21)
    if head is None or head[0:1] != MAGIC:
        return None
    n = struct.unpack('>I', head[1:5])[0]
    if n > 65536:
        return None
    body = await read_exact(reader, n + 32)
    if body is None:
        return None
    return decrypt_frame(head + body, key)


async def read_headers(reader):
    """Read the request line + headers (until \\r\\n\\r\\n). Returns (request_line, headers, rest)."""
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = await reader.read(4096)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 65536:
            return None
    head, _, rest = buf.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    request_line = lines[0].decode('latin-1')
    headers = {}
    for line in lines[1:]:
        if b':' in line:
            k, _, v = line.partition(b':')
            headers[k.decode('latin-1').strip().lower()] = v.decode('latin-1').strip()
    return request_line, headers, rest


async def _probe(host, port, token):
    """Probe the upstream server: can we reach it, and is the token valid?

    Sends an encrypted CONNECT frame to a probe target and interprets the ACK:
      - connection error  -> server unreachable (IP/port/firewall)
      - ACK 200           -> reachable + auth OK
      - ACK 407           -> token wrong
      - timeout / closed  -> network/other problem (协议不匹配/握手被拒)
    """
    probe_target = 'example.com:443'
    key = _key_for(token)
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except Exception as e:
        return {'code': 'unreachable', 'ok': False,
                'msg': f'无法连接服务端 {host}:{port}（{e}）'}
    try:
        payload = json.dumps({'m': 'CONNECT', 't': probe_target}).encode()
        writer.write(encrypt_frame(payload, key))
        await writer.drain()
        try:
            ack = await asyncio.wait_for(read_frame(reader, key), timeout=8)
        except asyncio.TimeoutError:
            return {'code': 'timeout', 'ok': False,
                    'msg': f'服务端 {host}:{port} 超时未响应（地址/端口错误或防火墙拦截）'}
        if ack is None:
            return {'code': 'closed', 'ok': False,
                    'msg': '服务端握手失败（token 错误或协议不匹配，端口可能不对）'}
        try:
            info = json.loads(ack)
        except Exception:
            return {'code': 'other', 'ok': False, 'msg': '服务端返回无法解析的数据'}
        code = info.get('c')
        if code == 200:
            return {'code': 'ok', 'ok': True, 'msg': '连接正常，鉴权通过'}
        if code == 407:
            return {'code': 'auth', 'ok': False,
                    'msg': 'Token 错误：服务端返回 407 Proxy Authentication Required'}
        msg = f'{code} {info.get("m", "")}'.strip()
        return {'code': 'other', 'ok': False, 'msg': f'服务端返回异常：{msg}'}
    finally:
        try:
            writer.close()
        except Exception:
            pass


def test_connection(host=None, port=None, token=None):
    """Synchronous probe of the upstream server. Uses current globals if omitted.

    Runs its own event loop so it is safe to call from the GUI thread or a
    worker thread without touching the proxy's running loop.
    """
    h = host if host is not None else SERVER_HOST
    p = port if port is not None else SERVER_PORT
    t = token if token is not None else SECRET
    return asyncio.run(_probe(h, p, t))


async def pipe_streams(a_reader, a_writer, b_reader, b_writer):
    async def pump(r, w):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.write_eof()
            except Exception:
                pass

    await asyncio.gather(pump(a_reader, b_writer), pump(b_reader, a_writer))
    for s in (a_writer, b_writer):
        try:
            s.close()
        except Exception:
            pass


async def serve_pac(writer):
    pac = build_pac(load_rules()).encode('utf-8')
    resp = (
        'HTTP/1.1 200 OK\r\n'
        'Content-Type: application/x-ns-proxy-autoconfig\r\n'
        f'Content-Length: {len(pac)}\r\n'
        'Connection: close\r\n\r\n'
    ).encode() + pac
    writer.write(resp)
    await writer.drain()
    writer.close()


async def forward_connect_to_server(reader, writer, host, port, head):
    """HTTPS CONNECT: pipe browser<->server, server does DNS+connect to target."""
    try:
        srv_reader, srv_writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
    except Exception as e:
        writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        await writer.drain()
        writer.close()
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端不可达({e})')
        return
    payload = json.dumps({'m': 'CONNECT', 't': f'{host}:{port}'}).encode()
    srv_writer.write(encrypt_frame(payload))
    if head:
        # 浏览器可能在 CONNECT 后立刻随包发送 TLS ClientHello 等早期数据，
        # 必须原样转发给服务端，否则 TLS 握手会因 ClientHello 丢失而挂起。
        srv_writer.write(head)
    await srv_writer.drain()
    try:
        ack = await asyncio.wait_for(read_frame(srv_reader), timeout=15)
    except asyncio.TimeoutError:
        srv_writer.close(); writer.close()
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端响应超时(15s)')
        return
    if ack is None:
        srv_writer.close(); writer.close()
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端握手失败(token错/协议不匹配)')
        return
    try:
        info = json.loads(ack)
    except Exception:
        srv_writer.close(); writer.close()
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端响应无法解析')
        return
    code = info.get('c')
    if code != 200:
        reason = info.get('m', 'Bad Gateway')
        writer.write(f'HTTP/1.1 {code} {reason}\r\n\r\n'.encode())
        await writer.drain()
        srv_writer.close(); writer.close()
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端拒绝({code} {reason})')
        return
    writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    await writer.drain()
    await pipe_streams(reader, writer, srv_reader, srv_writer)


async def connect_direct(reader, writer, host, port, head):
    try:
        t_reader, t_writer = await asyncio.open_connection(host, port)
    except Exception:
        writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        await writer.drain(); writer.close(); return
    if head:
        # 直连场景同理：浏览器随 CONNECT 发来的早期数据（如 TLS ClientHello）要转发给目标
        t_writer.write(head)
    writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    await writer.drain()
    await pipe_streams(reader, writer, t_reader, t_writer)


async def http_to_server(reader, writer, request_line, headers, rest):
    try:
        srv_reader, srv_writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
    except Exception as e:
        writer.close()
        _log_req('SERVER-FAIL', f'{request_line.split(" ", 2)[1]} 服务端不可达({e})')
        return
    payload = json.dumps({'m': 'HTTP', 'r': request_line, 'h': headers}).encode()
    srv_writer.write(encrypt_frame(payload))
    if rest:
        srv_writer.write(rest)
    await srv_writer.drain()
    await pipe_streams(reader, writer, srv_reader, srv_writer)


async def http_direct(reader, writer, request_line, headers, rest):
    method, target, _version = request_line.split(' ', 2)
    u = urlparse(target)
    host = u.hostname
    port = u.port or 80
    try:
        t_reader, t_writer = await asyncio.open_connection(host, port)
    except Exception:
        writer.close(); return
    path = u.path or '/' + (('?' + u.query) if u.query else '')
    out = f'{method} {path} HTTP/1.1\r\n'
    for k, v in headers.items():
        if k in ('proxy-authorization', 'proxy-connection', 'connection'):
            continue
        out += f'{k}: {v}\r\n'
    out += 'Connection: close\r\n\r\n'
    t_writer.write(out.encode())
    if rest:
        t_writer.write(rest)
    await t_writer.drain()
    await pipe_streams(reader, writer, t_reader, t_writer)


async def handle(reader, writer):
    try:
        parsed = await read_headers(reader)
        if parsed is None:
            writer.close(); return
        request_line, headers, rest = parsed
        parts = request_line.split(' ')
        if len(parts) < 2:
            writer.close(); return
        method, target = parts[0], parts[1]

        # Serve the PAC file. The OS/browser fetches it directly (GET /proxy.pac),
        # so the request target is a relative path, not an absolute URL.
        if method.upper() == 'GET' and 'proxy.pac' in target:
            u = urlparse(target)
            if u.hostname in ('127.0.0.1', 'localhost', None):
                await serve_pac(writer)
                return

        rules = load_rules()
        if method.upper() == 'CONNECT':
            host, _, port_s = target.rpartition(':')
            port = int(port_s) if port_s.isdigit() else 443
            via = _use_server(host, rules)
            _log_req('TUNNEL' if via else 'DIRECT', f'{host}:{port}')
            if via:
                await forward_connect_to_server(reader, writer, host, port, rest)
            else:
                await connect_direct(reader, writer, host, port, rest)
        else:
            u = urlparse(target)
            via = _use_server(u.hostname, rules)
            _log_req('SERVER' if via else 'DIRECT', target)
            if via:
                await http_to_server(reader, writer, request_line, headers, rest)
            else:
                await http_direct(reader, writer, request_line, headers, rest)
    except Exception:
        try:
            writer.close()
        except Exception:
            pass


# Track active connection handler tasks so we can cancel them on shutdown.
_active_connections: set = set()


async def _handle_tracked(reader, writer):
    task = asyncio.current_task()
    _active_connections.add(task)
    try:
        await handle(reader, writer)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        pass
    finally:
        _active_connections.discard(task)
        try:
            writer.close()
        except Exception:
            pass


async def serve():
    global _server
    _server = await asyncio.start_server(_handle_tracked, '127.0.0.1', CLIENT_PORT)

    try:
        async with _server:
            print(f'[client] proxy listening on 127.0.0.1:{CLIENT_PORT}')
            print(f'[client] PAC file: http://127.0.0.1:{CLIENT_PORT}/proxy.pac')
            print(f'[client] upstream server: {SERVER_HOST}:{SERVER_PORT}')
            await _server.serve_forever()
    finally:
        # Reached on normal shutdown OR when the task is cancelled.
        # Cancel all in-flight connection handler tasks and wait for cleanup.
        for t in list(_active_connections):
            t.cancel()
        if _active_connections:
            await asyncio.gather(*_active_connections, return_exceptions=True)


def close_server():
    if _server:
        _server.close()


def main():
    set_request_logger(lambda tag, t: print(f'[{tag}] {t}', flush=True))
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    finally:
        print('\n[client] stopped')


if __name__ == '__main__':
    main()
