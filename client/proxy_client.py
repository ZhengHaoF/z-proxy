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
import contextvars
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

DEFAULT_TOKEN = 'z-proxy-dev'
VALID_MODES = ('matched', 'all')

DEFAULTS = {
    'client_port': 8787,
    'server_host': '127.0.0.1',
    'server_port': 8443,
    'token': DEFAULT_TOKEN,
    'mode': 'matched',
    'bypass': ['localhost', '127.0.0.1', '::1'],
}

# ---- 超时（秒）----
CONNECT_TIMEOUT = 10      # TCP 建连（服务端 / 直连目标）
HEADER_TIMEOUT = 30       # 浏览器请求行 + 首部读取
HANDSHAKE_TIMEOUT = 15    # 服务端 CONNECT ACK 帧
PROBE_TIMEOUT = 8         # 测试连接 ACK
MAX_HEADER_BYTES = 65536


# ---------------------------------------------------------------- config
def validate_port(value, name='port'):
    """Return value as an int in 1..65535, or raise ValueError.

    Accepts ints and decimal strings (e.g. from env vars / GUI entries).
    bool is rejected even though it is an int subclass.
    """
    if isinstance(value, bool):
        raise ValueError(f'{name} 必须是整数端口，而不是布尔值')
    if isinstance(value, str):
        s = value.strip()
        if not s.isdigit():
            raise ValueError(f'{name} 必须是 1-65535 的整数: {value!r}')
        value = int(s)
    if not isinstance(value, int):
        raise ValueError(f'{name} 必须是 1-65535 的整数: {value!r}')
    if not 1 <= value <= 65535:
        raise ValueError(f'{name} 超出范围 1-65535: {value}')
    return value


def normalize_config(raw, defaults=None):
    """Validate/coerce a config mapping. Returns (cfg, warnings).

    Invalid fields fall back to defaults instead of crashing the client, and a
    human-readable warning is recorded (never containing the token value).
    """
    base = dict(DEFAULTS if defaults is None else defaults)
    warnings = []
    if raw is None:
        return base, warnings
    if not isinstance(raw, dict):
        warnings.append('配置文件顶层不是 JSON 对象，已使用默认配置')
        return base, warnings
    cfg = dict(base)
    # Keep unknown keys for forward compatibility.
    for k, v in raw.items():
        if k not in DEFAULTS:
            cfg[k] = v
    for k in ('client_port', 'server_port'):
        if k in raw:
            try:
                cfg[k] = validate_port(raw[k], k)
            except ValueError as e:
                warnings.append(f'{e}，已回退为 {base[k]}')
    if 'server_host' in raw:
        v = raw['server_host']
        if isinstance(v, str) and v.strip() and not any(c.isspace() for c in v.strip()):
            cfg['server_host'] = v.strip()
        else:
            warnings.append(f'server_host 无效，已回退为 {base["server_host"]}')
    if 'token' in raw:
        v = raw['token']
        if isinstance(v, str):
            cfg['token'] = v
        else:
            warnings.append('token 必须是字符串，已回退为默认值')
    if 'mode' in raw:
        v = raw['mode']
        if isinstance(v, str) and v.strip().lower() in VALID_MODES:
            cfg['mode'] = v.strip().lower()
        else:
            warnings.append(f'mode 无效: {v!r}（可选 matched/all），已回退为 {base["mode"]}')
    if 'bypass' in raw:
        v = raw['bypass']
        if isinstance(v, str):
            v = [v]
        if isinstance(v, (list, tuple)):
            items = [x.strip() for x in v if isinstance(x, str) and x.strip()]
            if len(items) != len(v):
                warnings.append('bypass 中存在非字符串/空项，已忽略')
            cfg['bypass'] = items
        else:
            warnings.append('bypass 必须是字符串数组，已回退为默认值')
    return cfg, warnings


def load_config(path=None, environ=None):
    """Load config.json (+ env overrides) and validate it.

    Signature is backward compatible: ``load_config()`` behaves as before but
    no longer crashes on bad ports / types; problems are stored in
    ``CONFIG_WARNINGS``.
    """
    global CONFIG_WARNINGS
    path = CONFIG_PATH if path is None else path
    env = os.environ if environ is None else environ
    raw = None
    warnings = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
    except FileNotFoundError:
        pass
    except Exception as e:
        warnings.append(f'读取配置失败（{type(e).__name__}），已使用默认配置')
    cfg, w = normalize_config(raw)
    warnings.extend(w)
    for k in ('client_port', 'server_port'):
        if env.get(k.upper()):
            try:
                cfg[k] = validate_port(env[k.upper()], k.upper())
            except ValueError as e:
                warnings.append(f'环境变量 {e}，已忽略')
    if env.get('SERVER_HOST'):
        cfg['server_host'] = env['SERVER_HOST'].strip()
    if env.get('TOKEN'):
        cfg['token'] = env['TOKEN']
    CONFIG_WARNINGS = warnings
    return cfg


MIN_TOKEN_LENGTH = 24  # mirrors the server's production requirement


def is_insecure_token(token):
    """True for an empty/short token or the well-known development default.

    Only used for warnings; the client never refuses to start because of it
    (the server enforces its own policy).
    """
    return not token or token == DEFAULT_TOKEN or len(token) < MIN_TOKEN_LENGTH


CONFIG_WARNINGS = []
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

# Per-serve() context (logger + listen port). Connection handler tasks inherit
# it, so a stale server instance never logs through a newer instance's logger.
_serve_ctx = contextvars.ContextVar('z_proxy_serve_ctx', default=None)


def set_request_logger(fn):
    global request_logger
    request_logger = fn


def _log_req(tag, target):
    ctx = _serve_ctx.get()
    fn = ctx['logger'] if ctx and ctx.get('logger') is not None else request_logger
    if fn:
        try:
            fn(tag, target)
        except Exception:
            pass


def _listen_port():
    ctx = _serve_ctx.get()
    if ctx and ctx.get('port'):
        return ctx['port']
    return CLIENT_PORT


def load_rules():
    try:
        with open(RULES_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        rules = data.get('rules', []) if isinstance(data, dict) else []
        return [r for r in rules if isinstance(r, str)]
    except Exception:
        return []


# ---------------------------------------------------------------- matching
# One normaliser shared by domain_matches / is_bypass / build_pac so that the
# PAC file and the proxy's own routing decision can never disagree.
#   "example.com", "*.example.com", ".example.com" all mean: the root domain
#   AND every subdomain. Matching is case-insensitive, trailing dots ignored.
_RULE_FORBIDDEN = set('"\'\\/*?#@ \t\r\n') | {chr(c) for c in range(0x20)} | {'\x7f'}


def _normalize_host(host):
    if not host or not isinstance(host, str):
        return ''
    h = host.strip().lower()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    return h.rstrip('.')


def normalize_rule(rule):
    """Return the canonical base domain of a rule, or '' if invalid/empty."""
    if not isinstance(rule, str):
        return ''
    r = rule.strip().lower()
    if r.startswith('*.'):
        r = r[2:]
    elif r.startswith('.'):
        r = r[1:]
    if r.startswith('[') and r.endswith(']'):
        r = r[1:-1]
    r = r.rstrip('.')
    if not r or any(c in _RULE_FORBIDDEN for c in r):
        return ''
    if not r.isascii():
        # Browsers / CONNECT targets use the punycode (A-label) form.
        try:
            r = r.encode('idna').decode('ascii').lower()
        except UnicodeError:
            return ''
    return r


def _normalized_rules(rules):
    out = []
    seen = set()
    for rule in rules or ():
        r = normalize_rule(rule)
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _host_matches(h, base):
    return h == base or h.endswith('.' + base)


def domain_matches(host, rules):
    h = _normalize_host(host)
    if not h:
        return False
    return any(_host_matches(h, r) for r in _normalized_rules(rules))


# Literal-IP ranges that always go direct. Shared with the PAC generator.
_DIRECT_V4_NETS = [ipaddress.ip_network(n) for n in (
    '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
)]
_DIRECT_V6_NETS = [ipaddress.ip_network(n) for n in (
    '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8',
)]


def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(_normalize_host(host).split('%', 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    nets = _DIRECT_V4_NETS if ip.version == 4 else _DIRECT_V6_NETS
    return any(ip in n for n in nets)


def is_bypass(host):
    """True if the host must connect directly (never via the upstream server).

    Applies in every mode and takes precedence over rules: literal
    loopback/private/link-local/multicast IPs, plain (dot-less) host names,
    ``*.local`` and the configured bypass list.
    """
    h = _normalize_host(host)
    if not h:
        return False
    if _is_private_ip(h):
        return True
    if '.' not in h and ':' not in h:   # plain intranet host name, e.g. "nas"
        return True
    if h.endswith('.local'):
        return True
    return any(_host_matches(h, r) for r in _normalized_rules(BYPASS))


def _use_server(host, rules):
    """Whether a request should be tunneled to the upstream server."""
    if not _normalize_host(host) or is_bypass(host):
        return False
    if MODE == 'all':
        return True
    return domain_matches(host, rules)


def _js_str(s):
    # json.dumps gives a valid, fully escaped JS string literal (ASCII only).
    return json.dumps(s, ensure_ascii=True)


def build_pac(rules, port=None):
    port = _listen_port() if port is None else port
    proxy = _js_str(f'PROXY 127.0.0.1:{port}')
    bypass = _normalized_rules(BYPASS)
    v4 = ', '.join(f'[{int(n.network_address)}, {int(n.netmask)}]' for n in _DIRECT_V4_NETS)
    lines = [
        'function _zpMatch(h, list) {',
        '  for (var i = 0; i < list.length; i++) {',
        '    var d = list[i];',
        '    if (h === d) return true;',
        '    if (h.length > d.length && h.substring(h.length - d.length - 1) === "." + d) return true;',
        '  }',
        '  return false;',
        '}',
        'function _zpDirectIp(h) {',
        '  var m = /^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/.exec(h);',
        '  if (m) {',
        '    var n = 0;',
        '    for (var i = 1; i <= 4; i++) { var o = parseInt(m[i], 10); if (o > 255) return false; n = n * 256 + o; }',
        f'    var nets = [{v4}];',
        '    for (var j = 0; j < nets.length; j++) {',
        '      if (((n & nets[j][1]) >>> 0) === nets[j][0]) return true;',
        '    }',
        '    return false;',
        '  }',
        '  if (h.indexOf(":") >= 0) {',
        '    var x = h.split("%")[0];',
        '    if (x === "::1" || x === "::") return true;',
        '    if (/^f[cd][0-9a-f]{2}:/.test(x) || /^fe[89ab][0-9a-f]:/.test(x) || /^ff[0-9a-f]{2}:/.test(x)) return true;',
        '    var mm = /^::ffff:(\\d+\\.\\d+\\.\\d+\\.\\d+)$/.exec(x);',
        '    if (mm) return _zpDirectIp(mm[1]);',
        '  }',
        '  return false;',
        '}',
        f'var ZP_BYPASS = {_js_str(bypass)};',
    ]
    if MODE != 'all':
        lines.append(f'var ZP_RULES = {_js_str(_normalized_rules(rules))};')
    lines += [
        'function FindProxyForURL(url, host) {',
        '  var h = String(host).toLowerCase();',
        '  if (h.charAt(0) === "[" && h.charAt(h.length - 1) === "]") h = h.substring(1, h.length - 1);',
        '  while (h.length && h.charAt(h.length - 1) === ".") h = h.substring(0, h.length - 1);',
        '  if (!h) return "DIRECT";',
        '  if (_zpDirectIp(h)) return "DIRECT";',
        '  if (h.indexOf(".") < 0 && h.indexOf(":") < 0) return "DIRECT";',
        '  if (h.length > 6 && h.substring(h.length - 6) === ".local") return "DIRECT";',
        '  if (_zpMatch(h, ZP_BYPASS)) return "DIRECT";',
    ]
    if MODE == 'all':
        lines.append(f'  return {proxy};')
    else:
        lines.append(f'  if (_zpMatch(h, ZP_RULES)) return {proxy};')
        lines.append('  return "DIRECT";')
    lines.append('}')
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------- crypto
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
        if len(buf) > MAX_HEADER_BYTES and b'\r\n\r\n' not in buf:
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


async def _open(host, port, timeout=None):
    """open_connection with a connect timeout."""
    return await asyncio.wait_for(asyncio.open_connection(host, port),
                                  timeout=CONNECT_TIMEOUT if timeout is None else timeout)


def _close(*writers):
    for w in writers:
        if w is None:
            continue
        try:
            w.close()
        except Exception:
            pass


async def _send_status(writer, code, reason):
    try:
        writer.write(f'HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
        await writer.drain()
    except Exception:
        pass
    _close(writer)


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
        port = validate_port(port, '端口')
    except ValueError as e:
        return {'code': 'invalid', 'ok': False, 'msg': str(e)}
    try:
        reader, writer = await _open(host, port)
    except asyncio.TimeoutError:
        return {'code': 'unreachable', 'ok': False,
                'msg': f'连接服务端 {host}:{port} 超时（{CONNECT_TIMEOUT}s）'}
    except Exception as e:
        return {'code': 'unreachable', 'ok': False,
                'msg': f'无法连接服务端 {host}:{port}（{e}）'}
    try:
        payload = json.dumps({'m': 'CONNECT', 't': probe_target}).encode()
        writer.write(encrypt_frame(payload, key))
        await writer.drain()
        try:
            ack = await asyncio.wait_for(read_frame(reader, key), timeout=PROBE_TIMEOUT)
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
        if not isinstance(info, dict):
            return {'code': 'other', 'ok': False, 'msg': '服务端返回无法解析的数据'}
        code = info.get('c')
        if code == 200:
            return {'code': 'ok', 'ok': True, 'msg': '连接正常，鉴权通过'}
        if code == 407:
            return {'code': 'auth', 'ok': False,
                    'msg': 'Token 错误：服务端返回 407 Proxy Authentication Required'}
        msg = f'{code} {info.get("m", "")}'.strip()
        return {'code': 'other', 'ok': False, 'msg': f'服务端返回异常：{msg}'}
    except Exception as e:
        return {'code': 'other', 'ok': False, 'msg': f'测试连接出错：{e}'}
    finally:
        _close(writer)


def test_connection(host=None, port=None, token=None):
    """Synchronous probe of the upstream server. Uses current globals if omitted.

    Runs its own event loop so it is safe to call from the GUI thread or a
    worker thread without touching the proxy's running loop.
    """
    h = host if host is not None else SERVER_HOST
    p = port if port is not None else SERVER_PORT
    t = token if token is not None else SECRET
    return asyncio.run(_probe(h, p, t))


# Keep unittest/pytest from collecting this public helper as a test.
test_connection.__test__ = False


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

    try:
        await asyncio.gather(pump(a_reader, b_writer), pump(b_reader, a_writer))
    finally:
        _close(a_writer, b_writer)


async def serve_pac(writer, port=None):
    pac = build_pac(load_rules(), port=port).encode('utf-8')
    resp = (
        'HTTP/1.1 200 OK\r\n'
        'Content-Type: application/x-ns-proxy-autoconfig\r\n'
        f'Content-Length: {len(pac)}\r\n'
        'Cache-Control: no-cache\r\n'
        'Connection: close\r\n\r\n'
    ).encode() + pac
    writer.write(resp)
    await writer.drain()
    writer.close()


def _safe_reason(s, default='Bad Gateway'):
    s = str(s if s is not None else default)
    s = ''.join(c for c in s if 32 <= ord(c) < 127)[:64].strip()
    return s or default


async def forward_connect_to_server(reader, writer, host, port, head):
    """HTTPS CONNECT: pipe browser<->server, server does DNS+connect to target."""
    try:
        srv_reader, srv_writer = await _open(SERVER_HOST, SERVER_PORT)
    except Exception as e:
        reason = f'连接超时({CONNECT_TIMEOUT}s)' if isinstance(e, asyncio.TimeoutError) else str(e)
        await _send_status(writer, 502, 'Bad Gateway')
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端不可达({reason})')
        return
    try:
        authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        payload = json.dumps({'m': 'CONNECT', 't': authority}).encode()
        srv_writer.write(encrypt_frame(payload))
        if head:
            # 浏览器可能在 CONNECT 后立刻随包发送 TLS ClientHello 等早期数据，
            # 必须原样转发给服务端，否则 TLS 握手会因 ClientHello 丢失而挂起。
            srv_writer.write(head)
        await srv_writer.drain()
        ack = await asyncio.wait_for(read_frame(srv_reader), timeout=HANDSHAKE_TIMEOUT)
    except asyncio.TimeoutError:
        _close(srv_writer)
        await _send_status(writer, 504, 'Gateway Timeout')
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端响应超时({HANDSHAKE_TIMEOUT}s)')
        return
    except Exception as e:
        _close(srv_writer)
        await _send_status(writer, 502, 'Bad Gateway')
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端连接中断({e})')
        return
    if ack is None:
        _close(srv_writer)
        await _send_status(writer, 502, 'Bad Gateway')
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端握手失败(token错/协议不匹配)')
        return
    try:
        info = json.loads(ack)
        if not isinstance(info, dict):
            raise ValueError('not an object')
    except Exception:
        _close(srv_writer)
        await _send_status(writer, 502, 'Bad Gateway')
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端响应无法解析')
        return
    code = info.get('c')
    if code != 200:
        reason = _safe_reason(info.get('m', 'Bad Gateway'))
        status = code if isinstance(code, int) and not isinstance(code, bool) and 400 <= code <= 599 else 502
        _close(srv_writer)
        await _send_status(writer, status, reason)
        _log_req('TUNNEL-FAIL', f'{host}:{port} 服务端拒绝({code} {reason})')
        return
    writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    await writer.drain()
    await pipe_streams(reader, writer, srv_reader, srv_writer)


async def connect_direct(reader, writer, host, port, head):
    try:
        t_reader, t_writer = await _open(host, port)
    except Exception:
        await _send_status(writer, 502, 'Bad Gateway')
        return
    if head:
        # 直连场景同理：浏览器随 CONNECT 发来的早期数据（如 TLS ClientHello）要转发给目标
        t_writer.write(head)
    writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    await writer.drain()
    await pipe_streams(reader, writer, t_reader, t_writer)


async def http_to_server(reader, writer, request_line, headers, rest):
    try:
        srv_reader, srv_writer = await _open(SERVER_HOST, SERVER_PORT)
    except Exception as e:
        reason = f'连接超时({CONNECT_TIMEOUT}s)' if isinstance(e, asyncio.TimeoutError) else str(e)
        parts = request_line.split(' ', 2)
        await _send_status(writer, 502, 'Bad Gateway')
        _log_req('SERVER-FAIL', f'{parts[1] if len(parts) > 1 else request_line} 服务端不可达({reason})')
        return
    payload = json.dumps({'m': 'HTTP', 'r': request_line, 'h': headers}).encode()
    srv_writer.write(encrypt_frame(payload))
    if rest:
        srv_writer.write(rest)
    await srv_writer.drain()
    await pipe_streams(reader, writer, srv_reader, srv_writer)


_HOP_BY_HOP = ('proxy-authorization', 'proxy-connection', 'connection', 'keep-alive')


def build_origin_request(method, target, headers):
    """Rewrite an absolute-form proxy request into origin-form for direct HTTP.

    Returns (host, port, request_head_bytes). Raises ValueError on bad targets.
    """
    u = urlparse(target)
    if u.scheme.lower() != 'http' or not u.hostname:
        raise ValueError(f'unsupported proxy target: {target!r}')
    host = u.hostname
    port = u.port or 80   # u.port raises ValueError for invalid ports
    path = (u.path or '/') + (('?' + u.query) if u.query else '')
    out = f'{method} {path} HTTP/1.1\r\n'
    for k, v in headers.items():
        if k in _HOP_BY_HOP:
            continue
        out += f'{k}: {v}\r\n'
    out += 'Connection: close\r\n\r\n'
    return host, port, out.encode('latin-1')


async def http_direct(reader, writer, request_line, headers, rest):
    method, target, _version = request_line.split(' ', 2)
    try:
        host, port, out = build_origin_request(method, target, headers)
    except (ValueError, UnicodeEncodeError):
        await _send_status(writer, 400, 'Bad Request')
        return
    try:
        t_reader, t_writer = await _open(host, port)
    except Exception:
        await _send_status(writer, 502, 'Bad Gateway')
        return
    t_writer.write(out)
    if rest:
        t_writer.write(rest)
    await t_writer.drain()
    await pipe_streams(reader, writer, t_reader, t_writer)


def parse_connect_target(target):
    """'host:port' / '[v6]:port' -> (host, port). Raises ValueError."""
    t = target.strip()
    if t.startswith('['):
        end = t.find(']')
        if end < 0:
            raise ValueError('bad IPv6 literal')
        host, rest = t[1:end], t[end + 1:]
        if rest and not rest.startswith(':'):
            raise ValueError('bad CONNECT target')
        port_s = rest[1:]
    elif t.count(':') == 1:
        host, _, port_s = t.partition(':')
    elif ':' not in t:
        host, port_s = t, ''
    else:
        raise ValueError('ambiguous IPv6 CONNECT target')
    if not host:
        raise ValueError('empty host')
    port = validate_port(port_s, 'port') if port_s else 443
    return host, port


def _is_self(host, port):
    h = _normalize_host(host)
    return port == _listen_port() and (h == 'localhost' or h == '::1' or h.startswith('127.'))


async def handle(reader, writer):
    try:
        try:
            parsed = await asyncio.wait_for(read_headers(reader), timeout=HEADER_TIMEOUT)
        except asyncio.TimeoutError:
            await _send_status(writer, 408, 'Request Timeout')
            return
        if parsed is None:
            writer.close(); return
        request_line, headers, rest = parsed
        parts = request_line.split(' ')
        if len(parts) < 3:
            await _send_status(writer, 400, 'Bad Request')
            return
        method, target = parts[0], parts[1]

        # Serve the PAC file. The OS/browser fetches it directly (GET /proxy.pac),
        # so the request target is a relative path, not an absolute URL.
        if method.upper() == 'GET':
            u = urlparse(target)
            if u.path == '/proxy.pac' and u.hostname in ('127.0.0.1', 'localhost', None):
                await serve_pac(writer, port=_listen_port())
                return

        rules = load_rules()
        if method.upper() == 'CONNECT':
            try:
                host, port = parse_connect_target(target)
            except ValueError:
                await _send_status(writer, 400, 'Bad Request')
                return
            if _is_self(host, port):
                await _send_status(writer, 508, 'Loop Detected')
                return
            via = _use_server(host, rules)
            _log_req('TUNNEL' if via else 'DIRECT', f'{host}:{port}')
            if via:
                await forward_connect_to_server(reader, writer, host, port, rest)
            else:
                await connect_direct(reader, writer, host, port, rest)
        else:
            u = urlparse(target)
            try:
                tport = u.port or 80
            except ValueError:
                await _send_status(writer, 400, 'Bad Request')
                return
            if not u.hostname or u.scheme.lower() != 'http':
                await _send_status(writer, 400, 'Bad Request')
                return
            if _is_self(u.hostname, tport):
                await _send_status(writer, 508, 'Loop Detected')
                return
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
# (Kept for backward compatibility; each serve() also keeps its own set so
# that a stale instance never cancels another loop's tasks.)
_active_connections: set = set()


async def _handle_tracked(reader, writer, _conns=None):
    task = asyncio.current_task()
    conns = _active_connections if _conns is None else _conns
    conns.add(task)
    try:
        await handle(reader, writer)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        pass
    finally:
        conns.discard(task)
        try:
            writer.close()
        except Exception:
            pass


async def serve(host='127.0.0.1', port=None, on_ready=None, logger=None, quiet=False):
    """Run the local proxy until cancelled.

    ``serve()`` with no arguments behaves as before. ``on_ready(port)`` is
    called only after the listening socket is bound successfully; if binding
    fails, the exception propagates and ``on_ready`` is never called.
    ``logger`` overrides the module-level request logger for this instance.
    """
    global _server
    listen_port = CLIENT_PORT if port is None else port
    conns = set()
    ctx = {'logger': logger, 'port': listen_port}

    async def _cb(reader, writer):
        _serve_ctx.set(ctx)
        await _handle_tracked(reader, writer, conns)

    server = await asyncio.start_server(_cb, host, listen_port)
    actual = server.sockets[0].getsockname()[1] if server.sockets else listen_port
    ctx['port'] = actual
    _server = server

    try:
        async with server:
            if not quiet:
                print(f'[client] proxy listening on {host}:{actual}')
                print(f'[client] PAC file: http://127.0.0.1:{actual}/proxy.pac')
                print(f'[client] upstream server: {SERVER_HOST}:{SERVER_PORT}')
            if on_ready is not None:
                on_ready(actual)
            await server.serve_forever()
    finally:
        # Reached on normal shutdown OR when the task is cancelled.
        # Cancel all in-flight connection handler tasks and wait for cleanup.
        server.close()
        for t in list(conns):
            t.cancel()
        if conns:
            await asyncio.gather(*conns, return_exceptions=True)
        if _server is server:
            _server = None


def close_server():
    if _server:
        _server.close()


def main():
    for w in CONFIG_WARNINGS:
        print(f'[client] 配置警告: {w}', file=sys.stderr)
    if is_insecure_token(SECRET):
        print('[client] 警告: 正在使用空 token 或默认开发 token，生产环境请配置与服务端一致的强随机 PROXY_TOKEN',
              file=sys.stderr)
    set_request_logger(lambda tag, t: print(f'[{tag}] {t}', flush=True))
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f'[client] 监听 127.0.0.1:{CLIENT_PORT} 失败: {e}', file=sys.stderr)
    finally:
        print('\n[client] stopped')


if __name__ == '__main__':
    main()
