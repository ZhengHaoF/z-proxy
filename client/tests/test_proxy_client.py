"""Regression tests for client/proxy_client.py (stdlib unittest, real loopback)."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import (pc, GlobalsGuard, FakeUpstream, TEST_TOKEN, start_proxy,  # noqa: E402
                      stop_task, read_http_head, free_port)


# ---------------------------------------------------------------- config
class ConfigTests(unittest.TestCase):
    def test_validate_port(self):
        self.assertEqual(pc.validate_port(8443), 8443)
        self.assertEqual(pc.validate_port(' 8080 '), 8080)
        for bad in (0, 65536, -1, True, 'abc', '80a', 1.5, None, ''):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pc.validate_port(bad)

    def test_normalize_config_types(self):
        cfg, warnings = pc.normalize_config({
            'client_port': '9000', 'server_port': 70000, 'server_host': 123,
            'token': 42, 'mode': 'ALL', 'bypass': ['a.com', 5, ''], 'extra': 1})
        self.assertEqual(cfg['client_port'], 9000)
        self.assertEqual(cfg['server_port'], pc.DEFAULTS['server_port'])
        self.assertEqual(cfg['server_host'], pc.DEFAULTS['server_host'])
        self.assertEqual(cfg['token'], pc.DEFAULTS['token'])
        self.assertEqual(cfg['mode'], 'all')
        self.assertEqual(cfg['bypass'], ['a.com'])
        self.assertEqual(cfg['extra'], 1)
        self.assertGreaterEqual(len(warnings), 4)
        self.assertFalse(any(TEST_TOKEN in w for w in warnings))

    def test_normalize_config_non_dict_and_bad_mode(self):
        cfg, w = pc.normalize_config(['x'])
        self.assertEqual(cfg, pc.DEFAULTS)
        self.assertTrue(w)
        cfg, w = pc.normalize_config({'mode': 'everything'})
        self.assertEqual(cfg['mode'], 'matched')

    def test_load_config_file_and_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'config.json')
            with open(p, 'w', encoding='utf-8') as f:
                json.dump({'server_port': '9443', 'client_port': True}, f)
            cfg = pc.load_config(p, environ={'CLIENT_PORT': 'oops', 'SERVER_HOST': ' h.example '})
            self.assertEqual(cfg['server_port'], 9443)
            self.assertEqual(cfg['client_port'], pc.DEFAULTS['client_port'])
            self.assertEqual(cfg['server_host'], 'h.example')
            self.assertTrue(pc.CONFIG_WARNINGS)
            with open(p, 'w', encoding='utf-8') as f:
                f.write('{not json')
            cfg = pc.load_config(p, environ={'SERVER_PORT': '1234'})
            self.assertEqual(cfg['server_port'], 1234)
        pc.CONFIG_WARNINGS = []

    def test_insecure_token(self):
        self.assertTrue(pc.is_insecure_token(''))
        self.assertTrue(pc.is_insecure_token(pc.DEFAULT_TOKEN))
        self.assertTrue(pc.is_insecure_token(TEST_TOKEN))  # < 24 chars
        self.assertFalse(pc.is_insecure_token('x' * 24))


# ---------------------------------------------------------------- matching
class MatchingTests(unittest.TestCase):
    def test_root_and_subdomains_for_all_rule_forms(self):
        for rule in ('example.com', '*.example.com', '.example.com', 'EXAMPLE.com.', ' *.Example.Com '):
            for host in ('example.com', 'a.example.com', 'A.B.EXAMPLE.COM', 'example.com.'):
                self.assertTrue(pc.domain_matches(host, [rule]), (rule, host))
            for host in ('badexample.com', 'example.com.evil', 'example.co', ''):
                self.assertFalse(pc.domain_matches(host, [rule]), (rule, host))

    def test_unsafe_rules_are_ignored(self):
        for rule in ('a"b.com', "x');alert(1)//", 'a\\b.com', 'foo*.com', 'a b.com', '*', '.', ''):
            self.assertEqual(pc.normalize_rule(rule), '', rule)
        self.assertFalse(pc.domain_matches('foo1.com', ['foo*.com']))
        self.assertFalse(pc.domain_matches('anything.com', ['*']))
        self.assertEqual(pc.normalize_rule(None), '')

    def test_idn_rule(self):
        self.assertTrue(pc.domain_matches('www.xn--fsqu00a.com', ['*.例子.com']))

    def test_bypass_precedence_in_every_mode(self):
        with GlobalsGuard():
            pc.BYPASS = ['localhost', 'corp.example.com']
            rules = ['example.com', '10.1.2.3']
            for mode in ('matched', 'all'):
                pc.MODE = mode
                self.assertFalse(pc._use_server('git.corp.example.com', rules), mode)
                self.assertFalse(pc._use_server('10.1.2.3', rules), mode)
                self.assertFalse(pc._use_server('[::1]', rules), mode)
                self.assertFalse(pc._use_server('fe80::1', rules), mode)
                self.assertFalse(pc._use_server('nas', rules), mode)
                self.assertFalse(pc._use_server('printer.local', rules), mode)
                self.assertFalse(pc._use_server(None, rules), mode)
                self.assertTrue(pc._use_server('www.example.com', rules), mode)
            pc.MODE = 'matched'
            self.assertFalse(pc._use_server('other.org', rules))
            pc.MODE = 'all'
            self.assertTrue(pc._use_server('other.org', rules))
            self.assertTrue(pc._use_server('8.8.8.8', rules))

    def test_parse_connect_target(self):
        self.assertEqual(pc.parse_connect_target('a.com:8443'), ('a.com', 8443))
        self.assertEqual(pc.parse_connect_target('a.com'), ('a.com', 443))
        self.assertEqual(pc.parse_connect_target('[::1]:443'), ('::1', 443))
        for bad in ('a.com:0', 'a.com:99999', 'a.com:x', ':443', '[::1', '::1:443'):
            with self.assertRaises(ValueError, msg=bad):
                pc.parse_connect_target(bad)

    def test_origin_request_keeps_query(self):
        host, port, head = pc.build_origin_request(
            'GET', 'http://Ex.com:8080/p/a?x=1&y=%20', {'host': 'ex.com', 'proxy-connection': 'k', 'accept': '*/*'})
        self.assertEqual((host, port), ('ex.com', 8080))
        self.assertTrue(head.startswith(b'GET /p/a?x=1&y=%20 HTTP/1.1\r\n'))
        self.assertNotIn(b'proxy-connection', head)
        _, port, head = pc.build_origin_request('GET', 'http://ex.com?q=1', {})
        self.assertEqual(port, 80)
        self.assertTrue(head.startswith(b'GET /?q=1 HTTP/1.1\r\n'))
        for bad in ('/relative', 'https://ex.com/', 'http://ex.com:bad/'):
            with self.assertRaises(ValueError, msg=bad):
                pc.build_origin_request('GET', bad, {})


# ---------------------------------------------------------------- PAC
NODE = shutil.which('node')

PAC_HOSTS = [
    'example.com', 'WWW.Example.COM', 'example.com.', 'badexample.com', 'foo.org', 'x.foo.org',
    'other.net', 'corp.example.com', 'a.corp.example.com', 'nas', 'printer.local', 'localhost',
    '127.0.0.1', '10.0.0.5', '172.16.3.4', '172.32.0.1', '192.168.1.1', '169.254.1.1', '8.8.8.8',
    '224.0.0.1', '255.255.255.255', '::1', 'fe80::1', 'fd00::1', '2001:db8::1', 'xn--fsqu00a.com',
    'sub.xn--fsqu00a.com', '999.1.1.1',
]


class PacTests(unittest.TestCase):
    RULES = ['*.Example.com', '.foo.org.', 'a"b.com', '例子.com', '', '  ']

    def test_pac_escapes_and_uses_port(self):
        with GlobalsGuard():
            pc.MODE = 'matched'
            pac = pc.build_pac(self.RULES, port=12345)
        self.assertIn('PROXY 127.0.0.1:12345', pac)
        self.assertNotIn('a"b', pac)
        self.assertNotIn('a\\"b', pac)
        self.assertNotIn('shExpMatch', pac)
        self.assertIn('"example.com"', pac)

    @unittest.skipUnless(NODE, 'node not installed; PAC/Python equivalence check skipped')
    def test_pac_agrees_with_python_routing(self):
        for mode in ('matched', 'all'):
            with GlobalsGuard():
                pc.MODE = mode
                pc.BYPASS = ['localhost', '127.0.0.1', '::1', '*.Corp.Example.com']
                pac = pc.build_pac(self.RULES, port=8787)
                expected = {h: ('PROXY 127.0.0.1:8787' if pc._use_server(h, self.RULES) else 'DIRECT')
                            for h in PAC_HOSTS}
            script = pac + '\nvar hosts = ' + json.dumps(PAC_HOSTS) + ';\n' \
                'var out = {}; hosts.forEach(function (h) { out[h] = FindProxyForURL("http://" + h + "/", h); });\n' \
                'process.stdout.write(JSON.stringify(out));\n'
            res = subprocess.run([NODE, '-e', script], capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(json.loads(res.stdout), expected, mode)


# ---------------------------------------------------------------- loopback I/O
class LoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.guard = GlobalsGuard().__enter__()
        pc.SECRET = TEST_TOKEN
        pc.MODE = 'matched'
        pc.BYPASS = ['localhost', '127.0.0.1', '::1']
        self.rules = []
        pc.load_rules = lambda: list(self.rules)
        self.logs = []
        self.proxy, self.port = await start_proxy(logger=lambda tag, t: self.logs.append((tag, t)))

    async def asyncTearDown(self):
        await stop_task(self.proxy)
        self.guard.__exit__(None, None, None)

    async def _client(self):
        return await asyncio.open_connection('127.0.0.1', self.port)

    async def test_http_direct_preserves_query(self):
        got = asyncio.get_running_loop().create_future()

        async def origin(reader, writer):
            head = await read_http_head(reader)
            got.set_result(head)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
            await writer.drain(); writer.close()

        srv = await asyncio.start_server(origin, '127.0.0.1', 0)
        oport = srv.sockets[0].getsockname()[1]
        try:
            r, w = await self._client()
            w.write(f'GET http://127.0.0.1:{oport}/search?q=a%20b&x=1 HTTP/1.1\r\n'
                    f'Host: 127.0.0.1:{oport}\r\nProxy-Connection: keep-alive\r\n\r\n'.encode())
            await w.drain()
            resp = await asyncio.wait_for(r.read(), 5)
            head = await asyncio.wait_for(got, 5)
            self.assertTrue(head.startswith(b'GET /search?q=a%20b&x=1 HTTP/1.1\r\n'), head)
            self.assertNotIn(b'proxy-connection', head.lower())
            self.assertTrue(resp.endswith(b'ok'))
            w.close()
        finally:
            srv.close(); await srv.wait_closed()

    async def test_pac_served_with_bound_port(self):
        r, w = await self._client()
        w.write(b'GET /proxy.pac?t=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        await w.drain()
        resp = await asyncio.wait_for(r.read(), 5)
        self.assertIn(b'200 OK', resp)
        self.assertIn(f'PROXY 127.0.0.1:{self.port}'.encode(), resp)
        w.close()

    async def test_bad_requests_get_400_or_508(self):
        for line, code in ((b'GET /not-absolute HTTP/1.1', b'400'),
                           (b'CONNECT host:99999 HTTP/1.1', b'400'),
                           (f'GET http://127.0.0.1:{self.port}/x HTTP/1.1'.encode(), b'508'),
                           (f'CONNECT 127.0.0.1:{self.port} HTTP/1.1'.encode(), b'508')):
            r, w = await self._client()
            w.write(line + b'\r\nHost: x\r\n\r\n')
            await w.drain()
            resp = await asyncio.wait_for(r.read(), 5)
            self.assertTrue(resp.startswith(b'HTTP/1.1 ' + code), (line, resp))
            w.close()

    async def test_header_timeout(self):
        pc.HEADER_TIMEOUT = 0.3
        r, w = await self._client()
        w.write(b'GET http://example.com/ HTTP/1.1\r\nHost: exa')  # never finishes
        await w.drain()
        resp = await asyncio.wait_for(r.read(), 5)
        self.assertTrue(resp.startswith(b'HTTP/1.1 408'), resp)
        w.close()

    async def test_connect_direct_forwards_early_data(self):
        async def echo(reader, writer):
            while data := await reader.read(65536):
                writer.write(data); await writer.drain()
            writer.close()

        srv = await asyncio.start_server(echo, '127.0.0.1', 0)
        eport = srv.sockets[0].getsockname()[1]
        try:
            r, w = await self._client()
            w.write(f'CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n\r\n'.encode() + b'EARLY')
            await w.drain()
            head = await read_http_head(r)
            self.assertIn(b'200 Connection Established', head)
            data = head.partition(b'\r\n\r\n')[2]
            while len(data) < 5:
                data += await asyncio.wait_for(r.read(100), 5)
            self.assertEqual(data, b'EARLY')
            self.assertEqual(self.logs[-1][0], 'DIRECT')
            w.close()
        finally:
            srv.close(); await srv.wait_closed()

    async def test_tunnel_via_upstream(self):
        self.rules = ['*.Tunnel.Test']
        async with FakeUpstream() as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(b'CONNECT tunnel.test:443 HTTP/1.1\r\n\r\nHELLO')
            await w.drain()
            head = await read_http_head(r)
            self.assertIn(b'200 Connection Established', head)
            data = head.partition(b'\r\n\r\n')[2]
            while len(data) < 5:
                data += await asyncio.wait_for(r.read(100), 5)
            self.assertEqual(data, b'HELLO')
            self.assertEqual(up.frames[0], {'m': 'CONNECT', 't': 'tunnel.test:443'})
            w.close()

    async def test_bypass_wins_over_rule_in_tunnel_path(self):
        # 127.0.0.1 is both a rule and a bypass entry: must go DIRECT.
        self.rules = ['127.0.0.1']
        async with FakeUpstream() as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(f'CONNECT 127.0.0.1:{free_port()} HTTP/1.1\r\n\r\n'.encode())
            await w.drain()
            await asyncio.wait_for(r.read(), 5)
            self.assertEqual(up.frames, [])
            self.assertEqual(self.logs[-1][0], 'DIRECT')
            w.close()

    async def test_ipv6_tunnel_authority_has_brackets(self):
        # Public IPv6 literal must reach the upstream with an unambiguous port.
        pc.MODE = 'all'
        async with FakeUpstream() as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(b'CONNECT [2001:4860:4860::8888]:443 HTTP/1.1\r\n\r\n')
            await w.drain()
            self.assertIn(b'200 Connection Established', await read_http_head(r))
            self.assertEqual(up.frames[0]['t'], '[2001:4860:4860::8888]:443')
            w.close()

    async def test_http_via_upstream_keeps_request_line(self):
        self.rules = ['tunnel.test']
        async with FakeUpstream(behaviour='http') as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(b'GET http://tunnel.test/a?b=1 HTTP/1.1\r\nHost: tunnel.test\r\n\r\n')
            await w.drain()
            resp = await asyncio.wait_for(r.read(), 5)
            self.assertTrue(resp.endswith(b'upstream-ok'))
            self.assertEqual(up.frames[0]['r'], 'GET http://tunnel.test/a?b=1 HTTP/1.1')
            w.close()

    async def test_upstream_handshake_timeout(self):
        self.rules = ['tunnel.test']
        pc.HANDSHAKE_TIMEOUT = 0.3
        async with FakeUpstream(behaviour='silent') as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(b'CONNECT tunnel.test:443 HTTP/1.1\r\n\r\n')
            await w.drain()
            resp = await asyncio.wait_for(r.read(), 5)
            self.assertTrue(resp.startswith(b'HTTP/1.1 504'), resp)
            self.assertEqual(self.logs[-1][0], 'TUNNEL-FAIL')
            w.close()

    async def test_upstream_deny_reason_sanitised(self):
        self.rules = ['tunnel.test']
        async with FakeUpstream(behaviour='deny') as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(b'CONNECT tunnel.test:443 HTTP/1.1\r\n\r\n')
            await w.drain()
            resp = await asyncio.wait_for(r.read(), 5)
            self.assertTrue(resp.startswith(b'HTTP/1.1 407 '), resp)
            self.assertNotIn(b'\r\nX-Evil', resp)
            w.close()

    async def test_wrong_token_closes_tunnel(self):
        self.rules = ['tunnel.test']
        async with FakeUpstream(token='another-test-token') as up:
            pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', up.port
            r, w = await self._client()
            w.write(b'CONNECT tunnel.test:443 HTTP/1.1\r\n\r\n')
            await w.drain()
            resp = await asyncio.wait_for(r.read(), 5)
            self.assertTrue(resp.startswith(b'HTTP/1.1 502'), resp)
            w.close()

    async def test_upstream_unreachable(self):
        self.rules = ['tunnel.test']
        pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', free_port()
        r, w = await self._client()
        w.write(b'CONNECT tunnel.test:443 HTTP/1.1\r\n\r\n')
        await w.drain()
        resp = await asyncio.wait_for(r.read(), 5)
        self.assertTrue(resp.startswith(b'HTTP/1.1 502'), resp)
        w.close()


class ServeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_bind_failure_never_reports_ready(self):
        blocker = await asyncio.start_server(lambda r, w: None, '127.0.0.1', 0)
        port = blocker.sockets[0].getsockname()[1]
        called = []
        try:
            with self.assertRaises(OSError):
                await pc.serve(port=port, on_ready=called.append, quiet=True)
            self.assertEqual(called, [])
        finally:
            blocker.close(); await blocker.wait_closed()

    async def test_connect_timeout_helper(self):
        async def hang(*a, **k):
            await asyncio.sleep(10)
        with GlobalsGuard():
            pc.CONNECT_TIMEOUT = 0.2
            with mock.patch.object(pc.asyncio, 'open_connection', hang):
                with self.assertRaises(asyncio.TimeoutError):
                    await pc._open('192.0.2.1', 80)

    async def test_logger_is_per_instance(self):
        with GlobalsGuard():
            a_logs, b_logs = [], []
            pc.load_rules = lambda: []
            ta, pa = await start_proxy(logger=lambda *x: a_logs.append(x))
            tb, pb = await start_proxy(logger=lambda *x: b_logs.append(x))
            try:
                r, w = await asyncio.open_connection('127.0.0.1', pb)
                w.write(f'CONNECT 127.0.0.1:{free_port()} HTTP/1.1\r\n\r\n'.encode())
                await w.drain(); await asyncio.wait_for(r.read(), 5); w.close()
                self.assertEqual(a_logs, [])
                self.assertEqual(len(b_logs), 1)
            finally:
                await stop_task(ta); await stop_task(tb)


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_probe_ok_auth_and_invalid(self):
        async with FakeUpstream() as up:
            res = await pc._probe('127.0.0.1', up.port, TEST_TOKEN)
            self.assertTrue(res['ok'], res)
        async with FakeUpstream(behaviour='deny') as up:
            res = await pc._probe('127.0.0.1', up.port, TEST_TOKEN)
            self.assertEqual(res['code'], 'auth')
        res = await pc._probe('127.0.0.1', 'bad', TEST_TOKEN)
        self.assertEqual(res['code'], 'invalid')
        res = await pc._probe('127.0.0.1', free_port(), TEST_TOKEN)
        self.assertEqual(res['code'], 'unreachable')

    def test_frame_roundtrip_unchanged(self):
        key = pc._key_for(TEST_TOKEN)
        frame = pc.encrypt_frame(b'{"m":"CONNECT"}', key)
        self.assertEqual(pc.decrypt_frame(frame, key), b'{"m":"CONNECT"}')
        self.assertIsNone(pc.decrypt_frame(frame, pc._key_for('x')))


if __name__ == '__main__':
    unittest.main()
