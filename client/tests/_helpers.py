"""Shared helpers for the client regression tests (stdlib only)."""

import asyncio
import json
import os
import socket
import sys

CLIENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CLIENT_DIR not in sys.path:
    sys.path.insert(0, CLIENT_DIR)

import proxy_client as pc  # noqa: E402

_GLOBALS = ('CLIENT_PORT', 'SERVER_HOST', 'SERVER_PORT', 'SECRET', 'MODE', 'BYPASS',
            'CONNECT_TIMEOUT', 'HEADER_TIMEOUT', 'HANDSHAKE_TIMEOUT', 'PROBE_TIMEOUT',
            'request_logger', 'load_rules')

TEST_TOKEN = 'unit-test-token'   # test-only value, not a real credential


class GlobalsGuard:
    """Snapshot/restore mutable proxy_client module globals around a test."""

    def __enter__(self):
        self._saved = {k: getattr(pc, k) for k in _GLOBALS}
        self._saved['BYPASS'] = list(pc.BYPASS)
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            setattr(pc, k, v)
        return False


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


async def start_proxy(**kw):
    """Start pc.serve() on an ephemeral loopback port; returns (task, port)."""
    ready = asyncio.get_running_loop().create_future()

    def on_ready(port):
        if not ready.done():
            ready.set_result(port)

    task = asyncio.create_task(pc.serve(port=0, on_ready=on_ready, quiet=True, **kw))
    done, _ = await asyncio.wait({task, ready}, timeout=5, return_when=asyncio.FIRST_COMPLETED)
    if ready not in done:
        if task in done:
            task.result()  # re-raise bind error
        raise TimeoutError('proxy did not become ready')
    return task, ready.result()


async def stop_task(task):
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


async def read_http_head(reader, timeout=5):
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = await asyncio.wait_for(reader.read(4096), timeout)
        if not chunk:
            break
        buf += chunk
    return buf


class FakeUpstream:
    """Minimal stand-in for server.js speaking the encrypted-frame protocol.

    behaviour: 'ok' (ACK 200 then echo), 'deny' (ACK 407), 'silent' (never ACK),
    'http' (record the HTTP frame and answer a canned response).
    """

    def __init__(self, token=TEST_TOKEN, behaviour='ok'):
        self.key = pc._key_for(token)
        self.behaviour = behaviour
        self.frames = []
        self.early = []
        self.server = None
        self.port = None

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            frame = await pc.read_frame(reader, self.key)
            if frame is None:
                writer.close(); return
            info = json.loads(frame)
            self.frames.append(info)
            if self.behaviour == 'silent':
                while await reader.read(65536):
                    pass   # never ACK; just wait for the client to give up
                writer.close(); return
            if self.behaviour == 'deny':
                writer.write(pc.encrypt_frame(json.dumps({'c': 407, 'm': 'Auth\r\nX-Evil: 1'}).encode(), self.key))
                await writer.drain(); writer.close(); return
            if info.get('m') == 'HTTP':
                body = b'upstream-ok'
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
                await writer.drain(); writer.close(); return
            writer.write(pc.encrypt_frame(json.dumps({'c': 200, 'm': 'Connection Established'}).encode(), self.key))
            await writer.drain()
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                self.early.append(data)
                writer.write(data)
                await writer.drain()
            writer.close()
        except (ConnectionError, asyncio.CancelledError):
            pass
