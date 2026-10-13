"""Regression tests for client/gui.py.

* ProxyRunner and the winreg helpers are tested without a display.
* App-level tests need Tk; they run under a display (e.g. ``xvfb-run``) and are
  skipped otherwise. The Windows registry is NEVER touched: a fake ``winreg``
  module is injected into sys.modules for every test.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _helpers import pc, GlobalsGuard, free_port  # noqa: E402

try:
    import gui  # noqa: E402
    import tkinter as tk
except Exception as e:  # pragma: no cover - tkinter missing
    gui = None
    _IMPORT_ERR = e


class FakeWinreg:
    """In-memory replacement for the subset of winreg used by gui.py."""
    HKEY_CURRENT_USER = 'HKCU'
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self, values=None):
        self.values = dict(values or {})
        self.lock = threading.Lock()

    def OpenKey(self, root, path, reserved, access):
        assert root == self.HKEY_CURRENT_USER and path == gui.INTERNET_SETTINGS_KEY
        return object()

    def CloseKey(self, key):
        pass

    def QueryValueEx(self, key, name):
        with self.lock:
            if name not in self.values:
                raise FileNotFoundError(name)
            return tuple(self.values[name])

    def SetValueEx(self, key, name, reserved, typ, value):
        with self.lock:
            self.values[name] = (value, typ)

    def DeleteValue(self, key, name):
        with self.lock:
            if name not in self.values:
                raise FileNotFoundError(name)
            del self.values[name]


ORIGINAL = {
    'ProxyEnable': (1, FakeWinreg.REG_DWORD),
    'ProxyServer': ('corp-proxy:3128', FakeWinreg.REG_SZ),
    'ProxyOverride': ('<local>', FakeWinreg.REG_SZ),
}


@unittest.skipIf(gui is None, 'gui import failed')
class WinregHelperTests(unittest.TestCase):
    def test_snapshot_apply_restore_roundtrip(self):
        reg = FakeWinreg(ORIGINAL)
        snap = gui.snapshot_proxy_settings(reg)
        self.assertIsNone(snap['AutoConfigURL'])
        gui.apply_pac_settings('http://127.0.0.1:1/proxy.pac', reg)
        self.assertEqual(reg.values['AutoConfigURL'][0], 'http://127.0.0.1:1/proxy.pac')
        self.assertNotIn('ProxyServer', reg.values)
        # JSON round trip (backup file) must still restore exactly.
        snap = json.loads(json.dumps(snap))
        gui.restore_proxy_settings(snap, reg)
        self.assertEqual(reg.values, ORIGINAL)

    def test_backup_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'b.json')
            gui.save_proxy_backup({'ProxyEnable': [0, 4]}, p)
            self.assertEqual(gui.load_proxy_backup(p)['settings'], {'ProxyEnable': [0, 4]})
            gui.clear_proxy_backup(p)
            self.assertIsNone(gui.load_proxy_backup(p))


@unittest.skipIf(gui is None, 'gui import failed')
class ProxyRunnerTests(unittest.TestCase):
    def setUp(self):
        self.guard = GlobalsGuard().__enter__()
        pc.load_rules = lambda: []

    def tearDown(self):
        self.guard.__exit__(None, None, None)

    def _runner(self, port, prev=None, logger=None):
        ev = {'ready': threading.Event(), 'error': [], 'stopped': threading.Event()}
        r = gui.ProxyRunner(port, on_ready=lambda p: ev['ready'].set(),
                            on_error=ev['error'].append, on_stopped=ev['stopped'].set,
                            prev=prev, logger=logger)
        return r.start(), ev

    def test_quick_restart_same_port(self):
        port = free_port()
        prev = None
        for i in range(5):
            r, ev = self._runner(port, prev=prev)
            self.assertTrue(ev['ready'].wait(5), f'iteration {i} never listened: {ev["error"]}')
            self.assertEqual(ev['error'], [])
            r.stop()            # immediately restart: the next runner joins this one
            prev = r
        self.assertTrue(prev.join(5))
        # Port is released afterwards.
        with socket.socket() as s:
            s.bind(('127.0.0.1', port))

    def test_stop_before_loop_started(self):
        r = gui.ProxyRunner(free_port())
        r.stop()
        r.start()
        self.assertTrue(r.join(5))
        self.assertIsNone(r.bound_port)

    def test_bind_failure_reports_error_not_ready(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); s.listen()
            r, ev = self._runner(s.getsockname()[1])
            self.assertTrue(ev['stopped'].wait(5))
            self.assertFalse(ev['ready'].is_set())
            self.assertEqual(len(ev['error']), 1)
            self.assertIsInstance(ev['error'][0], OSError)

    def test_old_instance_logger_not_used_by_new(self):
        port = free_port()
        old_logs, new_logs = [], []
        r1, ev1 = self._runner(port, logger=lambda *a: old_logs.append(a))
        self.assertTrue(ev1['ready'].wait(5))
        r1.stop()
        r2, ev2 = self._runner(port, prev=r1, logger=lambda *a: new_logs.append(a))
        self.assertTrue(ev2['ready'].wait(5))
        with socket.create_connection(('127.0.0.1', port), timeout=5) as c:
            c.sendall(f'CONNECT 127.0.0.1:{free_port()} HTTP/1.1\r\n\r\n'.encode())
            c.recv(100)
        r2.stop(); r2.join(5)
        self.assertEqual(old_logs, [])
        self.assertEqual(len(new_logs), 1)


def _tk_available():
    if gui is None:
        return False
    try:
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


@unittest.skipUnless(_tk_available(), 'Tk display not available (run under xvfb-run)')
class AppTests(unittest.TestCase):
    def setUp(self):
        self.guard = GlobalsGuard().__enter__()
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = FakeWinreg(ORIGINAL)
        pc.CLIENT_PORT = free_port()
        pc.SERVER_HOST, pc.SERVER_PORT = '127.0.0.1', free_port()   # unreachable upstream
        pc.load_rules = lambda: []
        cfg = os.path.join(self.tmp.name, 'config.json')
        self.patches = [
            mock.patch.dict(sys.modules, {'winreg': self.reg}),
            mock.patch.object(gui, 'CONFIG_PATH', cfg),
            mock.patch.object(gui, 'RULES_PATH', os.path.join(self.tmp.name, 'rules.json')),
            mock.patch.object(gui, 'SYSPROXY_BACKUP_PATH', os.path.join(self.tmp.name, 'bk.json')),
            mock.patch.object(gui.messagebox, 'showerror'),
        ]
        for p in self.patches:
            p.start()
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = gui.App(self.root)

    def tearDown(self):
        try:
            self.app.on_close()
        except Exception:
            pass
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()
        self.guard.__exit__(None, None, None)

    def _pump_until(self, cond, timeout=5):
        end = time.time() + timeout
        while time.time() < end:
            self.root.update()
            if cond():
                return True
            time.sleep(0.01)
        return False

    def _log_text(self):
        return self.app.log_text.get('1.0', 'end')

    def test_pac_only_after_listen_and_restored_on_stop(self):
        self.app._start()
        # Immediately after _start the listener may not be bound: PAC must not be set yet.
        self.assertNotIn('AutoConfigURL', self.reg.values)
        self.assertTrue(self._pump_until(lambda: self.app._pac_enabled))
        self.assertEqual(self.reg.values['AutoConfigURL'][0], gui.pac_url())
        self.assertTrue(os.path.exists(gui.SYSPROXY_BACKUP_PATH))
        self.app._stop()
        self.assertEqual(self.reg.values, ORIGINAL)
        self.assertFalse(os.path.exists(gui.SYSPROXY_BACKUP_PATH))

    def test_rapid_restart_no_stale_callbacks(self):
        for _ in range(4):
            self.app._start()
            self.app._stop()
        self.app._start()
        self.assertTrue(self._pump_until(lambda: self.app._pac_enabled, 10))
        # let any stale callbacks from the stopped instances drain
        self._pump_until(lambda: False, 0.5)
        self.assertTrue(self.app.running)
        self.assertEqual(self._log_text().count('本地代理已监听'), 1)
        self.app._stop()
        self.assertEqual(self.reg.values, ORIGINAL)

    def test_port_busy_never_enables_pac(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', pc.CLIENT_PORT)); s.listen()
            self.app._start()
            self.assertTrue(self._pump_until(lambda: not self.app.running))
        self.assertFalse(self.app._pac_enabled)
        self.assertEqual(self.reg.values, ORIGINAL)
        self.assertIn('失败', self._log_text())

    def test_invalid_port_blocks_start(self):
        self.app.srv_port_var.set('70000')
        self.app._start()
        self.assertFalse(self.app.running)
        gui.messagebox.showerror.assert_called()
        self.app.srv_port_var.set('8443')

    def test_mode_toggle_with_bad_port_does_not_raise(self):
        self.app.srv_port_var.set('abc')
        self.app.mode_var.set(True)
        self.app._on_mode_toggle()
        self.assertEqual(pc.MODE, 'all')
        self.assertIn('保存配置失败', self._log_text())
        self.app.srv_port_var.set('8443')

    def test_crash_backup_is_recovered_on_launch(self):
        snap = gui.snapshot_proxy_settings(self.reg)
        gui.save_proxy_backup(snap)
        gui.apply_pac_settings(gui.pac_url(), self.reg)
        root2 = tk.Tk(); root2.withdraw()
        try:
            app2 = gui.App(root2)
            self.assertEqual(self.reg.values, ORIGINAL)
            self.assertFalse(os.path.exists(gui.SYSPROXY_BACKUP_PATH))
            app2.on_close()
        finally:
            try:
                root2.destroy()
            except Exception:
                pass


if __name__ == '__main__':
    unittest.main()
