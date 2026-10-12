#!/usr/bin/env python3
"""Tkinter GUI for the traffic-forward client (Windows).

Reuses the winreg system-proxy control pattern from the evaluated proxy-route
project, but switches the OS from a full proxy to a PAC auto-config URL so that
only matched domains are routed through the local proxy.

The user's original Windows proxy settings are snapshotted before the PAC URL
is installed and restored on stop/exit (a backup file allows recovery after a
crash). The PAC URL is only installed after the local listener is bound.

Run:  python gui.py   (activate the venv first)
"""

import asyncio
import json
import os
import queue
import sys
import threading
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

import proxy_client as pc

CONFIG_PATH = pc.CONFIG_PATH
RULES_PATH = pc.RULES_PATH
MAX_LOG_LINES = 1000
TRIM_LOG_TO = 500
UI_POLL_MS = 50

INTERNET_SETTINGS_KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
PROXY_VALUE_NAMES = ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')
SYSPROXY_BACKUP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sysproxy_backup.json')


# ---------------------------------------------------------------- winreg helpers
def _winreg(reg=None):
    if reg is not None:
        return reg
    import winreg  # Windows only
    return winreg


def pac_url(port=None):
    return f'http://127.0.0.1:{pc.CLIENT_PORT if port is None else port}/proxy.pac'


def snapshot_proxy_settings(reg=None):
    """Read the current per-user proxy values: {name: [value, type] | None}."""
    reg = _winreg(reg)
    snap = {}
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, reg.KEY_READ)
    try:
        for name in PROXY_VALUE_NAMES:
            try:
                value, typ = reg.QueryValueEx(key, name)
                snap[name] = [value, typ]
            except OSError:
                snap[name] = None
    finally:
        reg.CloseKey(key)
    return snap


def read_auto_config_url(reg=None):
    reg = _winreg(reg)
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, reg.KEY_READ)
    try:
        try:
            return reg.QueryValueEx(key, 'AutoConfigURL')[0]
        except OSError:
            return None
    finally:
        reg.CloseKey(key)


def apply_pac_settings(url, reg=None):
    reg = _winreg(reg)
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, reg.KEY_SET_VALUE)
    try:
        reg.SetValueEx(key, 'ProxyEnable', 0, reg.REG_DWORD, 1)
        reg.SetValueEx(key, 'AutoConfigURL', 0, reg.REG_SZ, url)
        try:
            reg.DeleteValue(key, 'ProxyServer')
        except OSError:
            pass
    finally:
        reg.CloseKey(key)


def restore_proxy_settings(snapshot, reg=None):
    """Write back exactly what snapshot_proxy_settings() captured."""
    reg = _winreg(reg)
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, reg.KEY_SET_VALUE)
    try:
        for name in PROXY_VALUE_NAMES:
            item = snapshot.get(name)
            if item is None:
                try:
                    reg.DeleteValue(key, name)
                except OSError:
                    pass
            else:
                value, typ = item
                reg.SetValueEx(key, name, 0, typ, value)
    finally:
        reg.CloseKey(key)


def save_proxy_backup(snapshot, path=None):
    path = SYSPROXY_BACKUP_PATH if path is None else path
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump({'version': 1, 'pac_url': pac_url(), 'settings': snapshot}, f, ensure_ascii=False)
    os.replace(tmp, path)


def load_proxy_backup(path=None):
    path = SYSPROXY_BACKUP_PATH if path is None else path
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get('settings'), dict):
            return data
    except Exception:
        pass
    return None


def clear_proxy_backup(path=None):
    path = SYSPROXY_BACKUP_PATH if path is None else path
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------- proxy runner
class ProxyRunner:
    """Runs ``pc.serve()`` on a private event loop in a daemon thread.

    * ``on_ready(port)`` fires only after the listener is bound.
    * ``on_error(exc)`` fires if binding/serving fails.
    * ``on_stopped()`` fires once the loop is fully closed.
    * ``prev`` (an older runner) is joined first, so a quick stop→start never
      races the old instance for the port.
    Callbacks run on the runner thread; the GUI marshals them to Tk itself.
    """

    def __init__(self, port, on_ready=None, on_error=None, on_stopped=None,
                 logger=None, prev=None, host='127.0.0.1', join_timeout=5.0):
        self.host = host
        self.port = port
        self.on_ready = on_ready
        self.on_error = on_error
        self.on_stopped = on_stopped
        self.logger = logger
        self.prev = prev
        self.join_timeout = join_timeout
        self.bound_port = None
        self._lock = threading.Lock()
        self._stop_requested = False
        self._loop = None
        self._task = None
        self.thread = threading.Thread(target=self._run, name='z-proxy-loop', daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        """Thread-safe and idempotent."""
        with self._lock:
            self._stop_requested = True
            loop, task = self._loop, self._task
        if loop is not None and task is not None:
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass  # loop already closed

    def join(self, timeout=None):
        if self.thread.is_alive():
            self.thread.join(timeout)
        return not self.thread.is_alive()

    def is_alive(self):
        return self.thread.is_alive()

    @staticmethod
    def _call(fn, *args):
        if fn is not None:
            try:
                fn(*args)
            except Exception:
                pass

    def _ready(self, port):
        self.bound_port = port
        self._call(self.on_ready, port)

    def _run(self):
        prev = self.prev
        self.prev = None
        if prev is not None:
            prev.stop()
            prev.join(self.join_timeout)
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            with self._lock:
                if self._stop_requested:
                    return
                self._task = loop.create_task(pc.serve(
                    host=self.host, port=self.port, on_ready=self._ready,
                    logger=self.logger, quiet=True))
                self._loop = loop
            try:
                loop.run_until_complete(self._task)
            except asyncio.CancelledError:
                pass
            except BaseException as e:  # bind failure etc.
                self._call(self.on_error, e)
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            with self._lock:
                self._loop = None
            loop.close()
            asyncio.set_event_loop(None)
            self._call(self.on_stopped)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title('流量转发客户端')
        self.root.geometry('580x720')
        self.root.resizable(False, False)

        self.loop = None            # kept for compatibility (loop lives in ProxyRunner)
        self.proxy_thread = None
        self.runner = None
        self.running = False
        self._gen = 0               # bumps on every start/stop; stale callbacks are dropped
        self._ui_queue = queue.Queue()
        self._closed = False
        self._pac_enabled = False
        self._proxy_snapshot = None

        self._build_ui()
        self._load_config()
        self._load_rules()
        for w in pc.CONFIG_WARNINGS:
            self._log(f'配置警告: {w}', 'WARN')
        self._recover_stale_proxy_backup()
        self._log('就绪')
        self._pump_after = self.root.after(UI_POLL_MS, self._pump_ui)

    # ---------------- UI ----------------
    def _build_ui(self):
        # 状态区
        status_frame = ttk.LabelFrame(self.root, text='代理状态', padding=10)
        status_frame.pack(fill='x', padx=12, pady=(12, 6))
        row = ttk.Frame(status_frame)
        row.pack(fill='x')
        self.status_label = ttk.Label(row, text='● 已停止', foreground='gray', font=('', 11, 'bold'))
        self.status_label.pack(side='left')
        self.start_btn = ttk.Button(row, text='启动代理', command=self._toggle)
        self.start_btn.pack(side='right')

        info = ttk.Frame(status_frame)
        info.pack(fill='x', pady=(6, 0))
        ttk.Label(info, text=f'本地代理: 127.0.0.1:{pc.CLIENT_PORT}  |  PAC: http://127.0.0.1:{pc.CLIENT_PORT}/proxy.pac',
                  foreground='#666').pack(side='left')
        self.sysproxy_label = ttk.Label(status_frame, text='系统代理(PAC): 未开启', foreground='gray')
        self.sysproxy_label.pack(anchor='w', pady=(4, 0))

        # 服务端配置区
        srv_frame = ttk.LabelFrame(self.root, text='服务端配置', padding=10)
        srv_frame.pack(fill='x', padx=12, pady=6)
        srv_frame.columnconfigure(1, weight=1)

        ttk.Label(srv_frame, text='地址:').grid(row=0, column=0, sticky='w', padx=(0, 4))
        self.srv_host_var = tk.StringVar(value=pc.SERVER_HOST)
        ttk.Entry(srv_frame, textvariable=self.srv_host_var, width=24).grid(row=0, column=1, sticky='ew', padx=(0, 16))
        ttk.Label(srv_frame, text='端口:').grid(row=0, column=2, sticky='w', padx=(0, 4))
        self.srv_port_var = tk.StringVar(value=str(pc.SERVER_PORT))
        ttk.Entry(srv_frame, textvariable=self.srv_port_var, width=10).grid(row=0, column=3, sticky='w', padx=(0, 6))

        ttk.Label(srv_frame, text='Key:').grid(row=1, column=0, sticky='w', padx=(0, 4), pady=(6, 0))
        self.token_var = tk.StringVar(value=pc.SECRET)
        ttk.Entry(srv_frame, textvariable=self.token_var, width=24, show='*').grid(row=1, column=1, sticky='ew', padx=(0, 16), pady=(6, 0))
        self.test_btn = ttk.Button(srv_frame, text='测试连接', command=self._test_connection)
        self.test_btn.grid(row=1, column=2, columnspan=2, sticky='e', pady=(6, 0))

        self.conn_status = ttk.Label(srv_frame, text='', foreground='#666')
        self.conn_status.grid(row=2, column=0, columnspan=4, sticky='w', pady=(6, 0))

        # 域名规则区
        rule_frame = ttk.LabelFrame(self.root, text='域名规则（命中 → 走服务端）', padding=10)
        rule_frame.pack(fill='both', expand=True, padx=12, pady=6)
        self.mode_var = tk.BooleanVar(value=(pc.MODE == 'all'))
        ttk.Checkbutton(rule_frame, text='代理全部流量（除 localhost/内网/自定义绕过列表外，所有流量走服务端）',
                        variable=self.mode_var, command=self._on_mode_toggle).pack(anchor='w', pady=(0, 4))
        self.mode_note = ttk.Label(rule_frame, text='', foreground='#888')
        self.mode_note.pack(anchor='w', pady=(0, 6))
        self.tree = ttk.Treeview(rule_frame, columns=('domain',), show='headings', height=6)
        self.tree.column('domain', width=380, anchor='w')
        self.tree.heading('domain', text='域名')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<Double-1>', self._on_tree_double_click)
        top = ttk.Frame(rule_frame)
        top.pack(fill='x', pady=(8, 0))
        self.del_btn = ttk.Button(top, text='删除选中', command=self._del_rule)
        self.del_btn.pack(side='right')
        self.add_btn = ttk.Button(top, text='添加', command=self._add_rule)
        self.add_btn.pack(side='right', padx=(0, 4))

        # 日志区
        log_frame = ttk.LabelFrame(self.root, text='运行日志', padding=6)
        log_frame.pack(fill='both', expand=True, padx=12, pady=(0, 12))
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=10, font=('Consolas', 9),
            state='disabled', bg='#1e1e1e', fg='#d4d4d4', insertbackground='white')
        self.log_text.pack(fill='both', expand=True)

    # ---------------- config / rules ----------------
    def _load_config(self):
        raw = None
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                raw = json.load(f)
        except FileNotFoundError:
            pass
        except Exception as e:
            self._log(f'读取配置失败（{type(e).__name__}），使用当前默认值', 'WARN')
        if raw is not None:
            defaults = {
                'client_port': pc.CLIENT_PORT, 'server_host': pc.SERVER_HOST,
                'server_port': pc.SERVER_PORT, 'token': pc.SECRET,
                'mode': pc.MODE, 'bypass': list(pc.BYPASS),
            }
            cfg, warnings = pc.normalize_config(raw, defaults)
            for w in warnings:
                self._log(f'配置警告: {w}', 'WARN')
            self.srv_host_var.set(cfg['server_host'])
            self.srv_port_var.set(str(cfg['server_port']))
            self.token_var.set(cfg['token'])
            self.mode_var.set(cfg['mode'] == 'all')
        self._refresh_mode_note()
        self._set_rules_enabled(not self.mode_var.get())

    def _read_form(self):
        """Validate the server form. Returns (host, port, token) or raises ValueError."""
        host = self.srv_host_var.get().strip()
        if not host or any(c.isspace() for c in host):
            raise ValueError('服务端地址不能为空且不能包含空白字符')
        port_s = self.srv_port_var.get().strip()
        port = pc.validate_port(port_s if port_s else pc.SERVER_PORT, '服务端端口')
        return host, port, self.token_var.get()

    def _save_config(self):
        host, port, token = self._read_form()   # raises ValueError on bad input
        cfg = {
            'client_port': pc.CLIENT_PORT,
            'server_host': host,
            'server_port': port,
            'token': token,
            'mode': 'all' if self.mode_var.get() else 'matched',
            'bypass': list(pc.BYPASS),
        }
        tmp = CONFIG_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_PATH)

    def _load_rules(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in pc.load_rules():
            self.tree.insert('', 'end', values=(r,))

    def _save_rules(self):
        rules = [self.tree.item(i, 'values')[0] for i in self.tree.get_children()]
        with open(RULES_PATH, 'w', encoding='utf-8') as f:
            json.dump({'rules': rules}, f, ensure_ascii=False, indent=2)

    def _refresh_mode_note(self):
        if self.mode_var.get():
            self.mode_note.config(text='全部模式：下方规则列表不生效，仅 localhost/内网/自定义绕过列表直连')
        else:
            self.mode_note.config(text='规则模式：仅下方命中规则走服务端，其余直连（绕过列表/内网始终优先直连）')

    def _set_rules_enabled(self, enabled):
        state = 'normal' if enabled else 'disabled'
        self.add_btn.config(state=state)
        self.del_btn.config(state=state)
        # 用 ttk 状态标志禁用树（兼容旧 Tk，不依赖 -state/-foreground 配置项）
        self.tree.state(('disabled',) if not enabled else ('!disabled',))
        self._rules_enabled = enabled

    def _on_mode_toggle(self):
        pc.MODE = 'all' if self.mode_var.get() else 'matched'
        try:
            self._save_config()
        except (ValueError, OSError) as e:
            self._log(f'保存配置失败: {e}', 'ERROR')
        self._refresh_mode_note()
        self._set_rules_enabled(not self.mode_var.get())
        self._log(f'代理模式切换为: {"全部流量" if self.mode_var.get() else "仅命中规则"}')


    # ---------------- rule editing ----------------
    def _add_rule(self):
        win = tk.Toplevel(self.root)
        win.title('添加域名规则')
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        frm = ttk.Frame(win, padding=12)
        frm.pack(fill='both', expand=True)
        ttk.Label(frm, text='域名 (例如 huggingface.co 或 *.huggingface.co):').pack(anchor='w')
        var = tk.StringVar()
        entry = ttk.Entry(frm, textvariable=var, width=36)
        entry.pack(fill='x', pady=6)

        def do_add():
            v = var.get().strip()
            if not v:
                messagebox.showwarning('提示', '请输入域名', parent=win)
                return
            exists = any(self.tree.item(i, 'values')[0] == v for i in self.tree.get_children())
            if exists:
                messagebox.showwarning('提示', f'域名 {v} 已存在', parent=win)
                return
            self.tree.insert('', 'end', values=(v,))
            self._save_rules()
            self._log(f'添加规则: {v}')
            win.destroy()

        btns = ttk.Frame(frm)
        btns.pack(pady=(10, 0))
        ttk.Button(btns, text='确定', width=8, command=do_add).pack(side='left', padx=6)
        ttk.Button(btns, text='取消', width=8, command=win.destroy).pack(side='left', padx=6)
        entry.focus_set()
        win.bind('<Return>', lambda e: do_add())
        win.bind('<Escape>', lambda e: win.destroy())
        # 居中在主窗口
        win.update_idletasks()
        w, h = 380, 130
        px = self.root.winfo_rootx() + (self.root.winfo_width() - w) // 2
        py = self.root.winfo_rooty() + (self.root.winfo_height() - h) // 2
        win.geometry(f'{w}x{h}+{max(px, 0)}+{max(py, 0)}')

    def _del_rule(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('提示', '请先选中要删除的规则')
            return
        for item in sel:
            self._log(f'删除规则: {self.tree.item(item, "values")[0]}')
            self.tree.delete(item)
        self._save_rules()

    def _on_tree_double_click(self, event):
        if not getattr(self, '_rules_enabled', True):
            return
        region = self.tree.identify('region', event.x, event.y)
        if region != 'cell':
            return
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not item:
            return
        x, y, w, h = self.tree.bbox(item, col)
        entry = ttk.Entry(self.tree)
        entry.place(x=x, y=y, width=w, height=h)
        entry.insert(0, self.tree.item(item, 'values')[0])
        entry.focus_set()
        entry.select_range(0, 'end')

        def commit(e=None):
            new = entry.get().strip()
            entry.destroy()
            if new and new != self.tree.item(item, 'values')[0]:
                self.tree.item(item, values=(new,))
                self._save_rules()
                self._log(f'更新规则: {new}')

        entry.bind('<Return>', commit)
        entry.bind('<Escape>', lambda e: entry.destroy())
        entry.bind('<FocusOut>', commit)

    # ---------------- thread → Tk marshalling ----------------
    def _post(self, gen, fn):
        """Queue fn to run on the Tk thread. gen=None → always run;
        otherwise it is dropped if a newer start/stop happened meanwhile."""
        self._ui_queue.put((gen, fn))

    def _pump_ui(self):
        if self._closed:
            return
        try:
            while True:
                gen, fn = self._ui_queue.get_nowait()
                if gen is not None and gen != self._gen:
                    continue  # stale callback from an old proxy instance / probe
                try:
                    fn()
                except Exception as e:
                    self._log(f'界面回调出错: {e}', 'ERROR')
        except queue.Empty:
            pass
        if not self._closed:
            self._pump_after = self.root.after(UI_POLL_MS, self._pump_ui)

    # ---------------- start / stop ----------------
    def _toggle(self):
        if self.running:
            self._stop()
        else:
            self._start()

    def _start(self):
        if self.running:
            return
        try:
            host, port, token = self._read_form()
        except ValueError as e:
            messagebox.showerror('配置错误', str(e))
            self._log(f'启动失败: {e}', 'ERROR')
            return
        # apply config
        pc.SERVER_HOST = host
        pc.SERVER_PORT = port
        pc.SECRET = token
        pc.MODE = 'all' if self.mode_var.get() else 'matched'
        try:
            self._save_config()
        except (ValueError, OSError) as e:
            self._log(f'保存配置失败: {e}', 'ERROR')
        if pc.is_insecure_token(token):
            self._log('当前使用空 Key 或默认开发 Key，生产环境请配置与服务端一致的强随机 Key', 'WARN')

        self._gen += 1
        gen = self._gen
        prev = self.runner
        self.runner = ProxyRunner(
            port=pc.CLIENT_PORT,
            on_ready=lambda p: self._post(gen, lambda: self._on_listen_ready(gen, p)),
            on_error=lambda e: self._post(gen, lambda: self._on_listen_failed(gen, e)),
            logger=lambda tag, t: self._post(gen, lambda: self._log(f'[{tag}] {t}')),
            prev=prev,
        )
        self.proxy_thread = self.runner.thread
        self.running = True
        self.status_label.config(text='● 启动中...', foreground='#cc8800')
        self.start_btn.config(text='停止代理')
        self._log(f'正在启动本地代理 127.0.0.1:{pc.CLIENT_PORT} -> {pc.SERVER_HOST}:{pc.SERVER_PORT}')
        self._log(f'模式={pc.MODE}  服务端={pc.SERVER_HOST}:{pc.SERVER_PORT}  绕过={",".join(pc.BYPASS)}')
        self.runner.start()

    def _on_listen_ready(self, gen, port):
        if not self.running or gen != self._gen:
            return
        self.status_label.config(text='● 运行中(检测中...)', foreground='#cc8800')
        self._log(f'本地代理已监听 127.0.0.1:{port}')
        self._enable_pac()
        self._preflight()

    def _on_listen_failed(self, gen, exc):
        if gen != self._gen:
            return
        self.running = False
        self.status_label.config(text='● 启动失败', foreground='#cc0000')
        self.start_btn.config(text='启动代理')
        self._log(f'本地代理监听 127.0.0.1:{pc.CLIENT_PORT} 失败（端口被占用？）: {exc}', 'ERROR')
        if self._pac_enabled:
            self._disable_pac()

    # ---------------- connection probe ----------------
    def _test_connection(self):
        host = self.srv_host_var.get().strip()
        try:
            port = pc.validate_port(self.srv_port_var.get().strip() or pc.SERVER_PORT, '服务端端口')
        except ValueError as e:
            self.conn_status.config(text=str(e), foreground='#cc0000')
            self._log(str(e), 'ERROR')
            return
        token = self.token_var.get()
        self.conn_status.config(text='检测中...', foreground='#cc8800')
        self.test_btn.config(state='disabled', text='测试中...')
        self._log(f'测试连接 {host}:{port} ...')

        def worker():
            try:
                res = pc.test_connection(host, port, token)
            except Exception as e:
                res = {'code': 'other', 'ok': False, 'msg': f'测试连接出错：{e}'}
            self._post(None, lambda: self._on_test_result(res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_test_result(self, res):
        self.test_btn.config(state='normal', text='测试连接')
        if res['ok']:
            self.conn_status.config(text=res['msg'], foreground='#22aa22')
            self._log(res['msg'], 'OK')
        else:
            self.conn_status.config(text=res['msg'], foreground='#cc0000')
            self._log(res['msg'], 'ERROR')

    def _preflight(self):
        """Probe the upstream server in the background right after starting."""
        host, port, token = pc.SERVER_HOST, pc.SERVER_PORT, pc.SECRET
        gen = self._gen

        def worker():
            try:
                res = pc.test_connection(host, port, token)
            except Exception as e:
                res = {'code': 'other', 'ok': False, 'msg': f'测试连接出错：{e}'}
            self._post(gen, lambda: self._apply_preflight(res))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_preflight(self, res):
        if not self.running:
            return
        if res['ok']:
            self.status_label.config(text='● 运行中', foreground='#22aa22')
            self.conn_status.config(text=res['msg'], foreground='#22aa22')
        else:
            self.status_label.config(text='● 运行中(服务端不可达)', foreground='#cc8800')
            self.conn_status.config(text=res['msg'], foreground='#cc0000')
            self._log(res['msg'], 'ERROR')

    def _safe_log_req(self, tag, target):
        # Kept for compatibility; thread-safe via the UI queue.
        self._post(None, lambda: self._log(f'[{tag}] {target}'))

    def _stop(self):
        self._gen += 1   # invalidate every pending callback of the old instance
        if self.runner is not None:
            self.runner.stop()
        self.running = False
        self.status_label.config(text='● 已停止', foreground='gray')
        self.start_btn.config(text='启动代理')
        if self._pac_enabled:
            self._disable_pac()
        self._log('本地代理已停止')

    # ---------------- system proxy (PAC) via winreg ----------------
    def _recover_stale_proxy_backup(self):
        """After a crash, put back the proxy settings saved by a previous run."""
        data = load_proxy_backup()
        if data is None:
            return
        try:
            current = read_auto_config_url()
            if current == data.get('pac_url', pac_url()):
                restore_proxy_settings(data['settings'])
                self._notify_proxy_change()
                self._log('检测到上次异常退出，已恢复启动前的系统代理设置', 'WARN')
            else:
                self._log('发现旧的系统代理备份，但当前设置已被修改，未覆盖', 'WARN')
            clear_proxy_backup()
        except Exception as e:
            self._log(f'恢复上次系统代理设置失败: {e}', 'ERROR')

    def _enable_pac(self):
        try:
            if self._proxy_snapshot is None:
                self._proxy_snapshot = snapshot_proxy_settings()
                try:
                    save_proxy_backup(self._proxy_snapshot)
                except OSError as e:
                    self._log(f'写入系统代理备份失败（不影响运行）: {e}', 'WARN')
            apply_pac_settings(pac_url())
            self._pac_enabled = True
            self._notify_proxy_change()
            self.sysproxy_label.config(text='系统代理(PAC): 已开启', foreground='#22aa22')
            self._log('系统代理(PAC)已开启（已保存原设置，停止时恢复）')
        except Exception as e:
            self._log(f'开启系统代理失败: {e}', 'ERROR')

    def _disable_pac(self):
        try:
            snap = self._proxy_snapshot
            if snap is not None:
                current = read_auto_config_url()
                if current == pac_url():
                    restore_proxy_settings(snap)
                    self._log('系统代理已恢复为启动前的设置')
                else:
                    self._log('系统代理已被其他程序修改，保留当前设置不覆盖', 'WARN')
            else:
                # No snapshot (should not happen) — fall back to the legacy behaviour.
                reg = _winreg()
                key = reg.OpenKey(reg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, reg.KEY_SET_VALUE)
                try:
                    reg.SetValueEx(key, 'ProxyEnable', 0, reg.REG_DWORD, 0)
                    try:
                        reg.DeleteValue(key, 'AutoConfigURL')
                    except OSError:
                        pass
                finally:
                    reg.CloseKey(key)
            self._proxy_snapshot = None
            self._pac_enabled = False
            clear_proxy_backup()
            self._notify_proxy_change()
            self.sysproxy_label.config(text='系统代理(PAC): 未开启', foreground='gray')
            self._log('系统代理(PAC)已关闭')
        except Exception as e:
            self._log(f'关闭系统代理失败: {e}', 'ERROR')

    def _notify_proxy_change(self):
        try:
            wininet = __import__('ctypes').windll.wininet
            wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        except Exception:
            pass

    # ---------------- log ----------------
    def _log(self, msg, level='INFO'):
        ts = datetime.now().strftime('%H:%M:%S')
        line = f'[{ts}] [{level}] {msg}\n'
        self.log_text.config(state='normal')
        self.log_text.insert('end', line)
        cur = int(self.log_text.index('end-1c').split('.')[0])
        if cur > MAX_LOG_LINES:
            self.log_text.delete('1.0', f'{cur - TRIM_LOG_TO}.0')
        self.log_text.see('end')
        self.log_text.config(state='disabled')

    def on_close(self):
        if self.running or self._pac_enabled:
            self._stop()
        if self.runner is not None:
            self.runner.stop()
            self.runner.join(3)
        self._closed = True
        try:
            self.root.after_cancel(self._pump_after)
        except Exception:
            pass
        self.root.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.protocol('WM_DELETE_WINDOW', app.on_close)
    root.mainloop()
