#!/usr/bin/env python3
"""Tkinter GUI for the traffic-forward client (Windows).

Reuses the winreg system-proxy control pattern from the evaluated proxy-route
project, but switches the OS from a full proxy to a PAC auto-config URL so that
only matched domains are routed through the local proxy.

Run:  python gui.py   (activate the venv first)
"""

import asyncio
import json
import os
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


class App:
    def __init__(self, root):
        self.root = root
        self.root.title('流量转发客户端')
        self.root.geometry('580x720')
        self.root.resizable(False, False)

        self.loop = None
        self.proxy_thread = None
        self.running = False

        self._build_ui()
        self._load_config()
        self._load_rules()
        self._log('就绪')

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
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            self.srv_host_var.set(cfg.get('server_host', pc.SERVER_HOST))
            self.srv_port_var.set(str(cfg.get('server_port', pc.SERVER_PORT)))
            self.token_var.set(cfg.get('token', pc.SECRET))
            self.mode_var.set(cfg.get('mode', 'matched') == 'all')
        except Exception:
            pass
        self._refresh_mode_note()
        self._set_rules_enabled(not self.mode_var.get())

    def _save_config(self):
        cfg = {
            'client_port': pc.CLIENT_PORT,
            'server_host': self.srv_host_var.get().strip(),
            'server_port': int(self.srv_port_var.get().strip() or pc.SERVER_PORT),
            'token': self.token_var.get(),
            'mode': 'all' if self.mode_var.get() else 'matched',
            'bypass': pc.CFG.get('bypass', ['localhost', '127.0.0.1', '::1']),
        }
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

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
            self.mode_note.config(text='规则模式：仅下方命中规则走服务端，其余直连')

    def _set_rules_enabled(self, enabled):
        state = 'normal' if enabled else 'disabled'
        self.add_btn.config(state=state)
        self.del_btn.config(state=state)
        # 用 ttk 状态标志禁用树（兼容旧 Tk，不依赖 -state/-foreground 配置项）
        self.tree.state(('disabled',) if not enabled else ('!disabled',))
        self._rules_enabled = enabled

    def _on_mode_toggle(self):
        pc.MODE = 'all' if self.mode_var.get() else 'matched'
        self._save_config()
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

    # ---------------- start / stop ----------------
    def _toggle(self):
        if self.running:
            self._stop()
        else:
            self._start()

    def _start(self):
        # apply config
        pc.SERVER_HOST = self.srv_host_var.get().strip()
        pc.SERVER_PORT = int(self.srv_port_var.get().strip() or pc.SERVER_PORT)
        pc.SECRET = self.token_var.get()
        pc.MODE = 'all' if self.mode_var.get() else 'matched'
        self._save_config()

        self.loop = asyncio.new_event_loop()
        self.proxy_thread = threading.Thread(target=self._run_loop, args=(self.loop,), daemon=True)
        self.proxy_thread.start()
        self.running = True
        self.status_label.config(text='● 运行中(检测中...)', foreground='#cc8800')
        self.start_btn.config(text='停止代理')
        self._log(f'本地代理已启动 -> {pc.SERVER_HOST}:{pc.SERVER_PORT}')
        self._log(f'模式={pc.MODE}  服务端={pc.SERVER_HOST}:{pc.SERVER_PORT}  绕过={",".join(pc.BYPASS)}')
        self._enable_pac()
        self._preflight()

    # ---------------- connection probe ----------------
    def _test_connection(self):
        host = self.srv_host_var.get().strip()
        try:
            port = int(self.srv_port_var.get().strip() or pc.SERVER_PORT)
        except ValueError:
            port = pc.SERVER_PORT
        token = self.token_var.get()
        self.conn_status.config(text='检测中...', foreground='#cc8800')
        self.test_btn.config(state='disabled', text='测试中...')
        self._log(f'测试连接 {host}:{port} ...')
        host, port, token = host, port, token  # captured for thread

        def worker():
            res = pc.test_connection(host, port, token)
            self.root.after(0, lambda: self._on_test_result(res))

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

        def worker():
            res = pc.test_connection(host, port, token)
            self.root.after(0, lambda: self._apply_preflight(res))

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

    def _run_loop(self, loop):
        pc.set_request_logger(self._safe_log_req)
        asyncio.set_event_loop(loop)
        loop.create_task(pc.serve())
        try:
            loop.run_forever()
        finally:
            # Cancel all pending tasks so they clean up before the loop is destroyed.
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    def _safe_log_req(self, tag, target):
        self.root.after(0, lambda: self._log(f'[{tag}] {target}'))

    def _stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.running = False
        self.status_label.config(text='● 已停止', foreground='gray')
        self.start_btn.config(text='启动代理')
        self._disable_pac()
        self._log('本地代理已停止')

    # ---------------- system proxy (PAC) via winreg ----------------
    def _enable_pac(self):
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, 'AutoConfigURL', 0, winreg.REG_SZ,
                              f'http://127.0.0.1:{pc.CLIENT_PORT}/proxy.pac')
            try:
                winreg.DeleteValue(key, 'ProxyServer')
            except Exception:
                pass
            winreg.CloseKey(key)
            self._notify_proxy_change()
            self.sysproxy_label.config(text='系统代理(PAC): 已开启', foreground='#22aa22')
            self._log('系统代理(PAC)已开启')
        except Exception as e:
            self._log(f'开启系统代理失败: {e}', 'ERROR')

    def _disable_pac(self):
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
                0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            try:
                winreg.DeleteValue(key, 'AutoConfigURL')
            except Exception:
                pass
            winreg.CloseKey(key)
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
        if self.running:
            self._stop()
        self.root.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.protocol('WM_DELETE_WINDOW', app.on_close)
    root.mainloop()
