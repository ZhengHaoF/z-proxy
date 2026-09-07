# z-proxy — 多端流量转发（服务端 / 桌面客户端 / Android VPN 客户端）

私有流量转发通道：**命中规则的域名**经加密隧道发往你自己的服务端（由服务端统一 DNS 解析并连接真实目标），**其余流量本地直连**。桌面端（浏览器/系统 PAC）与 Android 端（系统 VPN）共用同一套加密帧协议与服务端，服务端零感知客户端类型。

| 子项目 | 形态 | 技术栈 |
|---|---|---|
| `server/` | 转发服务端 + 内嵌 Web 管理台（单进程双端口） | Node.js（纯内置模块 + better-sqlite3），前端 Vue3 + Naive UI |
| `client/` | 桌面客户端：本地 HTTP 代理 + PAC 自动系统代理 | Python 3（纯标准库，GUI/无头两种形态） |
| `android_client/` | Android 系统级 VPN 客户端，全 App 流量按规则分流 | Flutter / Dart 核心引擎 + Kotlin VpnService + tun2socks(JNI) |

## 架构

```
  桌面浏览器 / 系统 (PAC)
        │  命中规则 → PROXY 127.0.0.1:8787        Android 手机 App（全流量）
        │  其余     → DIRECT                        │ VpnService 建 TUN
        ▼                                           ▼  tun2socks 还原 TCP
 ┌───────────────────────────┐      ┌───────────────────────────────┐
 │ Python 客户端 (client/)    │      │ Dart 代理引擎 (android_client/) │
 │ 127.0.0.1:8787            │      │ 127.0.0.1:<SOCKS5 端口>        │
 │ · HTTP/CONNECT 入口       │      │ · SOCKS5 入口 + 规则分流        │
 │ · PAC 生成/系统代理(winreg)│      │ · 请求日志 / 连接测试           │
 └────────────┬──────────────┘      └───────────────┬───────────────┘
              │     每连接一个「加密帧」(目标域名不可见) + 后续原始字节流
              ▼                                     ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ 服务端 (server/server.js, 监听 0.0.0.0:8443)                     │
 │ · 解帧验 HMAC tag（验 tag 即验 token，两端需同一 PROXY_TOKEN）    │
 │ · 服务端做 DNS 解析 → TCP 透传（CONNECT）/ http.request（HTTP）    │
 │ · 内嵌 Web 管理台 :9090（统计 / 实时隧道 / 实时日志 / SQLite）     │
 └─────────────────────────────────┬────────────────────────────────┘
                                   ▼
                              真实目标服务器
```

> 协议要点：每条连接以「一个加密帧」开头（目标、请求头全部加密，链路上看不到任何域名），
> 之后即原始双向字节流。帧格式、算法与字段见下文「加密帧协议」。

## 目录

```
server/           Node.js 服务端（部署单元自包含：转发 + 管理台前端源码/构建产物）
client/           Python 客户端（config.json / rules.json / proxy_client.py / gui.py）
android_client/   Flutter Android 客户端（Dart 核心库 + 原生 VPN 层 + UI）
docs/plans/       各阶段实施计划（web-admin、Android 客户端）
```

## 关键设计决策

| 议题 | 决定 | 理由 |
|------|------|------|
| DNS 解析位置 | **服务端** | 客户端只传域名，服务端解析后直连，最简单；多出口 IP 自动重试 |
| HTTPS 处理 | **TCP 隧道透传**（不做 MITM） | 不碰 SNI、不装 CA、性能好 |
| 桌面分流 | **PAC 自动配置** | 仅命中规则的域名走代理，内网/局域网直连不受影响 |
| Android 分流 | 系统 VPN + tun2socks 还原 TCP | 覆盖全 App（不只是浏览器），与桌面同一套引擎与协议 |
| 鉴权 | 帧内 HMAC-SHA256 校验（token 派生密钥） | 验 tag 即验 token；无额外握手 |
| 防域名过滤 | **对称加密请求帧**（PRF 密钥流 XOR） | 链路上看不到目标域名 |
| 安全边界 | 单用户单 token | 仅自己使用；token 即全部权限 |

---

## 服务端 `server/`（Node.js）

转发面（:8443）与管理面（:9090）同进程，纯 Node 内置模块，唯一第三方依赖 `better-sqlite3`（数据存储）。管理面故障不影响转发面。

```bash
cd server
npm install        # 首次部署需要（better-sqlite3）
node server.js     # 前台运行
# 或 pm2 守护（无需额外配置文件）：
pm2 start server.js --name z-proxy && pm2 save
```

### 配置 `server/.env`

全部配置从 `.env` 读取（不设任何环境变量也可启动）。`cp .env.example .env` 后填写，`.env` 不进 git：

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | 8443 | 转发面端口 |
| `HOST` | 0.0.0.0 | 转发面监听地址 |
| `PROXY_TOKEN` | — | 转发密钥，**必须与所有客户端 token 一致**；缺失时回退 `z-proxy-dev` 并应更换 |
| `IDLE_TIMEOUT` | 0 | 空闲超时（秒），0=关闭 |
| `ADMIN_PASSWORD` | `admin`（会告警） | 管理台密码，请务必设置强密码 |
| `ADMIN_PORT` / `ADMIN_HOST` | 9090 / 0.0.0.0 | 管理台端口/地址 |

### 转发行为

- 每连接收一个加密帧：`{m:"CONNECT",t:"host:port"}`（HTTPS 隧道）或 `{m:"HTTP",r:"请求行",h:{头}}`（明文 HTTP）。
- 验签失败 → 回 `407 Proxy Authentication Required` 并断开。
- CONNECT：服务端 `dns.resolve4/6`（避免 getaddrinfo 对超大 AAAA 集合的域名挂起）→ `net.connect`，首个可用 IP 失败自动尝试下一个 → 回 ACK `{m:"Connection Established",c:200}` 后双向透传。
- HTTP：服务端用 `http.request` 转发，响应体原样回传（请求体按 `Content-Length` 计数结束；chunked 依赖 socket 关闭，属已知退化）。

### Web 管理台（:9090）

同进程托管 `web-admin/dist`（构建产物），登录后可用：

- **状态总览**：活跃/累计连接、累计/今日流量、错误数 + 流量历史曲线（1h/24h/7d，echarts）
- **实时隧道**：目标 / 出口 IP / 时长 / 收发字节，可强制断开
- **实时日志**：SSE 推送，级别过滤 / 清屏 / 暂停
- **配置查看**：只读 key-value；登录 token 内存态 24h 过期 + 登录限速

历史会话、流量采样（30s/条）、日志均持久化在 `server/data/z-proxy.db`（better-sqlite3，WAL，自动容量清理）。`web-admin/` 前端改动后需重新构建（`npm install && npm run build`，产物到 `web-admin/dist`）。

> ⚠️ 管理面默认监听 0.0.0.0，公网可直接访问。务必设置强 `ADMIN_PASSWORD`，并建议在云防火墙对 9090 做 IP 白名单。

---

## 桌面客户端 `client/`（Python）

仅标准库（`asyncio` / `tkinter` / `winreg`），无需 pip 安装任何包。启动后自动把系统代理设为本地 PAC（`AutoConfigURL`），停止时自动清除，避免断网。

```bash
cd client
python gui.py                 # 图形界面（需带 tkinter 的 Python）
# 或纯命令行（无 GUI 也能跑代理）：
python proxy_client.py
```

GUI 提供：服务端配置编辑、**测试连接**（区分 可达/鉴权错 407/超时/不可达）、模式切换（按规则匹配 / 代理全部流量）、规则增删、运行日志、一键开关。

### 配置 `client/config.json`

> 真实配置（含 token）存 `client/config.json`，已被 .gitignore 排除、**不要提交**；
> 仓库内提供脱敏模板 `client/config.example.json`，复制改名后填写即可。

```json
{
  "client_port": 8787,
  "server_host": "1.2.3.4",
  "server_port": 8443,
  "token": "与服务端 PROXY_TOKEN 一致",
  "mode": "matched",
  "bypass": ["localhost", "127.0.0.1", "::1"]
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `client_port` | 8787 | 本地代理端口（默认 8787 是因为本机 Mihomo 已占用 7890/7892） |
| `server_host` / `server_port` | 127.0.0.1:8443 | 服务端地址 |
| `token` | — | 必须与服务端 `PROXY_TOKEN` 一致 |
| `mode` | `matched` | `matched`：仅规则命中走服务端；`all`：除 bypass/内网/私网外全部走服务端（此时规则列表不生效） |
| `bypass` | localhost/127.0.0.1/::1 | 永远直连的名单（`all` 模式下尤其重要） |

可用环境变量覆盖：`CLIENT_PORT` / `SERVER_PORT` / `SERVER_HOST` / `token`。

### 规则 `client/rules.json`

```json
{ "rules": ["github.com", "*.githubusercontent.com", "huggingface.co"] }
```

匹配语义（大小写不敏感）：`example.com` 匹配自身及 `*.example.com` 子域，但不匹配 `anexample.com`；`*.example.com` / `.example.com` 显式支持子域。GUI 中增删改，保存即生效。

### PAC 行为

- `matched`：PAC 只把命中规则的域名指到 `PROXY 127.0.0.1:8787`，其余 `DIRECT`。
- `all`：除 localhost / 内网私网段 / 自定义 bypass 外全部走代理。
- PAC 地址 `http://127.0.0.1:<client_port>/proxy.pac`，由 `rules.json` + 模式动态生成。

---

## Android 客户端 `android_client/`（Flutter）

系统级 VPN 形态：手机**所有 App** 的流量进 TUN，按规则分流——命中域名经加密隧道到服务端，其余本机直连。服务端与协议零改动（帧协议兼容由 Python ↔ Dart 黄金向量测试保证）。

### 架构（三层）

| 层 | 位置 | 职责 |
|---|---|---|
| 纯 Dart 核心库 | `lib/core/` | 加密帧、规则引擎、HTTP/CONNECT 代理、SOCKS5 入口 + UDP 中继、上游探测——与 `client/proxy_client.py` 逐函数语义对齐，可单测（`test/` 有与 Python 互通的黄金向量 `vectors/frames.json`） |
| Android 原生层 | `android/.../service/` | `VpnService` 建 TUN 并 `detachFd`；**同进程** tun2socks 引擎（`libtun2socks.so`，xjasonlyu/tun2socks v2.7.0 编译的 JNI 封装，`--tun-fd` 传 fd，避免 Android 子进程无法继承 fd）；网络切换自动重建；MethodChannel/EventChannel 桥 |
| Flutter UI | `lib/pages/` | 首页（开关、运行时长、服务端/SOCKS5 连接测试）、规则（增删改、模式切换）、日志（实时流）、设置 |

关键细节：VPN 构建时 `addDisallowedApplication(自身包名)` 防环路；SOCKS5 **UDP ASSOCIATE** 由本进程 RawDatagramSocket 直连转发（DNS 等 UDP 在 VPN 内可用，但**不进加密隧道**，属已知限制）；UI 里模式标签为「按规则匹配 / 代理全部流量」。

### 配置与构建

配置字段与桌面端一致（`client_port/server_host/server_port/token/mode/bypass`），另加 Android 专用的 `dns_server`（注入 VPN 的 DNS，默认阿里 `223.5.5.5`，保证 TUN 内 DNS 可达真实网络）。设置页可编辑并本地持久化，保存后提示重启代理。

```bash
cd android_client
flutter pub get
flutter test            # 含 Python 互通黄金向量测试
flutter build apk --release
```

### Android 已知限制

- **单进程模型**：应用进程被杀 → VPN 随之断开（前台服务 + 电池优化豁免可缓解）。
- UDP/QUIC（HTTP/3）不加密转发：浏览器会回退 TCP，实际影响小；DNS 经 UDP 中继本机直连。
- 纯 TCP 透传，不做 SNI 级智能分流（分流粒度 = 规则域名）。

---

## 加密帧协议

```
magic(0x5A) | len(4B BE) | nonce(16B) | ciphertext(len) | tag(32B)

enc_key   = HMAC-SHA256(token, "z-proxy:enc:v1")
密钥流     = HMAC-SHA256(enc_key, nonce || counter32)   // CTR 式 PRF
ciphertext = payload XOR 密钥流
tag        = HMAC-SHA256(enc_key, nonce || ciphertext)  // 服务端验 tag 即验 token
```

帧后紧跟原始字节流（CONNECT 双向透传 / HTTP 请求体）。载荷为 JSON：

| 消息 | 字段 | 说明 |
|---|---|---|
| CONNECT | `{m:"CONNECT", t:"host:port"}` | HTTPS 隧道；服务端回 ACK 帧 `{m:…, c:200\|407\|400\|502}` |
| HTTP | `{m:"HTTP", r:"GET http://… HTTP/1.1", h:{头}}` | 明文 HTTP；响应不回帧，直接字节流 |
| （可选） | `c: "client_id"` | V3 客户端标识，服务端记入统计；旧客户端不带则为 null，向后兼容 |

参考实现：Python `client/proxy_client.py`、Dart `android_client/lib/core/crypto_frame.dart`、服务端 `server/server.js` 顶部注释。

---

## 快速验证（本地回环，无需外网）

1. 服务端：`cd server && node server.js`（管理台 9090 一并启动）。
2. 桌面端：`cd client && python gui.py` → 填 `127.0.0.1:8443` 与 token → 「测试连接」通过 → 启动代理（自动设置系统 PAC）。
3. `curl -x http://127.0.0.1:8787 https://example.com` 命中规则走服务端出口；其余域名直连。
4. 浏览器开 `http://127.0.0.1:9090` 登录管理台查看隧道与日志。

Android 端需真机/模拟器，配置同上的服务端地址与 token，授权 VPN 后开关即可；可用「SOCKS5 代理测试」排查隧道连通性。

## 安全注意事项

- **token 即全部权限**：任何持有 token 者都能以你的服务端出口转发流量。桌面端 `client/config.json` 与本仓库 `server/.env.example` 里的值都应视为机密——`client/config.json` 含真实 token，**不要提交进 git**（建议改为 `config.example.json` 模板 + gitignore 真实配置）。
- 服务端不要依赖弱默认：务必设置强 `PROXY_TOKEN`（勿用 `z-proxy-dev`）与强 `ADMIN_PASSWORD`（勿用 `admin`）。
- 管理面暴露公网时建议在云防火墙对 `ADMIN_PORT` 做 IP 白名单。

## 已知限制（汇总）

- 不拦截 SNI、不做基于域名之外的智能分流；纯 TCP 透传（无 MITM，不装 CA）。
- HTTP/3（QUIC/UDP）不转发：桌面端回落 TCP CONNECT；Android 端 UDP 仅本机直连（含 DNS）。
- Windows 桌面 GUI 依赖带 tkinter 的 Python。
- DNS over HTTPS（DoH）未处理：Windows/Android 默认 DoH 直连 DNS，不影响本方案。

## 相关文档

- `docs/plans/2026-08-21-android-flutter-client.md` — Android 客户端实施计划（架构选型与里程碑）
- `docs/plans/2026-08-24-web-admin-management.md` — Web 管理台实施计划（DB 设计 / REST / SSE）
