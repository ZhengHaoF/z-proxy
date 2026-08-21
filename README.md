# 流量转发项目（客户端 / 服务端）

基于 `proxy-route` 评估后重新设计的「客户端 + 服务端」转发方案。
服务端集中转发流量，客户端把**指定域名**的流量通过隧道发往服务端；其余流量直连。

## 架构

```
 浏览器 / 系统 (PAC)
        │  命中规则的域名 → PROXY 127.0.0.1:8787
        │  其余域名 → DIRECT
        ▼
 ┌─────────────────────┐        加密帧(目标不可见)        ┌─────────────────────┐
 │  客户端 (本地)        │ ───────────────────────────► │  服务端 (远程)        │
 │  Python asyncio 代理  │   帧内 HMAC 校验即鉴权          │  Node.js 22 转发代理   │
 │  127.0.0.1:8787      │                               │  监听 0.0.0.0:8443    │
 │  - 规则引擎          │                               │  - 服务端做 DNS 解析   │
 │  - PAC 文件          │                               │  - TCP 透传(不做MITM)  │
 │  - 系统代理(winreg)   │                               │  - 双向 pipe 转发      │
 └─────────────────────┘                               └─────────────────────┘
                                                              │
                                                              ▼
                                                        真实目标服务器
```

> 加密帧协议：客户端→服务端的每条连接以「一个加密帧」开始（目标域名、请求头全部加密，
> 链路上看不到任何域名，可绕过本地按关键词过滤的 DPI）。帧格式与算法见 `server/server.js`
> 顶部注释；密钥由共享 token 派生（`enc_key = HMAC-SHA256(token, "zhihu-proxy:enc:v1")`）。

## 关键设计决策（来自前期评估）

| 议题 | 决定 | 理由 |
|------|------|------|
| DNS 在哪解析 | **服务端** | 客户端只传域名，服务端 `dns.lookup` 后直连，最简单 |
| HTTPS 处理 | **TCP 隧道透传**（不做 MITM） | 不碰 SNI、不装 CA 证书、性能更好 |
| 非 HTTP 协议 | 不管，只覆盖浏览器 | 仅处理 HTTP/HTTPS（设置系统代理后浏览器走 TCP CONNECT） |
| 服务端可达性 | 公网 IP 直连 | 服务端监听端口，客户端直连 |
| 系统代理 | **PAC 自动配置** | 只有命中规则的域名才走代理，内网/局域网直连不受影响 |
| 鉴权 | 加密帧内 HMAC-SHA256 校验（共享密钥派生） | 验帧 tag 即验 token；防误用 |
| 防域名过滤 | **对称加密请求帧**（PRF 密钥流 XOR） | 链路上看不到目标域名，绕过本地关键词 DPI |
| 安全边界 | 单用户，默认即可 | 仅自己使用 |

## 目录

```
server/   Node.js 22 服务端
client/   Python 客户端（含 venv、GUI、规则、配置）
```

## 服务端（Node.js 22）

纯 Node 内置模块（`http` / `net` / `dns` / `crypto`），无第三方依赖。

```bash
cd server
PORT=8443 PROXY_TOKEN=你的密钥 node server.js
# 或默认（PORT=8443，TOKEN=zhihu-proxy-dev）
node server.js
```

- 监听 `0.0.0.0:8443`，接收客户端的**加密帧**（内含 CONNECT 隧道目标或 HTTP 请求头，
  目标域名在链路上不可见）。
- 解密后**自己做 DNS 解析**并 `net.connect` 到真实目标，回 ACK 帧
  （`200 Connection Established`）后双向透传。
- 鉴权：帧内 HMAC tag 校验（密钥由 `PROXY_TOKEN` 派生）。两端 `PROXY_TOKEN` 必须一致。
- 环境变量：`PORT` / `HOST` / `PROXY_TOKEN` / `IDLE_TIMEOUT`（秒，0=关）。

## 客户端（Python + 虚拟环境）

仅用标准库（`asyncio` / `tkinter` / `winreg`），**无需 pip 安装任何包**。

```bash
cd client
python -m venv venv
venv\Scripts\activate
python gui.py        # 图形界面（需要带 tkinter 的 Python）
# 或纯命令行（无 GUI 也能跑代理）：
python proxy_client.py
```

### 配置 `client/config.json`

```json
{
  "client_port": 8787,        // 本地代理端口（改用 8787 是因为本机 Mihomo 已占用 7890/7892）
  "server_host": "127.0.0.1", // 远程服务端地址（部署时改成服务端公网 IP）
  "server_port": 8443,
  "token": "zhihu-proxy-dev"  // 必须与服务端 PROXY_TOKEN 一致
}
```

### 规则 `client/rules.json`

```json
{ "rules": ["huggingface.co", "github.com", "example.com"] }
```

匹配规则：`host == 规则` 或 `host 以 .规则 结尾`；`*.example.com` 形式也会匹配子域。
命中 → 走服务端隧道；未命中 → 直连。GUI 里可增删改，保存即生效。

### PAC 与系统代理

- 客户端在 `http://127.0.0.1:<client_port>/proxy.pac` 提供 PAC 文件，
  由 `rules.json` 自动生成。
- 启动代理时通过 `winreg` 把系统代理设为该 PAC（`AutoConfigURL`），
  并调用 `InternetSetOption` 立即刷新，使浏览器无需重启即生效。
- 停止时自动清除系统代理，避免断网。

> 说明：本机已有 Mihomo 代理占用 7890/7892，因此客户端默认端口改成了 **8787**。
> 如要改回，编辑 `config.json` 的 `client_port` 即可（确保不与其它代理冲突）。

## 验证（本地回环，无需外网）

1. 启动服务端：`node server.js`
2. 启动客户端：`python proxy_client.py`（或 `gui.py` 点「启动代理」）
3. 浏览器/系统设置走 PAC（GUI 启动会自动设置）
4. `curl -x http://127.0.0.1:8787 https://huggingface.co` 等命中域名会经服务端出口；
   其它域名直连。

## 已知限制

- 不支持 HTTP/3 (QUIC/UDP)：设置系统代理后浏览器对走代理的域名会回落到 TCP CONNECT，
  因此实际不影响使用。
- 纯 TCP 透传，不拦截 SNI、不做域名级智能分流（按前期评估，符合需求）。
- GUI 依赖带 `tkinter` 的 Python（本仓库的 managed Python 不含 tkinter，
  请用你本机已安装的 Python 运行 `gui.py`）。
- DNS over HTTPS (DoH)：按前期评估，未处理（Windows 默认 DoH 直连 DNS 服务器）。
