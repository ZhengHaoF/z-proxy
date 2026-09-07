# z-proxy Web 管理系统实施方案（V1 + V3 部分）

> 目标：给 Node 转发服务端加一个 Web 管理系统。本轮实现：**状态总览 + 实时隧道列表 + 实时日志 + 配置查看 + 流量历史图表**（V1 全量 + V3 的 client_id 服务端兼容）。
> 前置评估结论见会话记录：后端零管理面，管理数据全在进程内，增量开发即可，不动转发核心逻辑。
> **状态：✅ 已实施完成（2026-08-24）**——后端 server/db.js + server/lib/log.js + server/metrics.js + server/admin_server.js，前端 web-admin/（Vue3+TS+Naive UI+echarts），本地联调与全链路验证通过。

## 0. 关键决策

| 决策点 | 决定 | 理由 |
|---|---|---|
| SQLite 库 | **better-sqlite3@11.10.0**（老版本，锁定） | v11 是支持 Node 14~22 的最后稳定大版本线，有 win32/mac/linux × Node 20/22 的 prebuilt 二进制，免编译；v12+ 面向更高 Node/编译链，违背「兼容 node 20」要求 |
| 备选（prebuilt 拉取失败时） | sql.js（wasm 零编译） | 需手动整库落盘，写放大严重，仅作降级，不首选 |
| 进程模型 | **同进程双端口**：转发面 :8443 不变，管理面 :9090 | 一个 node 进程同时起两个 server，pm2 单实例配置不动；管理面故障不影响转发面 |
| 前端托管 | **admin_server 同端口托管构建产物**（单端口 9090 访问全部） | 部署只需放行 9090 一个端口；API 与页面同源，无跨域 |
| 前端技术栈 | Vue 3 + Vite + **TypeScript** + Naive UI + vue-router + pinia + axios + **echarts** | Naive UI 官方推荐搭配；echarts 做流量历史曲线；TS 保证接口类型一致 |
| 管理面鉴权 | 登录接口 + 内存 token；密码读 `server/.env` 的 `ADMIN_PASSWORD`（固定写死） | 密码不进 git、不进 ecosystem；token 简易内存 Map，重启失效，够用 |
| .env 加载 | **admin 模块启动时自读 `server/.env`**（约 10 行解析，不引 dotenv） | 兼容 pm2 与手动 `node server.js` 两种启动方式，不依赖 `--env-file`（Node 20.6+ 才有，行为差异多） |
| 实时推送 | SSE（`text/event-stream`），事件类型 3 种 | 单向推送够用，比 WebSocket 轻；Naive UI 侧 EventSource 即收 |
| 日志落库 | 内存环形缓冲（近 2000 条）+ 批量写库（50ms 攒批，WAL 模式），库中保留近 7 天 | 高频写库不卡转发面；有历史可翻 |
| V3 client_id | 帧载荷 JSON 加**可选字段 `c`**，服务端记录；旧客户端不带 → null | 向后兼容，存量客户端零影响；本轮不改 PC/Android 客户端发送逻辑 |
| 端口/协议限制 | 管理面监听 `ADMIN_HOST`（**默认 0.0.0.0，公网可访问**），安全靠密码登录 + 登录限速 + token 过期；部署时建议防火墙再加 IP 白名单 | 用户确认远程访问；管理 API 是新增攻击面，密码要强 |

## 1. 数据库设计（server/data/z-proxy.db）

三张业务表 + 一张预留表，better-sqlite3 同步 API，`PRAGMA journal_mode=WAL`：

```sql
CREATE TABLE IF NOT EXISTS connections (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id  TEXT,                        -- V3: 可选，旧客户端为 NULL
  proto      TEXT NOT NULL,               -- 'CONNECT' | 'HTTP'
  target     TEXT NOT NULL,               -- 原始目标 host:port
  host       TEXT,                        -- 解析出的 host
  port       INTEGER,
  ip         TEXT,                        -- 实际连上的 IP
  started_at INTEGER NOT NULL,            -- epoch ms
  ended_at   INTEGER,
  bytes_up   INTEGER DEFAULT 0,           -- 客户端→目标
  bytes_down INTEGER DEFAULT 0,           -- 目标→客户端
  status     TEXT NOT NULL                -- 'active' | 'closed' | 'denied' | 'error'
);
CREATE INDEX IF NOT EXISTS idx_conn_started ON connections(started_at);
CREATE INDEX IF NOT EXISTS idx_conn_status  ON connections(status);

CREATE TABLE IF NOT EXISTS samples (       -- 流量历史采样（图表用，平滑曲线）
  ts          INTEGER PRIMARY KEY,         -- epoch ms，每 30s 一条
  bytes_up    INTEGER NOT NULL,            -- 本区间累计上行
  bytes_down  INTEGER NOT NULL,            -- 本区间累计下行
  active      INTEGER NOT NULL             -- 采样时刻活跃连接数
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS logs (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  ts    INTEGER NOT NULL,                  -- epoch ms
  level TEXT NOT NULL,                     -- info | warn | error
  msg   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);

CREATE TABLE IF NOT EXISTS settings (      -- 预留：V2 热更新用
  key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER
);
```

容量控制：logs 每插一批顺带 `DELETE WHERE id <= (SELECT MAX(id)-50000 FROM logs)`；samples 保留 30 天；connections 保留 30 天。

## 2. server.js 埋点（转发核心零逻辑改动）

只加「观测」，不改转发行为：

1. 连接建立（验签通过后）：`metrics.connOpen({client_id: info.c || null, proto, target, host, port})`
2. CONNECT 连上真实目标（拿到 ip）：`metrics.connUpgraded(id, ip)`
3. 双向 pipe 处挂 `data` 监听计数：`metrics.connBytes(id, up, down)`（pipe 照常，监听不干扰）
4. 连接关闭/拒绝/失败：`metrics.connClose(id, status)`
5. 拒绝计数：`metrics.deny(code)`（407/400/502）

帧解析处读 `info.c`（可选字段），旧客户端没有则 null，其余逻辑不变。

## 3. 管理面 admin_server.js（:9090）

### 3.1 鉴权

- `POST /api/login` body `{password}` → 与 `ADMIN_PASSWORD`（.env）比对 → 发 `{token}`（crypto.randomBytes，内存 Map，24h 过期）
- 其余接口要求 `Authorization: Bearer <token>`；SSE 用 query `?token=`（EventSource 不能带 header）
- 全接口 5 次/秒/IP 限速（简易计数）

### 3.2 REST API

| 方法/路径 | 说明 |
|---|---|
| `GET /api/status` | 总览：运行时长、当前活跃连接数、累计连接数、累计 up/down、今日 up/down、错误计数、服务端版本、Node 版本、pm2 进程信息（环境变量 PWD / pm2 实例名） |
| `GET /api/connections` | 活跃隧道列表（实时字节/时长/IP），按 started_at 倒序 |
| `GET /api/connections/history?from&to&limit&proto` | 历史会话记录（表格翻页） |
| `GET /api/traffic?range=1h\|24h\|7d` | 流量历史图表：从 samples 聚合，返回 `[{ts, up, down, active}]` |
| `GET /api/logs?limit&level&afterId` | 最近日志（默认内存缓冲近 2000 条，可传 afterId 增量拉取） |
| `GET /api/config` | 只读：PORT / HOST / IDLE_TIMEOUT / ADMIN_PORT / 是否配置 ADMIN_PASSWORD / DB 路径 / WAL 状态 |
| `GET /api/stream` | SSE 事件流（见 3.3） |
| `POST /api/connections/:id/close` | 强制断开活跃隧道（顺手做，成本低） |

### 3.3 SSE 事件（`GET /api/stream?token=`）

| 事件 | 频率 | 载荷 |
|---|---|---|
| `status` | 每 5s | 同 `/api/status` |
| `conn` | 实时 | `{action:'open'\|'close'\|'bytes', id, ...}` |
| `log` | 实时 | `{ts, level, msg}` |

### 3.4 静态托管

`web-admin/dist` 构建产物由同 server 托管：非 `/api/` 路径一律返回 `index.html`（SPA history 模式）。

## 4. 日志捕获 lib/log.js

- 拦截 `console.log/warn/error`（转发核心 + 管理面共用），统一走 `log.info/warn/error`
- 输出格式：`[ts] [level] msg`，同时推入环形缓冲 + 批量写库 + SSE 广播
- 转发面现有 console 调用零改动（拦截在 console 上）

## 5. 配置与 .env

```
# server/.env（不进 git）
ADMIN_PASSWORD=你的后台密码
# 可选
ADMIN_PORT=9090
ADMIN_HOST=0.0.0.0
```

- `admin_server.js` 启动时自读 `server/.env`（KEY=VALUE 解析，忽略注释/空行），缺失时用默认 `admin` 并打印告警
- ecosystem.config.js 不动（pm2 只管转发进程；管理面同进程自动起来）；`.gitignore` 增加 `.env`、`server/data/`

## 6. 前端 web-admin/（Vue 3 + Vite + Naive UI）

页面 5 个，路由：`/login` → `/`（Dashboard）/ `/tunnels` / `/logs` / `/config`：

| 页面 | 内容 |
|---|---|
| Login | 密码输入 → login API → 存 token（pinia + localStorage） |
| Dashboard | 指标卡（活跃连接 / 累计流量 / 今日流量 / 错误数）+ 流量历史折线图（1h/24h/7d 切换，echarts，上行/下行双线）+ 吞吐数字 |
| Tunnels | 活跃隧道表格（目标/IP/协议/时长/收/发/状态）+ 5s 轮询 + 断开按钮 |
| Logs | SSE 实时日志流（级别过滤、清屏、暂停/恢复） |
| Config | 只读 key-value 表格 |

技术要点：Naive UI 全量组件（n-config-provider 中文 locale + 亮色主题）；axios 拦截器统一带 token / 401 跳登录；Vite 构建 `base: './'`。

## 7. 实施顺序（6 步，每步可验证）

1. **地基**：`server/db.js`（better-sqlite3 v11 初始化 + schema + 容量清理）、`server/lib/log.js`（console 拦截 + 缓冲 + 批量写库）。验证：启动后 db 文件生成、表齐全。
2. **metrics**：`server/metrics.js`（计数器 + 连接注册表 + 事件总线）。server.js 埋点 + client_id 解析。验证：转发流量后 metrics 数据正确。
3. **admin_server.js**：REST + SSE + 鉴权 + 静态托管 + .env 读取。验证：curl 各接口、SSE 收事件。
4. **联调**：本地起服务端 → 客户端发请求 → 观察 DB 落库与接口数据。
5. **前端**：脚手架 → 登录 → 四页面 → 对接 API/SSE → build。
6. **收尾**：.gitignore、README 补一段管理台说明、pm2 验证、Windows 本地 prebuilt 验证。

## 8. 风险与对策

| 风险 | 对策 |
|---|---|
| better-sqlite3 prebuilt 拉取失败（Windows 无编译链） | 锁定 v11.10.0（prebuilt 覆盖广）；失败则换 sql.js 降级（接口层封装，换库成本低） |
| 高并发日志写库卡转发 | WAL + 50ms 攒批 + 环形缓冲先出；写库失败静默降级不阻断转发 |
| 管理面 0.0.0.0 暴露公网被爆破 | 强密码 + 登录限速 + token 24h 过期 + 部署文档强调防火墙 IP 白名单 |
| SSE 连接数/内存 | 每客户端限 1 条 SSE；环形缓冲封顶；samples/logs 定期清理 |
| 旧客户端不兼容 | client_id 为可选字段，缺失即 null，帧解析兼容 |

## 9. 明确不做（本轮范围外）

- 配置热更新（V2）、错误告警（V2）、域名黑名单/限速（V2 安全策略）
- PC Python / Android Flutter 客户端发送 client_id（V3 客户端侧，另行排期）
- 多管理用户/角色、审计日志
