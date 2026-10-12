# z-proxy 第一轮加固与正确性优化

这轮保留 Node / Python / Flutter / Kotlin 技术栈与原有首帧协议，优先处理异常输入、HTTP 语义、连接超时、桌面系统代理恢复和可重复测试。基线为 `7e84dc3566ea2fa0c8cd6d345a2bb7dbf22c27f6`，工作分支为 `hardening/proxy-correctness`；本文不代表线上已部署这些修改。（[上游仓库](https://github.com/ZhengHaoF/z-proxy)）

## 已实现的改动

- **管理面**：非对象 JSON 不再使服务退出；统一捕获异步路由错误；请求体、日志查询、会话及 SSE 数量有上限；登录会话可注销，注销/过期释放 SSE 监听器并限制退出等待；管理端口绑定错误不退出转发进程。
- **安全启动配置**：生产要求至少 24 字符的代理 token 和至少 12 字符的管理密码，拒绝公开开发值及模板值；管理面默认 `127.0.0.1`；显式 `ALLOW_INSECURE_DEV=1` 只能回环监听；可用 `ADMIN_ENABLED=0` 关闭管理面。
- **HTTP 代理**：使用 Node HTTP 解析器处理请求体和响应流，保留状态码、重复 Set-Cookie、CL/chunked 和查询参数；拒绝 CL+TE、非法头和不支持的 Upgrade/Expect；客户端 FIN 后继续返回完整响应，GET/DELETE/OPTIONS 的 chunked body 正确重新分帧。
- **HTTP 长传输**：上传使用无数据超时，上传结束后才开始响应首字节期限；开始返回响应后使用空闲超时，不因固定总时长截断活跃下载；显式 `agent:false`，避免连接复用与建链定时器混用。
- **DNS 与 CONNECT**：每个地址族独立可取消解析；先使用有结果的地址族，失败后交错尝试另一族，而不是耗尽一整个失败地址族；首帧握手、单 IP 建链、总建链都有期限；延迟解析结果不能重新建立已结束连接。
- **TCP 数据完整性**：首帧到转发切换前暂停 socket，保留等待期间的早期数据；Dart 保留 ACK 后同批到达的 payload；Python/Dart 使用带方括号的 IPv6 CONNECT authority。
- **桌面代理**：修复 query 拼接；PAC 与 Python 引擎共用规则规范，通配规则包含根域，忽略大小写和域名尾点，PAC 使用转义 JSON；所有模式先检查绕过；不再借 PAC 的 isInNet 触发域名解析。
- **桌面 GUI**：监听成功后才设置 PAC；保存并恢复原 Windows 代理值；保存异常退出恢复备份；旧线程结束后才绑定新实例，旧回调不得污染新会话；备份文件已加入 gitignore。
- **Android 局部修正**：连接与探测有连接期限，UDP relay 仅回环监听，matched 模式也优先 bypass；watchdog 带 generation 并移除旧回调；界面明确“全部 TCP”而非“全部流量”，并说明 DNS/UDP 与 IP 化目标的边界。
- **流量观测**：按全局单调字节计数差值采样，不再漏掉已关闭的短连接；同毫秒采样不会互相覆盖；界面明确内存统计属于本次进程；退出时刷新采样、日志并关闭数据库。
- **持续验证入口**：增加 Node 与 Python 回归测试和真实跨进程 Python→Node→HTTP 测试；增加 Node 20/22、Python 3.11/3.13、前端构建及固定 Flutter 的 GitHub Actions 配置。

## 兼容性和升级注意事项

- **必须检查 `.env`**：原先无密钥、短密钥或模板配置可启动的行为已收紧。请先自行生成随机密钥并同步客户端，或只在回环环境显式启用开发模式；本轮没有替你修改真实凭据或轮换线上 token。
- **管理台不再默认公网监听**：需要远程访问时，用 SSH 转发或带 HTTPS 的反向代理；不要为方便恢复成明文公网登录。
- **域名分流绕过优先**：桌面中的私网/回环、无点主机名、`.local` 及显式绕过名单在所有模式优先直连，原来依赖规则强行代理这些目标的配置会改变。
- **HTTP 功能边界**：一帧对应一个请求，强制关闭连接；不支持 HTTP Upgrade 或 Expect。HTTP 头仍来自 JSON 对象，客户端解析时重复请求头可能折叠，这个限制尚未消除。
- **解析与重试**：c-ares 不读 hosts 文件。HTTP 给另一个地址族 100ms 宽限，然后将可用地址交错交给 Node；极迟返回的地址族仍可能赶不上这次 HTTP 建链。
- **依赖不顺带升级**：保留原 `pubspec.lock` 及其镜像源；Flutter 检查使用固定工具链和 `--enforce-lockfile`，没有把本地首次解析出的升级提交进来。

## 验证方式

测试在隔离 Linux 环境执行，使用临时测试 token、回环源站和临时 SQLite 数据库。桌面 GUI 使用 Xvfb，Windows 注册表使用内存替身；Flutter 核心测试和静态分析可以执行，但它们不能覆盖 Kotlin 编译、JNI、真实系统 VPN 或 Android 后台进程行为。

```bash
# 服务端，含 Python/Node 的真实跨进程互通
cd server
npm ci
npm test

# 桌面端，包括 GUI 测试
cd ..
xvfb-run -a python -W error::ResourceWarning -m unittest discover -s client/tests -v

# 管理台
cd server/web-admin
npm ci
npm run build

# Flutter：保留原锁文件，使用本次验证的工具链
cd ../../android_client
PUB_HOSTED_URL=https://pub.flutter-io.cn flutter pub get --enforce-lockfile
flutter test --no-pub
flutter analyze --no-pub
```

工具链基线：Node 20.20.2、Python 3.14.3、Flutter 3.47.7 / Dart 3.13.5。远端 Actions 的 Node/Python 矩阵不等于本地已经测完这些版本；需要推送后看真实 CI 结果。

本地最终验证结果：

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| Node 服务端 | 29/29 通过，无跳过 | 包含两条 Python/Node 互通测试、DNS 回退、长传输与异常输入 |
| Python 桌面端 | 43/43 通过，无跳过 | Xvfb GUI，ResourceWarning 作为错误处理 |
| Flutter | 74/74 通过 | 使用原锁文件和固定工具链 |
| Flutter 静态分析 | No issues found | 不等于 Kotlin/JNI 编译通过 |
| 管理台 | 生产构建通过 | 未执行浏览器端 E2E |
| Git 差异 | `git diff --check` 通过 | 不包含构建产物、真实配置或密钥 |

实现与独立复查使用了 Claude Opus 5.5，复查暴露的问题已纳入修复与回归测试。测试通过不代表完整链路加密、抗公网攻击能力或真实系统平台已经验收。

## 没有做、也不能宣称已解决的事

- **完整 TLS 传输与防重放**：仍只加密首帧，后续载荷原样传输。下一阶段需要三端协同的 TLS、服务器身份验证、迁移及回滚设计，而不是只给服务端加一个 tls listener。
- **Android 真正的域名恢复**：没有实现 fake-IP、DNS 映射或 SNI 恢复。真实 TUN 目标是 IP 时，域名规则仍可能不生效；下一阶段必须连同 bypass 和 fake-IP 地址策略一起设计并真机验证。
- **公网抗滥用**：全局连接上限与握手超时不能替代按来源限额、防火墙和更完整的抗连接耗尽设计。单 token 仍意味着持有者可访问服务端可达的内网目标。
- **Windows / Android 实机验收**：没有在真实 Windows 注册表或 Android 设备上测试；没有编译 APK、验证 JNI ABI 或配置正式 release 签名。
- **线上操作与 Git 发布**：没有修改线上服务、真实配置、历史提交或主分支；没有推送分支、发 PR 或触发远端 Actions。

## 下一阶段建议

先把本轮分支通过真实 CI 和两端实机验收，再单独设计协议 v2 的 TLS 升级与 Android 域名恢复。密钥轮换、部署切换、公开推送、PR 和合并需要明确对应范围，避免把代码优化自动变成线上操作。

拟发布到 `ZhengHaoF/z-proxy` 的 PR 标题为 `fix(proxy): harden lifecycle and correct HTTP forwarding`，目标分支 `master`，来源分支 `hardening/proxy-correctness`。拟 PR 正文为：

> 修复管理路由异常、HTTP 状态/响应头/body framing、半关闭及连接超时；完善 DNS 地址族重试、桌面 PAC/系统代理恢复、Dart ACK 尾随数据及流量采样，加入回归测试和 CI。生产启动要求强凭据，管理面默认回环监听；完整 TLS、Android 域名恢复和实机验收仍在后续范围。本 PR 不部署、不轮换真实密钥，也不自动合并。
