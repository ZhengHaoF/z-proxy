# z-proxy 安卓客户端(Flutter)实施计划

> **For Claude:** REQUIRED SUB-SKILL: 使用 executing-plans 按任务逐条实施本计划。

**Goal:** 在 Android 上实现 z-proxy 客户端(系统级 VPN 形态):手机所有 App 的流量经规则分流,命中的域名走加密隧道到现有 Node 服务端,未命中的直连;服务端与加密协议零改动。

**Architecture:** 三明治结构——① 纯 Dart 核心库(加密帧协议、规则引擎、HTTP/CONNECT 代理、SOCKS5 入口,全部可单测,参照 `client/proxy_client.py` 逐函数移植,新增 SOCKS5 协议入口供 tun2socks 接入);② 最小 Android 原生层(VpnService 建 TUN 并 detachFd,把 fd 交给 tun2socks 进程,由其把 IP 包还原成 SOCKS5 流打到本地 Dart 代理;MethodChannel 桥接);③ Flutter UI(开关/设置/规则管理/日志)。原生层参照 FlClash 的实现形态自行精简实现(FlClash 为 GPL-3.0,本项目按"参考 API 形态、自行实现"处理,不逐行复制,避免许可负担)。

**Tech Stack:** Flutter 3.x (Dart 3)、package:crypto(HMAC-SHA256)、Kotlin + VpnService、tun2socks(Go 二进制,arm64/armv7)、MethodChannel/EventChannel。

---

## 0. 关键设计决策(执行前必须理解)

| 决策点 | 决定 | 理由 |
|---|---|---|
| 进程模型 | 单进程:引擎 Dart isolate 跑在 Flutter 进程内,VpnService 同进程 | Dart 无法嵌入原生 service 进程(除非嵌 FlutterEngine,复杂度高,YAGNI)。取舍:进程被杀 → VPN 断开 → 用户重开 App |
| TUN→TCP 还原 | tun2socks 独立进程,`--tun-fd` 传 fd + `--proxy socks5://127.0.0.1:<SOCKS_PORT>` | 不自己写 TCP 协议栈;与 FlClash 的 `Core.startTun(fd,...)` 模式同构,只是引擎换成了进程 |
| 防环路 | VpnService Builder `addDisallowedApplication(自身包名)` | 自身进程(含 Dart 直连 socket、tun2socks 出站)不经 TUN,无环路,无需 protect |
| DNS | TCP 域名连接由 Dart 在自身进程内解析(系统 DNS 正常可用),不依赖 TUN 内 DNS | HTTP/HTTPS 全走 TCP;UDP(QUIC/游戏)初始版本不可用,浏览器会自动回退 TCP,记为已知限制 |
| UDP | SOCKS5 仅实现 CONNECT;UDP ASSOCIATE 返回不支持 | 与服务端协议(TCP frame)一致;后续可加 DNS-relay 增强 |
| setHttpProxy | 可选开关(仅 Android 10+),默认关闭;主链路不依赖 | 与 FlClash 的 `systemProxy` 选项同机制,验证通过后作为增强 |
| 配置兼容 | Dart `Config` 模型字段与 `client/config.json` 完全一致;规则文件复用 `{"rules":[...]}` 结构 | GUI/PC 客户端配置可无痛迁移 |
| 版本 | minSdk 26 (Android 8.0)+,targetSdk 34 | VpnService 稳定;覆盖主流机型 |

## 1. 模块划分与 FlClash 借鉴映射

| 模块 | 本项目位置 | 借鉴 FlClash 源文件 | 借鉴内容 |
|---|---|---|---|
| VpnService(原生) | `android_client/android/service/src/main/kotlin/.../VpnService.kt`(新建) | `FlClash/android/service/src/main/java/com/follow/clash/service/VpnService.kt` | TUN 参数(172.19.0.1/30、DNS 172.19.0.2、MTU 9000、setBlocking(false)、setMetered(false))、detachFd、排除自身、onRevoke、onStartCommand(Always-on) |
| 服务生命周期(原生) | `.../ServiceController.kt`(新建) | `FlClash/android/app/src/main/kotlin/com/follow/clash/ServiceController.kt` | bind/解绑、超时、Mutex 串行化 start/stop |
| 权限(原生) | `.../plugins/AppPlugin.kt`(新建) | `FlClash/android/app/src/main/kotlin/com/follow/clash/plugins/AppPlugin.kt` | VpnService.prepare 授权、POST_NOTIFICATIONS、电池优化豁免 |
| 前台通知/网络观察(原生) | `.../service/modules/NotificationModule.kt`、`NetworkObserveModule.kt`(新建) | `FlClash/android/service/.../modules/` | 前台服务通知(带停止按钮)、网络切换重建 VPN |
| Manifest | `android_client/android/.../AndroidManifest.xml`(改造) | `FlClash/android/service/.../AndroidManifest.xml`、app `AndroidManifest.xml` | VpnService 声明(specialUse + PROPERTY_SPECIAL_USE_FGS_SUBTYPE)、FOREGROUND_SERVICE*、POST_NOTIFICATIONS、REQUEST_IGNORE_BATTERY_OPTIMIZATIONS |
| Flutter↔原生桥 | `android_client/lib/plugins/service.dart`、`lib/plugins/app.dart`(新建) | `FlClash/lib/plugins/service.dart`、`lib/plugins/app.dart` | MethodChannel `start/stop/init/syncState` + event 事件流;VPN 授权状态机 |
| 授权状态机 | `android_client/lib/common/permission.dart`(新建) | `FlClash/lib/common/permission.dart`、`lib/providers/actions/setup.dart` 的 `requestAdmin`(L348-374) | TUN 授权 none→unauthorized→authorized;配置变更后重新授权 |
| 配置变更重启 | `android_client/lib/providers/vpn_manager.dart`(新建) | `FlClash/lib/manager/vpn_manager.dart` | 检测 VPN/配置变化,提示重启核心 |
| 核心逻辑(自研) | `android_client/lib/core/*.dart`(新建) | 无借鉴,对照 `client/proxy_client.py` 逐函数移植 | 见 §2 |

> 注意:`FlClash` 源码在 `D:\work\FlClash`(本地已 clone),建议保持只读引用;本项目代码在 `d:\work\z-proxy\android_client\` 新建,不修改 `client/`(Python)与 `server/`。

## 2. 仓库结构与 Dart 核心库(参考 `client/proxy_client.py`)

```
d:\work\z-proxy\
├── docs\plans\2026-08-21-android-flutter-client.md   (本计划)
└── android_client\
    ├── pubspec.yaml              # deps: crypto
    ├── assets\                   # tun2socks 二进制 (arm64-v8a / armeabi-v7a)
    ├── tools\gen_vectors.py      # 黄金向量生成(Python)
    ├── lib\core\                 # 纯 Dart 核心库,零 Flutter 依赖
    │   ├── crypto_frame.dart     # ← proxy_client.py L60-271  (_key_for/_keystream/encrypt_frame/decrypt_frame/read_frame 语义)
    │   ├── config.dart           # ← L26-58                   (DEFAULTS/load_config,字段完全一致)
    │   ├── rules.dart            # ← L87-153                  (domain_matches/_is_private_ip/is_bypass/_use_server)
    │   ├── http_parse.dart       # ← L274-292                 (read_headers, 65536 上限)
    │   ├── proxy_engine.dart     # ← L354-571                 (pipe_streams/serve_pac/forward_connect_to_server/connect_direct/http_to_server/http_direct/handle/serve/close_server + request_logger 等价物)
    │   ├── probe.dart            # ← L295-351                 (_probe/test_connection)
    │   └── socks5.dart           # 新增:握手 + CONNECT + UDP 拒绝
    ├── lib\common\permission.dart          # VPN 授权/通知/电池优化 (借 FlClash)
    ├── lib\plugins\service.dart            # 原生服务桥 (借 FlClash)
    ├── lib\plugins\app.dart                # 权限通道 (借 FlClash)
    ├── lib\providers\vpn_manager.dart      # 配置变更检测 (借 FlClash)
    ├── lib\views\                           # home/settings/rules/logs
    ├── android\...\VpnService.kt            # (新建,借 FlClash 形态)
    └── test\
        ├── vectors\frames.json              # 黄金向量
        ├── crypto_frame_test.dart
        ├── rules_test.dart
        ├── config_test.dart
        ├── http_parse_test.dart
        ├── proxy_engine_test.dart
        └── socks5_test.dart
```

## 3. 里程碑拆解

### M0:环境与脚手架

**Step 1** 确认工具链:
```pwsh
flutter --version      # 需 3.x
dart --version
java -version          # JDK 17
```
预期:均输出版本号;缺则先安装(Flutter SDK 需含 android toolchain)。

**Step 2** 脚手架:
```pwsh
cd d:\work\z-proxy
flutter create --project-name zproxy_client --org io.zproxy --platforms android,windows android_client
cd android_client
flutter pub add crypto
flutter pub add --dev flutter_lints
```
预期:目录生成、`flutter pub get` 成功。

**Step 3** 提交基线(如果 `d:\work\z-proxy` 是空 git 仓库;它当前不是 git 仓库,如后续要建仓:`git init` 后提交,并将 `android_client/android/.gradle`、`build/` 加入 .gitignore)。

### M1:Dart 核心库(TDD,本计划重点)

#### Task M1-1:黄金向量生成器 + 互通测试

**Files:**
- Create: `android_client/tools/gen_vectors.py`
- Create: `android_client/test/vectors/frames.json`
- Create: `android_client/test/crypto_frame_test.dart`

**Step 1** 写 `tools/gen_vectors.py`(基于 `client/proxy_client.py` 的协议函数):
```python
import json, sys
sys.path.insert(0, r'd:\work\z-proxy\client')
from proxy_client import _key_for, encrypt_frame, decrypt_frame

token = 'z-proxy-dev'
payloads = [b'hello world', b'\x00\x01\x02\xff' * 64, json.dumps({'m': 'CONNECT', 't': 'example.com:443'}).encode()]
vec = []
for p in payloads:
    frame = encrypt_frame(payload=p, key=_key_for(token))
    assert decrypt_frame(frame, _key_for(token)) == p
    vec.append({'payload_hex': p.hex(), 'frame_hex': frame.hex()})
with open(r'd:\work\z-proxy\android_client\test\vectors\frames.json', 'w') as f:
    json.dump({'token': token, 'vectors': vec}, f, indent=2)
print('OK', len(vec))
```
生成逻辑说明:帧格式 `magic(0x5A)|len(4B BE)|nonce(16B)|ct|tag(32B)`,enc_key = HMAC-SHA256(token, "z-proxy:enc:v1")。向量是 Python 侧加密 → Dart 侧解密,保证跨语言互通。

**Step 2** 用 PowerShell 7 运行:
```pwsh
cd d:\work\z-proxy\android_client
python ..\client\..\tools\gen_vectors.py
```
预期:输出 `OK 3`,`test/vectors/frames.json` 生成。注意 `python` 需 3.10+(项目 venv:`..\client\venv\Scripts\python.exe` 备选)。

**Step 3** 写失败测试 `test/crypto_frame_test.dart`:
```dart
import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zproxy_client/core/crypto_frame.dart';

void main() {
  final vectors = jsonDecode(
      File('test/vectors/frames.json').readAsStringSync());
  final token = vectors['token'] as String;
  final key = keyFor(token);

  test('decrypts vectors generated by the Python client', () {
    for (final v in vectors['vectors'] as List) {
      final frame = _hexToBytes(v['frame_hex'] as String);
      final payload = decryptFrame(frame, key);
      expect(payload, _hexToBytes(v['payload_hex'] as String));
    }
  });
  // (roundtrip / tamper / overlong 用例同文件,见 M1-1 附录)
}
```
(脚注:`_hexToBytes` 为测试局部 helper;`keyFor`/`decryptFrame` 为下文 M1-2 中待实现的 API,此处先编译失败——即测试先行。)

**Step 4** 运行确认失败:
```pwsh
flutter test test/crypto_frame_test.dart
```
预期:编译失败,`keyFor`/`decryptFrame` undefined。

**Step 5** 实现 `crypto_frame.dart`(协议逐行对应 Python L64-271):
```dart
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

const magicByte = 0x5A;
const encCtx = 'z-proxy:enc:v1';
const maxPayload = 65536;
const nonceLen = 16;
const tagLen = 32;

Uint8List keyFor(String token) => hmacSha256(utf8.encode(token), utf8.encode(encCtx));

Uint8List keystream(Uint8List key, Uint8List nonce, int length) {
  final out = BytesBuilder();
  var counter = 0;
  while (out.length < length) {
    final b = BytesBuilder();
    b.add(nonce);
    b.add((counter >> 24) & 0xff); b.add((counter >> 16) & 0xff);
    b.add((counter >> 8) & 0xff); b.add(counter & 0xff);
    out.add(hmacSha256(key, b.toBytes()));
    counter++;
  }
  return out.takeBytes().sublist(0, length);
}
// encryptFrame / decryptFrame 按 Python 语义实现(帧布局、hmac.compare_digest 等价用 constant-time 比较)
// readFrame(Stream<List<int>>, key): 读 21B 头 → 校验 magic/len → 读 len+32 → decrypt —— 与 Python read_frame 行为一致(EOF/格式错/tag 错 → null)
```
要求:Dart 实现必须与 Python 的 BE 打包、截取规则完全一致;测试通过 M1-1 Step 5 的向量验证。

**Step 6** 运行确认通过:
```pwsh
flutter test test/crypto_frame_test.dart
```
预期:PASS(3 向量 + 本文件其他用例)。

**Step 7** 提交:`feat(core): crypto frame protocol with Python-compatible golden vectors`

#### Task M1-2:规则引擎 + 配置模型

**Files:**
- Create: `test/rules_test.dart`、`test/config_test.dart`
- Create: `lib/core/rules.dart`、`lib/core/config.dart`

**Step 1** 失败测试(`rules_test.dart`,用例直接照抄 Python 行为):
- `domainMatches('example.com', ['example.com']) == true`,`('www.example.com') == true`,`('anexample.com') == false`(裸域名不匹配子串)
- `*.example.com` 规则:匹配 `example.com` 与 `a.b.example.com`,不匹配 `notexample.com`
- `.example.com`(点开头):匹配 `example.com`、`www.example.com`
- 大小写不敏感:`Example.COM` 匹配 `example.com`
- 空 host / 空规则均 false
- `isBypass('192.168.1.1') == true`、`isBypass('127.0.0.1') == true`、`isBypass('::1') == true`、`isBypass('example.com') == false`(默认 bypass 列表)
- `useServer(host, rules, mode)`:matched 模式仅规则命中 true;all 模式非 bypass 全 true

`config_test.dart`:`loadConfig({String? path})` 缺文件 → 返回 DEFAULTS;JSON 覆盖字段;`client_port` 非法类型不做强制(与 Python 容忍行为一致);`Config.toJson()` 输出字段与 `client/config.json` 完全一致(`client_port/server_host/server_port/token/mode/bypass`)。

**Step 2** 运行确认失败→**Step 3** 实现(`rules.dart` 逐行移植 Python L96-153;`config.dart` 移植 L26-49,增加 `loadConfigFromJsonString` 便于测试与远程持久化)→**Step 4** 运行确认通过:
```pwsh
flutter test test/rules_test.dart test/config_test.dart
```
**Step 5** 提交:`feat(core): rules engine and config model`

#### Task M1-3:HTTP 头解析

**Files:**
- Create: `test/http_parse_test.dart`
- Create: `lib/core/http_parse.dart`

**Step 1** 失败测试:用 `StreamController<List<int>>` 分片喂数据,断言:
- 正常请求:返回 `(requestLine, headers, rest)`;headers 键小写、值去空格
- 关键场景:头部与 body 同包到达(`rest` 非空且必含后续字节)
- 头部跨多次写、单字节分片
- 超 65536 无终止 → null;连接中途 EOF → null
- latin-1 解码(不可打印字节不抛错)

**Step 2** 运行确认失败 → **Step 3** 实现:基于 `Stream<List<int>>` 的缓冲累积(build 读接口设计为 `Future<HttpHead?> readHeaders(Stream<List<int>> stream, {List<int> Function() collector})`,`proxy_engine` 内用 `Subscription`/`StreamIterator` 消费,rest 字节回灌给后续管道)→ **Step 4** 通过 → **Step 5** 提交:`feat(core): http header parser`

#### Task M1-4:代理引擎(核心分组)

**Files:**
- Create: `test/proxy_engine_test.dart`(含 Mock 服务端)
- Create: `lib/core/proxy_engine.dart`

**Step 1** 失败测试设计(本任务重点,含协议集成验证):
- **CONNECT→隧道灰盒测试**:测试内起 Mock Upstream(Dart `ServerSocket`,监听随机端口,按协议实现:读帧→回 `{"c":200}`→pipe),再起 `ProxyEngine`(监听随机端口,serverHost=127.0.0.1:mockPort);用 `Socket.connect` 发 `CONNECT www.example.com:443` → 断言 `HTTP/1.1 200 Connection Established`,双向 echo 数据往返成功;Mock 断言收到 payload 含 `{"m":"CONNECT","t":"www.example.com:443"}`(解密后)。
- **CONNECT→407**:Mock 回 `{"c":407}` → 断言客户端收到 `HTTP/1.1 407 ...`。
- **CONNECT→直连(Mock 目标)**:规则不含目标域名,mode=matched → 客户端直连测试内 Mock 目标端口,断言 200 + echo。
- **隧道超时**:Mock 不回帧,15s 超时过长,测试注入 `timeout` 参数(引擎构造时可选,默认 15)为 300ms → 断言 502/关闭。
- **HTTP 转发**:发 `GET http://example.com/ HTTP/1.1` + Host 头 → Mock 断言收到 `HTTP` 帧含 method/path/headers;响应回传客户端。
- **优雅关闭**:`stop()` 取消所有活跃连接、`close()` 后端口释放。
- **请求日志**:`setRequestLogger` 收到 `(tag, target)`。

**Step 2** 运行确认失败 → **Step 3** 实现 `proxy_engine.dart`:
- `PipeStreams` 双向 pipe 等价于 Python L354-376(注意 Dart `Socket` 单读流:用 `Stream<List<int>>` + `StreamController.add(rest)` 回灌);
- `forwardConnectToServer`(L392-435):先读 ACK(默认 15s,可注入),期间 `rest`(如 TLS ClientHello)随帧后透传——**必须保留**,否则 TLS 挂起(保留 Python 的处理细节);
- `connectDirect`(L438-449)与 `httpToServer`(L452-464)同语义;
- `httpDirect`(L467-487):请求行重写(绝对 URL→path)、剥离 `proxy-authorization/proxy-connection/connection` 头、强制 `Connection: close`;
- `servePac` 可选移植(安卓无 PAC,保留函数与测试以便桌面 Debug 形态复用);
- `handle` 分流(SOCKS 入口与 HTTP 入口共用 `_useServer` 决策)。

**Step 4** 运行全部通过:
```pwsh
flutter test test/proxy_engine_test.dart
```
**Step 5** 提交:`feat(core): proxy engine (tunnel/direct/http) with mock-upstream integration tests`

#### Task M1-5:连接测试 probe

**Files:**
- Create: `test/probe_test.dart`
- Create: `lib/core/probe.dart`

**Step 1** 失败测试:Mock 服务端回 ACK 200 → `probe(...)` 返回 `{ok:true, code:'ok'}`;回 407 → `code:'auth'`;连接拒接 → `code:'unreachable'`;超时(注入短 timeout)→ `code:'timeout'`。
**Step 2-4** 实现(`probe.dart` 移植 L295-351,payload 为 CONNECT 到 `example.com:443`,Dart 侧用 `Socket.connect` + 短超时),通过:
```pwsh
flutter test test/probe_test.dart
```
**Step 5** 提交:`feat(core): upstream probe`

#### Task M1-6:SOCKS5 入口

**Files:**
- Create: `test/socks5_test.dart`
- Create: `lib/core/socks5.dart`

**Step 1** 失败测试(RFC 1928):
- 握手(`\x05\x01\x00` → `\x05\x00`)
- 客户端支持的方法不含 `0x00` → `\x05\xFF`
- CONNECT:IPv4 目标解析;域名目标(ATYP=3)→ 正确目标 host:port;响应 `\x05\x00\x00\x01 0.0.0.0:0`
- CONNECT 成功后数据可双向透传(与引擎 `useServer` 分流打通:匹配规则域名走 Mock 上游,不匹配直连 Mock 目标)
- UDP ASSOCIATE / BIND → 回复 `\x05\x07`(command not supported)后关闭

**Step 2** 运行确认失败 → **Step 3** 实现:握手解析 + `CONNECT` 转交引擎共享的 `Handler`(复用 M1-4 的 `handle` 决策管线;响应用固定的 `0.0.0.0:0` 即可,客户端不校验)→ **Step 4** 通过 → **Step 5** 提交:`feat(core): socks5 entry (connect only)`

#### M1 完成标准
`flutter test` 全绿;`dart analyze lib/core test` 0 告警;任何用例改动先破坏再修复的 TDD 节奏保持。

### M2:Android 原生桥 + tun2socks(对照 FlClash,精简实现)

| Task | 内容 | 借鉴/验证 |
|---|---|---|
| M2.1 | **Manifest**:app 清单加 `FOREGROUND_SERVICE`、`FOREGROUND_SERVICE_SPECIAL_USE`、`POST_NOTIFICATIONS`、`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` 权限;`VpnService` 声明 `android:permission="android.permission.BIND_VPN_SERVICE"` + `foregroundServiceType="specialUse"` + `PROPERTY_SPECIAL_USE_FGS_SUBTYPE=vpn` | 依 FlClash `android/service/.../AndroidManifest.xml`、app 清单 |
| M2.2 | **VpnService.kt**:Builder(`172.19.0.1/30`、`addDnsServer 172.19.0.2`、MTU 9000、`setBlocking(false)`、`setMetered(false)`、`addDisallowedApplication(自身包名)`、可选 `setHttpProxy` 开关)、`establish()?.detachFd()`、前台服务(通知含停止按钮)、`onRevoke` → 停 tun2socks + 通知 Flutter、`onStartCommand` → 通知 UI 恢复(Always-on 提示) | 依 FlClash `VpnService.kt`;验收:真机开启 VPN 授权后系统出现 VPN 图标,撤销授权服务停止 |
| M2.3 | **tun2socks 集成**:获取二进制(优先官方 release `tun2socks-android-*`,其次 `CGO_ENABLED=0 GOOS=android GOARCH=arm64/armv7 go build`,确认许可);放入 `assets/`;运行时拷贝到 app 私有目录,`ProcessBuilder` 启动:`tun2socks --tun-fd <fd> --proxy socks5://127.0.0.1:<SOCKS_PORT> --mtu 9000`(参数以 `tun2socks -h` 实际为准,若不支持 `--tun-fd` 则退回 `--tun-name` + `--tun-post-up` 方案,执行时验证);fd 用 `ParcelFileDescriptor.detachFd()` 派生;child process 终止(进程退出)→ 停 VPN | 验收:日志可见 tun2socks 启动无错;UDP 选项关闭 |
| M2.4 | **ServiceController.kt + AppPlugin.kt**:MethodChannel(`start/stop/syncState` + event 推状态);`VpnService.prepare()` 授权流程、`POST_NOTIFICATIONS` 申请、电池优化豁免拉起设置页 | 依 FlClash `ServiceController.kt`、`AppPlugin.kt`;验收:授权弹窗、通知权限弹窗、电池优化页跳转 |
| M2.5 | **NetworkObserveModule**:监听网络变化(`ConnectivityManager`),切换即重建 VPN + 重启 tun2socks | 依 FlClash `NetworkObserveModule.kt`;验收:Wi-Fi ↔ 流量切换后分流仍正常 |

### M3:Flutter UI

| Task | 内容 | 对应 Python GUI(`client/gui.py`) |
|---|---|---|
| M3.1 | 首页:连接开关(大按钮)、状态卡(服务端/规则数/运行时长)、授权状态机(`none→unauthorized→authorized`,依 FlClash `requestAdmin`) | `_toggle/_start/_stop` + `_preflight` |
| M3.2 | 设置页:server_host/server_port/token/mode(matched/all)/bypass 编辑与本地持久化;保存后提示重启代理 | `_load_config/_save_config` |
| M3.3 | 规则页:列表 + 添加/删除/双击编辑,持久化 `{"rules":[...]}`;模式切换联动说明 | `_add_rule/_del_rule/_on_tree_double_click/_on_mode_toggle` |
| M3.4 | 连接测试:按钮 + 结果对话框(ok/auth/unreachable/timeout 错误文案对齐 Python L295-334) | `_test_connection/_on_test_result` |
| M3.5 | 日志页:EventChannel 实时日志流(与 `set_request_logger` 语义一致,`[TUNNEL]/[DIRECT]/[SERVER]/...` 标签),支持清空 | `_log/_safe_log_req` |
| M3.6 | 通知/电池优化设置入口 + 关于页(VPN 提示文案:说明"仅转发匹配规则域名,其余直连") | — |

### M4:端到端联调与发布

| Task | 内容 | 验证方式 |
|---|---|---|
| M4.1 | **桌面先行**:`lib/core/` 是纯 Dart,在 Windows 上写临时 main(监听 8787,输出请求日志),对本地 Node 服务端(`server/server.js`)跑通与 PC Python 客户端等价的分流(用 curl 验证:匹配域名走隧道、非匹配直连、`proxy.pac` 可访问) | curl `-x http://127.0.0.1:8787 http://example.com` 等 4 组用例 |
| M4.2 | **模拟器联调**:Android 模拟器 + 宿主 Node 服务端;开启 VPN 后:系统浏览器访问匹配域名(通过宿主映射)与不匹配域名流程;验证规则/配置/日志 UI | 模拟器端手工清单 |
| M4.3 | **真机验收**:清单——授权弹窗、开关与状态、隧道/直连日志、切网络自动重建、锁屏 10 分钟后隧道仍活(前台服务+电池优化豁免)、系统"始终开启 VPN"场景提示、撤销授权处理、错误 token 提示 407 | 真机手工清单 |
| M4.4 | 发布:`flutter build apk --release`(split-per-abi 或 fat);`assets/` 中 tun2socks 按 ABI 选择(如 `flutter_assets` 全打包则体积 ~8MB,可接受) | `flutter build apk --release` 成功,安装后冒烟 |

## 4. 已知限制与后续增强(记录在案,不做)

- UDP 流量(QUIC/游戏协议)不可用:浏览器自动回退 TCP/HTTP1.1;后续可加 SOCKS5 UDP ASSOCIATE + DNS relay。
- 进程被杀 → VPN 断开:单进程模型取舍;后续增强可做双进程(原生 service 进程内嵌 FlutterEngine 或把核心下推到原生层)。
- 系统 `setHttpProxy`(Android 10+)为可选开关,默认关闭,验证后启用。
- App 白名单分流(FlClash AccessControl)与 `dnsHijacking` 暂不做。

## 5. 执行交接

M1(纯 Dart,TDD)可在 `d:\work\z-proxy\android_client` 独立完成,不依赖真机;M2 起需要 Android SDK/模拟器/真机。每完成一个 Task 提交一次;M1 完成时服务端无需任何改动,协议兼容由黄金向量保证。