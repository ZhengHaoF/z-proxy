import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'crypto_frame.dart';

/// Probe outcome, mirroring Python `_probe`'s dict:
/// `code` is one of: `ok`, `auth`, `unreachable`, `timeout`, `closed`, `other`.
typedef ProbeResult = ({String code, bool ok, String msg});

const _probeTarget = 'example.com:443';

/// Port of Python `_probe` (proxy_client.py L295-339): opens one connection to
/// the upstream server, sends an encrypted CONNECT frame to a fixed probe
/// target and interprets the ACK.
///
///   - connection error -> `unreachable`
///   - ACK 200          -> `ok` (reachable + token valid)
///   - ACK 407          -> `auth` (token wrong)
///   - no ACK within [timeout] -> `timeout`
///   - EOF / bad frame  -> `closed`
Future<ProbeResult> probe({
  required String serverHost,
  required int serverPort,
  required String token,
  Duration timeout = const Duration(seconds: 8),
}) async {
  final key = keyFor(token);
  late Socket socket;
  try {
    socket = await Socket.connect(serverHost, serverPort);
  } catch (e) {
    return (
      code: 'unreachable',
      ok: false,
      msg: '无法连接服务端 $serverHost:$serverPort ($e)',
    );
  }
  final it = StreamIterator(socket);
  try {
    socket.add(encryptFrame(
        utf8.encode(jsonEncode({'m': 'CONNECT', 't': _probeTarget})), key));
    await socket.flush();
    final ackData = await readFrame(it, key).timeout(timeout);
    if (ackData == null) {
      return (
        code: 'closed',
        ok: false,
        msg: '服务端握手失败(token 错误或协议不匹配,端口可能不对)',
      );
    }
    final info = jsonDecode(utf8.decode(ackData.payload));
    if (info is! Map<String, dynamic>) {
      return (code: 'other', ok: false, msg: '服务端返回无法解析的数据');
    }
    final code = info['c'];
    if (code == 200) {
      return (code: 'ok', ok: true, msg: '连接正常,鉴权通过');
    }
    if (code == 407) {
      return (
        code: 'auth',
        ok: false,
        msg: 'Token 错误:服务端返回 407 Proxy Authentication Required',
      );
    }
    final m = '${info['m'] ?? ''}'.trim();
    final why = m.isEmpty ? '$code' : '$code $m';
    return (code: 'other', ok: false, msg: '服务端返回异常:$why');
  } on TimeoutException {
    return (
      code: 'timeout',
      ok: false,
      msg: '服务端 $serverHost:$serverPort 超时未响应(地址/端口错误或防火墙拦截)',
    );
  } catch (_) {
    return (code: 'other', ok: false, msg: '服务端返回无法解析的数据');
  } finally {
    try {
      await it.cancel();
    } catch (_) {}
    try {
      socket.destroy();
    } catch (_) {}
  }
}