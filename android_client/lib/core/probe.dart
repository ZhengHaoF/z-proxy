import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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

/// Tests connectivity through a local SOCKS5 proxy (RFC 1928).
///
/// Opens a connection to [proxyPort], performs the no-auth handshake and a
/// CONNECT request to [target]:[targetPort], then reports where the chain
/// breaks. Useful for diagnosing VPN tunnel issues: if this succeeds but
/// the browser behind the VPN can't access websites, the problem is DNS or
/// TUN routing rather than the proxy engine.
Future<ProbeResult> probeSocksProxy({
  required int proxyPort,
  String target = 'example.com',
  int targetPort = 443,
  Duration timeout = const Duration(seconds: 8),
}) async {
  late Socket socket;
  try {
    socket = await Socket.connect(
      InternetAddress.loopbackIPv4,
      proxyPort,
    ).timeout(timeout);
    final it = StreamIterator(socket);
    try {
      // Greeting: SOCKS5, one method, no-auth.
      socket.add(const [0x05, 0x01, 0x00]);
      await socket.flush();
      final method = await _readExact(it, 2).timeout(timeout);
      if (method == null) {
        return (code: 'closed', ok: false, msg: 'SOCKS5 代理未响应握手');
      }
      if (method[0] != 0x05) {
        return (code: 'other', ok: false, msg: '代理返回非 SOCKS5 响应');
      }
      if (method[1] == 0xff) {
        return (code: 'other', ok: false, msg: '代理不接受无鉴权方式');
      }
      // CONNECT request with domain name (ATYP=3).
      final hostBytes = utf8.encode(target);
      final req = <int>[
        0x05, 0x01, 0x00, 0x03, hostBytes.length,
        ...hostBytes,
        (targetPort >> 8) & 0xff,
        targetPort & 0xff,
      ];
      socket.add(req);
      await socket.flush();
      // Read first 4 bytes: VER, REP, RSV, ATYP.
      final head = await _readExact(it, 4).timeout(timeout);
      if (head == null) {
        return (code: 'closed', ok: false, msg: '代理未响应 CONNECT 请求');
      }
      if (head[0] != 0x05) {
        return (code: 'other', ok: false, msg: '代理返回非 SOCKS5 响应');
      }
      final rep = head[1];
      if (rep == 0x00) {
        return (
          code: 'ok',
          ok: true,
          msg: 'SOCKS5 代理正常,可访问 $target:$targetPort',
        );
      }
      const reasons = {
        0x01: '一般性失败',
        0x02: '连接不被允许',
        0x03: '网络不可达',
        0x04: '主机不可达',
        0x05: '连接被拒绝',
        0x06: 'TTL 过期',
        0x07: '命令不支持',
        0x08: '地址类型不支持',
      };
      final why = reasons[rep] ?? '错误码 0x${rep.toRadixString(16)}';
      return (
        code: 'other',
        ok: false,
        msg: 'SOCKS5 CONNECT 失败: $why (目标 $target:$targetPort)',
      );
    } finally {
      try {
        await it.cancel();
      } catch (_) {}
      try {
        socket.destroy();
      } catch (_) {}
    }
  } on SocketException catch (e) {
    return (
      code: 'unreachable',
      ok: false,
      msg: '无法连接本地 SOCKS5 代理 127.0.0.1:$proxyPort ($e)',
    );
  } on TimeoutException {
    return (
      code: 'timeout',
      ok: false,
      msg: '本地 SOCKS5 代理 127.0.0.1:$proxyPort 超时未响应',
    );
  } catch (e) {
    return (code: 'other', ok: false, msg: '测试失败: $e');
  }
}

Future<Uint8List?> _readExact(StreamIterator<List<int>> it, int n) async {
  final builder = BytesBuilder(copy: false);
  while (builder.length < n) {
    if (!await it.moveNext()) {
      return null;
    }
    builder.add(it.current);
  }
  return builder.takeBytes();
}