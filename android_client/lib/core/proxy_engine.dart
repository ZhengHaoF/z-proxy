import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'crypto_frame.dart';
import 'http_parse.dart';
import 'rules.dart';
import 'socks5.dart';

/// Reply style for tunnel setup (HTTP proxy vs SOCKS5 write different bytes).
typedef _ReplyOnDown = Future<void> Function(Socket client);
typedef _ReplyOnRejected =
    Future<void> Function(Socket client, int? code, String? reason);
typedef _ReplyOnEstablished = Future<void> Function(Socket client);

/// Local HTTP proxy engine, port of `client/proxy_client.py` (L352-537).
///
/// Listens on a loopback port and consumes HTTP proxy requests (CONNECT or
/// absolute-URL GET/POST). For each request it decides via [rules]/[mode]
/// whether to tunnel bytes to the upstream server inside encrypted frames
/// (tag `TUNNEL`/`SERVER`) or to connect the target directly (tag `DIRECT`),
/// then pipes both directions with the shared single-consumer model.
class ProxyEngine {
  ProxyEngine({
    required this.serverHost,
    required this.serverPort,
    required this.token,
    required this.rules,
    required this.mode,
    this.bypass,
    this.timeout = const Duration(seconds: 15),
  });

  final String serverHost;
  final int serverPort;
  final String token;
  final List<String> rules;
  final String mode;
  final List<String>? bypass;

  /// Upstream ACK timeout for CONNECT tunnels (Python default: 15s).
  final Duration timeout;

  late final Uint8List _key = keyFor(token);

  ServerSocket? _server;
  ServerSocket? _socksServer;
  final _active = <Socket>{};
  void Function(String tag, String target)? _onRequest;

  /// Starts listening on a random loopback port; returns the bound port.
  Future<int> serve() async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    _server = server;
    server.listen(_onClient, onError: (_) {});
    return server.port;
  }

  /// Starts listening for SOCKS5 clients (RFC 1928) on a random loopback
  /// port; returns the bound port. CONNECT is routed through the same
  /// `useServer` decision as the HTTP proxy.
  Future<int> serveSocks() async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    _socksServer = server;
    server.listen(_onSocksClient, onError: (_) {});
    return server.port;
  }

  /// Cancels all active client connections (the listener stays up).
  Future<void> stop() async {
    for (final s in List<Socket>.of(_active)) {
      _closeQuietly(s);
    }
  }

  /// Cancels active connections and releases the listening ports.
  Future<void> close() async {
    await stop();
    final s = _server;
    _server = null;
    if (s != null) {
      await s.close();
    }
    final socks = _socksServer;
    _socksServer = null;
    if (socks != null) {
      await socks.close();
    }
  }

  /// Registers the per-request logger; receives `(tag, target)` with tag in
  /// {TUNNEL, DIRECT, SERVER} mirroring Python `_log_req`.
  void setRequestLogger(void Function(String tag, String target) logger) {
    _onRequest = logger;
  }

  void _onClient(Socket client) {
    _active.add(client);
    unawaited(_handleClient(client));
  }

  void _onSocksClient(Socket client) {
    _active.add(client);
    unawaited(_handleSocks(client));
  }

  Future<void> _handleSocks(Socket client) async {
    final it = StreamIterator(client);
    final buf = SocksBuf();
    const granted = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    try {
      final method = await readSocksHandshake(it, buf);
      if (method == null) {
        return;
      }
      if (method < 0) {
        await _replyAndClose(client, const [0x05, 0xFF]);
        return;
      }
      client.add(const [0x05, 0x00]);
      await client.flush();
      final req = await readSocksRequest(it, buf);
      if (req == null) {
        return;
      }
      if (req.command != 1) {
        // Only CONNECT is implemented (BIND / UDP ASSOCIATE unsupported).
        await _replyAndClose(client, const [0x05, socksCommandNotSupported]);
        return;
      }
      final via = useServer(req.host, rules: rules, mode: mode, bypass: bypass);
      _logRequest(via ? 'TUNNEL' : 'DIRECT', '${req.host}:${req.port}');
      final early = buf.takeRemaining();
      if (via) {
        await _forwardConnectToServer(
          client,
          it,
          req.host,
          req.port,
          early,
          onDown: (c) =>
              _replyAndClose(c, const [0x05, socksConnectionRefused]),
          onRejected: (c, code, reason) =>
              _replyAndClose(c, const [0x05, socksGeneralFailure]),
          onEstablished: (c) async {
            c.add(granted);
            await c.flush();
          },
        );
      } else {
        await _connectDirect(
          client,
          it,
          req.host,
          req.port,
          early,
          onDown: (c) =>
              _replyAndClose(c, const [0x05, socksConnectionRefused]),
          onEstablished: (c) async {
            c.add(granted);
            await c.flush();
          },
        );
      }
    } catch (_) {
    } finally {
      _active.remove(client);
      try {
        await it.cancel();
      } catch (_) {}
      _closeQuietly(client);
    }
  }

  Future<void> _handleClient(Socket client) async {
    final it = StreamIterator(client);
    try {
      final head = await readHeaders(it);
      if (head == null) {
        return;
      }
      final parts = head.requestLine.split(' ');
      if (parts.length < 2) {
        return;
      }
      final method = parts[0].toUpperCase();
      final target = parts[1];

      // Serve the PAC file; the browser fetches it directly so the target is
      // a relative path or a localhost URL (desktop debug reuse, like Python).
      if (method == 'GET' && target.contains('proxy.pac')) {
        final u = Uri.tryParse(target);
        if (u == null ||
            u.host.isEmpty ||
            u.host == '127.0.0.1' ||
            u.host == 'localhost') {
          await _servePac(client);
          return;
        }
      }

      if (method == 'CONNECT') {
        final (host, port) = _splitHostPort(target);
        final via = useServer(host, rules: rules, mode: mode, bypass: bypass);
        _logRequest(via ? 'TUNNEL' : 'DIRECT', '$host:$port');
        if (via) {
          await _forwardConnectToServer(
            client,
            it,
            host,
            port,
            head.rest,
            onDown: (c) async =>
                _respondAndClose(c, 'HTTP/1.1 502 Bad Gateway\r\n\r\n'),
            onRejected: (c, code, reason) async =>
                _respondAndClose(c, 'HTTP/1.1 $code $reason\r\n\r\n'),
            onEstablished: (c) async {
              c.add(utf8.encode('HTTP/1.1 200 Connection Established\r\n\r\n'));
              await c.flush();
            },
          );
        } else {
          await _connectDirect(
            client,
            it,
            host,
            port,
            head.rest,
            onDown: (c) async =>
                _respondAndClose(c, 'HTTP/1.1 502 Bad Gateway\r\n\r\n'),
            onEstablished: (c) async {
              c.add(utf8.encode('HTTP/1.1 200 Connection Established\r\n\r\n'));
              await c.flush();
            },
          );
        }
        return;
      }

      final h = Uri.tryParse(target)?.host ?? '';
      final via = useServer(h, rules: rules, mode: mode, bypass: bypass);
      _logRequest(via ? 'SERVER' : 'DIRECT', target);
      if (via) {
        await _httpToServer(client, it, head.requestLine, head.headers, head.rest);
      } else {
        await _httpDirect(client, it, head.requestLine, head.headers, head.rest);
      }
    } catch (_) {
    } finally {
      _active.remove(client);
      try {
        await it.cancel();
      } catch (_) {}
      _closeQuietly(client);
    }
  }

  // Shared CONNECT tunnel to the upstream server (port of Python
  // `forward_connect_to_server` L390-433): send the CONNECT frame (plus any
  // early client bytes such as TLS ClientHello), require the ACK within
  // [timeout], invoke the reply callbacks, then pipe both directions. The
  // HTTP proxy and the SOCKS5 entry drive this with different reply bytes.
  Future<void> _forwardConnectToServer(
    Socket client,
    StreamIterator<List<int>> clientIt,
    String host,
    int port,
    Uint8List rest, {
    required _ReplyOnDown onDown,
    required _ReplyOnRejected onRejected,
    required _ReplyOnEstablished onEstablished,
  }) async {
    late Socket upstream;
    try {
      upstream = await Socket.connect(serverHost, serverPort);
    } catch (_) {
      await onDown(client);
      return;
    }
    final ackIt = StreamIterator(upstream);
    var established = false;
    try {
      upstream.add(encryptFrame(
          utf8.encode(jsonEncode({'m': 'CONNECT', 't': '$host:$port'})), _key));
      if (rest.isNotEmpty) {
        upstream.add(rest);
      }
      await upstream.flush();
      final ackData = await readFrame(ackIt, _key).timeout(timeout);
      if (ackData == null) {
        return;
      }
      final info = jsonDecode(utf8.decode(ackData.payload));
      if (info is! Map<String, dynamic>) {
        return;
      }
      if (info['c'] != 200) {
        final code = info['c'] is int ? info['c'] as int : null;
        await onRejected(client, code, '${info['m'] ?? 'Bad Gateway'}');
        return;
      }
      established = true;
    } catch (_) {
      return;
    } finally {
      if (!established) {
        try {
          await ackIt.cancel();
        } catch (_) {}
        _closeQuietly(upstream);
        _closeQuietly(client);
      }
    }
    await onEstablished(client);
    await _pipe(client, clientIt, upstream, ackIt);
  }

  // Shared direct connection to the CONNECT target (port of Python
  // `connect_direct` L436-447).
  Future<void> _connectDirect(
    Socket client,
    StreamIterator<List<int>> clientIt,
    String host,
    int port,
    Uint8List rest, {
    required _ReplyOnDown onDown,
    required _ReplyOnEstablished onEstablished,
  }) async {
    late Socket target;
    try {
      target = await Socket.connect(host, port);
    } catch (_) {
      await onDown(client);
      return;
    }
    final targetIt = StreamIterator(target);
    try {
      if (rest.isNotEmpty) {
        target.add(rest);
        await target.flush();
      }
      await onEstablished(client);
    } catch (_) {
      _closeQuietly(target);
      _closeQuietly(client);
      return;
    }
    await _pipe(client, clientIt, target, targetIt);
  }

  // Port of `http_to_server` (proxy_client.py L450-462).
  Future<void> _httpToServer(
    Socket client,
    StreamIterator<List<int>> clientIt,
    String requestLine,
    Map<String, String> headers,
    Uint8List rest,
  ) async {
    late Socket upstream;
    try {
      upstream = await Socket.connect(serverHost, serverPort);
    } catch (_) {
      _closeQuietly(client);
      return;
    }
    final upstreamIt = StreamIterator(upstream);
    try {
      upstream.add(encryptFrame(
          utf8.encode(jsonEncode({'m': 'HTTP', 'r': requestLine, 'h': headers})),
          _key));
      if (rest.isNotEmpty) {
        upstream.add(rest);
      }
      await upstream.flush();
    } catch (_) {
      _closeQuietly(upstream);
      _closeQuietly(client);
      return;
    }
    await _pipe(client, clientIt, upstream, upstreamIt);
  }

  // Port of `http_direct` (proxy_client.py L465-485): rewrite the request
  // line from absolute URL to path, drop proxy-only headers, force
  // `Connection: close`.
  Future<void> _httpDirect(
    Socket client,
    StreamIterator<List<int>> clientIt,
    String requestLine,
    Map<String, String> headers,
    Uint8List rest,
  ) async {
    final parts = requestLine.split(' ');
    if (parts.length < 3) {
      _closeQuietly(client);
      return;
    }
    final method = parts[0];
    final u = Uri.tryParse(parts[1]);
    if (u == null || u.host.isEmpty) {
      _closeQuietly(client);
      return;
    }
    final host = u.host;
    final port = u.hasPort ? u.port : 80;
    late Socket target;
    try {
      target = await Socket.connect(host, port);
    } catch (_) {
      _closeQuietly(client);
      return;
    }
    final targetIt = StreamIterator(target);
    final path = u.path.isEmpty ? '/' : u.path;
    final query = u.query.isEmpty ? '' : '?${u.query}';
    final out = StringBuffer('$method $path$query HTTP/1.1\r\n');
    for (final e in headers.entries) {
      if (e.key == 'proxy-authorization' ||
          e.key == 'proxy-connection' ||
          e.key == 'connection') {
        continue;
      }
      out.write('${e.key}: ${e.value}\r\n');
    }
    out.write('Connection: close\r\n\r\n');
    try {
      target.add(utf8.encode(out.toString()));
      if (rest.isNotEmpty) {
        target.add(rest);
      }
      await target.flush();
    } catch (_) {
      _closeQuietly(target);
      _closeQuietly(client);
      return;
    }
    await _pipe(client, clientIt, target, targetIt);
  }

  Future<void> _servePac(Socket client) async {
    final pac = utf8.encode(buildPac(
      rules: rules,
      mode: mode,
      proxyPort: _server?.port ?? 0,
      bypass: bypass,
    ));
    final head = 'HTTP/1.1 200 OK\r\n'
        'Content-Type: application/x-ns-proxy-autoconfig\r\n'
        'Content-Length: ${pac.length}\r\n'
        'Connection: close\r\n\r\n';
    try {
      client.add(utf8.encode(head));
      client.add(pac);
      await client.flush();
    } catch (_) {
    } finally {
      try {
        client.close();
      } catch (_) {
        _closeQuietly(client);
      }
    }
  }

  void _logRequest(String tag, String target) {
    _onRequest?.call(tag, target);
  }

  void _closeQuietly(Socket s) {
    try {
      s.destroy();
    } catch (_) {}
  }

  Future<void> _replyAndClose(Socket client, List<int> bytes) async {
    try {
      client.add(bytes);
      await client.flush();
      client.close();
    } catch (_) {
      _closeQuietly(client);
    }
  }

  Future<void> _respondAndClose(Socket client, String text) async {
    try {
      client.add(utf8.encode(text));
      await client.flush();
      client.close();
    } catch (_) {
      _closeQuietly(client);
    }
  }

  Future<void> _pipe(
    Socket a,
    StreamIterator<List<int>> aIt,
    Socket b,
    StreamIterator<List<int>> bIt,
  ) async {
    await Future.wait([_pump(aIt, b), _pump(bIt, a)]);
  }

  Future<void> _pump(StreamIterator<List<int>> src, Socket dst) async {
    try {
      while (await src.moveNext()) {
        dst.add(src.current);
        await dst.flush();
      }
    } catch (_) {
    } finally {
      try {
        dst.close();
      } catch (_) {}
      try {
        await src.cancel();
      } catch (_) {}
    }
  }

  static (String, int) _splitHostPort(String target) {
    final i = target.lastIndexOf(':');
    if (i < 0) {
      return ('', 443);
    }
    final host = target.substring(0, i);
    final port = int.tryParse(target.substring(i + 1)) ?? 443;
    return (host, port);
  }
}

/// PAC file content, port of Python `build_pac` (proxy_client.py L156-203)
/// with the proxy endpoint parameterized by the engine's local port.
String buildPac({
  required List<String> rules,
  required String mode,
  required int proxyPort,
  List<String>? bypass,
}) {
  if (mode == 'all') {
    final lines = <String>[
      '  if (isPlainHostName(host) || host == "localhost" || dnsDomainIs(host, ".local") || shExpMatch(host, "*.local")) return "DIRECT";',
      '  if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";',
      '  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";',
      '  if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";',
      '  if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";',
      '  if (isInNet(host, "169.254.0.0", "255.255.0.0")) return "DIRECT";',
    ];
    for (final b in bypass ?? defaultBypass) {
      final r = b.trim();
      if (r.isEmpty || r == 'localhost' || r == '127.0.0.1' || r == '::1') {
        continue;
      }
      if (r.startsWith('*.')) {
        lines.add('  if (shExpMatch(host, "*${r.substring(1)}")) return "DIRECT";');
      } else if (r.startsWith('.')) {
        lines.add('  if (shExpMatch(host, "*$r")) return "DIRECT";');
      } else {
        lines.add('  if (host == "$r" || shExpMatch(host, "*.$r")) return "DIRECT";');
      }
    }
    lines.add('  return "PROXY 127.0.0.1:$proxyPort";');
    return 'function FindProxyForURL(url, host) {\n${lines.join('\n')}\n}\n';
  }
  final lines = <String>[];
  for (final rule in rules) {
    final r = rule.trim();
    if (r.isEmpty) {
      continue;
    }
    if (r.startsWith('*.')) {
      lines.add(
          '  if (shExpMatch(host, "*${r.substring(1)}")) return "PROXY 127.0.0.1:$proxyPort";');
    } else if (r.startsWith('.')) {
      lines.add('  if (shExpMatch(host, "*$r")) return "PROXY 127.0.0.1:$proxyPort";');
    } else {
      lines.add(
          '  if (host == "$r" || shExpMatch(host, "*.$r")) return "PROXY 127.0.0.1:$proxyPort";');
    }
  }
  return 'function FindProxyForURL(url, host) {\n'
      '${lines.join('\n')}\n'
      '  return "DIRECT";\n'
      '}\n';
}