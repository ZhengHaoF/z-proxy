import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zhihu_proxy_client/core/crypto_frame.dart';
import 'package:zhihu_proxy_client/core/probe.dart';

const _token = 'probe-test-token';
final _key = keyFor(_token);

Future<ServerSocket> _startProbeServer({Map<String, dynamic>? ack}) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) {
    unawaited(_handleProbe(socket, ack));
  }, onError: (_) {});
  return server;
}

Future<void> _handleProbe(Socket socket, Map<String, dynamic>? ack) async {
  final it = StreamIterator(socket);
  try {
    final data = await readFrame(it, _key);
    if (data == null) {
      return;
    }
    if (ack != null) {
      socket.add(encryptFrame(utf8.encode(jsonEncode(ack)), _key));
      await socket.flush();
    } else {
      // Stay silent but keep the connection open: the probe side owns the
      // timeout and closes the socket.
      try {
        await socket.done;
      } catch (_) {}
    }
  } finally {
    await it.cancel();
    socket.destroy();
  }
}

void main() {
  group('probe', () {
    test('ACK 200 -> ok', () async {
      final server = await _startProbeServer(ack: {'c': 200});
      final r = await probe(
        serverHost: '127.0.0.1',
        serverPort: server.port,
        token: _token,
      );
      expect(r.ok, isTrue);
      expect(r.code, 'ok');
      await server.close();
    });

    test('ACK 407 -> auth', () async {
      final server = await _startProbeServer(
          ack: {'c': 407, 'm': 'Proxy Authentication Required'});
      final r = await probe(
        serverHost: '127.0.0.1',
        serverPort: server.port,
        token: _token,
      );
      expect(r.ok, isFalse);
      expect(r.code, 'auth');
      await server.close();
    });

    test('connection refused -> unreachable', () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final port = server.port;
      await server.close();
      final r = await probe(
        serverHost: '127.0.0.1',
        serverPort: port,
        token: _token,
      );
      expect(r.ok, isFalse);
      expect(r.code, 'unreachable');
    });

    test('silent upstream -> timeout', () async {
      final server = await _startProbeServer();
      final r = await probe(
        serverHost: '127.0.0.1',
        serverPort: server.port,
        token: _token,
        timeout: const Duration(milliseconds: 300),
      );
      expect(r.ok, isFalse);
      expect(r.code, 'timeout');
      await server.close();
    });
  });
}