import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zproxy_client/core/crypto_frame.dart';
import 'package:zproxy_client/core/proxy_engine.dart';

const _token = 'tunnel-test-token';
final _key = keyFor(_token);

Future<ServerSocket> _startMockUpstream(
  List<Map<String, dynamic>> frames, {
  Map<String, dynamic>? ack,
  FutureOr<List<int>> Function()? reply,
}) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) {
    unawaited(_mockUpstreamHandle(socket, frames, ack: ack, reply: reply));
  }, onError: (_) {});
  return server;
}

Future<void> _mockUpstreamHandle(
  Socket socket,
  List<Map<String, dynamic>> frames, {
  Map<String, dynamic>? ack,
  FutureOr<List<int>> Function()? reply,
}) async {
  final it = StreamIterator(socket);
  try {
    final data = await readFrame(it, _key);
    if (data == null) {
      return;
    }
    frames.add(jsonDecode(utf8.decode(data.payload)) as Map<String, dynamic>);
    if (ack != null) {
      socket.add(encryptFrame(utf8.encode(jsonEncode(ack)), _key));
      await socket.flush();
    }
    if (reply != null) {
      socket.add(await reply());
      await socket.flush();
    } else {
      if (data.rest.isNotEmpty) {
        socket.add(data.rest);
        await socket.flush();
      }
      while (await it.moveNext()) {
        socket.add(it.current);
        await socket.flush();
      }
    }
    socket.close();
  } finally {
    await it.cancel();
    socket.destroy();
  }
}

Future<ServerSocket> _startEchoServer() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) {
    socket.listen((data) {
      socket.add(data);
      socket.flush();
    }, onDone: () {
      socket.close();
    });
  }, onError: (_) {});
  return server;
}

Future<String> _readHead(StreamIterator<List<int>> it) async {
  final buf = BytesBuilder();
  var text = '';
  while (!text.contains('\r\n\r\n')) {
    try {
      if (!await it.moveNext()) {
        break;
      }
    } catch (_) {
      break;
    }
    buf.add(it.current);
    text = latin1.decode(buf.toBytes());
  }
  return text;
}

Future<void> _waitUntil(bool Function() cond,
    {Duration timeout = const Duration(seconds: 3)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!cond()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('condition not met within $timeout');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

Future<List<int>> _readUpTo(StreamIterator<List<int>> it, int target) async {
  final data = <int>[];
  while (data.length < target) {
    if (!await it.moveNext()) {
      break;
    }
    data.addAll(it.current);
  }
  return data;
}

void main() {
  group('CONNECT', () {
    test('matched rule -> encrypted tunnel: 200, echo roundtrip, mock asserts frame', () async {
      final frames = <Map<String, dynamic>>[];
      final upstream = await _startMockUpstream(frames, ack: {'c': 200});
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode(
            'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n'));
        await client.flush();
        final head = await _readHead(it);
        expect(head, startsWith('HTTP/1.1 200 Connection Established'));

        client.add(utf8.encode('ping'));
        await client.flush();
        expect(utf8.decode((await _readUpTo(it, 4)).take(4).toList()), 'ping');

        await _waitUntil(() => frames.length == 1);
        expect(frames.single['m'], 'CONNECT');
        expect(frames.single['t'], 'www.example.com:443');
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }
    });

    test('upstream ACK 407 -> client receives HTTP 407', () async {
      final frames = <Map<String, dynamic>>[];
      final upstream = await _startMockUpstream(frames,
          ack: {'c': 407, 'm': 'Proxy Authentication Required'});
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode(
            'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n'));
        await client.flush();
        final head = await _readHead(it);
        expect(head, startsWith('HTTP/1.1 407 Proxy Authentication Required'));
        await _waitUntil(() => frames.length == 1);
        expect(frames.single['t'], 'www.example.com:443');
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }
    });

    test('unmatched rule -> direct connection to target', () async {
      final target = await _startEchoServer();
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: 1,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode(
            'CONNECT 127.0.0.1:${target.port} HTTP/1.1\r\n'
            'Host: 127.0.0.1:${target.port}\r\n\r\n'));
        await client.flush();
        final head = await _readHead(it);
        expect(head, startsWith('HTTP/1.1 200 Connection Established'));

        client.add(utf8.encode('ping'));
        await client.flush();
        expect(utf8.decode((await _readUpTo(it, 4)).take(4).toList()), 'ping');
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await target.close();
      }
    });

    test('ack timeout -> engine closes the tunnel when upstream is silent', () async {
      final frames = <Map<String, dynamic>>[];
      final upstream = await _startMockUpstream(frames);
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
        timeout: const Duration(milliseconds: 300),
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode(
            'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n'));
        await client.flush();
        final head = await _readHead(it);
        expect(head, isEmpty);
        await _waitUntil(() => frames.length == 1);
        expect(frames.single['t'], 'www.example.com:443');
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }
    });
  });

  group('HTTP', () {
    test('matched rule -> http frame carries method/path/headers, response relayed', () async {
      final frames = <Map<String, dynamic>>[];
      final upstream = await _startMockUpstream(
        frames,
        reply: () => utf8.encode('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'),
      );
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode('GET http://example.com/ HTTP/1.1\r\n'
            'Host: example.com\r\n\r\n'));
        await client.flush();
        await _waitUntil(() => frames.length == 1);
        expect(frames.single['m'], 'HTTP');
        expect(frames.single['r'], 'GET http://example.com/ HTTP/1.1');
        final headers = frames.single['h'] as Map<String, dynamic>;
        expect(headers['host'], 'example.com');

        final response = await _readUpTo(it, 2);
        final text = latin1.decode(response);
        expect(text, contains('HTTP/1.1 200 OK'));
        expect(text, contains('ok'));
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }
    });
  });

  group('lifecycle', () {
    test('stop() cancels active tunnels; close() releases the port', () async {
      final frames = <Map<String, dynamic>>[];
      final upstream = await _startMockUpstream(frames, ack: {'c': 200});
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode(
            'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n'));
        await client.flush();
        final head = await _readHead(it);
        expect(head, startsWith('HTTP/1.1 200 Connection Established'));
        expect(frames.single['t'], 'www.example.com:443');

        await engine.stop();
        expect(await _readHead(it), isEmpty);
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }

      final rebind = await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
      await rebind.close();
    });
  });

  group('logging', () {
    test('setRequestLogger receives (tag, target)', () async {
      final frames = <Map<String, dynamic>>[];
      final upstream = await _startMockUpstream(frames, ack: {'c': 200});
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      final logs = <(String, String)>[];
      engine.setRequestLogger((tag, target) => logs.add((tag, target)));
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        client.add(utf8.encode(
            'CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n'));
        await client.flush();
        final head = await _readHead(it);
        expect(head, startsWith('HTTP/1.1 200 Connection Established'));
        await _waitUntil(() => logs.isNotEmpty);
        expect(logs.single.$1, 'TUNNEL');
        expect(logs.single.$2, 'www.example.com:443');
      } finally {
        await it.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }
    });
  });
}