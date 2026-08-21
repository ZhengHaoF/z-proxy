import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zhihu_proxy_client/core/crypto_frame.dart';
import 'package:zhihu_proxy_client/core/proxy_engine.dart';

const _token = 'socks5-test-token';
final _key = keyFor(_token);

Future<ServerSocket> _startMockUpstream(List<Map<String, dynamic>> frames) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) {
    unawaited(_handleMock(socket, frames));
  }, onError: (_) {});
  return server;
}

Future<void> _handleMock(Socket socket, List<Map<String, dynamic>> frames) async {
  final it = StreamIterator(socket);
  try {
    final data = await readFrame(it, _key);
    if (data == null) {
      return;
    }
    frames.add(jsonDecode(utf8.decode(data.payload)) as Map<String, dynamic>);
    socket.add(encryptFrame(utf8.encode(jsonEncode({'c': 200})), _key));
    await socket.flush();
    if (data.rest.isNotEmpty) {
      socket.add(data.rest);
      await socket.flush();
    }
    while (await it.moveNext()) {
      socket.add(it.current);
      await socket.flush();
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

Future<void> _writeBytes(Socket socket, List<int> bytes) async {
  socket.add(bytes);
  await socket.flush();
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

void main() {
  late ProxyEngine engine;
  late int port;

  setUp(() {
    engine = ProxyEngine(
      serverHost: '127.0.0.1',
      serverPort: 1,
      token: _token,
      rules: ['*.example.com'],
      mode: 'matched',
    );
  });

  tearDown(() async {
    await engine.close();
  });

  test('handshake: no-auth offered -> 05 00', () async {
    port = await engine.serveSocks();
    final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
    final it = StreamIterator(client);
    try {
      await _writeBytes(client, [5, 1, 0]);
      expect(await _readUpTo(it, 2), [5, 0]);
    } finally {
      await it.cancel();
      client.destroy();
    }
  });

  test('handshake: no acceptable method -> 05 FF then close', () async {
    port = await engine.serveSocks();
    final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
    final it = StreamIterator(client);
    try {
      await _writeBytes(client, [5, 1, 1]);
      expect(await _readUpTo(it, 2), [5, 255]);
      expect(await it.moveNext(), isFalse);
    } finally {
      await it.cancel();
      client.destroy();
    }
  });

  test('CONNECT ipv4 target -> direct, fixed success reply, echo roundtrip',
      () async {
    final target = await _startEchoServer();
    try {
      port = await engine.serveSocks();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        await _writeBytes(client, [5, 1, 0]);
        expect(await _readUpTo(it, 2), [5, 0]);
        final octets = InternetAddress.loopbackIPv4.address
            .split('.')
            .map(int.parse);
        final p = target.port;
        await _writeBytes(client, [
          5, 1, 0, 1, ...octets, (p >> 8) & 0xff, p & 0xff,
        ]);
        expect(await _readUpTo(it, 10), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        await _writeBytes(client, utf8.encode('ping'));
        expect(utf8.decode(await _readUpTo(it, 4)), 'ping');
      } finally {
        await it.cancel();
        client.destroy();
      }
    } finally {
      await target.close();
    }
  });

  test('CONNECT domain matching rule -> upstream tunnel, frame + echo',
      () async {
    final frames = <Map<String, dynamic>>[];
    final upstream = await _startMockUpstream(frames);
    try {
      engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: upstream.port,
        token: _token,
        rules: ['*.example.com'],
        mode: 'matched',
      );
      port = await engine.serveSocks();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final it = StreamIterator(client);
      try {
        await _writeBytes(client, [5, 1, 0]);
        expect(await _readUpTo(it, 2), [5, 0]);
        final dom = utf8.encode('example.com');
        await _writeBytes(
            client, [5, 1, 0, 3, dom.length, ...dom, 0x01, 0xbb]);
        expect(await _readUpTo(it, 10), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        await _writeBytes(client, utf8.encode('hi'));
        expect(utf8.decode(await _readUpTo(it, 2)), 'hi');
        await _waitUntil(() => frames.isNotEmpty);
        expect(frames.single['m'], 'CONNECT');
        expect(frames.single['t'], 'example.com:443');
      } finally {
        await it.cancel();
        client.destroy();
      }
    } finally {
      await upstream.close();
    }
  });

  test('BIND / UDP ASSOCIATE -> 05 07 then close', () async {
    port = await engine.serveSocks();
    final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
    final it = StreamIterator(client);
    try {
      await _writeBytes(client, [5, 1, 0]);
      expect(await _readUpTo(it, 2), [5, 0]);
      await _writeBytes(client, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
      expect(await _readUpTo(it, 2), [5, 7]);
      expect(await it.moveNext(), isFalse);
    } finally {
      await it.cancel();
      client.destroy();
    }
  });
}