import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zproxy_client/core/crypto_frame.dart';
import 'package:zproxy_client/core/proxy_engine.dart';
import 'package:zproxy_client/core/socks5.dart';

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
    test('ACK and upstream greeting in one write preserves trailing payload', () async {
      final upstream = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      upstream.listen((socket) {
        unawaited(() async {
          final input = StreamIterator(socket);
          try {
            await readFrame(input, _key);
            socket.add([
              ...encryptFrame(utf8.encode(jsonEncode({'c': 200})), _key),
              ...utf8.encode('upstream-greeting'),
            ]);
            await socket.flush();
            await socket.close();
          } finally {
            await input.cancel();
            socket.destroy();
          }
        }());
      });
      final engine = ProxyEngine(
        serverHost: '127.0.0.1', serverPort: upstream.port,
        token: _token, rules: ['example.com'], mode: 'matched',
      );
      final port = await engine.serve();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, port);
      final input = StreamIterator(client);
      try {
        client.add(utf8.encode('CONNECT example.com:443 HTTP/1.1\r\n\r\n'));
        await client.flush();
        final bytes = <int>[];
        while (await input.moveNext().timeout(const Duration(seconds: 3))) {
          bytes.addAll(input.current);
        }
        expect(latin1.decode(bytes),
            'HTTP/1.1 200 Connection Established\r\n\r\nupstream-greeting');
      } finally {
        await input.cancel();
        client.destroy();
        await engine.close();
        await upstream.close();
      }
    });
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

  group('isDnsTarget', () {
    test('DNS ports and the configured server match; everything else does not', () {
      expect(isDnsTarget('223.5.5.5', 53, null), isTrue);
      expect(isDnsTarget('223.5.5.5', 853, null), isTrue);
      expect(isDnsTarget('dns.example.com', 853, '223.5.5.5'), isTrue);
      expect(isDnsTarget('223.5.5.5', 443, '223.5.5.5'), isTrue);
      expect(isDnsTarget('www.example.com', 443, '223.5.5.5'), isFalse);
      expect(isDnsTarget('www.example.com', 443, null), isFalse);
      expect(isDnsTarget('www.example.com', 53, '223.5.5.5'), isTrue);
    });
  });

  group('UDP relay', () {
    test('DNS datagrams round-trip through the relay', () async {
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: 1, // unused by the UDP relay
        token: _token,
        rules: [],
        mode: 'matched',
        dnsServer: '127.0.0.1',
      );
      final socksPort = await engine.serveSocks();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, socksPort);
      final it = StreamIterator(client);
      RawDatagramSocket? target;
      RawDatagramSocket? relay;
      try {
        // Greeting + UDP ASSOCIATE (RFC 1928 §7).
        client.add([0x05, 0x01, 0x00]);
        await client.flush();
        expect((await _readUpTo(it, 2)).toList(), [0x05, 0x00]);
        client.add([0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
        await client.flush();
        final granted = (await _readUpTo(it, 10)).toList();
        expect(granted.sublist(0, 4), [0x05, 0x00, 0x00, 0x01]);
        expect(granted.sublist(4, 8), [127, 0, 0, 1]);
        final relayPort = (granted[8] << 8) | granted[9];
        expect(relayPort, isNonZero);

        // Local UDP "DNS server" that echoes payloads back.
        target = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
        final echoTarget = target;
        echoTarget.listen((event) {
          if (event == RawSocketEvent.read) {
            final dg = echoTarget.receive();
            if (dg != null) {
              echoTarget.send(dg.data, dg.address, dg.port);
            }
          }
        });

        relay = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
        final relaySock = relay;

        // host == dnsServer ('127.0.0.1'): forwarded to the target and the
        // echo comes back wrapped in a fresh envelope.
        final reply = await _waitUdp(relay, send: () {
          relaySock.send(
            buildUdpEnvelope(host: '127.0.0.1', port: echoTarget.port, payload: [1, 2, 3]),
            InternetAddress.loopbackIPv4,
            relayPort,
          );
        });
        expect(reply, isNotNull);
        final back = parseUdpEnvelope(reply!.data);
        expect(back, isNotNull);
        expect(back!.port, target.port);
        expect(back.payload, [1, 2, 3]);
      } finally {
        relay?.close();
        target?.close();
        await it.cancel();
        client.destroy();
        await engine.close();
      }
    });

    test('non-DNS datagrams (QUIC etc.) are dropped, not forwarded', () async {
      final engine = ProxyEngine(
        serverHost: '127.0.0.1',
        serverPort: 1,
        token: _token,
        rules: [],
        mode: 'all',
        dnsServer: '127.0.0.1',
      );
      final socksPort = await engine.serveSocks();
      final client = await Socket.connect(InternetAddress.loopbackIPv4, socksPort);
      final it = StreamIterator(client);
      RawDatagramSocket? target;
      RawDatagramSocket? relay;
      try {
        client.add([0x05, 0x01, 0x00]);
        await client.flush();
        expect((await _readUpTo(it, 2)).toList(), [0x05, 0x00]);
        client.add([0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0]);
        await client.flush();
        final granted = (await _readUpTo(it, 10)).toList();
        final relayPort = (granted[8] << 8) | granted[9];

        target = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
        var received = 0;
        target.listen((event) {
          if (event == RawSocketEvent.read && target!.receive() != null) {
            received++;
          }
        });
        relay = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);

        // 'www.example.com:443' is neither a DNS port nor the configured
        // dnsServer: the relay must drop it instead of egressing directly.
        final none = await _waitUdp(relay, timeout: const Duration(milliseconds: 500), send: () {
          relay!.send(
            buildUdpEnvelope(host: 'www.example.com', port: 443, payload: [9]),
            InternetAddress.loopbackIPv4,
            relayPort,
          );
        });
        expect(none, isNull);
        // The datagram must not have reached the (loopback-bindable) target
        // either — 'www.example.com' resolves elsewhere, but the drop happens
        // before any lookup/socket work, which the zero receive count and the
        // quiet relay window above confirm.
        expect(received, 0);
      } finally {
        relay?.close();
        target?.close();
        await it.cancel();
        client.destroy();
        await engine.close();
      }
    });
  });
}

Future<Datagram?> _waitUdp(
  RawDatagramSocket socket, {
  void Function()? send,
  Duration timeout = const Duration(seconds: 2),
}) async {
  // Subscribe BEFORE triggering the send: a RawDatagramSocket drops
  // datagrams that arrive while no listener is registered.
  final completer = Completer<Datagram?>();
  late final StreamSubscription<RawSocketEvent> sub;
  sub = socket.listen((event) {
    if (event == RawSocketEvent.read && !completer.isCompleted) {
      // Consume first, cancel later: cancelling the subscription up front
      // can discard the buffered datagram and yield a null receive().
      final dg = socket.receive();
      if (dg != null) {
        sub.cancel();
        completer.complete(dg);
      }
    }
  });
  send?.call();
  final timer = Timer(timeout, () {
    if (!completer.isCompleted) {
      sub.cancel();
      completer.complete(null);
    }
  });
  final result = await completer.future;
  timer.cancel();
  return result;
}
