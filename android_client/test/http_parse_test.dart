import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zproxy_client/core/http_parse.dart';

Stream<List<int>> streamOf(List<List<int>> chunks) => Stream.fromIterable(chunks);

/// Convenience for tests that do not need the shared-iterator semantics:
/// reads the head and cancels the iterator afterwards.
Future<HttpHead?> readFrom(Stream<List<int>> stream) async {
  final it = StreamIterator(stream);
  try {
    return await readHeaders(it);
  } finally {
    await it.cancel();
  }
}

void main() {
  group('readHeaders', () {
    test('parses request line and headers, lowercasing keys and trimming values', () async {
      final raw = "GET http://example.com/ HTTP/1.1\r\n"
          "Host: Example.COM\r\n"
          "User-Agent: curl/8.0  \r\n"
          "X-Custom:  a  b  \r\n"
          "\r\n";
      final h = await readFrom(streamOf([utf8.encode(raw)]));
      expect(h, isNotNull);
      expect(h!.requestLine, 'GET http://example.com/ HTTP/1.1');
      expect(h.headers, {
        'host': 'Example.COM',
        'user-agent': 'curl/8.0',
        'x-custom': 'a  b',
      });
      expect(h.rest, isEmpty);
    });

    test('rest carries bytes after the header terminator from the same chunk', () async {
      final bytes = utf8.encode('GET / HTTP/1.1\r\nHost: a\r\n\r\n{"hello":1}');
      final h = await readFrom(streamOf([bytes]));
      expect(h, isNotNull);
      expect(h!.requestLine, 'GET / HTTP/1.1');
      expect(h.headers['host'], 'a');
      expect(utf8.decode(h.rest), '{"hello":1}');
    });

    test('header split across writes; body continues on the same iterator', () async {
      final bytes = utf8.encode('POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\nab');
      final chunks = <List<int>>[for (final b in bytes) [b]];
      final it = StreamIterator(streamOf(chunks));
      try {
        final h = await readHeaders(it);
        expect(h, isNotNull);
        expect(h!.requestLine, 'POST /x HTTP/1.1');
        expect(h.headers['content-length'], '2');
        final body = <int>[...h.rest];
        while (await it.moveNext()) {
          body.addAll(it.current);
        }
        expect(utf8.decode(body), 'ab');
      } finally {
        await it.cancel();
      }
    });

    test('terminator split across chunk boundaries is still found', () async {
      final bytes = utf8.encode('GET / HTTP/1.1\r\nHost: a\r\n\r\n');
      final splitAt = bytes.length - 3;
      final h = await readFrom(streamOf([
        bytes.sublist(0, splitAt),
        bytes.sublist(splitAt),
      ]));
      expect(h, isNotNull);
      expect(h!.requestLine, 'GET / HTTP/1.1');
      expect(h.rest, isEmpty);
    });

    test('lines without a colon are ignored', () async {
      final raw = 'GET / HTTP/1.1\r\n'
          'not-a-header\r\n'
          'X-A: 1\r\n'
          '     \r\n'
          '\r\n';
      final h = await readFrom(streamOf([utf8.encode(raw)]));
      expect(h, isNotNull);
      expect(h!.requestLine, 'GET / HTTP/1.1');
      expect(h.headers, {'x-a': '1'});
    });

    test('repeated headers keep the last value', () async {
      final raw = 'GET / HTTP/1.1\r\n'
          'X-A: 1\r\n'
          'X-A: 2\r\n'
          '\r\n';
      final h = await readFrom(streamOf([utf8.encode(raw)]));
      expect(h, isNotNull);
      expect(h!.headers['x-a'], '2');
    });

    test('returns null when stream ends before the header terminator', () async {
      final h = await readFrom(streamOf([utf8.encode('GET / HTTP/1.1\r\nHost: a')]));
      expect(h, isNull);
    });

    test('returns null on an empty stream', () async {
      expect(await readFrom(streamOf(const [])), isNull);
    });

    test('returns null when header block exceeds 65536 bytes without terminator', () async {
      final h = await readFrom(streamOf([List<int>.filled(65537, 0x61)]));
      expect(h, isNull);
    });

    test('allows a block that fits exactly within 65536 bytes when it terminates', () async {
      final line = List<int>.filled(65536 - 4, 0x61);
      final h = await readFrom(streamOf([[...line, 13, 10, 13, 10]]));
      expect(h, isNotNull);
      expect(h!.requestLine.length, 65532);
      expect(h.headers, isEmpty);
    });

    test('latin-1 decodes non-ascii bytes without throwing', () async {
      final raw = <int>[
        ...utf8.encode('GET / HTTP/1.1\r\nX-Weird: caf'),
        0xE9,
        ...utf8.encode('\r\n\r\n'),
      ];
      final h = await readFrom(streamOf([raw]));
      expect(h, isNotNull);
      expect(h!.requestLine, 'GET / HTTP/1.1');
      expect(h.headers['x-weird'], 'café');
    });

    test('works with delayed async chunks on a shared iterator', () async {
      final controller = StreamController<List<int>>();
      final it = StreamIterator(controller.stream);
      final future = readHeaders(it);
      controller.add(utf8.encode('GET / HTTP/1.1\r\n'));
      await Future<void>.delayed(Duration.zero);
      controller.add(utf8.encode('Host: a\r\n\r\n'));
      final h = await future;
      await it.cancel();
      await controller.close();
      expect(h, isNotNull);
      expect(h!.requestLine, 'GET / HTTP/1.1');
      expect(h.headers['host'], 'a');
    });
  });
}