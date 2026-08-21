import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

const maxHeaderBytes = 65536;

/// Parsed HTTP head, mirroring Python `read_headers`' triple return
/// (request_line, headers, rest).
typedef HttpHead = ({String requestLine, Map<String, String> headers, Uint8List rest});

/// Port of Python `read_headers` (proxy_client.py L274-292).
///
/// Consumes the shared [StreamIterator] until `\r\n\r\n`, returning the
/// request line, headers (keys lowercased, values trimmed) and, in `rest`,
/// any bytes trailing the terminator inside the terminating chunk.
///
/// Single-consumer model: the caller owns [it] and must keep consuming the
/// same iterator afterwards to read the body bytes that arrive after the
/// header block (mirroring Python's `StreamReader` buffered `read`, where the
/// caller continues reading from the same reader). The caller is also
/// responsible for cancelling the iterator once the connection is done.
///
/// Returns `null` on EOF before the terminator or when the buffered head
/// exceeds [maxHeaderBytes].
Future<HttpHead?> readHeaders(StreamIterator<List<int>> it) async {
  final buf = <int>[];
  var scanned = 0;
  while (true) {
    if (!await it.moveNext()) {
      return null;
    }
    buf.addAll(it.current);
    final start = max(0, scanned - 3);
    for (var i = start; i + 3 < buf.length; i++) {
      if (buf[i] == 13 && buf[i + 1] == 10 && buf[i + 2] == 13 && buf[i + 3] == 10) {
        final head = buf.sublist(0, i);
        final rest = Uint8List.fromList(buf.sublist(i + 4));
        return _parseHead(head, rest);
      }
    }
    scanned = buf.length;
    if (buf.length > maxHeaderBytes) {
      return null;
    }
  }
}

HttpHead _parseHead(List<int> head, Uint8List rest) {
  final text = latin1.decode(head);
  final lines = text.split('\r\n');
  final requestLine = lines.first;
  final headers = <String, String>{};
  for (final line in lines.skip(1)) {
    final i = line.indexOf(':');
    if (i < 0) {
      continue;
    }
    final key = line.substring(0, i).trim().toLowerCase();
    final value = line.substring(i + 1).trim();
    headers[key] = value;
  }
  return (requestLine: requestLine, headers: headers, rest: rest);
}