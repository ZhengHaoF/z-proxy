import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// Buffered reads over a shared [StreamIterator], mirroring the rest/buffer
/// semantics of `readFrame`/`readHeaders`.
///
/// The SOCKS client may pipeline the greeting and the CONNECT request (or
/// early payload bytes) in one TCP segment; bytes consumed past the parsed
/// fields are kept here so the caller can re-inject them after routing.
class SocksBuf {
  final BytesBuilder _rest = BytesBuilder(copy: false);

  bool get hasRemaining => _rest.length > 0;

  /// Reads exactly [n] bytes (buffered first, then the shared [it]), or
  /// returns `null` on EOF before [n] bytes are available.
  Future<Uint8List?> readExact(StreamIterator<List<int>> it, int n) async {
    while (_rest.length < n) {
      if (!await it.moveNext()) {
        return null;
      }
      _rest.add(it.current);
    }
    final all = _rest.takeBytes();
    final out = Uint8List.fromList(all.sublist(0, n));
    if (all.length > n) {
      _rest.add(all.sublist(n));
    }
    return out;
  }

  /// Bytes buffered past the last parsed field.
  Uint8List takeRemaining() => _rest.takeBytes();
}

/// Parsed SOCKS5 request (RFC 1928 §4).
class SocksRequest {
  const SocksRequest({
    required this.command,
    required this.host,
    required this.port,
  });

  /// 1 = CONNECT, 2 = BIND, 3 = UDP ASSOCIATE.
  final int command;
  final String host;
  final int port;
}

const socksMethodNoAuth = 0;
const socksOk = 0x00; // request granted
const socksGeneralFailure = 0x01;
const socksConnectionNotAllowed = 0x02;
const socksConnectionRefused = 0x05;
const socksHostUnreachable = 0x04;
const socksCommandNotSupported = 0x07;

/// Parses the SOCKS5 greeting (RFC 1928 §3): returns the selected method
/// (0 = no-auth) or `-1` when none of the offered methods is acceptable,
/// or `null` on EOF before the greeting completes.
Future<int?> readSocksHandshake(StreamIterator<List<int>> it, SocksBuf buf) async {
  final head = await buf.readExact(it, 2);
  if (head == null) {
    return null;
  }
  final nmethods = head[1];
  final methods = await buf.readExact(it, nmethods);
  if (methods == null) {
    return null;
  }
  return methods.contains(socksMethodNoAuth) ? 0 : -1;
}

/// Parses the SOCKS5 request (RFC 1928 §4) with ATYP 1/3/4 (IPv4 / domain /
/// IPv6), returning the parsed [SocksRequest] or `null` on EOF or malformed
/// fields. The implemented commands are then up to the caller.
Future<SocksRequest?> readSocksRequest(
    StreamIterator<List<int>> it, SocksBuf buf) async {
  final head = await buf.readExact(it, 4);
  if (head == null || head[0] != 5) {
    return null;
  }
  final command = head[1];
  final atyp = head[3];
  String? host;
  switch (atyp) {
    case 1:
      final b = await buf.readExact(it, 4);
      if (b == null) {
        return null;
      }
      host = '${b[0]}.${b[1]}.${b[2]}.${b[3]}';
    case 3:
      final len = await buf.readExact(it, 1);
      if (len == null) {
        return null;
      }
      final b = await buf.readExact(it, len[0]);
      if (b == null) {
        return null;
      }
      host = latin1.decode(b);
    case 4:
      final b = await buf.readExact(it, 16);
      if (b == null) {
        return null;
      }
      host = InternetAddress.fromRawAddress(b).address;
    default:
      return null;
  }
  final portBytes = await buf.readExact(it, 2);
  if (portBytes == null) {
    return null;
  }
  final port = (portBytes[0] << 8) | portBytes[1];
  return SocksRequest(command: command, host: host, port: port);
}