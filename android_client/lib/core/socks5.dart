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

/// Parsed SOCKS5 UDP relay datagram (RFC 1928 §7 envelope).
class UdpEnvelope {
  const UdpEnvelope({
    required this.host,
    required this.port,
    required this.payload,
  });

  final String host;
  final int port;
  final Uint8List payload;
}

/// Parses a SOCKS5 UDP envelope (RSV/Frag must be zero per RFC 1928);
/// returns `null` for malformed or fragmented datagrams.
UdpEnvelope? parseUdpEnvelope(List<int> data) {
  if (data.length < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0) {
    return null;
  }
  final atyp = data[3];
  var offset = 4;
  String host;
  switch (atyp) {
    case 1:
      if (data.length < offset + 4) return null;
      host = '${data[4]}.${data[5]}.${data[6]}.${data[7]}';
      offset += 4;
    case 3:
      if (data.length < offset + 1) return null;
      final len = data[offset];
      if (data.length < offset + 1 + len) return null;
      host = latin1.decode(data.sublist(offset + 1, offset + 1 + len));
      offset += 1 + len;
    case 4:
      if (data.length < offset + 16) return null;
      host = InternetAddress.fromRawAddress(
        Uint8List.fromList(data.sublist(offset, offset + 16)),
      ).address;
      offset += 16;
    default:
      return null;
  }
  if (data.length < offset + 2) {
    return null;
  }
  final port = (data[offset] << 8) | data[offset + 1];
  return UdpEnvelope(
    host: host,
    port: port,
    payload: Uint8List.fromList(data.sublist(offset + 2)),
  );
}

/// Builds a SOCKS5 UDP envelope addressed to [host]:[port] (IPv4/IPv6 as
/// numeric strings, falling back to a domain name otherwise).
Uint8List buildUdpEnvelope({
  required String host,
  required int port,
  required List<int> payload,
}) {
  final b = <int>[0, 0];
  final v4 = InternetAddress.tryParse(host);
  if (v4 != null && v4.rawAddress.length == 4) {
    b..addAll(const [0, 1])..addAll(v4.rawAddress);
  } else if (v4 != null && v4.rawAddress.length == 16) {
    b
      ..addAll([0, 4])
      ..addAll(v4.rawAddress);
  } else {
    final hp = utf8.encode(host);
    b
      ..addAll([0, 3, hp.length])
      ..addAll(hp);
  }
  b
    ..add((port >> 8) & 0xff)
    ..add(port & 0xff)
    ..addAll(payload);
  return Uint8List.fromList(b);
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