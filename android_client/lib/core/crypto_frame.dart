import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

const magicByte = 0x5A;
const encCtx = 'zhihu-proxy:enc:v1';
const maxPayload = 65536;
const nonceLen = 16;
const tagLen = 32;
const headerLen = 1 + 4 + nonceLen;

Uint8List keyFor(String token) =>
    Uint8List.fromList(Hmac(sha256, utf8.encode(token)).convert(utf8.encode(encCtx)).bytes);

Uint8List keystream(Uint8List key, Uint8List nonce, int length) {
  final out = BytesBuilder(copy: false);
  var counter = 0;
  while (out.length < length) {
    final b = BytesBuilder(copy: false);
    b.add(nonce);
    b.addByte((counter >> 24) & 0xff);
    b.addByte((counter >> 16) & 0xff);
    b.addByte((counter >> 8) & 0xff);
    b.addByte(counter & 0xff);
    out.add(Hmac(sha256, key).convert(b.toBytes()).bytes);
    counter++;
  }
  final bytes = out.takeBytes();
  return bytes.sublist(0, length);
}

Uint8List encryptFrame(Uint8List payload, Uint8List key) {
  final rng = Random.secure();
  final nonce = Uint8List.fromList(List.generate(nonceLen, (_) => rng.nextInt(256)));
  final ks = keystream(key, nonce, payload.length);
  final ct = Uint8List(payload.length);
  for (var i = 0; i < payload.length; i++) {
    ct[i] = payload[i] ^ ks[i];
  }
  final tag = Hmac(sha256, key).convert([...nonce, ...ct]).bytes;
  final frame = BytesBuilder(copy: false);
  frame.addByte(magicByte);
  frame.add([
    (ct.length >> 24) & 0xff,
    (ct.length >> 16) & 0xff,
    (ct.length >> 8) & 0xff,
    ct.length & 0xff,
  ]);
  frame.add(nonce);
  frame.add(ct);
  frame.add(tag);
  return frame.takeBytes();
}

Uint8List? decryptFrame(Uint8List frame, Uint8List key) {
  if (frame.length < headerLen || frame[0] != magicByte) {
    return null;
  }
  final n = (frame[1] << 24) | (frame[2] << 16) | (frame[3] << 8) | frame[4];
  if (n > maxPayload || frame.length != headerLen + n + tagLen) {
    return null;
  }
  final nonce = frame.sublist(5, 21);
  final ct = frame.sublist(21, 21 + n);
  final tag = frame.sublist(21 + n);
  final expect = Hmac(sha256, key).convert([...nonce, ...ct]).bytes;
  if (!constEquals(tag, expect)) {
    return null;
  }
  final ks = keystream(key, nonce, ct.length);
  final out = Uint8List(ct.length);
  for (var i = 0; i < ct.length; i++) {
    out[i] = ct[i] ^ ks[i];
  }
  return out;
}

typedef FrameData = ({Uint8List payload, Uint8List rest});

/// Reads one encrypted frame from the shared [it], returning the decrypted
/// [FrameData.payload] plus any [FrameData.rest] bytes that arrived in the
/// same chunk(s) but trail the frame end.
///
/// Single-consumer model (mirrors `readHeaders`): the caller owns [it] and
/// must keep consuming the same iterator afterwards — e.g. when a frame and
/// following data arrive together, the trailing bytes are handed back via
/// [FrameData.rest] instead of being lost (Python's `StreamReader` keeps
/// them in its internal buffer; Dart has no such buffer).
///
/// Returns `null` on EOF before the frame completes, bad magic, an oversized
/// declared length, or a tag mismatch.
Future<FrameData?> readFrame(StreamIterator<List<int>> it, Uint8List key) async {
  final head = await _readExact(it, headerLen);
  if (head == null || head.length < headerLen || head[0] != magicByte) {
    return null;
  }
  final n = (head[1] << 24) | (head[2] << 16) | (head[3] << 8) | head[4];
  if (n > maxPayload) {
    return null;
  }
  final total = headerLen + n + tagLen;
  final body = await _readExact(it, total - head.length);
  if (body == null || head.length + body.length < total) {
    return null;
  }
  final bytes = BytesBuilder(copy: false)..add(head)..add(body);
  final all = bytes.takeBytes();
  final payload = decryptFrame(all.sublist(0, total), key);
  if (payload == null) {
    return null;
  }
  return (payload: payload, rest: all.sublist(total));
}

Future<Uint8List?> _readExact(StreamIterator<List<int>> it, int n) async {
  final buf = BytesBuilder(copy: false);
  while (buf.length < n) {
    if (!await it.moveNext()) {
      return null;
    }
    buf.add(it.current);
  }
  return buf.takeBytes();
}

bool constEquals(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}