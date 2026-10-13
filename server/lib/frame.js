'use strict';
const crypto = require('crypto');
const MAGIC = 0x5a;
const MAX_PAYLOAD = 65536;
const HEADER_LEN = 21;
const TAG_LEN = 32;

function keyFor(secret) {
  return crypto.createHmac('sha256', secret).update('z-proxy:enc:v1').digest();
}
function xor(payload, key, nonce) {
  const out = Buffer.alloc(payload.length);
  for (let offset = 0, counter = 0; offset < payload.length; offset += 32, counter++) {
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(counter);
    const ks = crypto.createHmac('sha256', key).update(nonce).update(ctr).digest();
    for (let i = 0; i < Math.min(32, payload.length - offset); i++) out[offset + i] = payload[offset + i] ^ ks[i];
  }
  return out;
}
function encryptFrame(payload, key) {
  if (payload.length > MAX_PAYLOAD) throw new Error('frame payload too large');
  const nonce = crypto.randomBytes(16);
  const ct = xor(payload, key, nonce);
  const tag = crypto.createHmac('sha256', key).update(nonce).update(ct).digest();
  const head = Buffer.alloc(HEADER_LEN);
  head[0] = MAGIC;
  head.writeUInt32BE(ct.length, 1);
  nonce.copy(head, 5);
  return Buffer.concat([head, ct, tag]);
}
function decryptFrame(frame, key) {
  if (frame.length < HEADER_LEN + TAG_LEN || frame[0] !== MAGIC) return null;
  const n = frame.readUInt32BE(1);
  if (n > MAX_PAYLOAD || frame.length !== HEADER_LEN + n + TAG_LEN) return null;
  const nonce = frame.subarray(5, HEADER_LEN);
  const ct = frame.subarray(HEADER_LEN, HEADER_LEN + n);
  const tag = frame.subarray(HEADER_LEN + n);
  const expected = crypto.createHmac('sha256', key).update(nonce).update(ct).digest();
  if (!crypto.timingSafeEqual(tag, expected)) return null;
  return xor(ct, key, nonce);
}

module.exports = { MAGIC, MAX_PAYLOAD, HEADER_LEN, TAG_LEN, keyFor, encryptFrame, decryptFrame };
