"""Golden vector generator for the cross-language encrypted frame protocol.

Generates test/vectors/frames.json containing frames produced by the Python
client implementation, used by the Dart test suite to verify byte-level
compatibility between the Python and Dart implementations.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'client'))
from proxy_client import _key_for, decrypt_frame, encrypt_frame

TOKEN = 'zhihu-proxy-dev'
OUT = Path(__file__).resolve().parent.parent / 'test' / 'vectors' / 'frames.json'


def main():
    key = _key_for(TOKEN)
    payloads = [
        b'hello world',
        b'\x00\x01\x02\xff' * 64,
        json.dumps({'m': 'CONNECT', 't': 'example.com:443'}).encode(),
    ]
    vectors = []
    for p in payloads:
        frame = encrypt_frame(payload=p, key=key)
        assert decrypt_frame(frame, key) == p
        assert frame[0] == 0x5A
        vectors.append({'payload_hex': p.hex(), 'frame_hex': frame.hex()})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({'token': TOKEN, 'vectors': vectors}, indent=2), encoding='utf-8')
    print('OK', len(vectors), '->', OUT)


if __name__ == '__main__':
    main()