import 'dart:io';

const defaultBypass = ['localhost', '127.0.0.1', '::1'];

/// Port of Python `domain_matches` (proxy_client.py L96-114).
bool domainMatches(String host, List<String> rules) {
  if (host.isEmpty) {
    return false;
  }
  final h = host.toLowerCase();
  for (final rule in rules) {
    final r = rule.trim().toLowerCase();
    if (r.isEmpty) {
      continue;
    }
    if (r.startsWith('*.')) {
      final base = r.substring(2);
      if (h == base || h.endsWith('.$base')) {
        return true;
      }
    } else if (r.startsWith('.')) {
      if (h == r.substring(1) || h.endsWith(r)) {
        return true;
      }
    } else {
      if (h == r || h.endsWith('.$r')) {
        return true;
      }
    }
  }
  return false;
}

/// Port of Python `_is_private_ip` (proxy_client.py L117-122).
///
/// Uses the same *effective* ranges as `ipaddress.ip_address(host).is_private
/// or is_link_local or is_multicast` for the ranges exercised by the rules.
bool isPrivateIp(String host) {
  final v4 = _parseIpv4(host);
  if (v4 != null) {
    final a = v4[0], b = v4[1];
    if (a == 10) return true; // 10.0.0.0/8
    if (a == 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10
    if (a == 127) return true; // loopback
    if (a == 169 && b == 254) return true; // 169.254.0.0/16 link-local
    if (a == 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a == 192 && b == 168) return true; // 192.168.0.0/16
    if (a == 198 && (b == 18 || b == 19)) return true; // 198.18.0.0/15
    if (a >= 224 && a <= 239) return true; // multicast
    if (a >= 240) return true; // reserved / broadcast
    return false;
  }
  final v6 = _parseIpv6(host);
  if (v6 != null) {
    final b = v6;
    if (b[0] == 0xff) return true; // ff00::/8 multicast
    if ((b[0] & 0xfe) == 0xfc) return true; // fc00::/7 ULA
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return true; // fe80::/10
    if (b[0] == 0x01 && b[1] == 0x00) return true; // 100::/64 discard
    if (b[0] == 0x20 && b[1] == 0x01) {
      // 2001::/23 (b[2] high 7 bits zero) is private per Python ipaddress
      if ((b[2] & 0xfe) == 0) return true;
      // 2001:db8::/32 documentation (not covered by 2001::/23)
      if (b[2] == 0x0d && b[3] == 0xb8) return true;
    }
    // :: / ::1
    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) {
      if (b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0) {
        if (b[8] == 0 && b[9] == 0) {
          if (b[10] == 0 && b[11] == 0) {
            if (b[12] == 0 && b[13] == 0) {
              // :: (unspecified) or ::1
              if (b[14] == 0 && b[15] <= 1) return true;
            }
          }
        }
      }
    }
    return false;
  }
  return false;
}

/// Port of Python `is_bypass` (proxy_client.py L125-146), parameterized.
bool isBypass(String host, List<String> bypass) {
  if (host.isEmpty) {
    return false;
  }
  final h = host.toLowerCase().trim();
  if (isPrivateIp(h)) {
    return true;
  }
  for (final entry in bypass) {
    final r = entry.trim().toLowerCase();
    if (r.isEmpty) {
      continue;
    }
    if (r.startsWith('*.')) {
      final base = r.substring(2);
      if (h == base || h.endsWith('.$base')) {
        return true;
      }
    } else if (r.startsWith('.')) {
      if (h == r.substring(1) || h.endsWith(r)) {
        return true;
      }
    } else {
      if (h == r || h.endsWith('.$r')) {
        return true;
      }
    }
  }
  return false;
}

/// Port of Python `_use_server` (proxy_client.py L149-153), parameterized.
///
/// Note: unlike Python, an empty host never goes to the server in `all` mode.
bool useServer(
  String host, {
  required List<String> rules,
  required String mode,
  List<String>? bypass,
}) {
  if (host.isEmpty) {
    return false;
  }
  if (mode == 'all') {
    return !isBypass(host, bypass ?? defaultBypass);
  }
  return domainMatches(host, rules);
}

List<int>? _parseIpv4(String host) {
  final parts = host.split('.');
  if (parts.length != 4) {
    return null;
  }
  final bytes = <int>[];
  for (final part in parts) {
    if (part.isEmpty || part.length > 3 || (part.length > 1 && part.startsWith('0'))) {
      return null;
    }
    final v = int.tryParse(part);
    if (v == null || v < 0 || v > 255) {
      return null;
    }
    bytes.add(v);
  }
  return bytes;
}

List<int>? _parseIpv6(String host) {
  final addr = InternetAddress.tryParse(host);
  if (addr == null || addr.rawAddress.length != 16) {
    return null;
  }
  return addr.rawAddress;
}