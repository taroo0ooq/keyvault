import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Pure-Dart TOTP (RFC 6238, HMAC-SHA1, 6 digits / 30s) for mock mode and UI.
/// Matches vault-core when secret is valid base32.
class TotpDart {
  TotpDart._();

  static const int periodSecs = 30;
  static const int digits = 6;

  /// Generate code from base32 secret (spaces/padding ignored) or otpauth:// URI.
  static Map<String, dynamic> generate(String secretOrUri, {int? unixTime}) {
    final secret = normalizeSecret(secretOrUri);
    final key = base32Decode(secret);
    if (key.isEmpty) {
      throw ArgumentError('empty TOTP secret');
    }
    final now =
        unixTime ?? DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final counter = now ~/ periodSecs;
    final remaining = periodSecs - (now % periodSecs);
    final code = hotp(key, counter, digits);
    return {
      'code': code,
      'period_secs': periodSecs,
      'remaining_secs': remaining,
      'digits': digits,
    };
  }

  static String normalizeSecret(String input) {
    final t = input.trim();
    final lower = t.toLowerCase();
    if (lower.startsWith('otpauth://')) {
      final q = t.contains('?') ? t.split('?').sublist(1).join('?') : '';
      for (final pair in q.split('&')) {
        final parts = pair.split('=');
        if (parts.length >= 2 && parts[0].toLowerCase() == 'secret') {
          return Uri.decodeComponent(parts.sublist(1).join('='))
              .replaceAll(RegExp(r'[\s=]'), '');
        }
      }
    }
    return t.replaceAll(RegExp(r'[\s=]'), '');
  }

  static String hotp(List<int> key, int counter, int digits) {
    final data = ByteData(8)..setUint64(0, counter, Endian.big);
    final hmac = Hmac(sha1, key);
    final digest = hmac.convert(data.buffer.asUint8List()).bytes;
    final offset = digest[19] & 0x0f;
    final bin = ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff);
    final mod = _pow10(digits);
    final code = bin % mod;
    return code.toString().padLeft(digits, '0');
  }

  static int _pow10(int n) {
    var v = 1;
    for (var i = 0; i < n; i++) {
      v *= 10;
    }
    return v;
  }

  /// RFC 4648 base32 decode.
  static List<int> base32Decode(String input) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final cleaned = input.toUpperCase().replaceAll(RegExp(r'[\s=]'), '');
    if (cleaned.isEmpty) return [];
    var buffer = 0;
    var bits = 0;
    final out = <int>[];
    for (final c in cleaned.codeUnits) {
      final idx = alphabet.codeUnits.indexOf(c);
      if (idx < 0) {
        throw ArgumentError(
          'invalid base32 character: ${String.fromCharCode(c)}',
        );
      }
      buffer = (buffer << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.add((buffer >> bits) & 0xff);
      }
    }
    return out;
  }
}
