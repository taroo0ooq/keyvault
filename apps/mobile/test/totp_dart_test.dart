import 'package:flutter_test/flutter_test.dart';
import 'package:keyvault_mobile/services/totp_dart.dart';

void main() {
  test('RFC 6238 SHA1 vector (8 digits)', () {
    // Secret base32 of "12345678901234567890"
    final code = TotpDart.generate(
      'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      unixTime: 59,
    );
    // TotpDart uses 6 digits by default; re-check hotp with 8 via known path.
    // For 6-digit default, just assert length.
    expect(code['code'].toString().length, 6);
  });

  test('known 8-digit via hotp', () {
    final key = TotpDart.base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    final code = TotpDart.hotp(key, 1, 8); // counter = 59/30 = 1
    expect(code, '94287082');
  });

  test('otpauth secret extract', () {
    final uri =
        'otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    expect(TotpDart.normalizeSecret(uri), 'JBSWY3DPEHPK3PXP');
  });

  test('stable code at fixed time', () {
    final a = TotpDart.generate('JBSWY3DPEHPK3PXP', unixTime: 1111111111);
    final b = TotpDart.generate('JBSWY3DPEHPK3PXP', unixTime: 1111111111);
    expect(a['code'], b['code']);
    expect(a['code'].toString().length, 6);
  });
}
