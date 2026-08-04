import 'package:flutter/foundation.dart';
import 'package:local_auth/local_auth.dart';

/// Host biometric / device-credential gate before enclave unlock.
///
/// When biometrics are unavailable (desktop tests, some emulators),
/// [authenticate] returns true so development is not blocked. When hardware
/// is available, a successful prompt is required.
class BiometricGate {
  BiometricGate({LocalAuthentication? auth})
      : _auth = auth ?? LocalAuthentication();

  final LocalAuthentication _auth;

  Future<bool> get canCheck async {
    try {
      return await _auth.canCheckBiometrics || await _auth.isDeviceSupported();
    } catch (e) {
      debugPrint('biometric canCheck failed: $e');
      return false;
    }
  }

  /// Prompt the user. Returns true if authenticated, or if no biometrics
  /// hardware is available (enclave still bound to OS key protection).
  Future<bool> authenticate({
    String reason = 'Unlock KeyVault with biometrics',
    bool allowDeviceCredential = true,
  }) async {
    try {
      final supported = await canCheck;
      if (!supported) {
        debugPrint('BiometricGate: no biometrics; allowing enclave unlock');
        return true;
      }
      return await _auth.authenticate(
        localizedReason: reason,
        options: AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: !allowDeviceCredential,
          useErrorDialogs: true,
        ),
      );
    } catch (e) {
      debugPrint('BiometricGate authenticate error: $e');
      final supported = await canCheck;
      return !supported;
    }
  }
}
