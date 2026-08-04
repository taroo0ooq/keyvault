import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../models/vault_item.dart';
import 'totp_dart.dart';
import 'vault_ffi.dart';

/// Mobile vault facade.
///
/// Prefers native `vault_ffi` (vault-core). If the dylib is unavailable
/// (e.g. pure Dart unit tests without native build), falls back to an
/// in-memory mock so the UI remains testable.
class VaultService extends ChangeNotifier {
  VaultService({VaultFfi? ffi}) : _ffi = ffi ?? VaultFfi.tryLoad();

  final VaultFfi? _ffi;
  final List<VaultItem> _mockItems = [];
  String? _handle;
  bool _unlocked = false;
  String? _vaultPath;

  bool get isUnlocked => _unlocked;
  String? get vaultPath => _vaultPath;
  bool get usingNativeCrypto => _ffi != null && _handle != null;
  bool get nativeAvailable => _ffi != null;
  String get backendLabel =>
      _ffi == null ? 'mock (no vault_ffi dylib)' : 'vault-core via vault_ffi';

  Future<String> defaultVaultPath() async {
    try {
      final dir = await getApplicationSupportDirectory();
      return p.join(dir.path, 'keyvault.vault');
    } catch (_) {
      return p.join(Directory.systemTemp.path, 'keyvault.vault');
    }
  }

  Future<void> createVault({
    required String path,
    required String masterPassword,
  }) async {
    if (masterPassword.length < 12 && !_isPin(masterPassword)) {
      throw ArgumentError(
        'Master password must be at least 12 characters (or use 8+ digit PIN)',
      );
    }
    if (_isPin(masterPassword) && masterPassword.length < 8) {
      throw ArgumentError('PIN must be at least 8 digits');
    }

    final secret = _isPin(masterPassword)
        ? 'kv-pin-v1:$masterPassword'
        : masterPassword;

    if (_ffi != null) {
      final parent = Directory(p.dirname(path));
      if (!parent.existsSync()) {
        parent.createSync(recursive: true);
      }
      _handle = _ffi.createVault(path, secret);
      _vaultPath = path;
      _unlocked = true;
      notifyListeners();
      return;
    }

    _vaultPath = path;
    _mockItems.clear();
    _unlocked = true;
    notifyListeners();
  }

  Future<void> unlock({
    required String path,
    required String masterPassword,
  }) async {
    if (masterPassword.isEmpty) {
      throw ArgumentError('Master password required');
    }
    final secret = _isPin(masterPassword)
        ? 'kv-pin-v1:$masterPassword'
        : masterPassword;

    if (_ffi != null) {
      _handle = _ffi.unlockVault(path, secret);
      _vaultPath = path;
      _unlocked = true;
      notifyListeners();
      return;
    }

    // Mock unlock for UI-only runs.
    _vaultPath = path;
    _unlocked = true;
    notifyListeners();
  }

  Future<bool> enclaveAvailable(String path) async {
    if (_ffi == null) return false;
    try {
      return _ffi.enclaveAvailable(path);
    } catch (_) {
      return false;
    }
  }

  /// OS-enclave quick unlock (DPAPI / software wrap). Gate with biometrics in UI.
  Future<void> unlockWithEnclave({required String path}) async {
    if (_ffi == null) {
      throw StateError('Native vault_ffi not loaded');
    }
    _handle = _ffi.unlockWithEnclave(path);
    _vaultPath = path;
    _unlocked = true;
    notifyListeners();
  }

  Future<void> lock() async {
    if (_ffi != null && _handle != null) {
      try {
        _ffi.lockVault(_handle!);
      } catch (_) {
        /* ignore */
      }
    }
    _handle = null;
    _unlocked = false;
    _mockItems.clear();
    notifyListeners();
  }

  Future<List<VaultItem>> list({String query = ''}) async {
    _ensureUnlocked();
    if (_ffi != null && _handle != null) {
      final raw = query.trim().isEmpty
          ? _ffi.listItems(_handle!)
          : _ffi.searchItems(_handle!, query.trim());
      return raw
          .map((e) => VaultItem.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList();
    }

    final q = query.trim().toLowerCase();
    if (q.isEmpty) return List.from(_mockItems);
    return _mockItems
        .where(
          (i) =>
              i.title.toLowerCase().contains(q) ||
              (i.username?.toLowerCase().contains(q) ?? false) ||
              (i.url?.toLowerCase().contains(q) ?? false) ||
              i.tags.any((t) => t.toLowerCase().contains(q)),
        )
        .toList();
  }

  Future<VaultItem> save(VaultItem item) async {
    _ensureUnlocked();
    if (_ffi != null && _handle != null) {
      final saved = _ffi.saveItem(_handle!, {
        'id': item.id,
        'title': item.title,
        'username': item.username,
        'password': item.password,
        'url': item.url,
        'notes': item.notes,
        'totp': item.totp,
        'tags': item.tags,
      });
      notifyListeners();
      return VaultItem.fromJson(saved);
    }

    final idx = _mockItems.indexWhere((e) => e.id == item.id);
    if (idx >= 0) {
      _mockItems[idx] = item;
      notifyListeners();
      return item;
    }
    final created =
        item.id.isEmpty ? item.copyWith(id: _newId()) : item;
    _mockItems.add(created);
    notifyListeners();
    return created;
  }

  Future<void> delete(String id) async {
    _ensureUnlocked();
    if (_ffi != null && _handle != null) {
      _ffi.deleteItem(_handle!, id);
      notifyListeners();
      return;
    }
    _mockItems.removeWhere((e) => e.id == id);
    notifyListeners();
  }

  /// Current TOTP code for an item. Prefers vault_ffi; mock uses pure-Dart TotpDart.
  Future<Map<String, dynamic>> totpCode(String id) async {
    _ensureUnlocked();
    if (_ffi != null && _handle != null) {
      return _ffi.totpCode(_handle!, id);
    }
    final matches = _mockItems.where((e) => e.id == id);
    if (matches.isEmpty || !matches.first.hasTotp) {
      throw StateError('item has no TOTP secret');
    }
    return TotpDart.generate(matches.first.totp!);
  }

  String generatePassword({
    int length = 20,
    bool lower = true,
    bool upper = true,
    bool digits = true,
    bool symbols = true,
  }) {
    if (_ffi != null) {
      return _ffi.generatePassword(length: length);
    }
    final buf = StringBuffer();
    if (lower) buf.write('abcdefghijklmnopqrstuvwxyz');
    if (upper) buf.write('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (digits) buf.write('0123456789');
    if (symbols) buf.write(r'!@#$%^&*()-_=+[]{}|;:,.<>?');
    final chars = buf.toString();
    if (chars.isEmpty || length < 8) {
      throw ArgumentError('Invalid password policy');
    }
    final rnd = Random.secure();
    return List.generate(length, (_) => chars[rnd.nextInt(chars.length)])
        .join();
  }

  bool _isPin(String s) => s.length >= 8 && RegExp(r'^\d+$').hasMatch(s);

  void _ensureUnlocked() {
    if (!_unlocked) {
      throw StateError('Vault is locked');
    }
  }

  String _newId() {
    final rnd = Random.secure();
    final bytes = List<int>.generate(16, (_) => rnd.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
