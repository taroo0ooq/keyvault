import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;

/// Low-level bindings to `vault_ffi` (Rust cdylib over vault-core).
///
/// Library resolution order:
/// 1. `VAULT_FFI_PATH` env var
/// 2. Next to the executable / common build outputs
/// 3. Falls back to mock mode if the dylib cannot be loaded
class VaultFfi {
  VaultFfi._(this._lib) {
    _version = _lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('kv_version');
    _health = _lib.lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>('kv_health_json');
    _create = _lib.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('kv_vault_create');
    _unlock = _lib.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('kv_vault_unlock');
    _unlockEnclave = _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('kv_vault_unlock_enclave');
    _enclaveAvailable = _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('kv_vault_enclave_available');
    _lock = _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('kv_vault_lock');
    _list = _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('kv_vault_list_json');
    _search = _lib.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('kv_vault_search_json');
    _save = _lib.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('kv_vault_save_json');
    _delete = _lib.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('kv_vault_delete');
    _totp = _lib.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('kv_vault_totp_json');
    _gen = _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('kv_generate_password_json');
    _score = _lib.lookupFunction<Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('kv_score_password_json');
    _free = _lib.lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>(
        'kv_string_free');
  }

  final DynamicLibrary _lib;

  late final Pointer<Utf8> Function() _version;
  late final Pointer<Utf8> Function() _health;
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _create;
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _unlock;
  late final Pointer<Utf8> Function(Pointer<Utf8>) _unlockEnclave;
  late final Pointer<Utf8> Function(Pointer<Utf8>) _enclaveAvailable;
  late final Pointer<Utf8> Function(Pointer<Utf8>) _lock;
  late final Pointer<Utf8> Function(Pointer<Utf8>) _list;
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _search;
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _save;
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _delete;
  late final Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>) _totp;
  late final Pointer<Utf8> Function(Pointer<Utf8>) _gen;
  late final Pointer<Utf8> Function(Pointer<Utf8>) _score;
  late final void Function(Pointer<Utf8>) _free;

  static VaultFfi? tryLoad() {
    try {
      final lib = _open();
      return VaultFfi._(lib);
    } catch (e, st) {
      debugPrint('vault_ffi load failed: $e\n$st');
      return null;
    }
  }

  static DynamicLibrary _open() {
    final fromEnv = Platform.environment['VAULT_FFI_PATH'];
    if (fromEnv != null && fromEnv.isNotEmpty) {
      return DynamicLibrary.open(fromEnv);
    }

    final names = <String>[
      if (Platform.isWindows) 'vault_ffi.dll',
      if (Platform.isLinux) 'libvault_ffi.so',
      if (Platform.isMacOS) 'libvault_ffi.dylib',
      if (Platform.isAndroid) 'libvault_ffi.so',
      if (Platform.isIOS) 'vault_ffi.framework/vault_ffi',
    ];

    final candidates = <String>[];
    for (final name in names) {
      candidates.add(name);
      candidates.add(p.join(Directory.current.path, name));
      candidates.add(p.join(Directory.current.path, 'target', 'release', name));
      candidates.add(p.join(Directory.current.path, 'target', 'debug', name));
      // monorepo root relative to apps/mobile
      candidates.add(p.join(Directory.current.path, '..', '..', 'target', 'release', name));
      candidates.add(p.join(Directory.current.path, '..', '..', 'target', 'debug', name));
    }

    Object? last;
    for (final c in candidates) {
      try {
        return DynamicLibrary.open(c);
      } catch (e) {
        last = e;
      }
    }
    throw StateError('Could not open vault_ffi dylib. Last error: $last');
  }

  String _take(Pointer<Utf8> ptr) {
    if (ptr.address == 0) {
      throw StateError('null string from vault_ffi');
    }
    final s = ptr.toDartString();
    _free(ptr);
    if (s.startsWith('ERR:')) {
      throw StateError(s.substring(4));
    }
    return s;
  }

  String version() => _take(_version());

  Map<String, dynamic> health() =>
      jsonDecode(_take(_health())) as Map<String, dynamic>;

  String createVault(String path, String masterPassword) {
    final pPath = path.toNativeUtf8();
    final pPw = masterPassword.toNativeUtf8();
    try {
      return _take(_create(pPath, pPw));
    } finally {
      malloc.free(pPath);
      malloc.free(pPw);
    }
  }

  String unlockVault(String path, String masterPassword) {
    final pPath = path.toNativeUtf8();
    final pPw = masterPassword.toNativeUtf8();
    try {
      return _take(_unlock(pPath, pPw));
    } finally {
      malloc.free(pPath);
      malloc.free(pPw);
    }
  }

  String unlockWithEnclave(String path) {
    final pPath = path.toNativeUtf8();
    try {
      return _take(_unlockEnclave(pPath));
    } finally {
      malloc.free(pPath);
    }
  }

  bool enclaveAvailable(String path) {
    final pPath = path.toNativeUtf8();
    try {
      return _take(_enclaveAvailable(pPath)) == '1';
    } finally {
      malloc.free(pPath);
    }
  }

  void lockVault(String handle) {
    final h = handle.toNativeUtf8();
    try {
      _take(_lock(h));
    } finally {
      malloc.free(h);
    }
  }

  List<dynamic> listItems(String handle) {
    final h = handle.toNativeUtf8();
    try {
      return jsonDecode(_take(_list(h))) as List<dynamic>;
    } finally {
      malloc.free(h);
    }
  }

  List<dynamic> searchItems(String handle, String query) {
    final h = handle.toNativeUtf8();
    final q = query.toNativeUtf8();
    try {
      return jsonDecode(_take(_search(h, q))) as List<dynamic>;
    } finally {
      malloc.free(h);
      malloc.free(q);
    }
  }

  Map<String, dynamic> saveItem(String handle, Map<String, dynamic> item) {
    final h = handle.toNativeUtf8();
    final j = jsonEncode(item).toNativeUtf8();
    try {
      return jsonDecode(_take(_save(h, j))) as Map<String, dynamic>;
    } finally {
      malloc.free(h);
      malloc.free(j);
    }
  }

  void deleteItem(String handle, String id) {
    final h = handle.toNativeUtf8();
    final i = id.toNativeUtf8();
    try {
      _take(_delete(h, i));
    } finally {
      malloc.free(h);
      malloc.free(i);
    }
  }

  /// Live TOTP code map: code, period_secs, remaining_secs, digits.
  Map<String, dynamic> totpCode(String handle, String id) {
    final h = handle.toNativeUtf8();
    final i = id.toNativeUtf8();
    try {
      return jsonDecode(_take(_totp(h, i))) as Map<String, dynamic>;
    } finally {
      malloc.free(h);
      malloc.free(i);
    }
  }

  String generatePassword({int length = 20}) {
    final policy = jsonEncode({
      'length': length,
      'lowercase': true,
      'uppercase': true,
      'digits': true,
      'symbols': true,
      'exclude_ambiguous': false,
    }).toNativeUtf8();
    try {
      return _take(_gen(policy));
    } finally {
      malloc.free(policy);
    }
  }

  Map<String, dynamic> scorePassword(String password) {
    final p = password.toNativeUtf8();
    try {
      return jsonDecode(_take(_score(p))) as Map<String, dynamic>;
    } finally {
      malloc.free(p);
    }
  }
}
