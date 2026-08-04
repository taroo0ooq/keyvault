import 'package:flutter/material.dart';

import '../services/biometric_gate.dart';
import '../services/vault_service.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key, required this.vault});

  final VaultService vault;

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  final _unlockPath = TextEditingController(text: 'keyvault.vault');
  final _unlockPassword = TextEditingController();
  final _createPath = TextEditingController(text: 'keyvault.vault');
  final _createPassword = TextEditingController();
  final _createPassword2 = TextEditingController();
  String? _error;
  bool _busy = false;
  bool _enclaveReady = false;
  final _biometrics = BiometricGate();

  @override
  void dispose() {
    _tabs.dispose();
    _unlockPath.dispose();
    _unlockPassword.dispose();
    _createPath.dispose();
    _createPassword.dispose();
    _createPassword2.dispose();
    super.dispose();
  }

  Future<void> _unlock() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      var path = _unlockPath.text.trim();
      if (path.isEmpty) {
        path = await widget.vault.defaultVaultPath();
        _unlockPath.text = path;
      }
      await widget.vault.unlock(
        path: path,
        masterPassword: _unlockPassword.text,
      );
      _unlockPassword.clear();
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _create() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (_createPassword.text != _createPassword2.text) {
        throw ArgumentError('Passwords do not match');
      }
      var path = _createPath.text.trim();
      if (path.isEmpty || path == 'keyvault.vault') {
        path = await widget.vault.defaultVaultPath();
        _createPath.text = path;
      }
      await widget.vault.createVault(
        path: path,
        masterPassword: _createPassword.text,
      );
      _createPassword.clear();
      _createPassword2.clear();
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 2, vsync: this);
    widget.vault.defaultVaultPath().then((path) async {
      if (!mounted) return;
      final enclave = await widget.vault.enclaveAvailable(path);
      if (!mounted) return;
      setState(() {
        _unlockPath.text = path;
        _createPath.text = path;
        _enclaveReady = enclave;
      });
    });
    _unlockPath.addListener(() async {
      final enclave = await widget.vault.enclaveAvailable(_unlockPath.text.trim());
      if (mounted) setState(() => _enclaveReady = enclave);
    });
  }

  Future<void> _enclaveUnlock() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final ok = await _biometrics.authenticate(
        reason: 'Authenticate to unlock your KeyVault',
      );
      if (!ok) {
        throw StateError('Biometric authentication cancelled or failed');
      }
      await widget.vault.unlockWithEnclave(path: _unlockPath.text.trim());
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'KeyVault',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Local-first zero-knowledge password manager',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 24),
                  TabBar(
                    controller: _tabs,
                    tabs: const [
                      Tab(text: 'Unlock'),
                      Tab(text: 'Create'),
                    ],
                  ),
                  const SizedBox(height: 16),
                  SizedBox(
                    height: 260,
                    child: TabBarView(
                      controller: _tabs,
                      children: [
                        _UnlockForm(
                          path: _unlockPath,
                          password: _unlockPassword,
                          busy: _busy,
                          enclaveReady: _enclaveReady,
                          onSubmit: _unlock,
                          onEnclave: _enclaveUnlock,
                        ),
                        _CreateForm(
                          path: _createPath,
                          password: _createPassword,
                          password2: _createPassword2,
                          busy: _busy,
                          onSubmit: _create,
                        ),
                      ],
                    ),
                  ),
                  if (_error != null) ...[
                    const SizedBox(height: 12),
                    Text(
                      _error!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ],
                  const SizedBox(height: 16),
                  Text(
                    'Backend: ${widget.vault.backendLabel}',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Use password (≥12) or PIN (≥8 digits) as master secret.',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _UnlockForm extends StatelessWidget {
  const _UnlockForm({
    required this.path,
    required this.password,
    required this.busy,
    required this.enclaveReady,
    required this.onSubmit,
    required this.onEnclave,
  });

  final TextEditingController path;
  final TextEditingController password;
  final bool busy;
  final bool enclaveReady;
  final VoidCallback onSubmit;
  final VoidCallback onEnclave;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: path,
          decoration: const InputDecoration(labelText: 'Vault path'),
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: 12),
        TextField(
          controller: password,
          decoration: const InputDecoration(labelText: 'Master password / PIN'),
          obscureText: true,
          onSubmitted: (_) => onSubmit(),
        ),
        const Spacer(),
        if (enclaveReady) ...[
          OutlinedButton(
            onPressed: busy ? null : onEnclave,
            child: const Text('Quick unlock (OS enclave)'),
          ),
          const SizedBox(height: 8),
        ],
        FilledButton(
          onPressed: busy ? null : onSubmit,
          child: busy
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Unlock'),
        ),
      ],
    );
  }
}

class _CreateForm extends StatelessWidget {
  const _CreateForm({
    required this.path,
    required this.password,
    required this.password2,
    required this.busy,
    required this.onSubmit,
  });

  final TextEditingController path;
  final TextEditingController password;
  final TextEditingController password2;
  final bool busy;
  final VoidCallback onSubmit;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: path,
          decoration: const InputDecoration(labelText: 'Vault path'),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: password,
          decoration: const InputDecoration(labelText: 'Master password'),
          obscureText: true,
        ),
        const SizedBox(height: 12),
        TextField(
          controller: password2,
          decoration: const InputDecoration(labelText: 'Confirm password'),
          obscureText: true,
          onSubmitted: (_) => onSubmit(),
        ),
        const Spacer(),
        FilledButton(
          onPressed: busy ? null : onSubmit,
          child: const Text('Create & unlock'),
        ),
      ],
    );
  }
}
