import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'screens/auth_screen.dart';
import 'screens/vault_screen.dart';
import 'services/vault_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
    ),
  );
  runApp(const KeyVaultApp());
}

class KeyVaultApp extends StatefulWidget {
  const KeyVaultApp({super.key});

  @override
  State<KeyVaultApp> createState() => _KeyVaultAppState();
}

class _KeyVaultAppState extends State<KeyVaultApp> {
  final VaultService _vault = VaultService();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'KeyVault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF3B82F6),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      ),
      home: AnimatedBuilder(
        animation: _vault,
        builder: (context, _) {
          if (_vault.isUnlocked) {
            return VaultScreen(vault: _vault);
          }
          return AuthScreen(vault: _vault);
        },
      ),
    );
  }
}
