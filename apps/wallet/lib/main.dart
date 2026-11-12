import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'presentation/screens/shell_screen.dart';

void main() {
  runApp(const ProviderScope(child: DatuWalletApp()));
}

class DatuWalletApp extends StatelessWidget {
  const DatuWalletApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DATU Signet Personal Vault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF238636),
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: const WalletShell(),
    );
  }
}
