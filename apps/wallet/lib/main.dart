import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'presentation/mobile/mobile_shell.dart';
import 'presentation/screens/shell_screen.dart';

void main() {
  runApp(const ProviderScope(child: DatuWalletApp()));
}

class DatuWalletApp extends StatelessWidget {
  const DatuWalletApp({super.key});

  @override
  Widget build(BuildContext context) {
    // Phones get the thumb-first shell (bottom navigation, sheets). The
    // desktop shell with its sidebar stays for macOS/Windows/Linux.
    final mobile = Platform.isAndroid || Platform.isIOS;
    return MaterialApp(
      title: 'DATU Signet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF238636),
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: mobile ? const MobileShell() : const WalletShell(),
    );
  }
}
