import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../providers/bridge_provider.dart';
import 'mobile_home.dart';
import 'mobile_identity.dart';
import 'mobile_settings.dart';
import 'mobile_sign.dart';
import 'mobile_verify.dart';

/// The phone shell: bottom navigation, no sidebar, thumb-reachable actions.
/// The desktop shell (WalletShell) stays untouched; main.dart picks this one
/// on Android and iOS.
class MobileShell extends ConsumerStatefulWidget {
  const MobileShell({super.key});

  @override
  ConsumerState<MobileShell> createState() => _MobileShellState();
}

class _MobileShellState extends ConsumerState<MobileShell> {
  int _index = 0;

  static const _titles = ['Signet vault', 'Sign', 'Verify', 'Settings'];

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(bridgeControllerProvider);
    final selected = ref.watch(selectedIdentityProvider);

    return Scaffold(
      appBar: AppBar(
        title: Text(_titles[_index]),
        actions: [
          if (state.identities.isNotEmpty && _index != 2)
            Padding(
              padding: const EdgeInsets.only(right: 12),
              child: ActionChip(
                avatar: CircleAvatar(
                  child: Text(
                    (selected ?? '?').substring(0, 1).toUpperCase(),
                    style: const TextStyle(fontSize: 12),
                  ),
                ),
                label: Text(selected ?? 'select'),
                onPressed: () => showIdentitySwitcher(context, ref),
              ),
            ),
        ],
      ),
      body: SafeArea(
        top: false,
        child: IndexedStack(
          index: _index,
          children: const [
            MobileHomeTab(),
            MobileSignTab(),
            MobileVerifyTab(),
            MobileSettingsTab(),
          ],
        ),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (value) => setState(() => _index = value),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.account_balance_wallet_outlined),
            selectedIcon: Icon(Icons.account_balance_wallet),
            label: 'Vault',
          ),
          NavigationDestination(
            icon: Icon(Icons.draw_outlined),
            selectedIcon: Icon(Icons.draw),
            label: 'Sign',
          ),
          NavigationDestination(
            icon: Icon(Icons.verified_outlined),
            selectedIcon: Icon(Icons.verified),
            label: 'Verify',
          ),
          NavigationDestination(
            icon: Icon(Icons.tune_outlined),
            selectedIcon: Icon(Icons.tune),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}
