import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/ledger/ledger_client.dart';
import '../../providers/bridge_provider.dart';
import 'consent_screen.dart';
import 'data_screen.dart';
import 'explorer_screen.dart';
import 'records_screen.dart';
import 'settings_screen.dart';
import 'verify_screen.dart';

/// The one-stop shell: a sidebar (the browser extension's tab bar, grown
/// up) + the active tab. Wide windows get the full sidebar; narrow ones
/// collapse to a rail. The header carries the identity selector, the seal
/// key hint and the node chip; the footer carries the bridge status - the
/// same anatomy as the extension panel.
class WalletShell extends ConsumerStatefulWidget {
  const WalletShell({super.key});

  @override
  ConsumerState<WalletShell> createState() => _WalletShellState();
}

class _WalletShellState extends ConsumerState<WalletShell> {
  Timer? _idle;

  @override
  void initState() {
    super.initState();
    _armIdleLock();
  }

  @override
  void dispose() {
    _idle?.cancel();
    super.dispose();
  }

  void _probeNode() {
    Future(() async {
      final client = LedgerClient(baseUrl: ref.read(nodeUrlProvider));
      try {
        final st = await client.status();
        final mode = st['policy'] is Map ? st['policy']['mode'] : '?';
        ref.read(nodeStatusProvider.notifier).set('$mode · ${st['entries']} entries');
      } catch (_) {
        ref.read(nodeStatusProvider.notifier).set('down');
      }
    });
  }

  void _armIdleLock() {
    _idle?.cancel();
    _idle = Timer(const Duration(minutes: 2), () {
      final hadSecrets =
          ref.read(passphraseProvider).isNotEmpty || ref.read(decryptedProvider) != null;
      ref.read(passphraseProvider.notifier).clear();
      ref.read(decryptedProvider.notifier).clear();
      if (hadSecrets && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('locked - passphrase and decrypted data cleared after 2 minutes idle'),
          ),
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(bridgeControllerProvider);
    final tab = ref.watch(tabProvider);
    final wide = MediaQuery.sizeOf(context).width >= 780;

    // The node chip reflects reality from the moment the shell is up, and
    // re-probes whenever the configured node changes (Settings).
    ref.listen(bridgeControllerProvider, (prev, next) {
      if (prev?.status != BridgeStatus.ready && next.status == BridgeStatus.ready) {
        _probeNode();
      }
    });
    ref.listen(nodeUrlProvider, (_, __) => _probeNode());

    return Listener(
      onPointerDown: (_) => _armIdleLock(),
      child: Scaffold(
        body: Row(
          children: [
            _Sidebar(wide: wide),
            const VerticalDivider(width: 1),
            Expanded(
              child: Column(
                children: [
                  Container(
                    width: double.infinity,
                    padding: EdgeInsets.fromLTRB(24, 14, 24, 14),
                    color: Theme.of(context).colorScheme.surfaceContainerLow,
                    child: Text(
                      switch (tab) {
                        WalletTab.records => 'Read from any node',
                        WalletTab.sign => 'Holder consent',
                        WalletTab.data => 'What is sealed to me',
                        WalletTab.explorer => 'Ledger explorer',
                        WalletTab.verify => 'Transaction verifier',
                        WalletTab.settings => 'Settings',
                      },
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                  ),
                  const Divider(height: 1),
                  Expanded(
                    child: switch (state.status) {
                      BridgeStatus.starting => const Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              CircularProgressIndicator(),
                              SizedBox(height: 12),
                              Text('starting your Signet service…'),
                            ],
                          ),
                        ),
                      BridgeStatus.error => _BridgeErrorPane(
                          message: state.error ?? 'unknown error',
                        ),
                      BridgeStatus.ready => IndexedStack(
                          index: WalletTab.values.indexOf(tab),
                          children: const [
                            RecordsTab(),
                            ConsentTab(),
                            DataTab(),
                            ExplorerTab(),
                            VerifyTab(),
                            SettingsTab(),
                          ],
                        ),
                    },
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Sidebar extends ConsumerWidget {
  const _Sidebar({required this.wide});

  final bool wide;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(bridgeControllerProvider);
    final identities = state.identities;
    final selected = ref.watch(selectedIdentityProvider);
    final identity = identities
        .where((id) => id['name'] == selected)
        .firstOrNull;
    final tab = ref.watch(tabProvider);
    final nodeStatus = ref.watch(nodeStatusProvider);
    final scheme = Theme.of(context).colorScheme;

    final items = const [
      (
        section: 'Signet',
        entries: [
          (tab: WalletTab.records, icon: Icons.folder_shared_outlined, label: 'My records'),
          (tab: WalletTab.sign, icon: Icons.draw_outlined, label: 'Sign'),
          (tab: WalletTab.data, icon: Icons.lock_open_outlined, label: 'My data'),
        ],
      ),
      (
        section: 'Ledger',
        entries: [
          (tab: WalletTab.explorer, icon: Icons.account_tree_outlined, label: 'Explorer'),
        ],
      ),
      (
        section: 'Tools',
        entries: [
          (tab: WalletTab.verify, icon: Icons.verified_outlined, label: 'Verifier'),
          (tab: WalletTab.settings, icon: Icons.settings_outlined, label: 'Settings'),
        ],
      ),
    ];

    return Container(
      width: wide ? 236 : 68,
      color: scheme.surfaceContainerLow,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (wide) ...[
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Row(
                children: [
                  Container(
                    width: 28,
                    height: 28,
                    decoration: BoxDecoration(
                      color: scheme.primary,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Icon(Icons.shield_outlined, color: scheme.onPrimary, size: 18),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('DATU Signet',
                            style: Theme.of(context).textTheme.titleSmall),
                        Text(
                          'Personal Vault · records · consent · ledger',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: scheme.onSurfaceVariant),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: DropdownButtonFormField<String>(
                initialValue: selected,
                isExpanded: true,
                decoration: const InputDecoration(
                  labelText: 'Identity',
                  border: OutlineInputBorder(),
                ),
                items: identities
                    .map((id) => DropdownMenuItem(
                          value: id['name'] as String,
                          child: Text(
                            '${id['name']} · ${(id['ed_public'] as String? ?? '').substring(0, 8)}…',
                            overflow: TextOverflow.ellipsis,
                          ),
                        ))
                    .toList(),
                onChanged: identities.isEmpty
                    ? null
                    : (v) => ref.read(selectedIdentityProvider.notifier).select(v),
              ),
            ),
            if (identity != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 6, 16, 0),
                child: Row(
                  children: [
                    Text(
                      'seal ${(identity['seal_public'] as String? ?? '').padRight(20).substring(0, 20)}…',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: scheme.onSurfaceVariant,
                            fontFamily: 'Menlo',
                          ),
                    ),
                    IconButton(
                      visualDensity: VisualDensity.compact,
                      tooltip: 'copy seal key',
                      icon: const Icon(Icons.copy, size: 12),
                      onPressed: () => Clipboard.setData(
                        ClipboardData(text: identity['seal_public'] as String? ?? ''),
                      ),
                    ),
                  ],
                ),
              ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 12),
              child: Row(
                children: [
                  Icon(
                    Icons.circle,
                    size: 8,
                    color: nodeStatus == 'down' ? scheme.error : scheme.tertiary,
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      nodeStatus == 'down' ? 'node down' : 'node $nodeStatus',
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
          ] else
            const SizedBox(height: 12),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(vertical: 8),
              children: [
                for (final section in items) ...[
                  if (wide)
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 10, 16, 4),
                      child: Text(
                        section.section.toUpperCase(),
                        style: Theme.of(context).textTheme.labelSmall?.copyWith(
                              color: scheme.onSurfaceVariant,
                              letterSpacing: 1.2,
                            ),
                      ),
                    ),
                  for (final entry in section.entries)
                    _RailButton(
                      icon: Icon(entry.icon),
                      label: entry.label,
                      extended: wide,
                      selected: tab == entry.tab,
                      onTap: () => ref.read(tabProvider.notifier).go(entry.tab),
                    ),
                ],
              ],
            ),
          ),
          const Divider(height: 1),
          Padding(
            padding: EdgeInsets.all(wide ? 12 : 8),
            child: wide
                ? Row(
                    children: [
                      Icon(
                        Icons.circle,
                        size: 8,
                        color: state.status == BridgeStatus.error
                            ? scheme.error
                            : scheme.primary,
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          state.status == BridgeStatus.error
                              ? 'bridge down'
                              : state.native
                                  ? 'native core · keys never leave this device'
                                  : 'bridge up · keys stay in the service',
                          overflow: TextOverflow.ellipsis,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ),
                      IconButton(
                        visualDensity: VisualDensity.compact,
                        tooltip: 'refresh',
                        icon: const Icon(Icons.refresh, size: 16),
                        onPressed: () => ref.read(bridgeControllerProvider.notifier).refresh(),
                      ),
                    ],
                  )
                : IconButton(
                    tooltip: 'refresh',
                    icon: const Icon(Icons.refresh, size: 18),
                    onPressed: () => ref.read(bridgeControllerProvider.notifier).refresh(),
                  ),
          ),
        ],
      ),
    );
  }
}

class _RailButton extends StatelessWidget {
  const _RailButton({
    required this.icon,
    required this.label,
    required this.extended,
    required this.selected,
    required this.onTap,
  });

  final Icon icon;
  final String label;
  final bool extended;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    if (!extended) {
      return IconButton(
        tooltip: label,
        isSelected: selected,
        onPressed: onTap,
        icon: icon,
      );
    }
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: Material(
        color: selected ? scheme.secondaryContainer : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
        child: InkWell(
          borderRadius: BorderRadius.circular(8),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
            child: Row(
              children: [
                IconTheme(
                  data: IconThemeData(
                    size: 18,
                    color: selected ? scheme.onSecondaryContainer : scheme.onSurfaceVariant,
                  ),
                  child: icon,
                ),
                const SizedBox(width: 12),
                Text(
                  label,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: selected ? FontWeight.w600 : FontWeight.w400,
                    color: selected ? scheme.onSecondaryContainer : scheme.onSurface,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _BridgeErrorPane extends ConsumerStatefulWidget {
  const _BridgeErrorPane({required this.message});

  final String message;

  @override
  ConsumerState<_BridgeErrorPane> createState() => _BridgeErrorPaneState();
}

class _BridgeErrorPaneState extends ConsumerState<_BridgeErrorPane> {
  final _url = TextEditingController(text: 'http://127.0.0.1:7488');
  final _token = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 480),
        child: ListView(
          shrinkWrap: true,
          padding: const EdgeInsets.all(24),
          children: [
            Card(
              color: Theme.of(context).colorScheme.errorContainer,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Text(widget.message),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _url,
              decoration: const InputDecoration(labelText: 'Bridge URL'),
            ),
            TextField(
              controller: _token,
              obscureText: true,
              decoration: const InputDecoration(labelText: 'Pairing token'),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                FilledButton(
                  onPressed: () => ref.read(bridgeControllerProvider.notifier).start(),
                  child: const Text('Start again'),
                ),
                const SizedBox(width: 8),
                OutlinedButton(
                  onPressed: () => ref.read(bridgeControllerProvider.notifier).attach(
                        baseUrl: _url.text,
                        token: _token.text,
                      ),
                  child: const Text('Attach with token'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
