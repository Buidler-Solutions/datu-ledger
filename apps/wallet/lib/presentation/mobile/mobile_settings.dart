import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/ledger/ledger_client.dart';
import '../../providers/bridge_provider.dart';
import 'mobile_identity.dart';
import 'mobile_widgets.dart';

/// Settings tab: identities, node address, backup and about.
class MobileSettingsTab extends ConsumerStatefulWidget {
  const MobileSettingsTab({super.key});

  @override
  ConsumerState<MobileSettingsTab> createState() => _MobileSettingsTabState();
}

class _MobileSettingsTabState extends ConsumerState<MobileSettingsTab> {
  late final TextEditingController _node =
      TextEditingController(text: ref.read(nodeUrlProvider));
  final _backup = TextEditingController();
  String? _importError;
  String? _nodeNote;
  bool _importBusy = false;

  @override
  void dispose() {
    _node.dispose();
    _backup.dispose();
    super.dispose();
  }

  Future<void> _export(String name) async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) return;
    final passphrase = await askSecret(context,
        title: 'Passphrase for $name', action: 'Export backup');
    if (passphrase == null || passphrase.isEmpty) return;
    if (!mounted) return;
    final backupPass = await askSecret(
      context,
      title: 'Backup passphrase',
      hint: 'Encrypts the backup file, separate from your wallet passphrase',
      action: 'Create backup',
    );
    if (backupPass == null || backupPass.length < 8) return;
    try {
      final backup = await bridge.exportIdentity(
        name: name,
        passphrase: passphrase,
        backupPassphrase: backupPass,
      );
      if (mounted) {
        showResult(
          context,
          title: 'Backup for $name',
          body: prettyJson(backup),
          note: 'Store it somewhere safe. It is encrypted with the backup passphrase only.',
          icon: Icons.archive_outlined,
        );
      }
    } catch (e) {
      if (mounted) {
        showResult(context, title: 'Export failed', body: '$e', ok: false);
      }
    }
  }

  Future<void> _import() async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) return;
    final passphrase = await askSecret(context,
        title: 'Backup passphrase', action: 'Open backup');
    if (passphrase == null || passphrase.isEmpty) return;
    setState(() {
      _importBusy = true;
      _importError = null;
    });
    try {
      final decoded = jsonDecode(_backup.text.trim());
      if (decoded is! Map<String, dynamic>) {
        setState(() => _importError = 'Paste the backup JSON object.');
        return;
      }
      final result = await bridge.importIdentity(
          backup: decoded, passphrase: passphrase);
      await ref.read(bridgeControllerProvider.notifier).refresh();
      if (mounted) {
        showResult(context,
            title: 'Identity imported', body: prettyJson(result), icon: Icons.person_add);
        _backup.clear();
      }
    } catch (e) {
      setState(() => _importError = 'Import failed: $e');
    } finally {
      if (mounted) setState(() => _importBusy = false);
    }
  }

  Future<void> _checkNode() async {
    final url = _node.text.trim();
    ref.read(nodeUrlProvider.notifier).set(url);
    try {
      final status = await LedgerClient(baseUrl: url).status();
      final mode = status['policy'] is Map ? status['policy']['mode'] : 'node';
      ref.read(nodeStatusProvider.notifier).set('$mode · ${status['entries']} entries');
      setState(() => _nodeNote = 'Node ok: $mode, ${status['entries']} entries');
    } catch (e) {
      ref.read(nodeStatusProvider.notifier).set('down');
      setState(() => _nodeNote =
          'Unreachable. On a phone, 127.0.0.1 is the phone itself - use your '
          'node machine\'s LAN address, for example http://192.168.1.20:7574');
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(bridgeControllerProvider);
    final selected = ref.watch(selectedIdentityProvider);
    final platform = Platform.isIOS ? 'iOS' : Platform.isAndroid ? 'Android' : 'Desktop';

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
      children: [
        SectionCard(
          title: 'Identities on this phone',
          trailing: TextButton.icon(
            onPressed: () => createIdentityFlow(context, ref),
            icon: const Icon(Icons.add),
            label: const Text('New'),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (state.identities.isEmpty)
                const Text('None yet. Create one to start signing.'),
              for (final id in state.identities)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: CircleAvatar(
                    child: Text(
                      (id['name'] as String? ?? '?').substring(0, 1).toUpperCase(),
                    ),
                  ),
                  title: Text(id['name'] as String? ?? 'unnamed'),
                  subtitle: Text(shortKey(id['ed_public'] as String?)),
                  trailing: (id['name'] as String?) == selected
                      ? const Icon(Icons.check_circle, color: Color(0xFF46D68C))
                      : IconButton(
                          tooltip: 'Use this identity',
                          icon: const Icon(Icons.chevron_right),
                          onPressed: () => ref
                              .read(selectedIdentityProvider.notifier)
                              .select(id['name'] as String?),
                        ),
                  onLongPress: () => _export(id['name'] as String? ?? ''),
                ),
              if (state.identities.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(
                    'Long-press an identity to export an encrypted backup.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        SectionCard(
          title: 'Restore a backup',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _backup,
                maxLines: 4,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                decoration: const InputDecoration(
                  hintText: 'Paste the backup JSON',
                  border: OutlineInputBorder(),
                  alignLabelWithHint: true,
                ),
              ),
              if (_importError != null) ...[
                const SizedBox(height: 8),
                Text(_importError!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ],
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: _importBusy ? null : _import,
                icon: const Icon(Icons.restore),
                label: Text(_importBusy ? 'Importing...' : 'Import backup'),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        SectionCard(
          title: 'Ledger node',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _node,
                keyboardType: TextInputType.url,
                decoration: const InputDecoration(
                  labelText: 'Node address',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: FilledButton.tonalIcon(
                      onPressed: _checkNode,
                      icon: const Icon(Icons.cloud_done_outlined),
                      label: const Text('Save and check'),
                    ),
                  ),
                ],
              ),
              if (_nodeNote != null) ...[
                const SizedBox(height: 8),
                Text(_nodeNote!,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        )),
              ],
            ],
          ),
        ),
        const SizedBox(height: 12),
        SectionCard(
          title: 'About',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('DATU Signet $platform app', style: Theme.of(context).textTheme.bodyLarge),
              const SizedBox(height: 4),
              Text(
                state.native
                    ? 'Signing runs in the embedded Rust core on this device. Keys never leave the phone.'
                    : 'Connected to ${state.bridge?.baseUrl ?? 'no service'}.',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
              const SizedBox(height: 8),
              Text('Passphrase is required for every signature and is never stored.',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      )),
            ],
          ),
        ),
      ],
    );
  }
}
