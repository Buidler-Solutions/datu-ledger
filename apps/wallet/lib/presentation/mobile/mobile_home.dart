import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/ledger/ledger_client.dart';
import '../../core/ledger/my_records.dart';
import '../../providers/bridge_provider.dart';
import 'mobile_identity.dart';
import 'mobile_widgets.dart';

/// Vault tab: who you are, what the ledger says concerns you, and the two
/// things a wallet must do instantly - refresh and reveal sealed fields.
class MobileHomeTab extends ConsumerStatefulWidget {
  const MobileHomeTab({super.key});

  @override
  ConsumerState<MobileHomeTab> createState() => _MobileHomeTabState();
}

class _MobileHomeTabState extends ConsumerState<MobileHomeTab> {
  final _records = <Map<String, dynamic>>[];
  bool _busy = false;
  String? _nodeNote;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Map<String, dynamic>? get _identity => identityByName(
        ref.watch(bridgeControllerProvider).identities,
        ref.watch(selectedIdentityProvider),
      );

  Future<void> _load() async {
    final identity = _identity;
    if (identity == null || _busy) return;
    setState(() {
      _busy = true;
    });
    final client = LedgerClient(baseUrl: ref.read(nodeUrlProvider));
    try {
      final status = await client.status();
      final mode = status['policy'] is Map ? status['policy']['mode'] : 'node';
      ref.read(nodeStatusProvider.notifier).set('$mode · ${status['entries']} entries');
      setState(() => _nodeNote = null);

      final ed = identity['ed_public'] as String? ?? '';
      final list = await client.entries(limit: 100);
      final mine = <Map<String, dynamic>>[];
      for (final item in list) {
        final full = await client.entry(item['id'] as String);
        final payload = LedgerClient.decodePayload(full['payload_base64'] as String?);
        if (payload != null && concernsMe(payload, ed)) {
          mine.add({
            'id': item['id'],
            'namespace': full['namespace'] ?? item['namespace'] ?? '',
            'seq': full['seq'] ?? item['seq'] ?? 0,
            'label': recordLabel(payload, item['id'] as String),
            'entry': full,
            'payload': payload,
          });
        }
      }
      if (mounted) {
        setState(() {
          _records
            ..clear()
            ..addAll(mine);
        });
      }
    } catch (_) {
      ref.read(nodeStatusProvider.notifier).set('down');
      if (mounted) {
        setState(() {
          _nodeNote =
              'No node reachable at ${ref.read(nodeUrlProvider)}. Your keys and '
              'signing work offline; set your node address in Settings to read '
              'records.';
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _openRecord(Map<String, dynamic> record) async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    final identity = _identity;
    if (bridge == null || identity == null) return;
    final payload = record['payload'] as Map<String, dynamic>;

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (context) => DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.6,
        maxChildSize: 0.95,
        builder: (context, scroll) => ListView(
          controller: scroll,
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
          children: [
            Text(record['label'] as String? ?? 'record',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text('${record['namespace']} · seq ${record['seq']}',
                style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 12),
            KeyRow(label: 'id', value: record['id'] as String? ?? ''),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: FilledButton.tonalIcon(
                    icon: const Icon(Icons.fact_check_outlined),
                    label: const Text('Verify locally'),
                    onPressed: () async {
                      try {
                        final verdict = await bridge.verifyEntry(
                          entry: Map<String, dynamic>.from(record['entry'] as Map),
                        );
                        if (!context.mounted) return;
                        showResult(
                          context,
                          title: verdict['ok'] == false ? 'Not valid' : 'Verified',
                          body: prettyJson(verdict),
                          ok: verdict['ok'] != false,
                          note: verdict['ok'] == false
                              ? 'Signature or party list failed on this device.'
                              : 'Signatures check out on this device; the node was not trusted.',
                        );
                      } catch (e) {
                        if (context.mounted) {
                          showResult(context,
                              title: 'Verify failed', body: '$e', ok: false);
                        }
                      }
                    },
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    icon: const Icon(Icons.lock_open),
                    label: const Text('Open sealed'),
                    onPressed: () async {
                      final passphrase = await askSecret(
                        context,
                        title: 'Open ${identity['name']}',
                        action: 'Decrypt fields',
                      );
                      if (passphrase == null || passphrase.isEmpty) return;
                      try {
                        final opened = await bridge.openFields(
                          name: identity['name'] as String,
                          passphrase: passphrase,
                          document: payload,
                        );
                        if (context.mounted) {
                          showResult(
                            context,
                            title: 'Fields sealed to you',
                            body: prettyJson(opened),
                            note: 'Decrypted on this device with your key.',
                          );
                        }
                      } catch (e) {
                        if (context.mounted) {
                          showResult(context,
                              title: 'Could not open', body: '$e', ok: false);
                        }
                      }
                    },
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Text('Payload', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(12),
              ),
              child: SelectableText(
                prettyJson(payload),
                maxLines: 14,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(bridgeControllerProvider);
    final identity = _identity;
    final nodeStatus = ref.watch(nodeStatusProvider);

    if (state.status == BridgeStatus.error) {
      return ListView(
        padding: const EdgeInsets.all(16),
        children: [
          EmptyHint(
            icon: Icons.memory,
            title: 'Wallet core unavailable',
            subtitle: state.error ?? 'unknown error',
            actionLabel: 'Retry',
            onAction: () => ref.read(bridgeControllerProvider.notifier).start(),
          ),
        ],
      );
    }

    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(bridgeControllerProvider.notifier).refresh();
        await _load();
      },
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
        children: [
          if (identity == null)
            EmptyHint(
              icon: Icons.person_add_alt_1,
              title: 'No identity yet',
              subtitle:
                  'Create your Signet identity. Keys are generated and encrypted on this phone; nothing leaves it.',
              actionLabel: 'Create identity',
              onAction: () => createIdentityFlow(context, ref),
            )
          else
            SectionCard(
              title: 'You sign as',
              trailing: TextButton(
                onPressed: () => showIdentitySwitcher(context, ref),
                child: const Text('Switch'),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    children: [
                      CircleAvatar(
                        radius: 24,
                        child: Text(
                          (identity['name'] as String? ?? '?')
                              .substring(0, 1)
                              .toUpperCase(),
                          style: const TextStyle(fontSize: 20),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(identity['name'] as String? ?? 'unnamed',
                            style: Theme.of(context).textTheme.titleLarge),
                      ),
                      _NativeChip(native: state.native),
                    ],
                  ),
                  const SizedBox(height: 8),
                  KeyRow(label: 'ed', value: identity['ed_public'] as String? ?? ''),
                  KeyRow(label: 'seal', value: identity['seal_public'] as String? ?? ''),
                ],
              ),
            ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: _busy ? null : _load,
                  icon: _busy
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Icon(Icons.sync),
                  label: const Text('Refresh records'),
                ),
              ),
              const SizedBox(width: 12),
              _NodeChip(status: nodeStatus),
            ],
          ),
          if (_nodeNote != null) ...[
            const SizedBox(height: 12),
            Text(_nodeNote!,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    )),
          ],
          const SizedBox(height: 16),
          Text('My records', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
          if (identity != null && _records.isEmpty && !_busy)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 24),
              child: Text(
                'Nothing on the ledger concerns this identity yet.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
              ),
            ),
          for (final record in _records)
            Card(
              elevation: 0,
              clipBehavior: Clip.antiAlias,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              child: ListTile(
                leading: const Icon(Icons.description_outlined),
                title: Text(record['label'] as String? ?? 'record',
                    maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text('${record['namespace']} · seq ${record['seq']}',
                    maxLines: 1, overflow: TextOverflow.ellipsis),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => _openRecord(record),
              ),
            ),
        ],
      ),
    );
  }
}

class _NativeChip extends StatelessWidget {
  const _NativeChip({required this.native});

  final bool native;

  @override
  Widget build(BuildContext context) {
    if (!native) return const SizedBox.shrink();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primaryContainer,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text('native core',
          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                color: Theme.of(context).colorScheme.onPrimaryContainer,
              )),
    );
  }
}

class _NodeChip extends StatelessWidget {
  const _NodeChip({required this.status});

  final String status;

  @override
  Widget build(BuildContext context) {
    final down = status == 'down';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(down ? Icons.cloud_off : Icons.cloud_done_outlined,
              size: 16,
              color: down
                  ? Theme.of(context).colorScheme.error
                  : const Color(0xFF46D68C)),
          const SizedBox(width: 6),
          Text(down ? 'node down' : status,
              style: Theme.of(context).textTheme.labelSmall),
        ],
      ),
    );
  }
}
