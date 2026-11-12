import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/bridge/wallet_bridge.dart';
import '../../core/ledger/ledger_client.dart';
import '../../providers/bridge_provider.dart';

/// The ledger explorer - a desktop mirror of the node's web explorer: node
/// summary + governance freshness, recent entries (filter by namespace or
/// author, expand for the full signed entry), witness checkpoints, and
/// preserved disputes. Read-only, like every wallet view of the ledger.
class ExplorerTab extends ConsumerStatefulWidget {
  const ExplorerTab({super.key});

  @override
  ConsumerState<ExplorerTab> createState() => _ExplorerTabState();
}

class _ExplorerTabState extends ConsumerState<ExplorerTab> {
  final _ns = TextEditingController();
  final _author = TextEditingController();
  Map<String, dynamic>? _status;
  List<Map<String, dynamic>> _entries = const [];
  List<Map<String, dynamic>> _checkpoints = const [];
  List<Map<String, dynamic>> _conflicts = const [];
  String? _error;
  bool _busy = false;

  LedgerClient get _client => LedgerClient(baseUrl: ref.read(nodeUrlProvider));

  Future<void> _load({bool withSideBars = false}) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final status = await _client.status();
      final mode = status['policy'] is Map ? status['policy']['mode'] : '?';
      ref.read(nodeStatusProvider.notifier).set('$mode · ${status['entries']} entries');
      final entries = await _client.entries(ns: _ns.text, author: _author.text, limit: 50);
      setState(() {
        _status = status;
        _entries = entries;
      });
      if (withSideBars) {
        final checkpoints = await _client.checkpoints();
        final conflicts = await _client.conflicts();
        setState(() {
          _checkpoints = checkpoints;
          _conflicts = conflicts;
        });
      }
    } catch (e) {
      ref.read(nodeStatusProvider.notifier).set('down');
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _verifyEntry(Map<String, dynamic> id) async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) return;
    try {
      final full = await _client.entry(id['id'] as String);
      final data = await bridge.verifyEntry(entry: full);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('verified ${data['id']} · ${data['note']}')),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('verification failed: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final manifest = _status?['manifest'] is Map ? _status!['manifest'] as Map : null;
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _ns,
                decoration: const InputDecoration(
                    labelText: 'Node URL is set in My records · namespace filter'),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _author,
                      decoration: const InputDecoration(
                          labelText: 'Author key (blank = all)'),
                    ),
                  ),
                  const SizedBox(width: 8),
                  FilledButton.icon(
                    onPressed: _busy ? null : () => _load(withSideBars: true),
                    icon: const Icon(Icons.refresh),
                    label: Text(_busy ? 'loading…' : 'Load'),
                  ),
                ],
              ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    _error!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
              if (_status != null) ...[
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Node summary',
                            style: Theme.of(context).textTheme.titleSmall),
                        const SizedBox(height: 8),
                        _row('entries', '${_status!['entries']}'),
                        _row('witness checkpoints', '${_status!['checkpoints']}'),
                        _row('policy mode',
                            '${_status!['policy'] is Map ? _status!['policy']['mode'] : '?'}'),
                        if (manifest != null) ...[
                          _row('governance',
                              'manifest ${manifest['manifest_id']} - ${manifest['freshness']}'
                                  '${manifest['reason'] != null && (manifest['reason'] as String).isNotEmpty ? ' (${manifest['reason']})' : ''}'),
                        ],
                      ],
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Text('Recent entries', style: Theme.of(context).textTheme.titleSmall),
              const SizedBox(height: 8),
              for (final e in _entries)
                Card(
                  child: ExpansionTile(
                    tilePadding: const EdgeInsets.symmetric(horizontal: 12),
                    title: Text(
                      '${e['namespace']} · seq ${e['seq']}',
                      style: const TextStyle(fontSize: 13),
                    ),
                    subtitle: Text(
                      '${(e['id'] as String?)?.substring(0, 16)}… · '
                      '${(e['payload_preview'] as String? ?? '').substring(0, (e['payload_preview'] as String? ?? '').length < 60 ? (e['payload_preview'] as String? ?? '').length : 60)}',
                      style: const TextStyle(fontSize: 11, fontFamily: 'Menlo'),
                    ),
                    children: [
                      Padding(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            FutureBuilder<Map<String, dynamic>>(
                              future: _client.entry(e['id'] as String),
                              builder: (context, snapshot) => snapshot.hasData
                                  ? SelectableText(
                                      WalletBridge.pretty(snapshot.data),
                                      style: const TextStyle(
                                          fontFamily: 'Menlo', fontSize: 11),
                                    )
                                  : const Text('loading full entry…'),
                            ),
                            const SizedBox(height: 8),
                            OutlinedButton.icon(
                              onPressed: () => _verifyEntry(e),
                              icon: const Icon(Icons.verified_outlined, size: 16),
                              label: const Text('Verify signatures locally'),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              if (_checkpoints.isNotEmpty) ...[
                const SizedBox(height: 16),
                Text('Witness checkpoints (latest per signer)',
                    style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 8),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: SelectableText(
                      WalletBridge.pretty(_checkpoints),
                      style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                    ),
                  ),
                ),
              ],
              if (_conflicts.isNotEmpty) ...[
                const SizedBox(height: 16),
                Text('Disputes (preserved evidence)',
                    style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 8),
                for (final c in _conflicts)
                  Card(
                    color: Theme.of(context).colorScheme.errorContainer,
                    child: ListTile(
                      title: Text('conflict ${c['id'] ?? '?'}',
                          style: const TextStyle(fontSize: 13)),
                      subtitle: Text(WalletBridge.pretty(c),
                          style: const TextStyle(fontFamily: 'Menlo', fontSize: 10)),
                    ),
                  ),
              ],
            ],
          ),
        ),
      ],
    );
  }

  Widget _row(String key, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 180,
            child: Text(key,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant)),
          ),
          Expanded(
            child: Text(value,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(fontWeight: FontWeight.w600)),
          ),
        ],
      ),
    );
  }
}
