import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/ledger/ledger_client.dart';
import '../../core/ledger/my_records.dart';
import '../../providers/bridge_provider.dart';

class _MyRecord {
  const _MyRecord({
    required this.id,
    required this.seq,
    required this.namespace,
    required this.kind,
    required this.label,
    required this.entry,
    this.payload,
  });

  final String id;
  final dynamic seq;
  final String namespace;
  final String kind;
  final String label;
  final Map<String, dynamic> entry;
  final Map<String, dynamic>? payload;
}

/// "My records" - read from any node (validator or observer), match the
/// entries that concern the selected identity, verify each one locally.
class RecordsTab extends ConsumerStatefulWidget {
  const RecordsTab({super.key});

  @override
  ConsumerState<RecordsTab> createState() => _RecordsTabState();
}

class _RecordsTabState extends ConsumerState<RecordsTab> {
  final _ns = TextEditingController();
  final _records = <_MyRecord>[];
  Map<String, dynamic>? _verdict;
  String? _error;
  String? _note;
  bool _busy = false;

  LedgerClient get _client =>
      LedgerClient(baseUrl: ref.read(nodeUrlProvider));

  Future<void> _checkNode() async {
    try {
      final st = await _client.status();
      final mode = st['policy'] is Map ? st['policy']['mode'] : '?';
      ref.read(nodeStatusProvider.notifier).set('$mode · ${st['entries']} entries');
      setState(() => _note = 'node ok - $mode, ${st['entries']} entries, '
          '${st['checkpoints']} witnesses');
    } catch (e) {
      ref.read(nodeStatusProvider.notifier).set('down');
      setState(() => _note = null);
      rethrow;
    }
  }

  Future<void> _find() async {
    final identity = identityByName(
      ref.read(bridgeControllerProvider).identities,
      ref.read(selectedIdentityProvider),
    );
    if (identity == null) {
      setState(() => _error = 'no identity - create one in Settings');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _verdict = null;
      _records.clear();
    });
    try {
      await _checkNode();
      final mine = <_MyRecord>[];
      final list = await _client.entries(limit: 200);
      for (final item in list) {
        if (!nsMatches(_ns.text, item['namespace'] as String? ?? '')) continue;
        final full = await _client.entry(item['id'] as String);
        final payload =
            LedgerClient.decodePayload(full['payload_base64'] as String?);
        if (!concernsMe(payload, identity['ed_public'] as String)) continue;
        mine.add(_MyRecord(
          id: item['id'] as String,
          seq: item['seq'],
          namespace: item['namespace'] as String? ?? '?',
          kind: payload?['kind'] is String ? payload!['kind'] as String : '(unsigned document)',
          label: recordLabel(payload, item['id'] as String),
          entry: full,
          payload: payload,
        ));
      }
      setState(() {
        _records.addAll(mine);
        _note = mine.isEmpty
            ? 'no records on this node concern you'
            : '${mine.length} record(s) concern you - verified locally before you trust them';
      });
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _verify(_MyRecord rec) async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) return;
    try {
      final data = await bridge.verifyEntry(entry: rec.entry);
      final parties = (data['parties'] as List? ?? const [])
          .map((p) => '[${(p as Map)['role']}] '
              '${((p['key'] as String?) ?? '').padRight(16).substring(0, 16)}… verified')
          .join('\n');
      setState(() => _verdict = {
        ...data,
        '_text': 'VERIFIED  ${data['id']}\n'
            'author     ${data['author']}\n'
            'namespace  ${data['namespace']} seq ${data['seq']}\n'
            'parties:\n${parties.isEmpty ? 'none' : parties}\n\n'
            '${data['note']}',
      });
    } catch (e) {
      setState(() => _verdict = {'_text': 'verification failed: $e'});
    }
  }

  Future<void> _decrypt(_MyRecord rec) async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    final identity = identityByName(
      ref.read(bridgeControllerProvider).identities,
      ref.read(selectedIdentityProvider),
    );
    if (bridge == null || identity == null) return;
    final payload = rec.payload;
    if (payload == null) {
      setState(() => _error = 'this entry carries no JSON document');
      return;
    }
    final passphrase = await _resolvePassphrase();
    if (passphrase == null || passphrase.isEmpty) return;
    try {
      final data = await bridge.openFields(
        name: identity['name'] as String,
        passphrase: passphrase,
        document: payload,
      );
      final document = data['document'] is Map ? data['document'] as Map : const {};
      final inner = document['doc'] is Map ? document['doc'] as Map<String, dynamic> : null;
      ref.read(decryptedProvider.notifier).set(DecryptedView(
        opened: data['opened'] as int? ?? 0,
        skipped: data['skipped'] as int? ?? 0,
        document: (inner ?? document).cast<String, dynamic>(),
      ));
      ref.read(tabProvider.notifier).go(WalletTab.data);
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  Future<String?> _resolvePassphrase() {
    final cached = ref.read(passphraseProvider);
    if (cached.isNotEmpty) return Future.value(cached);
    return _askPassphrase();
  }

  Future<String?> _askPassphrase() {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Vault passphrase'),
        content: TextField(
          controller: controller,
          obscureText: true,
          autofocus: true,
          decoration: const InputDecoration(
              hintText: 'the one you chose for this identity'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, controller.text),
              child: const Text('Unlock')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _ns,
                decoration: const InputDecoration(
                  labelText: 'Namespace filter (blank = every namespace)',
                  hintText: 'gov.titles.* · gov.licenses.* · procurement.*',
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  FilledButton.icon(
                    onPressed: _busy ? null : _find,
                    icon: const Icon(Icons.search),
                    label: Text(_busy ? 'searching…' : 'Find my records'),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    onPressed: _checkNode,
                    icon: const Icon(Icons.wifi_tethering),
                    label: const Text('Check node'),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                'A record is “mine” when a party signature key is yours or the document '
                'names your key (holder_key, bidder_key, licensee_key, …) - any namespace, '
                'any transaction kind. The node is never trusted: verification is local.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
        if (_note != null)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: Text(_note!, style: Theme.of(context).textTheme.bodySmall),
          ),
        if (_error != null)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: Text(
              _error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        const SizedBox(height: 8),
        for (final rec in _records)
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(rec.label,
                            style: Theme.of(context).textTheme.titleSmall),
                      ),
                      Text('${rec.kind} · seq ${rec.seq}',
                          style: Theme.of(context).textTheme.bodySmall),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${rec.namespace} · ${rec.id.substring(0, 12)}…',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        fontFamily: 'Menlo', fontSize: 11),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      OutlinedButton.icon(
                        onPressed: () => _verify(rec),
                        icon: const Icon(Icons.verified_outlined, size: 16),
                        label: const Text('Verify'),
                      ),
                      const SizedBox(width: 8),
                      OutlinedButton.icon(
                        onPressed: () => _decrypt(rec),
                        icon: const Icon(Icons.lock_open_outlined, size: 16),
                        label: const Text('Decrypt'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        if (_verdict != null) ...[
          const SizedBox(height: 8),
          Card(
            color: Theme.of(context).colorScheme.secondaryContainer,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: SelectableText(
                _verdict!['_text'] as String? ?? '',
                style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
              ),
            ),
          ),
        ],
      ],
    );
  }
}
