import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/bridge/wallet_bridge.dart';
import '../../core/ledger/ledger_client.dart';
import '../../providers/bridge_provider.dart';

/// "My data" - what is sealed to me: the decrypted view handed over from
/// My records, plus paste-anything-and-open. Decrypted views clear after
/// 2 minutes of idle (the shell's lock).
class DataTab extends ConsumerStatefulWidget {
  const DataTab({super.key});

  @override
  ConsumerState<DataTab> createState() => _DataTabState();
}

class _DataTabState extends ConsumerState<DataTab> {
  final _openDoc = TextEditingController();
  String? _opened;
  String? _error;
  bool _busy = false;

  Future<void> _open() async {
    final identity = identityByName(
      ref.read(bridgeControllerProvider).identities,
      ref.read(selectedIdentityProvider),
    );
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (identity == null || bridge == null) return;
    final raw = _openDoc.text.trim();
    if (raw.isEmpty) {
      setState(() => _error = 'paste a record first');
      return;
    }
    final passphrase = await _resolvePassphrase();
    if (passphrase == null || passphrase.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final parsed = jsonDecode(raw);
      Map<String, dynamic> document;
      if (parsed is Map<String, dynamic> && parsed['payload_base64'] is String) {
        final payload = LedgerClient.decodePayload(parsed['payload_base64'] as String);
        if (payload == null) throw StateError('entry payload is not a JSON document');
        document = payload;
      } else if (parsed is Map<String, dynamic>) {
        document = parsed;
      } else {
        throw StateError('not a JSON object');
      }
      final data = await bridge.openFields(
        name: identity['name'] as String,
        passphrase: passphrase,
        document: document,
      );
      final doc = data['document'] is Map ? data['document'] as Map : const {};
      final inner = doc['doc'] is Map ? doc['doc'] as Map : doc;
      setState(() => _opened =
          '${data['opened']} field(s) decrypted for you, ${data['skipped']} sealed for others\n\n'
          '${WalletBridge.pretty(inner)}');
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
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
    final decrypted = ref.watch(decryptedProvider);
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (decrypted != null) ...[
                Text('From “My records” - your data, decrypted locally',
                    style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 8),
                Card(
                  color: Theme.of(context).colorScheme.secondaryContainer,
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${decrypted.opened} field(s) decrypted for you, '
                          '${decrypted.skipped} sealed for others',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                        const SizedBox(height: 8),
                        SelectableText(
                          WalletBridge.pretty(decrypted.document),
                          style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
              ],
              TextField(
                controller: _openDoc,
                minLines: 4,
                maxLines: 10,
                decoration: const InputDecoration(
                  labelText: 'Paste entry JSON or a document',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: _busy ? null : _open,
                icon: const Icon(Icons.lock_open_outlined),
                label: Text(_busy ? 'opening…' : 'Decrypt what belongs to me'),
              ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    _error!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
              if (_opened != null) ...[
                const SizedBox(height: 12),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: SelectableText(
                      _opened!,
                      style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 8),
              Text(
                'Decrypted views clear automatically after 2 minutes of inactivity.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ],
    );
  }
}
