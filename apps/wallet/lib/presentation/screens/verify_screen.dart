import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/bridge/wallet_bridge.dart';
import '../../core/ledger/ledger_client.dart';
import '../../providers/bridge_provider.dart';

/// The transaction verifier: paste (or load, or fetch by id from a node) any
/// signed entry and check it locally - Ed25519 + ML-DSA-65 + the party
/// signatures inside. The node that served the entry is never trusted,
/// which is the whole point.
class VerifyTab extends ConsumerStatefulWidget {
  const VerifyTab({super.key});

  @override
  ConsumerState<VerifyTab> createState() => _VerifyTabState();
}

class _VerifyTabState extends ConsumerState<VerifyTab> {
  final _doc = TextEditingController();
  final _entryId = TextEditingController();
  Map<String, dynamic>? _verdict;
  String? _error;
  bool _busy = false;

  Map<String, dynamic>? get _parsed {
    if (_doc.text.trim().isEmpty) return null;
    try {
      final decoded = jsonDecode(_doc.text);
      return decoded is Map<String, dynamic> ? decoded : null;
    } catch (_) {
      return null;
    }
  }

  Future<void> _verify([Map<String, dynamic>? entry]) async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) return;
    final target = entry ?? _parsed;
    if (target == null) {
      setState(() => _error = 'paste a signed entry (or fetch one by id first)');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _verdict = null;
    });
    try {
      final data = await bridge.verifyEntry(entry: target);
      final parties = (data['parties'] as List? ?? const [])
          .map((p) => '[${(p as Map)['role']}] '
              '${((p['key'] as String?) ?? '').padRight(16).substring(0, 16)}… verified')
          .join('\n');
      setState(() => _verdict = {
        ...data,
        '_text': 'VERIFIED  ${data['id']}\n'
            'author     ${data['author']}\n'
            'namespace  ${data['namespace']} seq ${data['seq']}\n'
            'timestamp  ${data['timestamp_ms']}\n'
            'parties:\n${parties.isEmpty ? 'none (no signed document inside)' : parties}\n\n'
            '${data['note']}',
      });
    } catch (e) {
      setState(() => _verdict = {
        '_text': 'NOT VERIFIED\n$e',
      });
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _fetchById() async {
    final id = _entryId.text.trim();
    if (id.isEmpty) {
      setState(() => _error = 'enter an entry id');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final client = LedgerClient(baseUrl: ref.read(nodeUrlProvider));
      final full = await client.entry(id);
      _doc.text = WalletBridge.pretty(full);
      await _verify(full);
    } catch (e) {
      setState(() => _error = 'fetch failed: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _loadFile() async {
    final files =
        await FilePicker.pickFiles(type: FileType.custom, allowedExtensions: ['json']);
    if (files.isEmpty || files.first.path == null) return;
    final text = await File(files.first.path!).readAsString();
    setState(() => _doc.text = text);
    await _verify();
  }

  @override
  Widget build(BuildContext context) {
    final verdict = _verdict;
    final ok = verdict != null && !((verdict['_text'] as String).startsWith('NOT'));
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _doc,
                minLines: 6,
                maxLines: 14,
                decoration: const InputDecoration(
                  labelText: 'Signed entry JSON (paste, load a file, or fetch by id)',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _entryId,
                      decoration: const InputDecoration(
                          labelText: 'Entry id (uses the node from My records)'),
                    ),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    onPressed: _busy ? null : _fetchById,
                    icon: const Icon(Icons.cloud_download_outlined),
                    label: const Text('Fetch'),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    onPressed: _loadFile,
                    icon: const Icon(Icons.folder_open),
                    label: const Text('Load'),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: _busy ? null : () => _verify(),
                icon: const Icon(Icons.verified_outlined),
                label: Text(_busy ? 'verifying…' : 'Verify locally'),
              ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    _error!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
              if (verdict != null) ...[
                const SizedBox(height: 16),
                Card(
                  color: ok
                      ? Theme.of(context).colorScheme.secondaryContainer
                      : Theme.of(context).colorScheme.errorContainer,
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: SelectableText(
                      verdict['_text'] as String,
                      style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 8),
              Text(
                'Verification happens in your Signet (Ed25519 + ML-DSA-65), never on the '
                'serving node - a lying node cannot forge a verdict.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ],
    );
  }
}
