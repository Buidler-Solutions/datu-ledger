import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/bridge/wallet_bridge.dart';
import '../../core/ledger/my_records.dart';
import '../../providers/bridge_provider.dart';

/// "Sign" - holder consent with a review step: paste or load the registry's
/// document, review exactly what will be signed (and whose key the document
/// names), then confirm. The signed envelope goes back to the registry.
class ConsentTab extends ConsumerStatefulWidget {
  const ConsentTab({super.key});

  @override
  ConsumerState<ConsentTab> createState() => _ConsentTabState();
}

class _ConsentTabState extends ConsumerState<ConsentTab> {
  final _doc = TextEditingController();
  final _role = TextEditingController(text: 'holder');
  final _kind = TextEditingController();
  Map<String, dynamic>? _pending;
  Map<String, dynamic>? _result;
  String? _error;
  bool _busy = false;

  Map<String, dynamic>? get _identity => identityByName(
        ref.watch(bridgeControllerProvider).identities,
        ref.watch(selectedIdentityProvider),
      );

  Map<String, dynamic>? get _parsedDoc {
    try {
      final decoded = jsonDecode(_doc.text);
      return decoded is Map<String, dynamic> ? decoded : null;
    } catch (_) {
      return null;
    }
  }

  Future<void> _loadFile() async {
    final files =
        await FilePicker.pickFiles(type: FileType.custom, allowedExtensions: ['json']);
    if (files.isEmpty || files.first.path == null) return;
    final text = await File(files.first.path!).readAsString();
    setState(() => _doc.text = text);
  }

  void _review() {
    final identity = _identity;
    if (identity == null) {
      setState(() => _error = 'no identity - create one in Settings');
      return;
    }
    final document = _parsedDoc;
    if (document == null) {
      setState(() => _error = 'document is not valid JSON yet');
      return;
    }
    final role = _role.text.trim().isEmpty ? 'holder' : _role.text.trim();
    final kind = document['kind'] is String
        ? document['kind'] as String
        : _kind.text.trim();
    if (kind.isEmpty) {
      setState(() => _error =
          'enter the document kind (e.g. land.title.application, procurement.bid)');
      return;
    }
    final docField = document['doc'] is Map ? document['doc'] as Map : const {};
    final namedKey = docField['${role}_key'];
    if (namedKey is String && namedKey != identity['ed_public']) {
      setState(() {
        _error = 'this document names ${role}_key ${namedKey.substring(0, 16)}… '
            'but you are ${(identity['ed_public'] as String).substring(0, 16)}… - '
            'not a party to this record';
        _pending = null;
      });
      return;
    }
    setState(() {
      _error = null;
      _pending = {'document': document, 'role': role, 'kind': kind};
    });
  }

  Future<void> _confirm() async {
    final identity = _identity;
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (identity == null || bridge == null || _pending == null) return;
    String? passphrase = ref.read(passphraseProvider);
    if (passphrase == null || passphrase.isEmpty) {
      passphrase = await _askPassphrase();
      if (passphrase == null || passphrase.isEmpty) return;
    }
    setState(() => _busy = true);
    try {
      final res = await bridge.partySign(
        name: identity['name'] as String,
        passphrase: passphrase,
        role: _pending!['role'] as String,
        kind: _pending!['kind'] as String,
        document: _pending!['document'] as Map<String, dynamic>,
      );
      final signed = (res['document'] as Map?)?.cast<String, dynamic>();
      if (signed == null) throw StateError(res['error']?.toString() ?? 'no signed document');
      setState(() {
        _result = signed;
        _pending = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
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
    final identity = _identity;
    final pending = _pending;
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
                  labelText: 'Consent request from the registry (paste, or load a file)',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _role,
                      decoration: const InputDecoration(
                        labelText: 'Role',
                        hintText: 'holder · licensee · bidder · officer',
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      controller: _kind,
                      decoration: const InputDecoration(
                        labelText: 'Kind (from document if set)',
                        hintText: 'land.title.application',
                      ),
                    ),
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
                onPressed: _review,
                icon: const Icon(Icons.receipt_long_outlined),
                label: const Text('Review consent request'),
              ),
              if (pending != null) ...[
                const SizedBox(height: 12),
                Card(
                  color: Theme.of(context).colorScheme.secondaryContainer,
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('Review before signing',
                            style: Theme.of(context).textTheme.titleSmall),
                        const SizedBox(height: 8),
                        _summaryRow('action', 'sign as ${pending['role']}'),
                        _summaryRow('identity', identity?['name'] as String? ?? '?'),
                        _summaryRow('kind', pending['kind'] as String),
                        _summaryRow(
                          'document subject',
                          recordLabel(
                            pending['document'] as Map<String, dynamic>?,
                            identity?['ed_public'] as String? ?? '',
                          ),
                        ),
                        _summaryRow(
                          'parties already signed',
                          ((pending['document'] as Map)['parties'] as List?)
                                  ?.map((p) => (p as Map)['role'])
                                  .join(', ') ??
                              'none yet',
                        ),
                        _summaryRow(
                          'document size',
                          '${jsonEncode(pending['document']).length} bytes',
                        ),
                        const SizedBox(height: 12),
                        Row(
                          children: [
                            FilledButton.icon(
                              onPressed: _busy ? null : _confirm,
                              icon: const Icon(Icons.fingerprint),
                              label:
                                  Text(_busy ? 'signing…' : 'Confirm & sign'),
                            ),
                            const SizedBox(width: 8),
                            OutlinedButton(
                              onPressed: () =>
                                  setState(() => _pending = null),
                              child: const Text('Cancel'),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ],
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    _error!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
              if (_result != null) ...[
                const SizedBox(height: 16),
                Text('Signed document - give it back to the registry dApp',
                    style: Theme.of(context).textTheme.titleSmall),
                const SizedBox(height: 8),
                SelectableText(
                  WalletBridge.pretty(_result),
                  style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    OutlinedButton.icon(
                      onPressed: () => Clipboard.setData(
                        ClipboardData(text: jsonEncode(_result)),
                      ),
                      icon: const Icon(Icons.copy, size: 16),
                      label: const Text('Copy signed consent'),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton.icon(
                      onPressed: () async {
                        final name =
                            '${((_result!['doc'] as Map?)?['parcel'] ?? 'document')}-signed.json';
                        await FilePicker.saveFile(
                          fileName: name,
                          bytes:
                              Uint8List.fromList(utf8.encode(WalletBridge.pretty(_result))),
                          mimeType: 'application/json',
                        );
                      },
                      icon: const Icon(Icons.save_outlined, size: 16),
                      label: const Text('Save to file'),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }

  Widget _summaryRow(String key, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 170,
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
