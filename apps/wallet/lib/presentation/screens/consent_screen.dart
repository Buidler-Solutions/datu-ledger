import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/bridge/wallet_bridge.dart';
import '../../providers/bridge_provider.dart';

/// Sign a consent request / envelope: paste or load JSON, pick the identity
/// and role, confirm, then share the signed envelope back by file.
class ConsentScreen extends ConsumerStatefulWidget {
  const ConsentScreen({super.key, required this.identities});

  final List<Map<String, dynamic>> identities;

  @override
  ConsumerState<ConsentScreen> createState() => _ConsentScreenState();
}

class _ConsentScreenState extends ConsumerState<ConsentScreen> {
  final _doc = TextEditingController();
  final _pass = TextEditingController();
  final _role = TextEditingController(text: 'holder');
  final _kind = TextEditingController(text: 'land.title.application');
  String? _identity;
  Map<String, dynamic>? _result;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    if (widget.identities.isNotEmpty) {
      _identity = widget.identities.first['name'] as String?;
    }
  }

  Future<void> _loadFile() async {
    final files = await FilePicker.pickFiles(type: FileType.custom, allowedExtensions: ['json']);
    if (files.isEmpty || files.first.path == null) return;
    final text = await File(files.first.path!).readAsString();
    setState(() => _doc.text = text);
  }

  Future<void> _sign() async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null || _identity == null) return;
    setState(() {
      _busy = true;
      _error = null;
      _result = null;
    });
    try {
      final decoded = jsonDecode(_doc.text) as Map<String, dynamic>;
      final isEnvelope = decoded['parties'] is List && decoded['doc'] != null;
      final res = await bridge.partySign(
        name: _identity!,
        passphrase: _pass.text,
        role: _role.text.trim(),
        kind: _kind.text.trim(),
        document: isEnvelope ? decoded : decoded,
      );
      final signed = (res['document'] as Map?)?.cast<String, dynamic>();
      if (signed == null) throw StateError(res['error']?.toString() ?? 'no signed document');
      setState(() => _result = signed);
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  String _summary() {
    try {
      final decoded = jsonDecode(_doc.text) as Map<String, dynamic>;
      final inner = (decoded['doc'] as Map?)?.cast<String, dynamic>() ?? decoded;
      final parties = (decoded['parties'] as List?) ?? const [];
      final roles = parties.map((p) => (p as Map)['role']).join(', ');
      return 'parcel ${inner['parcel'] ?? '?'} · signatures so far: ${roles.isEmpty ? 'none' : roles}';
    } catch (_) {
      return 'document is not valid JSON yet';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign consent')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(
            children: [
              Expanded(
                child: DropdownButtonFormField<String>(
                  initialValue: _identity,
                  decoration: const InputDecoration(labelText: 'Identity'),
                  items: widget.identities
                      .map(
                        (id) => DropdownMenuItem(
                          value: id['name'] as String,
                          child: Text(id['name'] as String),
                        ),
                      )
                      .toList(),
                  onChanged: (v) => setState(() => _identity = v),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _role,
                  decoration: const InputDecoration(labelText: 'Role'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _kind,
                  decoration: const InputDecoration(labelText: 'Kind'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _pass,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Wallet passphrase'),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              OutlinedButton.icon(
                onPressed: _loadFile,
                icon: const Icon(Icons.folder_open),
                label: const Text('Load JSON file'),
              ),
              const SizedBox(width: 8),
              Text(_summary(), style: Theme.of(context).textTheme.bodySmall),
            ],
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _doc,
            minLines: 8,
            maxLines: 16,
            decoration: const InputDecoration(
              labelText: 'Consent request / envelope JSON',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: _busy ? null : _sign,
            icon: const Icon(Icons.fingerprint),
            label: Text(_busy ? 'signing…' : 'Confirm & sign'),
          ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
            ),
          if (_result != null) ...[
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Signed envelope - hand this back'),
                    const SizedBox(height: 8),
                    SelectableText(
                      WalletBridge.pretty(_result),
                      style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                    ),
                    Row(
                      children: [
                        TextButton.icon(
                          onPressed: () => Clipboard.setData(
                            ClipboardData(text: jsonEncode(_result)),
                          ),
                          icon: const Icon(Icons.copy, size: 16),
                          label: const Text('Copy'),
                        ),
                        TextButton.icon(
                          onPressed: () async {
                            final name =
                                '${((_result!['doc'] as Map?)?['parcel'] ?? 'document')}-signed.json';
                            final uri = await FilePicker.saveFile(
                              fileName: name,
                              bytes: Uint8List.fromList(utf8.encode(WalletBridge.pretty(_result))),
                              mimeType: 'application/json',
                            );
                            if (context.mounted && uri != null) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('saved: $uri')),
                              );
                            }
                          },
                          icon: const Icon(Icons.save_alt, size: 16),
                          label: const Text('Save file'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
