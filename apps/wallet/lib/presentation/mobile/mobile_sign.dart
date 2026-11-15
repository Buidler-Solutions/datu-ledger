import 'dart:convert';

import 'package:flutter/services.dart';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../providers/bridge_provider.dart';
import 'mobile_widgets.dart';

/// Sign tab: holder consent in a phone flow - paste, review, confirm,
/// passphrase. The review step is the same contract the desktop panel shows.
class MobileSignTab extends ConsumerStatefulWidget {
  const MobileSignTab({super.key});

  @override
  ConsumerState<MobileSignTab> createState() => _MobileSignTabState();
}

class _MobileSignTabState extends ConsumerState<MobileSignTab> {
  final _doc = TextEditingController();
  final _role = TextEditingController(text: 'holder');
  final _kind = TextEditingController();
  Map<String, dynamic>? _reviewed;
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _doc.dispose();
    _role.dispose();
    _kind.dispose();
    super.dispose();
  }

  Map<String, dynamic>? get _identity => identityByName(
        ref.watch(bridgeControllerProvider).identities,
        ref.watch(selectedIdentityProvider),
      );

  void _review() {
    final identity = _identity;
    if (identity == null) {
      setState(() => _error = 'No identity yet. Create one in Settings.');
      return;
    }
    try {
      final decoded = jsonDecode(_doc.text);
      if (decoded is! Map<String, dynamic>) {
        setState(() => _error = 'The document must be a JSON object.');
        return;
      }
      setState(() {
        _error = null;
        _reviewed = decoded;
      });
    } catch (e) {
      setState(() => _error = 'Not valid JSON: $e');
    }
  }

  Future<void> _sign() async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    final identity = _identity;
    final document = _reviewed;
    if (bridge == null || identity == null || document == null) return;

    final passphrase = await askSecret(
      context,
      title: 'Sign as ${identity['name']}',
      action: 'Sign document',
    );
    if (passphrase == null || passphrase.isEmpty) return;

    setState(() => _busy = true);
    try {
      final signed = await bridge.partySign(
        name: identity['name'] as String,
        passphrase: passphrase,
        role: _role.text.trim().isEmpty ? 'holder' : _role.text.trim(),
        kind: _kind.text.trim().isEmpty ? 'datu.party-consent' : _kind.text.trim(),
        document: document,
      );
      ref.read(passphraseProvider.notifier).set(passphrase);
      if (mounted) {
        showResult(
          context,
          title: 'Signed as ${_role.text.trim().isEmpty ? 'holder' : _role.text.trim()}',
          body: prettyJson(signed),
          note: 'Send this envelope back to the registry. Nothing was published anywhere.',
          icon: Icons.draw,
        );
        setState(() {
          _reviewed = null;
          _doc.clear();
        });
      }
    } catch (e) {
      if (mounted) setState(() => _error = 'Signing failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
      children: [
        SectionCard(
          title: 'Document to sign',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _doc,
                maxLines: 8,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                decoration: const InputDecoration(
                  hintText: '{\n  "holder_name": "...",\n  "parcel": "..."\n}',
                  border: OutlineInputBorder(),
                  alignLabelWithHint: true,
                ),
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: () async {
                  final data = await Clipboard.getData('text/plain');
                  if (data?.text != null) _doc.text = data!.text!;
                },
                icon: const Icon(Icons.content_paste),
                label: const Text('Paste from clipboard'),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _role,
                      decoration: const InputDecoration(
                        labelText: 'Role',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: TextField(
                      controller: _kind,
                      decoration: const InputDecoration(
                        labelText: 'Kind (optional)',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          Text(_error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error)),
        ],
        const SizedBox(height: 12),
        if (_reviewed == null)
          FilledButton(
            onPressed: _doc.text.trim().isEmpty ? null : _review,
            child: const Text('Review'),
          )
        else
          SectionCard(
            title: 'Review before signing',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: _ReviewLine(
                          label: 'Signer', value: _identity?['name'] as String? ?? '-'),
                    ),
                    Expanded(
                      child: _ReviewLine(
                          label: 'Role',
                          value: _role.text.trim().isEmpty ? 'holder' : _role.text.trim()),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                _ReviewLine(
                  label: 'Fields',
                  value: '${_reviewed!.length} top-level keys',
                ),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(12),
                  constraints: const BoxConstraints(maxHeight: 180),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SingleChildScrollView(
                    child: Text(
                      prettyJson(_reviewed),
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton.icon(
                  onPressed: _busy ? null : _sign,
                  icon: const Icon(Icons.draw),
                  label: Text(_busy ? 'Signing...' : 'Confirm and sign'),
                ),
                TextButton(
                  onPressed: () => setState(() => _reviewed = null),
                  child: const Text('Back to edit'),
                ),
              ],
            ),
          ),
      ],
    );
  }
}

class _ReviewLine extends StatelessWidget {
  const _ReviewLine({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                )),
        Text(value, style: Theme.of(context).textTheme.bodyLarge),
      ],
    );
  }
}
