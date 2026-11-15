import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../providers/bridge_provider.dart';
import 'mobile_widgets.dart';

/// Verify tab: paste any entry from any node and check it on this device.
/// The node is never trusted - only the local signature math counts.
class MobileVerifyTab extends ConsumerStatefulWidget {
  const MobileVerifyTab({super.key});

  @override
  ConsumerState<MobileVerifyTab> createState() => _MobileVerifyTabState();
}

class _MobileVerifyTabState extends ConsumerState<MobileVerifyTab> {
  final _entry = TextEditingController();
  Map<String, dynamic>? _verdict;
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _entry.dispose();
    super.dispose();
  }

  Future<void> _verify() async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) {
      setState(() => _error = 'The wallet core is not ready yet.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _verdict = null;
    });
    try {
      final decoded = jsonDecode(_entry.text);
      final entry = decoded is Map && decoded['entry'] is Map
          ? Map<String, dynamic>.from(decoded['entry'] as Map)
          : decoded is Map<String, dynamic>
              ? decoded
              : null;
      if (entry == null) {
        setState(() => _error = 'Paste a single entry JSON object.');
        return;
      }
      final verdict = await bridge.verifyEntry(entry: entry);
      if (mounted) setState(() => _verdict = verdict);
    } catch (e) {
      if (mounted) setState(() => _error = 'Verification failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ok = _verdict?['ok'] != false;
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
      children: [
        SectionCard(
          title: 'Entry JSON',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _entry,
                maxLines: 8,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                decoration: const InputDecoration(
                  hintText: 'Paste an entry from any node',
                  border: OutlineInputBorder(),
                  alignLabelWithHint: true,
                ),
              ),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: () async {
                  final data = await Clipboard.getData('text/plain');
                  if (data?.text != null) _entry.text = data!.text!;
                },
                icon: const Icon(Icons.content_paste),
                label: const Text('Paste'),
              ),
            ],
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
        ],
        const SizedBox(height: 12),
        FilledButton.icon(
          onPressed: _busy || _entry.text.trim().isEmpty ? null : _verify,
          icon: const Icon(Icons.fact_check_outlined),
          label: Text(_busy ? 'Checking...' : 'Verify entry'),
        ),
        if (_verdict != null) ...[
          const SizedBox(height: 16),
          SectionCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(
                  children: [
                    Icon(
                      ok ? Icons.verified_user : Icons.gpp_bad,
                      size: 32,
                      color: ok
                          ? const Color(0xFF46D68C)
                          : Theme.of(context).colorScheme.error,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        ok ? 'Valid entry' : 'Not valid',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  ok
                      ? 'Signatures and the party list check out on this device.'
                      : 'Verification failed here. Do not trust what the node served.',
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(12),
                  constraints: const BoxConstraints(maxHeight: 220),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SingleChildScrollView(
                    child: Text(prettyJson(_verdict),
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}
