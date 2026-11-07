import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../providers/bridge_provider.dart';
import 'consent_screen.dart';
import 'records_screen.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(bridgeControllerProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('DATU Wallet'),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            onPressed: () => ref.read(bridgeControllerProvider.notifier).refresh(),
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: switch (state.status) {
        BridgeStatus.starting => const Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                CircularProgressIndicator(),
                SizedBox(height: 12),
                Text('starting the local wallet service…'),
              ],
            ),
          ),
        BridgeStatus.error => _ErrorPane(
            message: state.error ?? 'unknown error',
            onRetry: () => ref.read(bridgeControllerProvider.notifier).start(),
            onAttach: (url, token) => ref
                .read(bridgeControllerProvider.notifier)
                .attach(baseUrl: url, token: token),
          ),
        BridgeStatus.ready => _ReadyPane(state: state),
      },
    );
  }
}

class _ReadyPane extends ConsumerWidget {
  const _ReadyPane({required this.state});

  final BridgeState state;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final bridge = state.bridge!;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: ListTile(
            leading: Icon(
              state.native ? Icons.memory : Icons.check_circle,
              color: Colors.green,
            ),
            title: Text(state.native
                ? 'Native wallet core · in-process Rust'
                : 'Wallet service: ${bridge.baseUrl}'),
            subtitle: Text(state.native
                ? '${state.identities.length} identities · keys never leave this device'
                : '${state.identities.length} identities · keys stay in the service'),
            trailing: state.native
                ? const Chip(
                    label: Text('native core'),
                    visualDensity: VisualDensity(horizontal: -4, vertical: -4),
                  )
                : null,
          ),
        ),
        const SizedBox(height: 8),
        ...state.identities.map(
          (id) => Card(
            child: ListTile(
              leading: const Icon(Icons.badge_outlined),
              title: Text(id['name'] as String? ?? '?'),
              subtitle: Text(
                'ed ${(id['ed_public'] as String? ?? '').padRight(16).substring(0, 16)}…  ·  '
                'seal ${(id['seal_public'] as String? ?? '').padRight(16).substring(0, 16)}…',
              ),
              trailing: IconButton(
                tooltip: 'copy ed key',
                icon: const Icon(Icons.copy, size: 18),
                onPressed: () => Clipboard.setData(
                  ClipboardData(text: id['ed_public'] as String? ?? ''),
                ),
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: () => Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => ConsentScreen(identities: state.identities)),
          ),
          icon: const Icon(Icons.draw_outlined),
          label: const Text('Sign a consent request / envelope'),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: () => Navigator.of(context).push(
            MaterialPageRoute(builder: (_) => const RecordsScreen()),
          ),
          icon: const Icon(Icons.cloud_outlined),
          label: const Text('Browse ledger records'),
        ),
      ],
    );
  }
}

class _ErrorPane extends StatefulWidget {
  const _ErrorPane({required this.message, required this.onRetry, required this.onAttach});

  final String message;
  final VoidCallback onRetry;
  final void Function(String url, String token) onAttach;

  @override
  State<_ErrorPane> createState() => _ErrorPaneState();
}

class _ErrorPaneState extends State<_ErrorPane> {
  final _url = TextEditingController(text: 'http://127.0.0.1:7482');
  final _token = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          color: Theme.of(context).colorScheme.errorContainer,
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Text(widget.message),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _url,
          decoration: const InputDecoration(labelText: 'Bridge URL'),
        ),
        TextField(
          controller: _token,
          obscureText: true,
          decoration: const InputDecoration(labelText: 'Pairing token'),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            FilledButton(onPressed: widget.onRetry, child: const Text('Start again')),
            const SizedBox(width: 8),
            OutlinedButton(
              onPressed: () => widget.onAttach(_url.text, _token.text),
              child: const Text('Attach with token'),
            ),
          ],
        ),
      ],
    );
  }
}
