import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/bridge/bridge_launcher.dart';
import '../../core/bridge/wallet_bridge.dart';
import '../../providers/bridge_provider.dart';

/// Settings - identity lifecycle: create (Argon2id passphrase), keys, the
/// portable encrypted backup, the bridge connection and the node this app
/// reads from. Mirrors the extension's Settings tab; the desktop's
/// "wallets" equivalent is the single bridge process, started or attached
/// from here when it is down.
class SettingsTab extends ConsumerStatefulWidget {
  const SettingsTab({super.key});

  @override
  ConsumerState<SettingsTab> createState() => _SettingsTabState();
}

class _SettingsTabState extends ConsumerState<SettingsTab> {
  final _newName = TextEditingController();
  final _newPass = TextEditingController();
  final _newPass2 = TextEditingController();
  final _backupPass = TextEditingController();
  final _importPass = TextEditingController();
  final _importRename = TextEditingController();
  final _nodeUrl = TextEditingController();
  String? _note;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _nodeUrl.text = ref.read(nodeUrlProvider);
  }

  void _say(String? note, [String? error]) =>
      setState(() {
        _note = note;
        _error = error;
      });

  Future<void> _create() async {
    final controller = ref.read(bridgeControllerProvider.notifier);
    final name = _newName.text.trim();
    final pass = _newPass.text;
    if (name.isEmpty) return _say(null, 'choose a name for this identity');
    if (pass.length < 8) return _say(null, 'passphrase must be at least 8 characters');
    if (pass != _newPass2.text) return _say(null, 'passphrases do not match');
    setState(() => _busy = true);
    try {
      final data = await controller.createIdentity(name: name, passphrase: pass);
      final identity = data['identity'] is Map ? data['identity'] as Map : const {};
      ref.read(selectedIdentityProvider.notifier)
          .select(identity['name'] as String? ?? name);
      _newName.clear();
      _newPass.clear();
      _newPass2.clear();
      _say('identity \'${identity['name']}\' created - seal key '
          '${(identity['seal_public'] as String? ?? '').padRight(20).substring(0, 20)}…\n'
          'Remember the passphrase: it cannot be recovered. Share only your seal key.');
    } catch (e) {
      _say(null, e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _export() async {
    final identity = identityByName(
      ref.read(bridgeControllerProvider).identities,
      ref.read(selectedIdentityProvider),
    );
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (identity == null || bridge == null) return;
    final backupPass = _backupPass.text;
    if (backupPass.length < 8) return _say(null, 'backup passphrase must be at least 8 characters');
    final passphrase = await _resolvePassphrase();
    if (passphrase == null || passphrase.isEmpty) return;
    setState(() => _busy = true);
    try {
      final data = await bridge.exportIdentity(
        name: identity['name'] as String,
        passphrase: passphrase,
        backupPassphrase: backupPass,
      );
      final backup = data['backup'];
      final uri = await FilePicker.saveFile(
        fileName: '${identity['name']}.datu-identity.json',
        bytes: Uint8List.fromList(utf8.encode(WalletBridge.pretty(backup))),
        mimeType: 'application/json',
      );
      if (uri != null) {
        _say('backup written to $uri - keep it with the backup passphrase '
            '(they are useless apart)');
      }
    } catch (e) {
      _say(null, e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _import() async {
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (bridge == null) return;
    final files = await FilePicker.pickFiles(
        type: FileType.custom, allowedExtensions: ['json']);
    if (files.isEmpty || files.first.path == null) return;
    final passphrase = _importPass.text;
    if (passphrase.isEmpty) return _say(null, 'enter the backup passphrase');
    Map<String, dynamic> backup;
    try {
      final decoded = jsonDecode(await File(files.first.path!).readAsString());
      if (decoded is! Map<String, dynamic>) throw StateError('not a JSON object');
      backup = decoded;
    } catch (e) {
      return _say(null, 'backup file is not valid JSON ($e)');
    }
    setState(() => _busy = true);
    try {
      final data = await bridge.importIdentity(
        backup: backup,
        passphrase: passphrase,
        rename: _importRename.text.trim().isEmpty ? null : _importRename.text.trim(),
      );
      await ref.read(bridgeControllerProvider.notifier).refresh();
      final identity = data['identity'] is Map ? data['identity'] as Map : const {};
      ref.read(selectedIdentityProvider.notifier).select(identity['name'] as String?);
      _importPass.clear();
      _importRename.clear();
      _say('identity \'${identity['name']}\' imported - it unlocks with the '
          'backup passphrase');
    } catch (e) {
      _say(null, e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<String?> _resolvePassphrase() {
    final cached = ref.read(passphraseProvider);
    if (cached.isNotEmpty) return Future.value(cached);
    return _askPassphrase('Identity passphrase');
  }

  Future<String?> _askPassphrase(String title) {
    final controller = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          obscureText: true,
          autofocus: true,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, controller.text),
              child: const Text('OK')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(bridgeControllerProvider);
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _sectionTitle('Create identity (set your passphrase)'),
              Text(
                'You choose the passphrase - it locks your keys with Argon2id. It is '
                'never stored or sent anywhere, and it cannot be recovered: if you '
                'lose it, the keys and the sealed data addressed to them are lost.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 8),
              TextField(
                  controller: _newName,
                  decoration: const InputDecoration(labelText: 'Name (e.g. alice)')),
              TextField(
                  controller: _newPass,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Passphrase (min 8 chars)')),
              TextField(
                  controller: _newPass2,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Confirm passphrase')),
              const SizedBox(height: 8),
              FilledButton.icon(
                onPressed: _busy ? null : _create,
                icon: const Icon(Icons.person_add_alt_outlined),
                label: const Text('Create identity'),
              ),

              const SizedBox(height: 24),
              _sectionTitle('Identities in this vault'),
              for (final id in state.identities)
                Card(
                  child: ListTile(
                    leading: const Icon(Icons.badge_outlined),
                    title: Text(id['name'] as String? ?? '?'),
                    subtitle: Text(
                      'ed ${(id['ed_public'] as String? ?? '').substring(0, 16)}…\n'
                      'seal ${id['seal_public'] as String? ?? ''}',
                      style: const TextStyle(fontFamily: 'Menlo', fontSize: 10),
                    ),
                    isThreeLine: true,
                    trailing: IconButton(
                      tooltip: 'copy seal key (share this so registries can encrypt to you)',
                      icon: const Icon(Icons.copy, size: 18),
                      onPressed: () => Clipboard.setData(
                        ClipboardData(text: id['seal_public'] as String? ?? ''),
                      ),
                    ),
                  ),
                ),

              const SizedBox(height: 24),
              _sectionTitle('Backup & move devices'),
              Text(
                'Exports the selected identity as a file encrypted with a separate '
                'backup passphrase. Import it on another device - the restored '
                'identity unlocks with that backup passphrase.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 8),
              TextField(
                  controller: _backupPass,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Backup passphrase (min 8 chars)')),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: _busy ? null : _export,
                icon: const Icon(Icons.download_outlined),
                label: const Text('Export encrypted backup'),
              ),
              const SizedBox(height: 12),
              TextField(
                  controller: _importPass,
                  obscureText: true,
                  decoration: const InputDecoration(labelText: 'Passphrase for the backup file')),
              TextField(
                  controller: _importRename,
                  decoration: const InputDecoration(
                      labelText: 'Import as (optional rename)')),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                onPressed: _busy ? null : _import,
                icon: const Icon(Icons.upload_outlined),
                label: const Text('Import identity (choose file)'),
              ),

              const SizedBox(height: 24),
              _sectionTitle('Node this app reads from'),
              TextField(
                controller: _nodeUrl,
                decoration: const InputDecoration(
                    labelText: 'Observer / validator URL',
                    hintText: 'http://127.0.0.1:7474'),
                onChanged: (v) => ref.read(nodeUrlProvider.notifier).set(v),
              ),
              const SizedBox(height: 24),
              _sectionTitle('Signet backend'),
              Card(
                child: ListTile(
                  leading: Icon(
                    state.native ? Icons.memory : Icons.dns_outlined,
                    color: Colors.green,
                  ),
                  title: Text(state.native
                      ? 'Native Signet core · in-process Rust'
                      : 'Signet service: ${state.bridge?.baseUrl}'),
                  subtitle: Text(state.native
                      ? 'keys never leave this device'
                      : 'keys stay in the service; this app only asks it to sign'),
                ),
              ),

              if (!state.native) ...[
                const SizedBox(height: 24),
                _sectionTitle('Pair the browser Signet extension'),
                Text(
                  'The extension usually pairs itself - open its panel and it finds '
                  'this bridge automatically. If it cannot (remote bridge, unusual '
                  'port), paste this token into the extension\u2019s Settings tab. '
                  'It grants the right to *ask* for signatures - every sign stays '
                  'passphrase-gated.',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: 8),
                FutureBuilder<String?>(
                  future: BridgeLauncher.readPairingToken(),
                  builder: (context, snapshot) => Card(
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Pairing token (wallet/bridge.token)',
                              style: Theme.of(context).textTheme.bodySmall),
                          const SizedBox(height: 6),
                          SelectableText(
                            snapshot.data ?? '…',
                            style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                          ),
                          const SizedBox(height: 6),
                          OutlinedButton.icon(
                            onPressed: snapshot.data == null
                                ? null
                                : () => Clipboard.setData(
                                    ClipboardData(text: snapshot.data!),
                                  ),
                            icon: const Icon(Icons.copy, size: 16),
                            label: const Text('Copy token'),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ],

              if (_note != null)
                Padding(
                  padding: const EdgeInsets.only(top: 16),
                  child: Card(
                    color: Theme.of(context).colorScheme.secondaryContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Text(_note!,
                          style: Theme.of(context).textTheme.bodySmall),
                    ),
                  ),
                ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    _error!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _sectionTitle(String text) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(text, style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
        ],
      );
}
