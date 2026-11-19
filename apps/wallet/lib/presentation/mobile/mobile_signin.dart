import 'package:app_links/app_links.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/auth/datu_auth.dart';
import '../../providers/bridge_provider.dart';
import 'mobile_widgets.dart';

/// Incoming deep links land here; the shell sets it and switches tabs, the
/// tab consumes it. Keeps link delivery and tab navigation decoupled.
class PendingSignInLink extends Notifier<String?> {
  @override
  String? build() => null;

  void set(String? link) => state = link;
}

final pendingSignInLinkProvider =
    NotifierProvider<PendingSignInLink, String?>(PendingSignInLink.new);

/// Login tab: Sign in to a dApp with this wallet, standalone.
///
/// The dApp shows a `datu-auth://sign?…` link (QR or button). This screen
/// receives it (deep link, paste, or the sample), reviews who is asking and
/// what they will get, unlocks the identity with the passphrase, signs the
/// challenge in the embedded Rust core, and hands back a return URL whose
/// fragment carries the assertion. No extension, no bridge token, no desktop.
class MobileSignInTab extends ConsumerStatefulWidget {
  const MobileSignInTab({super.key});

  @override
  ConsumerState<MobileSignInTab> createState() => _MobileSignInTabState();
}

class _MobileSignInTabState extends ConsumerState<MobileSignInTab> {
  final _link = TextEditingController();
  final _passphrase = TextEditingController();
  SignInRequest? _request;
  Map<String, dynamic>? _assertion;
  String? _returnUrl;
  String? _error;
  bool _busy = false;
  late final AppLinks _links;
  final _results = ScrollController();
  bool _scanHandled = false;

  @override
  void initState() {
    super.initState();
    _links = AppLinks();
    _wireDeepLinks();
  }

  Future<void> _wireDeepLinks() async {
    try {
      final initial = await _links.getInitialLink();
      if (initial != null) _accept(initial.toString());
      _links.uriLinkStream.listen((uri) => _accept(uri.toString()));
    } catch (_) {
      // Deep links are best effort (simulator, desktop, tests).
    }
  }

  @override
  @override
  void dispose() {
    _link.dispose();
    _passphrase.dispose();
    _results.dispose();
    super.dispose();
  }

  Map<String, dynamic>? get _identity => identityByName(
        ref.watch(bridgeControllerProvider).identities,
        ref.watch(selectedIdentityProvider),
      );

  void _accept(String raw) {
    if (!mounted) return;
    setState(() {
      _link.text = raw;
      _error = null;
      _assertion = null;
      _returnUrl = null;
      try {
        _request = SignInRequest.parse(raw);
      } on DatuAuthException catch (e) {
        _request = null;
        _error = e.message;
      }
    });
    // A scan or link can arrive while the list is scrolled anywhere; the
    // review card is the thing the user must see.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_results.hasClients) {
        _results.animateTo(0, duration: const Duration(milliseconds: 260), curve: Curves.easeOut);
      }
    });
  }

  void _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text?.trim();
    if (text != null && text.isNotEmpty) _accept(text);
  }

  Future<void> _sign() async {
    final request = _request;
    final identity = _identity;
    final bridge = ref.read(bridgeControllerProvider).bridge;
    if (request == null) return;
    if (identity == null) {
      setState(() => _error = 'No identity yet. Create one in Settings.');
      return;
    }
    if (request.expired) {
      setState(() => _error = 'This challenge has expired. Ask the dApp for a new link.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _assertion = null;
      _returnUrl = null;
    });
    try {
      final assertion = await bridge!.authAssert(
        name: identity['name'] as String,
        passphrase: _passphrase.text,
        rpId: request.rpId,
        origin: request.origin,
        nonce: request.nonce,
        expiresAtMs: request.expiresAtMs,
      );
      // The core reports failures as {"error": ...} inside an otherwise
      // successful call; a signature card must never render over that.
      final coreError = assertion['error'];
      if (coreError != null) {
        setState(() => _error = coreError.toString());
        return;
      }
      if (assertion['signature'] is! String || assertion['pubkey'] is! String) {
        setState(() => _error = 'The core returned no signature.');
        return;
      }
      final url = buildReturnUri(request.redirect, assertion);
      setState(() {
        _assertion = assertion;
        _returnUrl = url.toString();
        _passphrase.clear();
      });
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Barcode login: the dApp's QR is just the same datu-auth link, so the
  /// scanner returns text that goes through the identical parser and review.
  Future<void> _scanQr() async {
    _scanHandled = false;
    final controller = MobileScannerController();
    final scanned = await Navigator.of(context).push<String>(
      MaterialPageRoute<String>(
        builder: (routeContext) => Scaffold(
          appBar: AppBar(title: const Text('Scan the dApp QR')),
          body: MobileScanner(
            controller: controller,
            onDetect: (capture) async {
              if (_scanHandled) return;
              String? value;
              for (final barcode in capture.barcodes) {
                final raw = barcode.rawValue;
                if (raw != null && raw.isNotEmpty) {
                  value = raw;
                  break;
                }
              }
              if (value == null) return;
              _scanHandled = true;
              // Stop the camera before leaving the route: popping while the
              // detection callback is still executing leaves a black view.
              await controller.stop();
              if (!routeContext.mounted) return;
              Navigator.of(routeContext).pop(value);
            },
          ),
        ),
      ),
    );
    await controller.dispose();
    if (!mounted || scanned == null || scanned.isEmpty) return;
    _accept(scanned);
  }

  Future<void> _copy(String value, String note) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(note)));
  }

  @override
  Widget build(BuildContext context) {
    ref.listen<String?>(pendingSignInLinkProvider, (previous, next) {
      if (next != null && next != previous) {
        _accept(next);
        ref.read(pendingSignInLinkProvider.notifier).set(null);
      }
    });
    final request = _request;
    return ListView(
      controller: _results,
      padding: const EdgeInsets.all(16),
      children: [
        const SectionTitle(
          title: 'Sign in to a dApp',
          subtitle:
              'Paste the dApp link or scan its QR. This wallet signs the challenge on this phone; '
              'nothing leaves the device until you hand back the return link.',
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _link,
          minLines: 1,
          maxLines: 3,
          decoration: InputDecoration(
            labelText: 'Sign-in link',
            hintText: 'datu-auth://sign?rp_id=…',
            border: const OutlineInputBorder(),
            suffixIcon: IconButton(
              tooltip: 'Paste from clipboard',
              icon: const Icon(Icons.content_paste),
              onPressed: _paste,
            ),
          ),
          onChanged: (value) {
            if (value.trim().isEmpty) return;
            _accept(value);
          },
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 4,
          children: [
            TextButton.icon(
              onPressed: _scanQr,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Scan a QR code'),
            ),
            TextButton.icon(
              onPressed: () => _accept(sampleSignInLink()),
              icon: const Icon(Icons.science_outlined),
              label: const Text('Use a sample link'),
            ),
          ],
        ),
        if (_error != null) ...[
          const SizedBox(height: 8),
          ErrorBanner(message: _error!),
        ],
        if (request != null) ...[
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.verified_user_outlined),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          request.rpId,
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                      ),
                      Chip(
                        label: Text('${request.remainingSeconds}s'),
                        visualDensity: VisualDensity.compact,
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  _Kv('origin', request.origin),
                  _Kv('nonce', request.nonce),
                  _Kv('returns to', request.redirect.toString()),
                  const SizedBox(height: 12),
                  Text(
                    'Approving signs exactly these bytes:\n${request.canonicalBytes}',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _passphrase,
                    obscureText: true,
                    decoration: InputDecoration(
                      labelText: 'Passphrase for ${_identity?['name'] ?? 'your identity'}',
                      border: const OutlineInputBorder(),
                    ),
                    onSubmitted: (_) => _busy ? null : _sign(),
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: _busy || request.expired ? null : _sign,
                      icon: const Icon(Icons.login),
                      label: Text(
                        request.expired ? 'Challenge expired' : 'Approve and sign',
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
        if (_assertion != null && _returnUrl != null) ...[
          const SizedBox(height: 12),
          Card(
            color: Theme.of(context).colorScheme.secondaryContainer,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.check_circle_outline),
                      const SizedBox(width: 8),
                      Text(
                        'Signed',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Give this link back to the dApp (or let it open automatically):',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 8),
                  SelectableText(
                    _returnUrl!,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    children: [
                      FilledButton.tonalIcon(
                        onPressed: () => _copy(_returnUrl!, 'Return link copied'),
                        icon: const Icon(Icons.content_copy),
                        label: const Text('Copy return link'),
                      ),
                      OutlinedButton.icon(
                        onPressed: () => launchUrl(
                          Uri.parse(_returnUrl!),
                          mode: LaunchMode.externalApplication,
                        ),
                        icon: const Icon(Icons.open_in_new),
                        label: const Text('Open in browser'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  ExpansionTile(
                    tilePadding: EdgeInsets.zero,
                    title: const Text('Show the assertion'),
                    children: [
                      SelectableText(
                        prettyJson(_assertion!),
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
        const SizedBox(height: 24),
        Text(
          'The dApp verifies the signature with your public key and checks the nonce it issued. '
          'A screenshot or a copied link is useless to an attacker: every challenge expires and is single use.',
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    );
  }
}

class _Kv extends StatelessWidget {
  const _Kv(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 84,
            child: Text(label, style: Theme.of(context).textTheme.labelSmall),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }
}
