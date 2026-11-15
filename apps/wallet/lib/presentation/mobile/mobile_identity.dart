import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../providers/bridge_provider.dart';
import 'mobile_widgets.dart';

/// Identity switcher: the mobile counterpart of the desktop selector, as a
/// bottom sheet so the thumb never leaves the lower half of the screen.
Future<void> showIdentitySwitcher(BuildContext context, WidgetRef ref) async {
  final identities = ref.read(bridgeControllerProvider).identities;
  final current = ref.read(selectedIdentityProvider);
  final picked = await showModalBottomSheet<String>(
    context: context,
    showDragHandle: true,
    builder: (context) => SafeArea(
      child: ListView(
        shrinkWrap: true,
        padding: const EdgeInsets.only(bottom: 12),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 8),
            child: Text('Sign as', style: Theme.of(context).textTheme.titleMedium),
          ),
          for (final id in identities)
            ListTile(
              leading: CircleAvatar(
                child: Text(
                  (id['name'] as String? ?? '?').substring(0, 1).toUpperCase(),
                ),
              ),
              title: Text(id['name'] as String? ?? 'unnamed'),
              subtitle: Text(shortKey(id['ed_public'] as String?)),
              trailing: (id['name'] as String?) == current
                  ? const Icon(Icons.check_circle, color: Color(0xFF46D68C))
                  : null,
              onTap: () => Navigator.pop(context, id['name'] as String?),
            ),
          if (identities.isEmpty)
            const Padding(
              padding: EdgeInsets.all(20),
              child: Text('No identities yet. Create one below.'),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 8, 20, 0),
            child: OutlinedButton.icon(
              onPressed: () {
                Navigator.pop(context);
                createIdentityFlow(context, ref);
              },
              icon: const Icon(Icons.person_add_alt_1),
              label: const Text('New identity'),
            ),
          ),
        ],
      ),
    ),
  );
  if (picked != null) {
    ref.read(selectedIdentityProvider.notifier).select(picked);
  }
}

/// Create an identity: name, passphrase, confirmation. Returns true on
/// success. Keeps the passphrase in the session cache so the first action
/// afterwards does not ask twice.
Future<bool> createIdentityFlow(BuildContext context, WidgetRef ref) async {
  final name = await askText(
    context,
    title: 'New identity',
    hint: 'Name (e.g. amina)',
    action: 'Next',
  );
  final trimmed = (name ?? '').trim();
  if (trimmed.isEmpty) return false;
  if (!context.mounted) return false;

  final passphrase = await askSecret(
    context,
    title: 'Passphrase for $trimmed',
    hint: 'At least 8 characters',
    action: 'Next',
  );
  if (passphrase == null || passphrase.length < 8) {
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Passphrase must be at least 8 characters')),
      );
    }
    return false;
  }
  if (!context.mounted) return false;

  final confirm = await askSecret(
    context,
    title: 'Confirm passphrase',
    hint: 'Type it again',
    action: 'Create identity',
  );
  if (confirm != passphrase) {
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Passphrases do not match')),
      );
    }
    return false;
  }

  try {
    await ref
        .read(bridgeControllerProvider.notifier)
        .createIdentity(name: trimmed, passphrase: passphrase);
    ref.read(selectedIdentityProvider.notifier).select(trimmed);
    ref.read(passphraseProvider.notifier).set(passphrase);
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Identity $trimmed created on this device')),
      );
    }
    return true;
  } catch (e) {
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Could not create identity: $e')),
      );
    }
    return false;
  }
}
