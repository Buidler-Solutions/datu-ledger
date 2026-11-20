import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// The ledger node this wallet reads from, remembered across launches.
///
/// On a phone the default (127.0.0.1) is the phone itself, so forgetting the
/// setting means the "who vouches" card and the records list go dark on
/// every restart. The setting is a plain file in the app directory, the same
/// place the wallet keeps its keys.
class NodeSetting {
  static Future<File> _file() async {
    final dir = await getApplicationDocumentsDirectory();
    return File('${dir.path}/datu-wallet/node.txt');
  }

  /// The last saved node URL, or null when none was saved. A lost or
  /// unreadable setting is indistinguishable from "never set": both fall
  /// back to the default, neither is an error worth showing.
  static Future<String?> read() async {
    try {
      final file = await _file();
      if (!await file.exists()) return null;
      final value = (await file.readAsString()).trim();
      return value.isEmpty ? null : value;
    } catch (_) {
      return null;
    }
  }

  /// Remember [url] for the next launch. Failing to persist is not worth
  /// blocking the setting the user just made in this session.
  static Future<void> write(String url) async {
    try {
      final file = await _file();
      await file.parent.create(recursive: true);
      await file.writeAsString(url.trim());
    } catch (_) {}
  }
}
