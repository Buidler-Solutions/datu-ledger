// Direct FFI smoke test outside Flutter: dart run tool/ffi_smoke.dart
// Mirrors NativeWalletBridge's plumbing to debug native crashes.
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:ffi/ffi.dart' as pffi;

typedef OpenC = ffi.Pointer<ffi.Void> Function(ffi.Pointer<pffi.Utf8>);
typedef OpenDart = ffi.Pointer<ffi.Void> Function(ffi.Pointer<pffi.Utf8>);
typedef RequestC = ffi.Pointer<pffi.Utf8> Function(
    ffi.Pointer<ffi.Void>, ffi.Pointer<pffi.Utf8>);
typedef RequestDart = ffi.Pointer<pffi.Utf8> Function(
    ffi.Pointer<ffi.Void>, ffi.Pointer<pffi.Utf8>);
typedef CloseC = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef CloseDart = void Function(ffi.Pointer<ffi.Void>);
typedef FreeC = ffi.Void Function(ffi.Pointer<pffi.Utf8>);
typedef FreeDart = void Function(ffi.Pointer<pffi.Utf8>);

void main(List<String> args) {
  final libPath = args.isNotEmpty
      ? args[0]
      : '../../target/debug/libdatu_wallet_ffi.dylib';
  final lib = ffi.DynamicLibrary.open(libPath);
  final open = lib.lookupFunction<OpenC, OpenDart>('datu_wallet_open');
  final request = lib.lookupFunction<RequestC, RequestDart>('datu_wallet_request');
  final close = lib.lookupFunction<CloseC, CloseDart>('datu_wallet_close');
  final free = lib.lookupFunction<FreeC, FreeDart>('datu_string_free');

  final dir = Directory.systemTemp.createTempSync('datu-ffi-smoke');
  print('data dir: ${dir.path}');

  final cDir = dir.path.toNativeUtf8();
  final core = open(cDir);
  pffi.malloc.free(cDir);
  print('core handle: $core');

  String ask(String json, {String tag = ''}) {
    print('ask $tag …');
    final cReq = json.toNativeUtf8();
    print('  request utf8 ok (${json.length} bytes)');
    final cAns = request(core, cReq);
    print('  native returned');
    pffi.malloc.free(cReq);
    if (cAns == ffi.nullptr) throw StateError('null answer');
    final ans = cAns.toDartString();
    print('  decoded (${ans.length} bytes)');
    free(cAns);
    print('  freed');
    return ans;
  }

  print('identities: ${ask('{"action":"identities"}', tag: 'identities')}');
  print('create: ${ask(jsonEncode({
        'action': 'create',
        'name': 'smoke',
        'passphrase': 'correct horse battery',
      }), tag: 'create')}');
  print('identities: ${ask('{"action":"identities"}', tag: 'identities2')}');

  close(core);
  dir.deleteSync(recursive: true);
  print('OK');
}
