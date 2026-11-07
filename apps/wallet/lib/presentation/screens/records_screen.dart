import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';

/// Read-only view of a ledger node - the wallet itself never needs to run one.
class RecordsScreen extends StatefulWidget {
  const RecordsScreen({super.key});

  @override
  State<RecordsScreen> createState() => _RecordsScreenState();
}

class _RecordsScreenState extends State<RecordsScreen> {
  final _node = TextEditingController(text: 'http://127.0.0.1:7474');
  final _ns = TextEditingController(text: 'gov.titles.application');
  final _dio = Dio(BaseOptions(connectTimeout: const Duration(seconds: 3)));
  List<Map<String, dynamic>> _entries = const [];
  String? _status;
  String? _error;
  bool _busy = false;

  Future<void> _load() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final base = _node.text.trim().replaceAll(RegExp(r'/+$'), '');
      final status = await _dio.get('$base/v1/status');
      final list = await _dio.get(
        '$base/v1/entries',
        queryParameters: {
          if (_ns.text.trim().isNotEmpty) 'ns': _ns.text.trim(),
          'limit': 20,
        },
      );
      setState(() {
        _status = 'entries ${status.data['entries']} · witnesses ${status.data['checkpoints']} · '
            'mode ${status.data['policy']?['mode'] ?? '?'}';
        _entries = ((list.data['entries'] as List?) ?? const [])
            .cast<Map<String, dynamic>>();
      });
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Ledger records')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _node,
                  decoration: const InputDecoration(labelText: 'Node URL'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _ns,
                  decoration: const InputDecoration(labelText: 'Namespace (blank = all)'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: _busy ? null : _load,
            icon: const Icon(Icons.search),
            label: Text(_busy ? 'loading…' : 'Load records'),
          ),
          if (_status != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_status!, style: Theme.of(context).textTheme.bodySmall),
            ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
            ),
          const SizedBox(height: 8),
          ..._entries.map(
            (e) => Card(
              child: ExpansionTile(
                title: Text(
                  '${(e['id'] as String? ?? '').substring(0, 16)}… · ${e['namespace']}',
                  style: const TextStyle(fontSize: 13),
                ),
                subtitle: Text(
                  'seq ${e['seq']} · ${(e['payload_preview'] as String? ?? '').substring(0, 60)}…',
                  style: const TextStyle(fontSize: 11),
                ),
                children: [
                  Padding(
                    padding: const EdgeInsets.all(12),
                    child: SelectableText(
                      const JsonEncoder.withIndent('  ').convert(e),
                      style: const TextStyle(fontFamily: 'Menlo', fontSize: 11),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
