import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/vault_item.dart';
import '../services/vault_service.dart';

class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key, required this.vault});

  final VaultService vault;

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  final _search = TextEditingController();
  List<VaultItem> _visible = [];
  String? _selectedId;

  @override
  void initState() {
    super.initState();
    widget.vault.addListener(_reload);
    _reload();
  }

  @override
  void dispose() {
    widget.vault.removeListener(_reload);
    _search.dispose();
    super.dispose();
  }

  Future<void> _reload() async {
    final items = await widget.vault.list(query: _search.text);
    if (!mounted) return;
    setState(() => _visible = items);
  }

  Future<void> _edit([VaultItem? existing]) async {
    final result = await showModalBottomSheet<VaultItem>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => _ItemEditor(
        item: existing,
        onGenerate: () => widget.vault.generatePassword(),
        onTotpCode: existing != null && existing.hasTotp
            ? () => widget.vault.totpCode(existing.id)
            : null,
      ),
    );
    if (result != null) {
      final saved = await widget.vault.save(result);
      setState(() => _selectedId = saved.id);
      await _reload();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('KeyVault'),
        actions: [
          IconButton(
            tooltip: 'Lock',
            onPressed: () => widget.vault.lock(),
            icon: const Icon(Icons.lock_outline),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _edit(),
        child: const Icon(Icons.add),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
            child: TextField(
              controller: _search,
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                hintText: 'Search…',
              ),
              onChanged: (_) => _reload(),
            ),
          ),
          if (widget.vault.vaultPath != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  widget.vault.vaultPath!,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ),
          Expanded(
            child: _visible.isEmpty
                ? const Center(child: Text('No items yet. Tap + to add.'))
                : ListView.separated(
                    itemCount: _visible.length,
                    separatorBuilder: (context, index) =>
                        const Divider(height: 1),
                    itemBuilder: (context, index) {
                      final item = _visible[index];
                      return ListTile(
                        selected: item.id == _selectedId,
                        title: Text(item.title),
                        subtitle: Text(
                          [
                            if (item.username != null) item.username!,
                            if (item.hasTotp) '2FA',
                            if (item.url != null) item.url!,
                          ].where((e) => e.isNotEmpty).join(' · ').ifEmpty('—'),
                        ),
                        trailing: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (item.hasTotp)
                              IconButton(
                                icon: const Icon(Icons.pin_outlined),
                                tooltip: 'Copy TOTP',
                                onPressed: () async {
                                  try {
                                    final code =
                                        await widget.vault.totpCode(item.id);
                                    final text =
                                        code['code']?.toString() ?? '';
                                    await Clipboard.setData(
                                      ClipboardData(text: text),
                                    );
                                    if (context.mounted) {
                                      ScaffoldMessenger.of(context)
                                          .showSnackBar(
                                        SnackBar(
                                          content: Text('TOTP $text copied'),
                                          duration: const Duration(seconds: 2),
                                        ),
                                      );
                                    }
                                  } catch (e) {
                                    if (context.mounted) {
                                      ScaffoldMessenger.of(context)
                                          .showSnackBar(
                                        SnackBar(content: Text('$e')),
                                      );
                                    }
                                  }
                                },
                              ),
                            IconButton(
                              icon: const Icon(Icons.copy),
                              tooltip: 'Copy password',
                              onPressed: () async {
                                await Clipboard.setData(
                                  ClipboardData(text: item.password),
                                );
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(
                                      content: Text('Password copied'),
                                      duration: Duration(seconds: 2),
                                    ),
                                  );
                                }
                              },
                            ),
                          ],
                        ),
                        onTap: () => _edit(item),
                        onLongPress: () async {
                          final ok = await showDialog<bool>(
                            context: context,
                            builder: (ctx) => AlertDialog(
                              title: const Text('Delete item?'),
                              content: Text('Delete "${item.title}"?'),
                              actions: [
                                TextButton(
                                  onPressed: () => Navigator.pop(ctx, false),
                                  child: const Text('Cancel'),
                                ),
                                FilledButton(
                                  onPressed: () => Navigator.pop(ctx, true),
                                  child: const Text('Delete'),
                                ),
                              ],
                            ),
                          );
                          if (ok == true) {
                            await widget.vault.delete(item.id);
                            await _reload();
                          }
                        },
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _ItemEditor extends StatefulWidget {
  const _ItemEditor({
    this.item,
    required this.onGenerate,
    this.onTotpCode,
  });

  final VaultItem? item;
  final String Function() onGenerate;
  final Future<Map<String, dynamic>> Function()? onTotpCode;

  @override
  State<_ItemEditor> createState() => _ItemEditorState();
}

class _ItemEditorState extends State<_ItemEditor> {
  late final TextEditingController _title;
  late final TextEditingController _username;
  late final TextEditingController _password;
  late final TextEditingController _url;
  late final TextEditingController _notes;
  late final TextEditingController _totp;
  late final TextEditingController _tags;
  bool _showPassword = false;
  String? _liveTotp;
  String? _totpRemain;

  @override
  void initState() {
    super.initState();
    final i = widget.item;
    _title = TextEditingController(text: i?.title ?? '');
    _username = TextEditingController(text: i?.username ?? '');
    _password = TextEditingController(text: i?.password ?? '');
    _url = TextEditingController(text: i?.url ?? '');
    _notes = TextEditingController(text: i?.notes ?? '');
    _totp = TextEditingController(text: i?.totp ?? '');
    _tags = TextEditingController(text: i?.tags.join(', ') ?? '');
    if (widget.onTotpCode != null) {
      _refreshTotp();
    }
  }

  Future<void> _refreshTotp() async {
    final fn = widget.onTotpCode;
    if (fn == null) return;
    try {
      final code = await fn();
      if (!mounted) return;
      setState(() {
        _liveTotp = code['code']?.toString();
        _totpRemain = code['remaining_secs']?.toString();
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _liveTotp = null;
        _totpRemain = null;
      });
    }
  }

  @override
  void dispose() {
    _title.dispose();
    _username.dispose();
    _password.dispose();
    _url.dispose();
    _notes.dispose();
    _totp.dispose();
    _tags.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final bottom = MediaQuery.viewInsetsOf(context).bottom;
    return Padding(
      padding: EdgeInsets.fromLTRB(16, 16, 16, 16 + bottom),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              widget.item == null ? 'Add item' : 'Edit item',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _title,
              decoration: const InputDecoration(labelText: 'Title'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _username,
              decoration: const InputDecoration(labelText: 'Username'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _password,
              obscureText: !_showPassword,
              decoration: InputDecoration(
                labelText: 'Password',
                suffixIcon: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      tooltip: 'Generate',
                      onPressed: () {
                        setState(() => _password.text = widget.onGenerate());
                      },
                      icon: const Icon(Icons.auto_awesome),
                    ),
                    IconButton(
                      onPressed: () =>
                          setState(() => _showPassword = !_showPassword),
                      icon: Icon(
                        _showPassword ? Icons.visibility_off : Icons.visibility,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _url,
              decoration: const InputDecoration(labelText: 'URL'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _notes,
              decoration: const InputDecoration(labelText: 'Notes'),
              maxLines: 3,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _totp,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'TOTP secret (base32 / otpauth://)',
                helperText: 'Optional authenticator 2FA secret',
              ),
            ),
            if (_liveTotp != null) ...[
              const SizedBox(height: 8),
              Row(
                children: [
                  Text(
                    'Code: $_liveTotp',
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                          fontFamily: 'monospace',
                        ),
                  ),
                  if (_totpRemain != null)
                    Padding(
                      padding: const EdgeInsets.only(left: 8),
                      child: Text('(${_totpRemain}s)'),
                    ),
                  IconButton(
                    tooltip: 'Refresh',
                    onPressed: _refreshTotp,
                    icon: const Icon(Icons.refresh),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 12),
            TextField(
              controller: _tags,
              decoration: const InputDecoration(
                labelText: 'Tags (comma-separated)',
              ),
            ),
            const SizedBox(height: 20),
            FilledButton(
              onPressed: () {
                if (_title.text.trim().isEmpty || _password.text.isEmpty) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Title and password are required'),
                    ),
                  );
                  return;
                }
                Navigator.pop(
                  context,
                  VaultItem(
                    id: widget.item?.id ?? '',
                    title: _title.text.trim(),
                    username: _username.text.trim().isEmpty
                        ? null
                        : _username.text.trim(),
                    password: _password.text,
                    url: _url.text.trim().isEmpty ? null : _url.text.trim(),
                    notes:
                        _notes.text.trim().isEmpty ? null : _notes.text.trim(),
                    totp: _totp.text.trim().isEmpty ? null : _totp.text.trim(),
                    tags: _tags.text
                        .split(',')
                        .map((e) => e.trim())
                        .where((e) => e.isNotEmpty)
                        .toList(),
                  ),
                );
              },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
  }
}

extension on String {
  String ifEmpty(String fallback) => isEmpty ? fallback : this;
}
