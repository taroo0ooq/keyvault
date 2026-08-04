/// Plaintext vault item view (mirrors vault-core `VaultItem` for UI / FFI).
class VaultItem {
  VaultItem({
    required this.id,
    required this.title,
    this.username,
    required this.password,
    this.url,
    this.notes,
    this.totp,
    this.tags = const [],
  });

  final String id;
  final String title;
  final String? username;
  final String password;
  final String? url;
  final String? notes;
  /// Base32 TOTP secret or empty when unset.
  final String? totp;
  final List<String> tags;

  bool get hasTotp => totp != null && totp!.trim().isNotEmpty;

  VaultItem copyWith({
    String? id,
    String? title,
    String? username,
    String? password,
    String? url,
    String? notes,
    String? totp,
    List<String>? tags,
  }) {
    return VaultItem(
      id: id ?? this.id,
      title: title ?? this.title,
      username: username ?? this.username,
      password: password ?? this.password,
      url: url ?? this.url,
      notes: notes ?? this.notes,
      totp: totp ?? this.totp,
      tags: tags ?? this.tags,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'username': username,
        'password': password,
        'url': url,
        'notes': notes,
        'totp': totp,
        'tags': tags,
      };

  factory VaultItem.fromJson(Map<String, dynamic> json) {
    return VaultItem(
      id: json['id'] as String? ?? '',
      title: json['title'] as String? ?? '',
      username: json['username'] as String?,
      password: json['password'] as String? ?? '',
      url: json['url'] as String?,
      notes: json['notes'] as String?,
      totp: json['totp'] as String?,
      tags: (json['tags'] as List<dynamic>?)?.map((e) => e.toString()).toList() ??
          const [],
    );
  }
}
