/// Describes a key used for signing operations.
///
/// Matches Go's wltsign.KeyDescription.
class KeyDescription {
  final String type;
  final String key;
  final String? id;

  const KeyDescription({
    required this.type,
    required this.key,
    this.id,
  });

  factory KeyDescription.storeKey(String key) =>
      KeyDescription(type: 'StoreKey', key: key);

  factory KeyDescription.remoteKey(String key) =>
      KeyDescription(type: 'RemoteKey', key: key);

  factory KeyDescription.password(String password) =>
      KeyDescription(type: 'Password', key: password);

  factory KeyDescription.plain(String key) =>
      KeyDescription(type: 'Plain', key: key);

  factory KeyDescription.fromJson(Map<String, dynamic> json) {
    return KeyDescription(
      type: json['Type'] as String,
      key: json['Key'] as String,
      id: json['Id'] as String?,
    );
  }

  Map<String, dynamic> toJson() => {
        'Type': type,
        'Key': key,
        if (id != null) 'Id': id,
      };
}

/// Key description with ID for transaction signing.
class SigningKey {
  final String id;
  final String key;
  final String? type;

  const SigningKey({
    required this.id,
    required this.key,
    this.type,
  });

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Key': key,
        if (type != null) 'Type': type,
      };
}
