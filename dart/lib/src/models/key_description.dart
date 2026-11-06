/// Describes a key used for signing operations.
///
/// Matches Go's wltsign.KeyDescription.
class KeyDescription {
  /// Key type: `StoreKey`, `RemoteKey`, `Password`, `Plain`, or `Vault`.
  final String type;

  /// Key material (encrypted blob, password, or raw key) — or, for `Vault`,
  /// the vault entry id.
  final String key;

  /// Optional server-assigned key identifier.
  final String? id;

  /// `Vault` only: the text of the Face ID / fingerprint prompt.
  final String? reason;

  /// `Vault` only: the password of a password-backend entry, for this one
  /// use (prefer [VaultApi.unlock] for repeated use).
  final String? password;

  const KeyDescription({
    required this.type,
    required this.key,
    this.id,
    this.reason,
    this.password,
  });

  /// The secret held in vault entry [entryId] — it is unsealed inside
  /// libwallet when needed and never reaches Dart. Pass [walletKeyId] when
  /// unlocking a specific wallet key share (signing), omit it when the entry
  /// is a recipient (wallet creation, recrypt target).
  factory KeyDescription.vault(String entryId,
          {String? walletKeyId, String? reason, String? password}) =>
      KeyDescription(
          type: 'Vault',
          key: entryId,
          id: walletKeyId,
          reason: reason,
          password: password);

  factory KeyDescription.storeKey(String key) =>
      KeyDescription(type: 'StoreKey', key: key);

  factory KeyDescription.remoteKey(String key) =>
      KeyDescription(type: 'RemoteKey', key: key);

  factory KeyDescription.password(String password) =>
      KeyDescription(type: 'Password', key: password);

  factory KeyDescription.plain(String key) =>
      KeyDescription(type: 'Plain', key: key);

  /// This description bound to wallet key share [walletKeyId].
  KeyDescription withId(String walletKeyId) => KeyDescription(
      type: type, key: key, id: walletKeyId, reason: reason, password: password);

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
        if (reason != null) 'Reason': reason,
        if (password != null) 'Password': password,
      };
}

/// Key description with ID for transaction signing.
class SigningKey {
  /// Server-assigned key share identifier.
  final String id;

  /// Key material used for signing.
  final String key;

  /// Key type: `StoreKey`, `RemoteKey`, `Password`, or `Plain`.
  final String? type;

  /// `Vault` only: the text of the Face ID / fingerprint prompt.
  final String? reason;

  const SigningKey({
    required this.id,
    required this.key,
    this.type,
    this.reason,
  });

  /// Unlock wallet key share [walletKeyId] with the secret in vault entry
  /// [entryId], without it ever reaching Dart.
  factory SigningKey.vault(String walletKeyId, String entryId,
          {String? reason}) =>
      SigningKey(id: walletKeyId, key: entryId, type: 'Vault', reason: reason);

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Key': key,
        if (type != null) 'Type': type,
        if (reason != null) 'Reason': reason,
      };
}
