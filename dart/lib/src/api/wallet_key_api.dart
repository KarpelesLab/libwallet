import '../client/transport.dart';
import '../models/key_description.dart';
import '../models/wallet.dart';

/// Wallet/Key operations.
class WalletKeyApi {
  final Transport _conn;

  WalletKeyApi(this._conn);

  /// Get a wallet key by ID.
  Future<WalletKey> get(String id) async {
    final data = await _conn.request('Wallet/Key/$id', 'GET');
    return WalletKey.fromJson(data as Map<String, dynamic>);
  }

  /// Change the password of a wallet key. Returns the re-encrypted key.
  Future<WalletKey> recrypt(
    String keyId, {
    required String oldPassword,
    required String newPassword,
  }) async {
    final data = await _conn.request('Wallet/Key/$keyId:recrypt', 'POST', {
      'Old': {'Type': 'Password', 'Key': oldPassword},
      'New': {'Type': 'Password', 'Key': newPassword},
    });
    return WalletKey.fromJson(data as Map<String, dynamic>);
  }

  /// Re-seal key share [keyId]: open it with [from], seal it to [to]. Either
  /// side can be a [KeyDescription.vault] reference.
  Future<WalletKey> rekey(
    String keyId, {
    required KeyDescription from,
    required KeyDescription to,
  }) async {
    final data = await _conn.request('Wallet/Key/$keyId:recrypt', 'POST', {
      'Old': from.toJson(),
      'New': to.toJson(),
    });
    return WalletKey.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Check that local share [keyId] opens, without changing anything.
  ///
  /// - With [key], the share is decrypted with it: a password
  ///   ([KeyDescription.password]), a vault reference
  ///   ([KeyDescription.vault], which prompts as the entry's policy says),
  ///   or a StoreKey. [WalletKeyCheck.valid] says whether that worked; a
  ///   wrong key is `valid: false`, a cancelled prompt throws.
  /// - Without [key], only a StoreKey (device) share can be checked: `valid`
  ///   says whether a vault entry on this device has the public key the share
  ///   is sealed to ([WalletKeyCheck.entryId] names it). Nothing is unsealed and
  ///   no prompt is shown, so this is the check to run right after
  ///   `wallets.restore`.
  ///
  /// RemoteKey shares live on the WalletSign servers and throw here.
  /// See `docs/key-handling.md`.
  Future<WalletKeyCheck> verify(String keyId, {KeyDescription? key}) async {
    final data = await _conn.request('Wallet/Key/$keyId:verify', 'POST', {
      if (key != null) 'Key': key.toJson(),
    });
    return WalletKeyCheck.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Migration helper: move a share the app protected itself (a password
  /// or StoreKey it stored) under vault entry [entryId]. Afterwards the
  /// app's own copy of [from]'s secret is no longer needed — delete it.
  Future<WalletKey> moveToVault(
    String keyId, {
    required KeyDescription from,
    required String entryId,
  }) =>
      rekey(keyId, from: from, to: KeyDescription.vault(entryId));
}

/// Result of [WalletKeyApi.verify].
class WalletKeyCheck {
  /// The wallet key id.
  final String id;

  /// The share opens with the given key, or (no key given) a vault entry on
  /// this device holds its key.
  final bool valid;

  /// `unsealed` (the share was decrypted) or `public` (only public keys were
  /// compared).
  final String checked;

  /// Password shares: `argon2id`, or `pbkdf2` for a share sealed before
  /// libwallet 0.5.11. Re-seal a `pbkdf2` share with [WalletKeyApi.recrypt]
  /// (same password on both sides is fine) to move it to Argon2id.
  final String? kdf;

  /// StoreKey shares checked without a key: the vault entry holding the key.
  final String? entryId;

  const WalletKeyCheck({
    required this.id,
    required this.valid,
    required this.checked,
    this.kdf,
    this.entryId,
  });

  /// Whether this is a Password share still on the legacy KDF.
  bool get needsKdfUpgrade => kdf == 'pbkdf2';

  factory WalletKeyCheck.fromJson(Map<String, dynamic> json) => WalletKeyCheck(
        id: json['Id'] as String? ?? '',
        valid: json['Valid'] as bool? ?? false,
        checked: json['Checked'] as String? ?? '',
        kdf: json['Kdf'] as String?,
        entryId: json['Entry'] as String?,
      );
}
