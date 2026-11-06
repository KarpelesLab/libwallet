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
