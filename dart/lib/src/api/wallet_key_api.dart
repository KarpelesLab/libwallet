import '../client/transport.dart';
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
}
