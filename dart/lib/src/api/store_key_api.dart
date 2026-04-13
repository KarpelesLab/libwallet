import '../client/transport.dart';

/// StoreKey management for biometric/device-secured keys.
class StoreKeyApi {
  final Transport _conn;

  StoreKeyApi(this._conn);

  /// Create a new store key. Returns `{"private": ..., "public": ...}`.
  Future<StoreKeyPair> create() async {
    final data = await _conn.request('StoreKey:create', 'POST');
    final map = data as Map<String, dynamic>;
    return StoreKeyPair(
      privateKey: map['private'] as String,
      publicKey: map['public'] as String,
    );
  }

  /// Derive a public key from a password and wallet key ID.
  Future<String> derivePassword({
    required String password,
    required String walletKeyId,
  }) async {
    final data = await _conn.request('StoreKey:derivePassword', 'POST', {
      'Password': password,
      'WalletKeyId': walletKeyId,
    });
    if (data is String) return data;
    return (data as Map<String, dynamic>)['public'] as String? ?? '';
  }
}

class StoreKeyPair {
  final String privateKey;
  final String publicKey;

  const StoreKeyPair({required this.privateKey, required this.publicKey});
}
