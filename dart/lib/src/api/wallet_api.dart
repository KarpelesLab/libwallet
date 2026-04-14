import '../client/transport.dart';
import '../client/response.dart';
import '../models/key_description.dart';
import '../models/wallet.dart';
import '../models/wallet_backup.dart';

/// Wallet CRUD, backup, restore, reshare, and multi-create operations.
class WalletApi {
  final Transport _conn;

  WalletApi(this._conn);

  /// List all wallets.
  Future<List<Wallet>> list() async {
    final data = await _conn.request('Wallet', 'GET');
    if (data == null) return [];
    return (data as List)
        .map((e) => Wallet.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a wallet by ID.
  Future<Wallet> get(String id) async {
    final data = await _conn.request('Wallet/$id', 'GET');
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Create a new wallet. Yields progress updates, then the created wallet.
  Stream<ProgressOr<Wallet>> create({
    required String name,
    required List<KeyDescription> keys,
    String? curve,
  }) async* {
    final stream = _conn.send('Wallet', 'POST', {
      'Name': name,
      'Keys': keys.map((k) => k.toJson()).toList(),
      if (curve != null) 'Curve': curve,
    });
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress(d['count'] as int, d['running'] as int);
      } else {
        yield Complete(Wallet.fromJson(resp.data as Map<String, dynamic>));
      }
    }
  }

  /// Create both secp256k1 and ed25519 wallets in one call.
  Stream<ProgressOr<Map<String, Wallet>>> multiCreate({
    required String name,
    required List<KeyDescription> keys,
  }) async* {
    final stream = _conn.send('Wallet:multiCreate', 'POST', {
      'Name': name,
      'Keys': keys.map((k) => k.toJson()).toList(),
    });
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress(d['count'] as int, d['running'] as int);
      } else {
        final d = resp.data as Map<String, dynamic>;
        yield Complete({
          'secp256k1': Wallet.fromJson(d['secp256k1'] as Map<String, dynamic>),
          'ed25519': Wallet.fromJson(d['ed25519'] as Map<String, dynamic>),
        });
      }
    }
  }

  /// Update a wallet's name.
  Future<Wallet> update(String id, {required String name}) async {
    final data = await _conn.request('Wallet/$id', 'PATCH', {'Name': name});
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a wallet and all associated data.
  Future<void> delete(String id) async {
    await _conn.request('Wallet/$id', 'DELETE');
  }

  /// Get a wallet backup. Returns one entry per wallet; each entry contains
  /// a suggested filename and base64url-encoded encrypted payload. Pass the
  /// entries (as a list of `{filename, data}` maps) back to [restore] to
  /// restore a wallet.
  Future<List<WalletBackupEntry>> backup(String walletId) async {
    final data = await _conn.request('Wallet/$walletId:backup', 'GET');
    if (data == null) return [];
    return (data as List)
        .map((e) => WalletBackupEntry.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Restore wallets from backup files.
  Future<Map<String, dynamic>> restore(
      List<Map<String, String>> files) async {
    final data = await _conn.request('Wallet:restore', 'POST', {
      'files': files,
    });
    return data as Map<String, dynamic>;
  }

  /// Reshare wallet keys. Yields progress updates, then the regenerated
  /// wallet with its new key shares.
  Stream<ProgressOr<Wallet>> reshare(
    String walletId, {
    required List<KeyDescription> oldKeys,
    required List<KeyDescription> newKeys,
  }) async* {
    final stream = _conn.send('Wallet/$walletId:reshare', 'POST', {
      'Old': oldKeys.map((k) => k.toJson()).toList(),
      'New': newKeys.map((k) => k.toJson()).toList(),
    });
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress(d['count'] as int, d['running'] as int);
      } else {
        yield Complete(Wallet.fromJson(resp.data as Map<String, dynamic>));
      }
    }
  }
}
