import '../client/transport.dart';
import '../client/response.dart';
import '../models/key_description.dart';
import '../models/transaction.dart';
import '../models/unsigned_transaction.dart';

/// Transaction creation, validation, signing, and history.
class TransactionApi {
  final Transport _conn;

  TransactionApi(this._conn);

  /// List transactions. Optionally filter by account (From) or network,
  /// and convert amounts to a fiat currency.
  Future<List<Transaction>> list({
    String? from,
    String? network,
    String? convert,
  }) async {
    final params = <String, dynamic>{};
    if (from != null) params['From'] = from;
    if (network != null) params['Network'] = network;
    if (convert != null) params['_convert'] = convert;
    final data = await _conn.request(
        'Transaction', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    return (data as List)
        .map((e) => Transaction.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a transaction by ID.
  Future<Transaction> get(String id) async {
    final data = await _conn.request('Transaction/$id', 'GET');
    return Transaction.fromJson(data as Map<String, dynamic>);
  }

  /// Validate a transaction without signing. Returns the transaction
  /// with backend-filled fields (gas estimate, fee, nonce, etc.).
  Future<Transaction> validate(UnsignedTransaction tx) async {
    final data = await _conn.request('Transaction:validate', 'POST', tx.toJson());
    return Transaction.fromJson(data as Map<String, dynamic>);
  }

  /// Sign and send a transaction. Yields progress, then the final signed
  /// and broadcast transaction.
  Stream<ProgressOr<Transaction>> signAndSend(UnsignedTransaction tx) async* {
    final stream = _conn.send('Transaction:signAndSend', 'POST', tx.toJson());
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress(d['count'] as int? ?? 0, d['running'] as int? ?? 0);
      } else {
        yield Complete(Transaction.fromJson(resp.data as Map<String, dynamic>));
      }
    }
  }

  /// Convenience: sign and send, returning only the final transaction
  /// (no progress events). [keys] is inlined into the request payload.
  Future<Transaction> signAndSendSimple(
    UnsignedTransaction tx, {
    required List<SigningKey> keys,
  }) async {
    final data = await _conn.request(
        'Transaction:signAndSend', 'POST', tx.withKeys(keys).toJson());
    return Transaction.fromJson(data as Map<String, dynamic>);
  }

  /// Delete transactions. Optionally filter by account (From) or network.
  /// With no parameters, deletes ALL transaction history.
  Future<void> delete({String? id, String? from, String? network}) async {
    if (id != null) {
      await _conn.request('Transaction/$id', 'DELETE');
    } else {
      final params = <String, dynamic>{};
      if (from != null) params['From'] = from;
      if (network != null) params['Network'] = network;
      await _conn.request(
          'Transaction', 'DELETE', params.isNotEmpty ? params : null);
    }
  }
}
