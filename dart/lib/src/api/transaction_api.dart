import '../client/transport.dart';
import '../client/response.dart';
import '../models/key_description.dart';
import '../models/transaction.dart';

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

  /// Validate a transaction without signing.
  Future<dynamic> validate(Map<String, dynamic> tx) async {
    return await _conn.request('Transaction:validate', 'POST', tx);
  }

  /// Sign and send a transaction. Yields progress, then the result.
  Stream<ProgressOr<dynamic>> signAndSend(Map<String, dynamic> tx) async* {
    final stream = _conn.send('Transaction:signAndSend', 'POST', tx);
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress(
            d['count'] as int? ?? 0, d['running'] as int? ?? 0);
      } else {
        yield Complete(resp.data);
      }
    }
  }

  /// Convenience: sign and send, returning only the final result.
  Future<dynamic> signAndSendSimple(
    Map<String, dynamic> tx, {
    required List<SigningKey> keys,
  }) async {
    tx['Keys'] = keys.map((k) => k.toJson()).toList();
    return await _conn.request('Transaction:signAndSend', 'POST', tx);
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
