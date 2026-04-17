import '../client/transport.dart';
import '../client/response.dart';
import '../models/key_description.dart';
import '../models/max_sendable_result.dart';
import '../models/transaction.dart';
import '../models/transaction_simulation.dart';
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

  /// Simulate a transaction — returns a structured preview the approval
  /// UI can show before the user signs. Per chain:
  ///
  /// - **EVM**: runs `eth_call` against the current network. On revert,
  ///   decodes the standard `Error(string)` payload into
  ///   [TransactionSimulation.revertReason]. On success, attaches an
  ///   `eth_estimateGas` result in [TransactionSimulation.gasEstimate].
  ///   Call data is ABI-decoded for common shapes (ERC-20
  ///   transfer/approve) and surfaced as [decodedMethod] + [decodedArgs].
  /// - **Solana**: wraps `simulateTransaction`. Returns the program
  ///   logs, compute-unit usage, and any error.
  /// - **Bitcoin**: parses `tx.Raw` via outscript and returns decoded
  ///   inputs / outputs so the UI can render "send X BTC to addr,
  ///   change Y BTC back to self".
  Future<TransactionSimulation> simulate(UnsignedTransaction tx) async {
    final data = await _conn.request('Transaction:simulate', 'POST', tx.toJson());
    return TransactionSimulation.fromJson(data as Map<String, dynamic>);
  }

  /// Sign and send a transaction. Yields progress, then the final signed
  /// and broadcast transaction.
  Stream<ProgressOr<Transaction>> signAndSend(UnsignedTransaction tx) async* {
    final stream = _conn.send('Transaction:signAndSend', 'POST', tx.toJson());
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress((d['progress'] as num?)?.toDouble() ?? 0.0);
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

  /// Compute the maximum amount sendable from [from] in the given
  /// [asset], accounting for network fees and, on Solana, the
  /// rent-exempt minimums the sender must retain and a new recipient
  /// must receive.
  ///
  /// Pass [to] on Solana to detect a brand-new recipient — when the
  /// recipient account doesn't exist yet, the returned [max] is
  /// reduced so the transfer can fund it to rent-exemption. On EVM
  /// and Bitcoin [to] is ignored in v1.
  ///
  /// [asset] defaults to the network's native currency. Token assets
  /// (ERC-20, SPL) return an error in v1 — the full token balance is
  /// always sendable, and fees are paid in native currency; call
  /// maxSendable for the native asset to verify the account can cover
  /// the fee.
  Future<MaxSendableResult> maxSendable({
    String? from,
    String? to,
    String? asset,
    String? network,
  }) async {
    final params = <String, dynamic>{};
    if (from != null) params['from'] = from;
    if (to != null) params['to'] = to;
    if (asset != null) params['asset'] = asset;
    if (network != null) params['network'] = network;
    final data = await _conn.request(
        'Transaction:maxSendable', 'POST', params.isNotEmpty ? params : null);
    return MaxSendableResult.fromJson(data as Map<String, dynamic>);
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
