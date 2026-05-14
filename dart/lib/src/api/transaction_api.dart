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

  /// List transactions, newest first.
  ///
  /// Filter by [from] (account) and / or [network]. Set [convert] to
  /// a fiat currency code (e.g. `"USD"`) to attach `fiatAmount` and
  /// `fiatCurrency` on each row.
  ///
  /// Paging is cursor-based on the `Created` timestamp. Pass
  /// [before] = the previous page's last item's `created` field
  /// (formatted as RFC3339Nano) to fetch the next page. [limit]
  /// caps the page size — defaults to 50, capped at 200.
  ///
  /// Example infinite-scroll pattern:
  ///
  /// ```dart
  /// var page = await client.transactions.list(limit: 50);
  /// while (page.length == 50) {
  ///   final next = await client.transactions.list(
  ///     limit: 50,
  ///     before: page.last.created!.toIso8601String(),
  ///   );
  ///   page.addAll(next);
  ///   if (next.length < 50) break;
  /// }
  /// ```
  Future<List<Transaction>> list({
    String? from,
    String? network,
    String? convert,
    String? before,
    int? limit,
  }) async {
    final params = <String, dynamic>{};
    if (from != null) params['From'] = from;
    if (network != null) params['Network'] = network;
    if (convert != null) params['_convert'] = convert;
    if (before != null) params['before'] = before;
    if (limit != null) params['limit'] = limit;
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
  /// [asset] is the canonical asset key returned by `Asset:list`
  /// (e.g. `"evm.1.NATIVE"`, `"solana.mainnet.<mint>"`). The
  /// network is derived from the `"<type>.<chainId>."` prefix; when
  /// [asset] is omitted or bare `"NATIVE"`, the current network's
  /// native currency is used.
  ///
  /// **Native assets** (SOL / ETH / BTC) reserve the network fee
  /// and (on Solana) the rent-exempt minimums from [max] so the
  /// returned value is immediately usable as a transfer/swap input.
  ///
  /// **Token assets** (ERC-20 / SPL) return [max] equal to the full
  /// on-chain token balance — fees are paid in the chain's native
  /// currency and don't reduce the spendable token amount. The
  /// returned [fee] reports the *native-currency* fee a token
  /// transfer would cost (different decimals from [max]); use it to
  /// warn when the user lacks enough native to cover the transfer.
  ///
  /// Bitcoin-family chains have no token model; passing a non-native
  /// [asset] on a Bitcoin network returns an error.
  ///
  /// Pass [to] on Solana native transfers to detect a brand-new
  /// recipient — when the recipient account doesn't exist yet, the
  /// returned [max] is reduced so the transfer can fund it to
  /// rent-exemption. On EVM and Bitcoin [to] is ignored in v1.
  ///
  /// **Bitcoin "send max" requires pinning** the inputs and fee
  /// rate this call computed against — otherwise the eventual
  /// `signAndSend` can fail with insufficient-funds (different
  /// `estimatesmartfee` reading, different greedy-selection
  /// outcome). The result carries `bitcoinUtxos` + `bitcoinFeeRate`
  /// for that purpose. Easiest path is the convenience constructor:
  ///
  /// ```dart
  /// final m = await client.transactions.maxSendable(asset: 'bitcoin.litecoin.NATIVE');
  /// final tx = UnsignedTransaction.maxSend(m, to: recipient);
  /// await client.transactions.signAndSendSimple(tx, keys: keys);
  /// ```
  ///
  /// Or build the [UnsignedTransaction] manually and pass
  /// `utxos: m.bitcoinUtxos` + `bitcoinFeeRate: m.bitcoinFeeRate`.
  ///
  /// [priority] selects how aggressive the fee budget is (cheap and
  /// slow vs expensive and fast). Bitcoin: maps to
  /// `estimatesmartfee`'s confirmation target (`"low"` = 144 blocks,
  /// `""` / `"medium"` = 6, `"high"` = 2). EVM and Solana ignore it
  /// here; the existing per-tx priority controls there are
  /// unchanged. Call this twice with different priorities to show
  /// the user a "cheap vs fast" comparison; pair the chosen result
  /// with [UnsignedTransaction.maxSend] (or hand-thread the
  /// pinned utxos + fee rate) so the eventual send uses the same
  /// fee budget.
  /// [data] is the 0x-prefixed hex calldata of the tx the caller
  /// intends to send. Only meaningful for EVM. With it, MaxSendable
  /// runs `eth_estimateGas({from, to, value, data})` to get the
  /// contract's actual gas cost — necessary for native swaps where
  /// the default 21000 reserves ~10x too little. Empty falls back to
  /// the 21000 EOA-transfer default. Pair with [to] (the contract
  /// address — usually the swap router).
  ///
  /// [value] is the call value (wei) the caller intends to send,
  /// used only by the EVM `eth_estimateGas` path when [data] is set.
  /// Some swap routers revert with `value: 0` when native is the
  /// input — pass the intended swap amount here for an accurate
  /// estimate. Optional; defaults to `balance/2`.
  ///
  /// **Better than computing max upfront: pass [Amount.max] as
  /// `Transaction.amount` directly.** libwallet's build path resolves
  /// it at signAndSend time using the actual tx contents, so there's
  /// no race between `maxSendable` and the broadcast. Use this
  /// `maxSendable` call only for previews where the user needs to see
  /// the number before committing to build the tx.
  Future<MaxSendableResult> maxSendable({
    String? from,
    String? to,
    String? asset,
    String? priority,
    String? data,
    String? value,
  }) async {
    final params = <String, dynamic>{};
    if (from != null) params['from'] = from;
    if (to != null) params['to'] = to;
    if (asset != null) params['asset'] = asset;
    if (priority != null) params['priority'] = priority;
    if (data != null) params['data'] = data;
    if (value != null) params['value'] = value;
    final data2 = await _conn.request(
        'Transaction:maxSendable', 'POST', params.isNotEmpty ? params : null);
    return MaxSendableResult.fromJson(data2 as Map<String, dynamic>);
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
