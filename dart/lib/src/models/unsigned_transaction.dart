import 'amount.dart';
import 'key_description.dart';
import 'max_sendable_result.dart';

/// Typed builder for `Transaction:validate` and `Transaction:signAndSend` input.
///
/// All fields except [type] and [to] are optional and filled in by the backend
/// when possible (gas estimation, fee lookup, nonce selection, default asset
/// = native currency of the current network).
class UnsignedTransaction {
  /// Transaction type. Common values:
  /// - `transfer` — native currency transfer (EVM/Solana/Bitcoin)
  /// - `erc20_transfer` — ERC-20 token transfer
  /// - `bitcoin_transfer` — BTC-family transfer
  /// - `evm` — raw EVM call (set [data])
  final String type;

  /// Sender account ID (defaults to current account if omitted).
  final String? from;

  /// Recipient address or ENS/SNS name.
  final String to;

  /// Transfer amount. For native transfers use the native decimals;
  /// for ERC-20, use the token's decimals.
  final Amount? amount;

  /// Extra native value to attach (for contract calls that aren't pure
  /// transfers). Most users want [amount] instead.
  final Amount? value;

  /// Asset ID. For ERC-20 this is the token XUID; omit for native transfers.
  final String? asset;

  /// Network ID (defaults to current network).
  final String? network;

  /// Hex-encoded calldata for raw EVM `evm`-type transactions.
  final String? data;

  /// Gas limit override. Leave null for auto-estimation.
  final int? gas;

  /// Legacy gas price (decimal string). Mutually exclusive with EIP-1559 fees.
  final String? gasPrice;

  /// EIP-1559 max fee per gas (decimal string).
  final String? maxFeePerGas;

  /// EIP-1559 max priority (tip) fee per gas (decimal string).
  final String? maxPriorityFeePerGas;

  /// Nonce override. Leave null for auto.
  final int? nonce;

  /// Transaction format override: `legacy` or `eip1559`. Normally auto-selected.
  final String? format;

  /// Solana only — compute-unit limit. Leave null for the default
  /// (~1000 CU for a simple transfer). Ignored on other chains.
  final int? computeUnitLimit;

  /// Solana only — compute-unit price in microlamports per CU.
  /// Set to 0 (or leave null) to let [priorityLevel] decide.
  final int? computeUnitPrice;

  /// Solana only — named shorthand for a priority fee: `none`
  /// (no ComputeBudget instructions), `low` (25th percentile of
  /// recent network fees), `medium` (50th), `high` (75th). When
  /// [computeUnitPrice] is set, that wins over [priorityLevel].
  final String? priorityLevel;

  /// Bitcoin-family only — manual coin selection. When set on a
  /// `bitcoin_transfer` tx, the build path skips greedy auto-
  /// selection and uses exactly these `"<txid>:<vout>"` UTXOs as
  /// inputs (each verified against the account's current set;
  /// foreign or stale refs error out cleanly). Source the strings
  /// from `accounts.listUTXOs(...)` or
  /// `MaxSendableResult.bitcoinUtxos`. Empty / null preserves the
  /// auto-selection behaviour.
  final List<String>? utxos;

  /// Bitcoin-family only — pinned fee rate in sat/vB. When set
  /// (non-zero) on a `bitcoin_transfer` tx, the build path skips
  /// the `estimatesmartfee` RPC and uses this rate exactly. Pass
  /// back `MaxSendableResult.bitcoinFeeRate` here when sending
  /// max so the build's fee math is identical to what max
  /// computed against — otherwise estimate drift between the two
  /// calls will sometimes make the build reject with
  /// insufficient-funds. Zero / null preserves the auto behaviour.
  final int? bitcoinFeeRate;

  /// Signing keys — required only for `signAndSend`, ignored by `validate`.
  final List<SigningKey>? keys;

  const UnsignedTransaction({
    required this.type,
    required this.to,
    this.from,
    this.amount,
    this.value,
    this.asset,
    this.network,
    this.data,
    this.gas,
    this.gasPrice,
    this.maxFeePerGas,
    this.maxPriorityFeePerGas,
    this.nonce,
    this.format,
    this.computeUnitLimit,
    this.computeUnitPrice,
    this.priorityLevel,
    this.utxos,
    this.bitcoinFeeRate,
    this.keys,
  });

  /// Convenience: build a "send the maximum amount" tx from a
  /// [MaxSendableResult]. Threads the inputs and fee rate that
  /// max-sendable computed against straight into the new tx so
  /// the build path's coin selection + fee math are identical to
  /// what produced [m.max]. Without this pinning, an
  /// `estimatesmartfee` drift between the two calls or a
  /// different greedy-selection outcome can make signAndSend
  /// reject the broadcast with insufficient-funds.
  ///
  /// Bitcoin-family only — for EVM / Solana max-sends just call
  /// the regular constructor; the fee math there isn't subject to
  /// the same race.
  ///
  /// ```dart
  /// final m = await client.transactions.maxSendable(asset: 'bitcoin.litecoin.NATIVE');
  /// final tx = UnsignedTransaction.maxSend(m, to: recipient);
  /// await client.transactions.signAndSendSimple(tx, keys: keys);
  /// ```
  factory UnsignedTransaction.maxSend(
    MaxSendableResult m, {
    required String to,
    String? from,
    String? network,
  }) {
    if (m.chain != 'bitcoin') {
      throw ArgumentError(
          'UnsignedTransaction.maxSend supports bitcoin-family chains only '
          '(got chain="${m.chain}"). For EVM/Solana max-sends, use the '
          'regular UnsignedTransaction constructor with amount: m.max.');
    }
    return UnsignedTransaction(
      type: 'bitcoin_transfer',
      to: to,
      from: from,
      amount: m.max,
      network: network,
      utxos: m.bitcoinUtxos.isEmpty ? null : m.bitcoinUtxos,
      bitcoinFeeRate: m.bitcoinFeeRate > 0 ? m.bitcoinFeeRate : null,
    );
  }

  /// Convenience: create a simple native-currency transfer.
  factory UnsignedTransaction.transfer({
    required String to,
    required Amount amount,
    String? from,
    String? network,
  }) =>
      UnsignedTransaction(
        type: 'transfer',
        to: to,
        from: from,
        amount: amount,
        network: network,
      );

  /// Convenience: create an ERC-20 token transfer.
  factory UnsignedTransaction.erc20Transfer({
    required String to,
    required Amount amount,
    required String tokenAsset,
    String? from,
    String? network,
  }) =>
      UnsignedTransaction(
        type: 'erc20_transfer',
        to: to,
        from: from,
        amount: amount,
        asset: tokenAsset,
        network: network,
      );

  /// Return a copy with [keys] populated. Used internally by `signAndSend`.
  UnsignedTransaction withKeys(List<SigningKey> k) => UnsignedTransaction(
        type: type,
        to: to,
        from: from,
        amount: amount,
        value: value,
        asset: asset,
        network: network,
        data: data,
        gas: gas,
        gasPrice: gasPrice,
        maxFeePerGas: maxFeePerGas,
        maxPriorityFeePerGas: maxPriorityFeePerGas,
        nonce: nonce,
        format: format,
        computeUnitLimit: computeUnitLimit,
        computeUnitPrice: computeUnitPrice,
        priorityLevel: priorityLevel,
        utxos: utxos,
        bitcoinFeeRate: bitcoinFeeRate,
        keys: k,
      );

  Map<String, dynamic> toJson() {
    final m = <String, dynamic>{'type': type, 'to': to};
    if (from != null) m['from'] = from;
    if (amount != null) m['amount'] = amount!.toJson();
    if (value != null) m['value'] = value!.toJson();
    if (asset != null) m['asset'] = asset;
    if (network != null) m['network'] = network;
    if (data != null) m['data'] = data;
    if (gas != null) m['gas'] = gas;
    if (gasPrice != null) m['gasPrice'] = gasPrice;
    if (maxFeePerGas != null) m['maxFeePerGas'] = maxFeePerGas;
    if (maxPriorityFeePerGas != null) {
      m['maxPriorityFeePerGas'] = maxPriorityFeePerGas;
    }
    if (nonce != null) m['nonce'] = nonce;
    if (format != null) m['format'] = format;
    if (computeUnitLimit != null) m['computeUnitLimit'] = computeUnitLimit;
    if (computeUnitPrice != null) m['computeUnitPrice'] = computeUnitPrice;
    if (priorityLevel != null) m['priorityLevel'] = priorityLevel;
    if (utxos != null && utxos!.isNotEmpty) m['utxos'] = utxos;
    if (bitcoinFeeRate != null && bitcoinFeeRate! > 0) {
      m['bitcoinFeeRate'] = bitcoinFeeRate;
    }
    if (keys != null) m['Keys'] = keys!.map((k) => k.toJson()).toList();
    return m;
  }
}
