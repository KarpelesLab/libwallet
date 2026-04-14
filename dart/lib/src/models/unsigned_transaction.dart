import 'amount.dart';
import 'key_description.dart';

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
    this.keys,
  });

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
    if (keys != null) m['Keys'] = keys!.map((k) => k.toJson()).toList();
    return m;
  }
}
