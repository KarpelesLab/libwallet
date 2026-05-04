import 'amount.dart';

/// Result of [TransactionApi.maxSendable].
///
/// Reports the largest amount of an asset that can be sent from an
/// account, with a breakdown of the fee and any chain-specific
/// reservations (Solana rent-exempt minimums) held back from the
/// balance.
///
/// When [max] is zero (e.g. balance is below the fee plus rent
/// reservations), [reason] is populated with a human-readable
/// explanation suitable for showing to the user.
///
/// **Bitcoin-family "send max" workflow**: building a transaction
/// with `amount = max` requires the build path to use the same
/// fee rate AND the same UTXO set this calculation used —
/// otherwise an `estimatesmartfee` drift between the two calls,
/// or a different greedy-selection outcome, will make the build
/// reject with insufficient-funds. [bitcoinUtxos] +
/// [bitcoinFeeRate] carry exactly that pinning. Pass them back
/// via [UnsignedTransaction.utxos] + [UnsignedTransaction.bitcoinFeeRate]:
///
/// ```dart
/// final m = await client.transactions.maxSendable(asset: 'bitcoin.litecoin.NATIVE');
/// final tx = UnsignedTransaction(
///   type: 'bitcoin_transfer',
///   to: recipient,
///   amount: m.max,
///   utxos: m.bitcoinUtxos,
///   bitcoinFeeRate: m.bitcoinFeeRate,
/// );
/// await client.transactions.signAndSendSimple(tx, keys: keys);
/// ```
///
/// Or use the convenience [maxSendTransaction] helper.
class MaxSendableResult {
  /// Which chain this result is for: `evm`, `solana`, or `bitcoin`.
  final String chain;

  /// Maximum amount the user can send. Zero when the balance cannot
  /// cover the fee + reservations.
  final Amount max;

  /// Raw account balance before any deduction.
  final Amount balance;

  /// Network fee reserved for the transaction.
  final Amount fee;

  /// Additional reserved amounts beyond the fee. On Solana this holds
  /// the sender's rent-exempt minimum and, if the recipient doesn't
  /// exist yet, the recipient's rent-exempt minimum. Empty on EVM and
  /// Bitcoin for v1.
  final List<ReservedAmount> reserved;

  /// Human-readable reason [max] is zero. Empty when [max] > 0.
  final String reason;

  /// Bitcoin-only: the `"<txid>:<vout>"` inputs the max calculation
  /// accounted for. Pass back via [UnsignedTransaction.utxos] when
  /// building the send so the build path consumes the same set
  /// (otherwise greedy selection might pick a different subset and
  /// the math drifts). Empty on non-bitcoin chains.
  final List<String> bitcoinUtxos;

  /// Bitcoin-only: the sat/vB rate the max calculation used. Pass
  /// back via [UnsignedTransaction.bitcoinFeeRate] to skip a second
  /// `estimatesmartfee` call at build time and pin the fee math.
  /// Zero on non-bitcoin chains.
  final int bitcoinFeeRate;

  const MaxSendableResult({
    required this.chain,
    required this.max,
    required this.balance,
    required this.fee,
    this.reserved = const [],
    this.reason = '',
    this.bitcoinUtxos = const [],
    this.bitcoinFeeRate = 0,
  });

  factory MaxSendableResult.fromJson(Map<String, dynamic> json) {
    List<ReservedAmount> parseReserved(dynamic v) {
      if (v is! List) return const [];
      return v
          .whereType<Map>()
          .map((e) => ReservedAmount.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }

    return MaxSendableResult(
      chain: (json['chain'] as String?) ?? '',
      max: Amount.fromJson(json['max']),
      balance: Amount.fromJson(json['balance']),
      fee: Amount.fromJson(json['fee']),
      reserved: parseReserved(json['reserved']),
      reason: (json['reason'] as String?) ?? '',
      bitcoinUtxos:
          (json['bitcoinUtxos'] as List?)?.whereType<String>().toList() ??
              const [],
      bitcoinFeeRate: (json['bitcoinFeeRate'] as num?)?.toInt() ?? 0,
    );
  }

  /// True when the account can send a positive amount.
  bool get hasRoom => !max.isZero;
}

/// One reservation line item: an amount held back from the balance
/// that the user cannot send.
class ReservedAmount {
  /// Kind of reservation: `fee`, `sender_rent`, `recipient_rent`.
  final String kind;

  /// Amount held back.
  final Amount amount;

  const ReservedAmount({required this.kind, required this.amount});

  factory ReservedAmount.fromJson(Map<String, dynamic> json) => ReservedAmount(
        kind: (json['kind'] as String?) ?? '',
        amount: Amount.fromJson(json['amount']),
      );
}
