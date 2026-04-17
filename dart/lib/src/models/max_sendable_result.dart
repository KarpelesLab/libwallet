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

  const MaxSendableResult({
    required this.chain,
    required this.max,
    required this.balance,
    required this.fee,
    this.reserved = const [],
    this.reason = '',
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
