import 'amount.dart';

/// A blockchain transaction.
class Transaction {
  /// Unique identifier for this transaction.
  final String id;

  /// Transaction type: `transfer`, `evm`, `solana_transfer`, etc.
  final String type;

  /// Asset key this transaction operates on.
  final String asset;

  /// Sender address.
  final String from;

  /// Recipient address.
  final String to;

  /// Gas limit for EVM transactions.
  final int gas;

  /// Gas price as a decimal string (for legacy EVM transactions).
  final String? gasPrice;

  /// Transaction fee amount.
  final Amount? fee;

  /// Sender nonce (sequence number).
  final int nonce;

  /// Transaction format: `legacy` or `eip1559`.
  final String? format;

  /// Raw signed transaction bytes (hex-encoded).
  final String? raw;

  /// On-chain transaction hash.
  final String? hash;

  /// Block explorer URL for this transaction.
  final String? url;

  /// Network ID this transaction was broadcast on.
  final String? network;

  /// Token/asset transfer amount.
  final Amount? amount;

  /// Native currency value attached to the transaction.
  final Amount? value;

  /// Hex-encoded calldata (for smart contract calls).
  final String? data;

  /// Timestamp when the transaction was created.
  final DateTime? created;

  /// Transaction amount converted to fiat currency.
  final Amount? fiatAmount;

  /// ISO 4217 fiat currency code for [fiatAmount].
  final String? fiatCurrency;

  const Transaction({
    required this.id,
    required this.type,
    required this.asset,
    required this.from,
    required this.to,
    required this.gas,
    this.gasPrice,
    this.fee,
    required this.nonce,
    this.format,
    this.raw,
    this.hash,
    this.url,
    this.network,
    this.amount,
    this.value,
    this.data,
    this.created,
    this.fiatAmount,
    this.fiatCurrency,
  });

  factory Transaction.fromJson(Map<String, dynamic> json) {
    return Transaction(
      id: json['id'] as String? ?? json['Id'] as String? ?? '',
      type: json['type'] as String? ?? json['Type'] as String? ?? '',
      asset: json['asset'] as String? ?? json['Asset'] as String? ?? '',
      from: json['from'] as String? ?? json['From'] as String? ?? '',
      to: json['to'] as String? ?? json['To'] as String? ?? '',
      gas: json['gas'] as int? ?? json['Gas'] as int? ?? 0,
      gasPrice: json['gasPrice'] as String? ?? json['GasPrice'] as String?,
      fee: json['fee'] != null
          ? Amount.fromJson(json['fee'])
          : json['Fee'] != null
              ? Amount.fromJson(json['Fee'])
              : null,
      nonce: json['nonce'] as int? ?? json['Nonce'] as int? ?? 0,
      format: json['format'] as String? ?? json['Format'] as String?,
      raw: json['raw'] as String? ?? json['Raw'] as String?,
      hash: json['hash'] as String? ?? json['Hash'] as String?,
      url: json['url'] as String? ?? json['URL'] as String?,
      network:
          json['network'] as String? ?? json['Network'] as String?,
      amount: json['amount'] != null
          ? Amount.fromJson(json['amount'])
          : json['Amount'] != null
              ? Amount.fromJson(json['Amount'])
              : null,
      value: json['value'] != null
          ? Amount.fromJson(json['value'])
          : json['Value'] != null
              ? Amount.fromJson(json['Value'])
              : null,
      data: json['data'] as String? ?? json['Data'] as String?,
      created: json['created'] != null
          ? DateTime.parse(json['created'] as String)
          : json['Created'] != null
              ? DateTime.parse(json['Created'] as String)
              : null,
      fiatAmount: json['fiat_amount'] != null
          ? Amount.fromJson(json['fiat_amount'])
          : json['FiatAmount'] != null
              ? Amount.fromJson(json['FiatAmount'])
              : null,
      fiatCurrency: json['fiat_currency'] as String? ??
          json['FiatCurrency'] as String?,
    );
  }
}
