import 'amount.dart';

/// A blockchain transaction.
class Transaction {
  final String id;
  final String type;
  final String asset;
  final String from;
  final String to;
  final int gas;
  final String? gasPrice;
  final Amount? fee;
  final int nonce;
  final String? format;
  final String? raw;
  final String? hash;
  final String? url;
  final String? network;
  final Amount? amount;
  final Amount? value;
  final String? data;
  final DateTime? created;
  final Amount? fiatAmount;
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
