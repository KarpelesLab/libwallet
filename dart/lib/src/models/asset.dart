import 'amount.dart';

/// An asset (native currency or token) with balance information.
class Asset {
  /// Server-assigned identifier.
  final String id;

  /// Canonical asset identifier in `"<type>.<chainId>.<address>"`
  /// form, e.g. `"evm.1.NATIVE"`, `"solana.mainnet.EPjFW…"`,
  /// `"evm.1.0xA0b86991…"`. Native assets end with `.NATIVE`; tokens
  /// end with the on-chain contract / mint address. Use [isNative]
  /// to branch.
  final String key;

  /// Human-readable asset name (e.g. `"Ethereum"`).
  final String name;

  /// Ticker symbol (e.g. `ETH`, `BTC`).
  final String symbol;

  /// Current balance of this asset.
  final Amount amount;

  /// Coarse-grained asset family — currently `"fungible"` for every
  /// runtime-emitted asset (native currencies + ERC-20 / SPL-token
  /// balances both). Reserved for a future `"nft"` distinction.
  ///
  /// **Don't branch native-vs-token on this field** — use
  /// [isNative] instead. Native is signalled by the `.NATIVE`
  /// suffix on [key], not by [type].
  final String type;

  /// Network ID this asset belongs to.
  final String network;

  /// Whether this asset is on a test network.
  final bool testNet;

  /// Balance converted to fiat currency.
  final Amount? fiatAmount;

  /// ISO 4217 fiat currency code for [fiatAmount].
  final String? fiatCurrency;

  /// Market price quote data for this asset.
  final FiatQuote? fiatQuote;

  /// Additional metadata about the asset.
  final Map<String, dynamic>? info;

  /// Timestamp when the asset was first seen.
  final DateTime created;

  /// Timestamp when the asset was last updated.
  final DateTime updated;

  const Asset({
    required this.id,
    required this.key,
    required this.name,
    required this.symbol,
    required this.amount,
    required this.type,
    required this.network,
    required this.testNet,
    this.fiatAmount,
    this.fiatCurrency,
    this.fiatQuote,
    this.info,
    required this.created,
    required this.updated,
  });

  /// True when this Asset is the chain's native currency (ETH / SOL /
  /// BTC / etc.) — i.e. when [key] ends with `.NATIVE` (libwallet's
  /// canonical native sentinel; see `wltnet/network.go`).
  ///
  /// Use this rather than matching on [type] / [symbol] / [name]:
  /// libwallet emits `Type: "fungible"` for native AND tokens, the
  /// symbol can collide (a token can ship as "ETH" too), and the
  /// name is localised in some hosts. The `.NATIVE` suffix on the
  /// key is the only invariant.
  bool get isNative => key.endsWith('.NATIVE');

  /// The on-chain mint / contract part of [key], or `null` for a
  /// native asset. For `"evm.1.0xA0b86991…"` returns
  /// `"0xA0b86991…"`; for `"solana.mainnet.EPjFW…"` returns
  /// `"EPjFW…"`; for `"evm.1.NATIVE"` returns `null`.
  String? get tokenAddress {
    if (isNative) return null;
    final idx = key.lastIndexOf('.');
    if (idx < 0 || idx == key.length - 1) return null;
    return key.substring(idx + 1);
  }

  factory Asset.fromJson(Map<String, dynamic> json) {
    return Asset(
      id: json['Id'] as String? ?? json['key'] as String? ?? '',
      key: json['key'] as String? ?? '',
      name: json['name'] as String? ?? json['Name'] as String? ?? '',
      symbol: json['symbol'] as String? ?? json['Symbol'] as String? ?? '',
      amount: Amount.fromJson(json['amount'] ?? json['Amount']),
      type: json['type'] as String? ?? json['Type'] as String? ?? '',
      network: json['network'] as String? ?? json['Network'] as String? ?? '',
      testNet: json['testnet'] as bool? ?? json['TestNet'] as bool? ?? false,
      fiatAmount: json['fiat_amount'] != null
          ? Amount.fromJson(json['fiat_amount'])
          : json['FiatAmount'] != null
              ? Amount.fromJson(json['FiatAmount'])
              : null,
      fiatCurrency: json['fiat_currency'] as String? ??
          json['FiatCurrency'] as String?,
      fiatQuote: json['fiat_quote'] != null
          ? FiatQuote.fromJson(json['fiat_quote'])
          : json['FiatQuote'] != null
              ? FiatQuote.fromJson(json['FiatQuote'])
              : null,
      info: json['info'] as Map<String, dynamic>?,
      created: DateTime.parse(
          json['Created'] as String? ?? DateTime.now().toIso8601String()),
      updated: DateTime.parse(
          json['Updated'] as String? ?? DateTime.now().toIso8601String()),
    );
  }
}

/// Price quote data from CoinMarketCap or similar.
class FiatQuote {
  /// Current price per unit in the quote currency.
  final double price;

  /// 24-hour trading volume.
  final double volume24h;

  /// 24-hour change in trading volume (percentage).
  final double volumeChange24h;

  /// 24-hour price change (percentage).
  final double percentChange24h;

  /// 1-hour price change (percentage).
  final double percentChange1h;

  /// Total market capitalization.
  final double marketCap;

  /// Timestamp of the last price update.
  final DateTime lastUpdate;

  const FiatQuote({
    required this.price,
    required this.volume24h,
    required this.volumeChange24h,
    required this.percentChange24h,
    required this.percentChange1h,
    required this.marketCap,
    required this.lastUpdate,
  });

  factory FiatQuote.fromJson(dynamic json) {
    return FiatQuote(
      price: (json['price'] as num).toDouble(),
      volume24h: (json['volume_24h'] as num).toDouble(),
      volumeChange24h: (json['volume_change_24h'] as num).toDouble(),
      percentChange24h: (json['percent_change_24h'] as num).toDouble(),
      percentChange1h: (json['percent_change_1h'] as num).toDouble(),
      marketCap: (json['market_cap'] as num).toDouble(),
      lastUpdate:
          DateTime.tryParse(json['last_updated'] ?? '') ?? DateTime.now(),
    );
  }
}
