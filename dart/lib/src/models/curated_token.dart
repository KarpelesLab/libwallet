/// A vetted well-known token from the per-chain curated registry
/// (e.g. USDT, USDC, WBTC on EVM; USDC, SOL, ChiefPussy on Solana).
///
/// Returned by `tokens.listCurated(network)`. Use this to:
/// - populate a "swap to X" dropdown without asking the user to
///   paste a contract address,
/// - enrich an `Asset` row whose `contract`/`mint` matches a known
///   token so the UI can render "USDT" instead of the raw address.
///
/// The underlying data is embedded in the libwallet binary — no
/// runtime external fetch, no API keys.
class CuratedToken {
  /// Canonical `"<type>.<chainId>"` form, matching `Asset.network`
  /// (e.g. `"evm.1"`, `"solana.mainnet"`). Split on `.` for family.
  final String chainKey;

  /// On-chain identifier: 0x-prefixed EIP-55 contract address for
  /// EVM, base58 mint for Solana.
  final String address;

  /// Ticker (e.g. `"USDT"`, `"SOL"`, `"ChiefPussy"`). Not globally
  /// unique — must be scoped by [chainKey].
  final String symbol;

  /// Human-readable name (e.g. `"Tether USD"`, `"Wrapped SOL"`).
  final String name;

  /// Number of decimals the on-chain amount is scaled by.
  final int decimals;

  /// Contract / mint flavour. Stable values:
  /// `"erc20"`, `"spl-token"`, `"spl-token-2022"`.
  final String type;

  /// Logo URL (HTTPS). Empty when no logo is available.
  final String logoUri;

  /// CoinGecko token id (e.g. `"tether"`). Useful for hitting
  /// CoinGecko's price API directly from the frontend. Empty
  /// when the curated feed did not carry one.
  final String coingeckoId;

  /// CoinMarketCap token id (e.g. `825` for USDT). Zero when the
  /// curated feed did not carry one.
  final int cmcId;

  /// Stable semantic tags from a small allowlist:
  /// `stablecoin`, `wrapped`, `lst`, `governance`, `meme`. Used by
  /// the libwallet-side sort to surface stablecoins first in the
  /// default view; frontends can use them as filters or badges.
  final List<String> tags;

  const CuratedToken({
    required this.chainKey,
    required this.address,
    required this.symbol,
    required this.name,
    required this.decimals,
    required this.type,
    this.logoUri = '',
    this.coingeckoId = '',
    this.cmcId = 0,
    this.tags = const [],
  });

  factory CuratedToken.fromJson(Map<String, dynamic> json) => CuratedToken(
        chainKey: (json['chainKey'] as String?) ?? '',
        address: (json['address'] as String?) ?? '',
        symbol: (json['symbol'] as String?) ?? '',
        name: (json['name'] as String?) ?? '',
        decimals: (json['decimals'] as num?)?.toInt() ?? 0,
        type: (json['type'] as String?) ?? '',
        logoUri: (json['logoURI'] as String?) ?? '',
        coingeckoId: (json['coingeckoId'] as String?) ?? '',
        cmcId: (json['cmcId'] as num?)?.toInt() ?? 0,
        tags: (json['tags'] as List?)?.whereType<String>().toList() ??
            const [],
      );

  /// Convenience: true when this token is tagged `stablecoin`.
  bool get isStablecoin => tags.contains('stablecoin');

  /// Convenience: true when this token is tagged `wrapped`.
  bool get isWrapped => tags.contains('wrapped');

  @override
  String toString() => 'CuratedToken($symbol on $chainKey @ $address)';
}
