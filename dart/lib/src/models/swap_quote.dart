import 'amount.dart';

/// A swap quote returned by [SwapApi.quote].
///
/// Quotes are short-lived: the server keeps them in an in-memory
/// cache for about 90 s (see [expiresAt]). After that, calling
/// [SwapApi.execute] with this [quoteId] returns `quote_expired` —
/// the app must re-quote and try again.
class SwapQuote {
  /// Opaque server-issued identifier. Pass this to [SwapApi.execute].
  final String quoteId;

  /// Which aggregator produced the quote: `jupiter_ultra`, `dflow`,
  /// or `1inch`.
  final String provider;

  /// Chain family: `solana` or `evm`.
  final String chain;

  /// Input token.
  final SwapTokenRef tokenIn;

  /// Output token.
  final SwapTokenRef tokenOut;

  /// Amount of [tokenIn] the user will send (base units).
  final Amount amountIn;

  /// Amount of [tokenOut] the aggregator expects to deliver. This
  /// is the best-case outcome; in practice the user receives between
  /// [minAmountOut] and [amountOut] depending on price movement
  /// between quote and execution.
  final Amount amountOut;

  /// Minimum acceptable [tokenOut] after [slippageBps]. If execution
  /// would settle below this, the swap reverts on-chain.
  final Amount minAmountOut;

  /// Provider-reported price impact as a fraction (0.01 = 1%). Zero
  /// when the provider doesn't report one.
  final double priceImpact;

  /// Platform fee in basis points — the 50 bps referral fee.
  final int feeBps;

  /// Slippage tolerance in basis points.
  final int slippageBps;

  /// Route breakdown — one entry per hop in the swap path. Purely
  /// informative; the aggregator decides actual routing.
  final List<SwapRouteHop> route;

  /// When this quote stops being accepted by [SwapApi.execute].
  final DateTime expiresAt;

  const SwapQuote({
    required this.quoteId,
    required this.provider,
    required this.chain,
    required this.tokenIn,
    required this.tokenOut,
    required this.amountIn,
    required this.amountOut,
    required this.minAmountOut,
    required this.expiresAt,
    this.priceImpact = 0,
    this.feeBps = 0,
    this.slippageBps = 0,
    this.route = const [],
  });

  factory SwapQuote.fromJson(Map<String, dynamic> json) {
    List<SwapRouteHop> parseRoute(dynamic v) {
      if (v is! List) return const [];
      return v
          .whereType<Map>()
          .map((e) => SwapRouteHop.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }

    return SwapQuote(
      quoteId: (json['quoteId'] as String?) ?? '',
      provider: (json['provider'] as String?) ?? '',
      chain: (json['chain'] as String?) ?? '',
      tokenIn:
          SwapTokenRef.fromJson(Map<String, dynamic>.from(json['tokenIn'] as Map)),
      tokenOut:
          SwapTokenRef.fromJson(Map<String, dynamic>.from(json['tokenOut'] as Map)),
      amountIn: Amount.fromJson(json['amountIn']),
      amountOut: Amount.fromJson(json['amountOut']),
      minAmountOut: Amount.fromJson(json['minAmountOut']),
      priceImpact: (json['priceImpact'] as num?)?.toDouble() ?? 0,
      feeBps: (json['feeBps'] as num?)?.toInt() ?? 0,
      slippageBps: (json['slippageBps'] as num?)?.toInt() ?? 0,
      route: parseRoute(json['route']),
      expiresAt: DateTime.parse(json['expiresAt'] as String),
    );
  }

  /// True when the quote has passed its server-side TTL.
  bool get isExpired => DateTime.now().isAfter(expiresAt);
}

/// A token by address + decimals. Pass `address: "NATIVE"` for the
/// chain's native currency (SOL on Solana, ETH on Ethereum).
class SwapTokenRef {
  final String address;
  final String symbol;
  final int decimals;

  const SwapTokenRef({
    required this.address,
    this.symbol = '',
    required this.decimals,
  });

  factory SwapTokenRef.fromJson(Map<String, dynamic> json) => SwapTokenRef(
        address: (json['address'] as String?) ?? '',
        symbol: (json['symbol'] as String?) ?? '',
        decimals: (json['decimals'] as num?)?.toInt() ?? 0,
      );

  Map<String, dynamic> toJson() => {
        'address': address,
        if (symbol.isNotEmpty) 'symbol': symbol,
        'decimals': decimals,
      };
}

/// One hop in a multi-hop swap path.
class SwapRouteHop {
  /// AMM / venue name, e.g. `"Raydium"`, `"Uniswap V3"`.
  final String venue;

  /// Input-side symbol, if provided by the aggregator.
  final String inSymbol;

  /// Output-side symbol, if provided by the aggregator.
  final String outSymbol;

  /// Share of the total input routed through this hop (0–1). Zero
  /// when the path doesn't split.
  final double share;

  const SwapRouteHop({
    required this.venue,
    this.inSymbol = '',
    this.outSymbol = '',
    this.share = 0,
  });

  factory SwapRouteHop.fromJson(Map<String, dynamic> json) => SwapRouteHop(
        venue: (json['venue'] as String?) ?? '',
        inSymbol: (json['inSymbol'] as String?) ?? '',
        outSymbol: (json['outSymbol'] as String?) ?? '',
        share: (json['share'] as num?)?.toDouble() ?? 0,
      );
}

/// The result of [SwapApi.execute]: a successfully broadcast swap.
class SwapResult {
  /// The quote ID that produced this result.
  final String quoteId;
  final String provider;
  final String chain;

  /// On-chain transaction signature (Solana) / transaction hash (EVM).
  final String hash;

  /// Block-explorer URL for [hash].
  final String url;

  /// A copy of the quote that was executed — convenient for the app
  /// to display "you swapped X for Y" without caching separately.
  final SwapQuote quote;

  const SwapResult({
    required this.quoteId,
    required this.provider,
    required this.chain,
    required this.hash,
    required this.url,
    required this.quote,
  });

  factory SwapResult.fromJson(Map<String, dynamic> json) => SwapResult(
        quoteId: (json['quoteId'] as String?) ?? '',
        provider: (json['provider'] as String?) ?? '',
        chain: (json['chain'] as String?) ?? '',
        hash: (json['hash'] as String?) ?? '',
        url: (json['url'] as String?) ?? '',
        quote: SwapQuote.fromJson(Map<String, dynamic>.from(json['quote'] as Map)),
      );
}
