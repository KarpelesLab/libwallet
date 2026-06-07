import 'amount.dart';
import 'transaction.dart';

/// A swap quote returned by [SwapApi.quote].
///
/// Quotes are short-lived: the server keeps them in an in-memory
/// cache for about 90 s (see [expiresAt]). After that, calling
/// [SwapApi.execute] with this [quoteId] returns `quote_expired` —
/// the app must re-quote and try again.
class SwapQuote {
  /// Opaque server-issued identifier. Pass this to [SwapApi.execute].
  final String quoteId;

  /// Which aggregator produced the quote: `"okx_solana"` or
  /// `"okx_evm"`.
  final String provider;

  /// Human-friendly provider name: `"OKX"`. Safe to show in UI
  /// without further mapping.
  final String providerLabel;

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

  /// Platform referral fee as an absolute amount in the INPUT
  /// token's units (`amountIn * feeBps / 10000`). Null when the
  /// provider doesn't report one. Use this for "Platform fee:
  /// 0.005 SOL" UI strings.
  final Amount? referralFee;

  /// Estimated chain-side fee the user pays (gas on EVM, signature
  /// + priority on Solana). Always in the chain's native currency.
  /// Render as "Network fee".
  final Amount? networkFee;

  /// Route breakdown — one entry per hop in the swap path. Purely
  /// informative; the aggregator decides actual routing.
  final List<SwapRouteHop> route;

  /// When this quote stops being accepted by [SwapApi.execute].
  final DateTime expiresAt;

  /// True when the swap needs an ERC-20 `approve` tx to run before
  /// [SwapApi.execute] can succeed. Always false on Solana (no
  /// allowance model) and false for native ETH → token swaps.
  final bool requiresApproval;

  /// The address that needs the allowance — typically the
  /// aggregator's router. Empty when [requiresApproval] is false.
  final String approvalSpender;

  /// The amount currently approved to [approvalSpender]. Null when
  /// unknown (RPC failure) or irrelevant (no approval needed).
  final Amount? currentAllowance;

  /// The minimum allowance the swap needs. Equal to [amountIn] for
  /// a token-in swap; null otherwise.
  final Amount? neededAllowance;

  /// When non-empty, this quote is NOT executable — passing it (or
  /// its [quoteId]) to [SwapApi.execute] will fail. Returned only by
  /// [SwapApi.maxSpendable] today, on two soft-failure paths that
  /// would otherwise hide an asset from source-list UIs:
  ///
  ///   - `"balance_too_small"` — the wallet's spendable balance
  ///     can't cover the network fee + any required rent reservation.
  ///     [amountIn] is zero; show `"needs more <native> to swap"` in
  ///     the row instead of dropping it.
  ///
  ///   - `"no_route"` — the provider (typically Jupiter Ultra on
  ///     tiny SOL trades) reported "Failed to get quotes" at the
  ///     resolved [amountIn]. The amount is real and reflects what
  ///     the user could send if a route existed; show the row with
  ///     a hint and re-quote when conditions change.
  ///
  /// [SwapApi.quote] / [SwapApi.quotes] still bubble these up as
  /// errors — the user is asking for a specific trade and a silent
  /// "no route" would be misleading there.
  final String status;

  /// Human-readable explanation when [status] is non-empty. Either
  /// libwallet's own description ("balance does not cover network
  /// fee + rent") or the provider's verbatim error
  /// ("Jupiter: Failed to get quotes"). Empty when [status] is.
  final String statusMessage;

  const SwapQuote({
    required this.quoteId,
    required this.provider,
    this.providerLabel = '',
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
    this.referralFee,
    this.networkFee,
    this.route = const [],
    this.requiresApproval = false,
    this.approvalSpender = '',
    this.currentAllowance,
    this.neededAllowance,
    this.status = '',
    this.statusMessage = '',
  });

  factory SwapQuote.fromJson(Map<String, dynamic> json) {
    List<SwapRouteHop> parseRoute(dynamic v) {
      if (v is! List) return const [];
      return v
          .whereType<Map>()
          .map((e) => SwapRouteHop.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }

    Amount? parseAmount(dynamic v) => v == null ? null : Amount.fromJson(v);

    return SwapQuote(
      quoteId: (json['quoteId'] as String?) ?? '',
      provider: (json['provider'] as String?) ?? '',
      providerLabel: (json['providerLabel'] as String?) ?? '',
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
      referralFee: parseAmount(json['referralFee']),
      networkFee: parseAmount(json['networkFee']),
      route: parseRoute(json['route']),
      expiresAt: DateTime.parse(json['expiresAt'] as String),
      requiresApproval: json['requiresApproval'] == true,
      approvalSpender: (json['approvalSpender'] as String?) ?? '',
      currentAllowance: parseAmount(json['currentAllowance']),
      neededAllowance: parseAmount(json['neededAllowance']),
      status: (json['status'] as String?) ?? '',
      statusMessage: (json['statusMessage'] as String?) ?? '',
    );
  }

  /// True when the quote has passed its server-side TTL.
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  /// True when this quote can be passed to [SwapApi.execute]. False
  /// for advisory quotes returned by [SwapApi.maxSpendable] when
  /// the wallet's balance is too small to swap or the provider has
  /// no route at the current amount — those are returned so the UI
  /// can keep the asset visible with a clear reason, not because
  /// the user can act on them right now.
  bool get isExecutable => status.isEmpty;
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

/// The result of [SwapApi.buildApproval] — everything a UI needs to
/// render the `"Approve <token> for <spender>"` sheet plus the
/// underlying [Transaction] to sign.
///
/// Typical approval UI:
///
/// ```
/// Approve ${preview.token.symbol}
/// to ${preview.spenderLabel}  (${preview.spender})
/// amount: ${preview.isUnlimited ? 'Unlimited' : preview.amount}
/// network fee ≈ ${preview.networkFee}
/// [Approve] [Cancel]
/// ```
///
/// On confirm:
///
/// ```dart
/// await client.transactions.signAndSendSimple(preview.tx, keys: keys);
/// ```
class ApprovalPreview {
  /// The token being approved.
  final SwapTokenRef token;

  /// The address that will receive the allowance — typically the
  /// aggregator's router contract.
  final String spender;

  /// Human-friendly label for [spender] (e.g. `"OKX DEX Router"`).
  final String spenderLabel;

  /// The approval amount in token base units. When
  /// [isUnlimited] is true, this encodes the classic
  /// `uint256.max`.
  final Amount amount;

  /// True when the approval is at or above `2^255` — effectively
  /// unlimited on any real-world token. Show a prominent warning
  /// in UI; a compromised spender contract can drain the full
  /// balance at any time.
  final bool isUnlimited;

  /// What's currently approved to [spender] — zero for first-time
  /// approvals. Handy for "current 0 → new 1.0" UI.
  final Amount? currentAllowance;

  /// Estimated chain gas cost for the approval tx itself.
  final Amount? networkFee;

  /// The validated transaction to sign. Pass to
  /// `client.transactions.signAndSendSimple(tx, keys: keys)`.
  final Transaction tx;

  const ApprovalPreview({
    required this.token,
    required this.spender,
    required this.amount,
    required this.tx,
    this.spenderLabel = '',
    this.isUnlimited = false,
    this.currentAllowance,
    this.networkFee,
  });

  factory ApprovalPreview.fromJson(Map<String, dynamic> json) => ApprovalPreview(
        token: SwapTokenRef.fromJson(
            Map<String, dynamic>.from(json['token'] as Map)),
        spender: (json['spender'] as String?) ?? '',
        spenderLabel: (json['spenderLabel'] as String?) ?? '',
        amount: Amount.fromJson(json['amount']),
        isUnlimited: json['isUnlimited'] == true,
        currentAllowance: json['currentAllowance'] == null
            ? null
            : Amount.fromJson(json['currentAllowance']),
        networkFee:
            json['networkFee'] == null ? null : Amount.fromJson(json['networkFee']),
        tx: Transaction.fromJson(Map<String, dynamic>.from(json['tx'] as Map)),
      );
}

/// Result of [SwapApi.availability] — feature-flag for the UI.
///
/// UIs typically call this once when the current network changes to
/// decide whether to render a "Swap" button / nav entry. No RPC
/// calls are made; the response is purely local policy.
///
/// The check is **per specific chain**, not per family — OKX routes
/// only on Solana mainnet (devnet / testnet return
/// `unsupported_chain`) and on a fixed list of EVM chain ids
/// (Ethereum, Polygon, BNB, Arbitrum, Optimism, Base, Avalanche,
/// Gnosis, Fantom, zkSync Era, Linea, Scroll, Mantle, Blast, Mode,
/// World Chain, X Layer, Manta, Polygon zkEVM, Klaytn/Kaia, Cronos,
/// Celo). An EVM chain outside that list returns `unsupported_chain`.
class SwapAvailability {
  /// True when `swap.quote()` / `swap.execute()` can succeed on the
  /// current network in this build. Gate the Swap button on this.
  final bool available;

  /// Canonical network identifier matching the format Asset:list
  /// uses — `"<type>.<chainId>"`, e.g. `"evm.1"`, `"evm.137"`,
  /// `"solana.mainnet"`, `"bitcoin.dogecoin"`. Split on `.` to
  /// get the chain family.
  final String network;

  /// Provider names eligible on this specific chain. With OKX as
  /// the only routed provider this is always either
  /// `["okx_solana"]` / `["okx_evm"]` or empty.
  final List<String> providers;

  /// Stable machine-readable reason when [available] is false:
  /// - `"unsupported_chain"` — chain family / specific chainId has
  ///   no provider (Bitcoin family, Solana devnet, unlisted EVM)
  ///
  /// Empty when [available] is true.
  final String reason;

  const SwapAvailability({
    required this.available,
    required this.network,
    this.providers = const [],
    this.reason = '',
  });

  factory SwapAvailability.fromJson(Map<String, dynamic> json) => SwapAvailability(
        available: json['available'] == true,
        network: (json['network'] as String?) ?? '',
        providers: (json['providers'] as List?)?.whereType<String>().toList() ?? const [],
        reason: (json['reason'] as String?) ?? '',
      );

  /// Convenience: the chain family portion of [network] (`"evm"`,
  /// `"solana"`, `"bitcoin"`).
  String get chainFamily {
    final i = network.indexOf('.');
    return i < 0 ? network : network.substring(0, i);
  }

  /// Convenience: the chain id portion of [network] (`"1"`, `"137"`,
  /// `"mainnet"`, `"dogecoin"`).
  String get chainId {
    final i = network.indexOf('.');
    return i < 0 ? '' : network.substring(i + 1);
  }
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

/// One provider's result from `Swap:quotes`. Exactly one of [quote] /
/// [error] is populated:
///
/// - [quote] set → provider returned a viable route; pass
///   [SwapQuote.quoteId] to [SwapApi.execute] when the user picks
///   this provider.
/// - [error] set → provider couldn't route (no liquidity, slippage
///   exceeded, provider unavailable, …); render
///   `"[providerLabel]: [SwapError.message]"` so the user understands
///   why a route is missing.
class QuoteAttempt {
  /// Stable provider name — `"okx_solana"` or `"okx_evm"`.
  final String provider;

  /// Display label — `"OKX"`. Pre-populated even on [error] so
  /// the picker UI can render `"OKX: Failed to get quotes"`
  /// without a [quote].
  final String providerLabel;

  /// The provider's quote when successful. Null when [error] is set.
  final SwapQuote? quote;

  /// Typed failure when the provider couldn't return a quote. Null
  /// when [quote] is set.
  final SwapError? error;

  const QuoteAttempt({
    required this.provider,
    required this.providerLabel,
    this.quote,
    this.error,
  });

  factory QuoteAttempt.fromJson(Map<String, dynamic> json) {
    final q = json['quote'];
    final e = json['error'];
    return QuoteAttempt(
      provider: (json['provider'] as String?) ?? '',
      providerLabel: (json['providerLabel'] as String?) ?? '',
      quote: q is Map
          ? SwapQuote.fromJson(Map<String, dynamic>.from(q))
          : null,
      error: e is Map
          ? SwapError.fromJson(Map<String, dynamic>.from(e))
          : null,
    );
  }

  /// Convenience predicate — `true` when [quote] is populated.
  bool get isOk => quote != null;
}

/// Typed error returned inside a [QuoteAttempt] when a provider
/// couldn't quote. The [code] is stable across releases; apps should
/// branch on it rather than the [message] (which is informational
/// and locale-free English).
class SwapError implements Exception {
  /// Stable code — `"no_liquidity"`, `"slippage_exceeded"`,
  /// `"provider_unavailable"`, `"provider_bad_request"`,
  /// `"unsupported_chain"`, `"unsupported_token_pair"`,
  /// `"missing_api_key"`, `"invalid_request"`,
  /// `"quote_expired"`, `"quote_not_found"`.
  final String code;

  /// Human-readable description. English; not localised.
  final String message;

  const SwapError({required this.code, required this.message});

  factory SwapError.fromJson(Map<String, dynamic> json) => SwapError(
        code: (json['code'] as String?) ?? '',
        message: (json['message'] as String?) ?? '',
      );

  @override
  String toString() => 'SwapError($code): $message';
}
