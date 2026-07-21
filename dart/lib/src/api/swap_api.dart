import '../client/transport.dart';
import '../models/key_description.dart';
import '../models/swap_quote.dart';

/// Token swaps — OKX DEX on both Solana and EVM families.
///
/// Two-step flow:
///
/// ```dart
/// final quote = await client.swap.quote(
///   tokenIn: SwapTokenRef(address: 'NATIVE', decimals: 9),
///   tokenOut: SwapTokenRef(
///     address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // USDC
///     decimals: 6,
///   ),
///   amountIn: '10000000', // 0.01 SOL in lamports
/// );
///
/// // Show quote in the approval UI (quote.amountOut, quote.route,
/// // quote.priceImpact), wait for user confirmation, then:
///
/// final result = await client.swap.execute(
///   quoteId: quote.quoteId,
///   keys: signingKeys,
/// );
/// // result.hash is the on-chain tx signature.
/// ```
///
/// Quotes expire quickly (~90 s) because aggregator prices move fast.
/// If [execute] returns `quote_expired`, call [quote] again.
class SwapApi {
  final Transport _conn;

  SwapApi(this._conn);

  /// Report whether swap is available on the current network.
  ///
  /// Call this once when the active network changes — use the
  /// result to gate a "Swap" button / screen entry in the UI. No
  /// RPC calls are made; the response is purely local policy.
  ///
  /// The check is **per specific chain id**, not per family:
  /// Solana mainnet routes through OKX; devnet / testnet don't.
  /// EVM coverage is the OKX-supported chain list (Ethereum,
  /// Polygon, BNB, Arbitrum, Optimism, Base, Avalanche, Gnosis,
  /// Fantom, zkSync Era, Linea, Scroll, Mantle, Blast, Mode,
  /// World Chain, X Layer, Manta, Polygon zkEVM, Klaytn/Kaia,
  /// Cronos, Celo) — other EVM chains return `unsupported_chain`.
  /// Bitcoin-family chains always return `unsupported_chain`.
  Future<SwapAvailability> availability() async {
    final data = await _conn.request('Swap:availability', 'GET');
    return SwapAvailability.fromJson(data as Map<String, dynamic>);
  }

  /// Get a swap quote.
  ///
  /// [tokenIn] and [tokenOut] are resolved by address + decimals — a
  /// SOL → USDC quote needs both `{address: "NATIVE", decimals: 9}`
  /// for SOL and `{address: "EPjFW…", decimals: 6}` for USDC. On
  /// Solana use `"NATIVE"` or the wSOL mint `So1111…1112`; on EVM
  /// use `"NATIVE"` or the specific ERC-20 contract address.
  ///
  /// [amountIn] is the input in base units (decimal string). Pass
  /// the literal string `"MAX"` to swap the full balance of
  /// [tokenIn] — the resolved amount lands in `quote.amountIn` so
  /// the UI can display "MAX → X.YZ TOKEN". Equivalent to calling
  /// [maxSpendable] without the sentinel handling.
  ///
  /// [slippageBps] defaults to 50 (0.5%) if omitted; clamp from the
  /// app if you want tighter control.
  ///
  /// [provider] forces a specific aggregator:
  /// - `"okx_solana"` — Solana
  /// - `"okx_evm"` — EVM
  ///
  /// Empty [provider] auto-selects the routed provider for the
  /// chain (currently OKX on both families). **There is no silent
  /// fallback** — if the primary provider errors, the caller sees
  /// that error.
  ///
  /// Known error codes:
  /// - `no_liquidity` — aggregator has no route for this pair/size
  /// - `provider_unavailable` — aggregator returned 5xx or timed out
  /// - `unsupported_chain` — current network doesn't support swap
  Future<SwapQuote> quote({
    required SwapTokenRef tokenIn,
    required SwapTokenRef tokenOut,
    required String amountIn,
    String? from,
    int? slippageBps,
    String? network,
    String? provider,
  }) async {
    final params = <String, dynamic>{
      'tokenIn': tokenIn.toJson(),
      'tokenOut': tokenOut.toJson(),
      'amountIn': amountIn,
    };
    if (from != null) params['from'] = from;
    if (slippageBps != null) params['slippageBps'] = slippageBps;
    if (network != null) params['network'] = network;
    if (provider != null) params['provider'] = provider;
    final data = await _conn.request('Swap:quote', 'POST', params);
    return SwapQuote.fromJson(data as Map<String, dynamic>);
  }

  /// Quote the same swap against every available provider for the
  /// chain and return one [QuoteAttempt] per provider — successful
  /// quotes carry [QuoteAttempt.quote]; failures carry
  /// [QuoteAttempt.error] with a typed error code. Hosts render the
  /// attempts side-by-side and let the user pick.
  ///
  /// Each successful attempt is cached server-side; call [execute]
  /// with the chosen `quoteId` to commit. Quotes expire after 90 s
  /// — same TTL as [quote].
  ///
  /// "MAX" amountIn is resolved once (against the chain's primary
  /// max calc) before fan-out so every provider sees the same input
  /// and the comparison is apples-to-apples.
  Future<List<QuoteAttempt>> quotes({
    required SwapTokenRef tokenIn,
    required SwapTokenRef tokenOut,
    required String amountIn,
    String? from,
    int? slippageBps,
    String? network,
  }) async {
    final params = <String, dynamic>{
      'tokenIn': tokenIn.toJson(),
      'tokenOut': tokenOut.toJson(),
      'amountIn': amountIn,
    };
    if (from != null) params['from'] = from;
    if (slippageBps != null) params['slippageBps'] = slippageBps;
    if (network != null) params['network'] = network;
    final data = await _conn.request('Swap:quotes', 'POST', params);
    final m = Map<String, dynamic>.from(data as Map);
    final raw = (m['attempts'] as List?) ?? const [];
    return raw
        .map((e) => QuoteAttempt.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  /// Get a quote that swaps the maximum amount of [tokenIn] the
  /// account can spend. Returns the same [SwapQuote] shape as
  /// [quote], with `quote.amountIn` populated from the resolved
  /// max — perfect for a "Max" button that needs to render the
  /// resolved amount before the user commits.
  ///
  /// For native assets (SOL / ETH) the max is balance minus the
  /// estimated network fee + (Solana) the rent-exempt minimums.
  ///
  /// On Solana, when [tokenIn] is native SOL and [tokenOut] is an
  /// SPL token the user does not yet hold, an extra ~2.04M lamports
  /// is reserved for the destination Associated Token Account that
  /// Jupiter / dFlow will create on the fly. Without this reserve
  /// Jupiter rejects the order with HTTP 400 "Failed to get quotes"
  /// when the wallet ends up at exactly the system-account rent
  /// minimum and can't cover the new ATA.
  ///
  /// For tokens (SPL / ERC-20) the max is the full token balance —
  /// fees are paid in the chain's native currency and don't reduce
  /// the spendable token amount. The frontend should still call
  /// [TransactionApi.maxSendable] on the *native* asset to confirm
  /// the user has enough native left to cover gas (and on Solana,
  /// any ATA-creation rent for the output mint).
  ///
  /// All other parameters behave the same as [quote]. Returns the
  /// same error codes as [quote] plus `invalid_request` when the
  /// resolved max would be zero (balance does not cover the fee).
  Future<SwapQuote> maxSpendable({
    required SwapTokenRef tokenIn,
    required SwapTokenRef tokenOut,
    String? from,
    int? slippageBps,
    String? network,
    String? provider,
  }) async {
    final params = <String, dynamic>{
      'tokenIn': tokenIn.toJson(),
      'tokenOut': tokenOut.toJson(),
    };
    if (from != null) params['from'] = from;
    if (slippageBps != null) params['slippageBps'] = slippageBps;
    if (network != null) params['network'] = network;
    if (provider != null) params['provider'] = provider;
    final data = await _conn.request('Swap:maxSpendable', 'POST', params);
    return SwapQuote.fromJson(data as Map<String, dynamic>);
  }

  /// Build the ERC-20 `approve` transaction the swap needs as a
  /// prerequisite on EVM.
  ///
  /// Only call this when [SwapQuote.requiresApproval] is true. The
  /// returned [ApprovalPreview] is everything a UI needs to render
  /// the approval sheet — spender address + human label, amount,
  /// unlimited flag, current allowance, network fee — plus the
  /// underlying validated transaction. Sign and broadcast via:
  ///
  /// ```dart
  /// await client.transactions.signAndSendSimple(preview.tx, keys: keys);
  /// ```
  ///
  /// [approvalAmount] defaults to the quote's exact input amount
  /// (tightest possible — a compromised router can only drain what
  /// the user already agreed to swap). Pass `"max"` to request the
  /// classic `uint256.max` unlimited approval; pass a decimal string
  /// to approve a specific amount (e.g. for batched trades across
  /// multiple swaps).
  ///
  /// Raising the approval amount above `amountIn` widens the blast
  /// radius if the router is ever exploited — use
  /// [ApprovalPreview.isUnlimited] to surface a clear warning in
  /// the UI.
  Future<ApprovalPreview> buildApproval({
    required String quoteId,
    String? approvalAmount,
    String? from,
  }) async {
    final params = <String, dynamic>{'quoteId': quoteId};
    if (approvalAmount != null) params['approvalAmount'] = approvalAmount;
    if (from != null) params['from'] = from;
    final data = await _conn.request('Swap:buildApproval', 'POST', params);
    return ApprovalPreview.fromJson(data as Map<String, dynamic>);
  }

  /// Execute a previously-issued quote.
  ///
  /// [keys] is the signing material. On success returns a
  /// [SwapResult] with the on-chain tx hash. On failure the quote
  /// stays in the server cache until its natural expiry so the caller
  /// can retry without re-quoting.
  ///
  /// Known error codes:
  /// - `quote_not_found` / `quote_expired` — re-quote and try again
  /// - `slippage_exceeded` — price moved; re-quote with tighter
  ///   slippage or accept more
  /// - `provider_unavailable` — aggregator or chain RPC failure
  /// [mevProtection] toggles OKX's MEV-protected broadcast for EVM swaps.
  /// Leave `null` to use the default (on); pass `false` to opt out (e.g.
  /// when the protected mempool is landing slowly). Ignored on Solana.
  Future<SwapResult> execute({
    required String quoteId,
    required List<SigningKey> keys,
    String? from,
    bool? mevProtection,
  }) async {
    final params = <String, dynamic>{
      'quoteId': quoteId,
      'Keys': keys.map((k) => k.toJson()).toList(),
    };
    if (from != null) params['from'] = from;
    if (mevProtection != null) params['mevProtection'] = mevProtection;
    final data = await _conn.request('Swap:execute', 'POST', params);
    return SwapResult.fromJson(data as Map<String, dynamic>);
  }

  /// Poll the settlement state of a previously executed swap.
  ///
  /// [execute] reports success the moment the provider *accepts* the
  /// broadcast — for OKX that's before the tx has even been validated (it
  /// returns an [SwapResult.orderId] for a malformed payload too), so the
  /// `hash` it returns is not proof the swap landed. To confirm, poll this
  /// with [SwapResult.orderId] until [SwapOrderStatus.isPending] is false:
  ///
  /// ```dart
  /// final r = await client.swap.execute(quoteId: q, keys: keys);
  /// var st = await client.swap.orderStatus(r.orderId);
  /// while (st.isPending) {
  ///   await Future.delayed(const Duration(seconds: 2));
  ///   st = await client.swap.orderStatus(r.orderId);
  /// }
  /// if (st.isFailed) showError(st.failReason);
  /// ```
  ///
  /// [from] selects the signing account (default: current); the order is
  /// keyed by that wallet's on-chain address. Pass the same account that
  /// executed the swap.
  Future<SwapOrderStatus> orderStatus(String orderId, {String? from}) async {
    final params = <String, dynamic>{'orderId': orderId};
    if (from != null) params['from'] = from;
    final data = await _conn.request('Swap:orderStatus', 'POST', params);
    return SwapOrderStatus.fromJson(data as Map<String, dynamic>);
  }
}
