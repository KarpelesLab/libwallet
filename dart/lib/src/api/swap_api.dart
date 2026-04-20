import '../client/transport.dart';
import '../models/key_description.dart';
import '../models/swap_quote.dart';

/// Token swaps — Jupiter Ultra / dFlow on Solana, 1inch on EVM.
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
  /// Solana mainnet is available via Jupiter + dFlow, but devnet /
  /// testnet aren't. 1inch covers a specific list of EVM chains
  /// (Ethereum / Polygon / BNB / Arbitrum / Optimism / Base /
  /// Avalanche / Gnosis / Fantom / zkSync Era / Linea) — other EVM
  /// chains return `unsupported_chain` even with a valid key.
  /// Bitcoin-family chains always return `unsupported_chain`.
  ///
  /// In the current build the 1inch API key ships empty, so EVM
  /// returns `reason: "missing_api_key"` on the supported chains.
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
  /// [amountIn] is the input in base units (decimal string).
  ///
  /// [slippageBps] defaults to 50 (0.5%) if omitted; clamp from the
  /// app if you want tighter control.
  ///
  /// [provider] forces a specific aggregator:
  /// - `"jupiter_ultra"` / `"dflow"` — Solana only
  /// - `"1inch"` — EVM only
  ///
  /// Empty [provider] auto-selects; Solana falls back from Jupiter
  /// to dFlow if Jupiter is unavailable.
  ///
  /// Known error codes:
  /// - `no_liquidity` — aggregator has no route for this pair/size
  /// - `provider_unavailable` — aggregator returned 5xx or timed out
  /// - `unsupported_chain` — current network doesn't support swap
  /// - `missing_api_key` — 1inch key not configured in this build
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
  Future<SwapResult> execute({
    required String quoteId,
    required List<SigningKey> keys,
    String? from,
  }) async {
    final params = <String, dynamic>{
      'quoteId': quoteId,
      'Keys': keys.map((k) => k.toJson()).toList(),
    };
    if (from != null) params['from'] = from;
    final data = await _conn.request('Swap:execute', 'POST', params);
    return SwapResult.fromJson(data as Map<String, dynamic>);
  }
}
