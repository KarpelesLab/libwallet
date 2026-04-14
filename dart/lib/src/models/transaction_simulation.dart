/// Result of `TransactionApi.simulate(...)`.
///
/// A flat per-tx view suitable for rendering an approval sheet. Per-chain
/// fields ([gasEstimate], [logs], [bitcoinInputs] etc.) are optional and
/// only populated for the matching chain family.
class TransactionSimulation {
  /// Which chain this was simulated on: `evm`, `solana`, or `bitcoin`.
  final String chain;

  /// True when the simulation failed — either the chain rejected the
  /// transaction (EVM revert, Solana logs err) or we couldn't parse it.
  /// Show a clear warning before letting the user approve.
  final bool willRevert;

  /// Human-readable failure reason. For EVM, this is the decoded
  /// `Error(string)` message (ERC-20 reverts, custom require strings).
  /// For Solana, the JSON-encoded `err` from `simulateTransaction`.
  final String? revertReason;

  /// High-level operation name when we can recognize the calldata shape:
  /// - `native_transfer` — plain coin send
  /// - `erc20_transfer` — ERC-20 `transfer(to, amount)` call
  /// - `erc20_approve`  — ERC-20 `approve(spender, amount)` call
  /// - `unknown`        — arbitrary contract call (decoded selector only)
  /// - null             — no calldata and no amount (rare)
  final String? decodedMethod;

  /// Typed arguments for [decodedMethod]. Shape depends on the method:
  /// - `native_transfer`: `{to, amount}`
  /// - `erc20_transfer`:  `{token, to, amount}`  (token = the contract)
  /// - `erc20_approve`:   `{token, spender, amount}` (amount may be 2^256-1 for "unlimited")
  /// - `unknown`:         `{selector, data}`
  final Map<String, dynamic> decodedArgs;

  /// Every transfer the simulated tx will cause, at any call depth.
  ///
  /// This is the anti-drainer signal: a dApp can send innocuous-looking
  /// calldata (e.g. `increaseAllowance` for a tiny amount) that triggers
  /// a massive Transfer event via a nested call. Showing the user every
  /// Effect catches that — the top-level [decodedMethod] alone does not.
  ///
  /// Populated on EVM chains via erigon's `debug_traceCall` with the
  /// `callTracer`. On nodes without `debug_*`, this list contains only
  /// the single effect corresponding to [decodedMethod] (if any).
  final List<Effect> effects;

  /// Native-balance deltas per address, from erigon's `prestateTracer`
  /// (diff mode). Values are signed decimal wei — negative means net
  /// spend (the sender pays gas + any native value attached).
  final List<BalanceChange> balanceChanges;

  // ── EVM ────────────────────────────────────────────────────
  /// EVM gas estimate via `eth_estimateGas` (only set on success).
  final int? gasEstimate;

  // ── Solana ─────────────────────────────────────────────────
  /// Solana simulation logs (program output lines).
  final List<String>? logs;

  /// Solana compute-unit budget consumed by the simulated tx.
  final int? unitsConsumed;

  // ── Bitcoin ────────────────────────────────────────────────
  /// Decoded inputs of a bitcoin-family tx. Amounts are NOT populated
  /// (would require separate RPC lookup of prev txouts).
  final List<BitcoinIO>? bitcoinInputs;

  /// Decoded outputs. `amount` is in satoshi; `script` is the raw
  /// hex script.
  final List<BitcoinIO>? bitcoinOutputs;

  /// Fee in satoshi, when available (libwallet knows it from
  /// tx-construction; external txs don't carry it).
  final int? bitcoinFee;

  const TransactionSimulation({
    required this.chain,
    required this.willRevert,
    this.revertReason,
    this.decodedMethod,
    this.decodedArgs = const {},
    this.effects = const [],
    this.balanceChanges = const [],
    this.gasEstimate,
    this.logs,
    this.unitsConsumed,
    this.bitcoinInputs,
    this.bitcoinOutputs,
    this.bitcoinFee,
  });

  factory TransactionSimulation.fromJson(Map<String, dynamic> json) {
    List<BitcoinIO>? parseIOs(dynamic v) {
      if (v is! List) return null;
      return v
          .whereType<Map>()
          .map((e) => BitcoinIO.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }

    List<Effect> parseEffects(dynamic v) {
      if (v is! List) return const [];
      return v
          .whereType<Map>()
          .map((e) => Effect.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }

    List<BalanceChange> parseBalanceChanges(dynamic v) {
      if (v is! List) return const [];
      return v
          .whereType<Map>()
          .map((e) => BalanceChange.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }

    return TransactionSimulation(
      chain: (json['chain'] as String?) ?? '',
      willRevert: json['willRevert'] == true,
      revertReason: json['revertReason'] as String?,
      decodedMethod: json['decodedMethod'] as String?,
      decodedArgs: json['decodedArgs'] is Map
          ? Map<String, dynamic>.from(json['decodedArgs'] as Map)
          : const <String, dynamic>{},
      effects: parseEffects(json['effects']),
      balanceChanges: parseBalanceChanges(json['balanceChanges']),
      gasEstimate: (json['gasEstimate'] as num?)?.toInt(),
      logs: (json['logs'] as List?)?.whereType<String>().toList(),
      unitsConsumed: (json['unitsConsumed'] as num?)?.toInt(),
      bitcoinInputs: parseIOs(json['bitcoinInputs']),
      bitcoinOutputs: parseIOs(json['bitcoinOutputs']),
      bitcoinFee: (json['bitcoinFee'] as num?)?.toInt(),
    );
  }

  bool get isEvm => chain == 'evm';
  bool get isSolana => chain == 'solana';
  bool get isBitcoin => chain == 'bitcoin';
}

/// One observable transfer the simulated tx will cause. Sourced from
/// erigon's `debug_traceCall` callTracer — every ERC-20 Transfer /
/// Approval event and every value-carrying CALL / CREATE at any depth.
class Effect {
  /// `native_transfer` | `erc20_transfer` | `erc20_approve`.
  final String type;

  /// ERC-20 token contract address. Empty for native transfers.
  final String token;

  /// Lowercase hex address.
  final String from;

  /// Lowercase hex address. For `erc20_approve`, this is the spender.
  final String to;

  /// Unsigned decimal integer string (wei or token base units).
  final String amount;

  const Effect({
    required this.type,
    this.token = '',
    required this.from,
    required this.to,
    required this.amount,
  });

  factory Effect.fromJson(Map<String, dynamic> json) => Effect(
        type: (json['type'] as String?) ?? '',
        token: (json['token'] as String?) ?? '',
        from: (json['from'] as String?) ?? '',
        to: (json['to'] as String?) ?? '',
        amount: (json['amount'] as String?) ?? '0',
      );

  bool get isNative => type == 'native_transfer';
  bool get isErc20Transfer => type == 'erc20_transfer';
  bool get isErc20Approve => type == 'erc20_approve';
}

/// Signed native-balance delta for one address across the simulation.
/// Negative means the address lost balance (paid gas, sent value, etc.).
class BalanceChange {
  final String address;

  /// Signed decimal integer string (wei for EVM).
  final String delta;

  const BalanceChange({required this.address, required this.delta});

  factory BalanceChange.fromJson(Map<String, dynamic> json) => BalanceChange(
        address: (json['address'] as String?) ?? '',
        delta: (json['delta'] as String?) ?? '0',
      );

  /// True if this address lost native balance.
  bool get isLoss => delta.startsWith('-');
}

/// One input or output of a bitcoin-family transaction.
class BitcoinIO {
  /// Recipient / sender address if resolvable from the script. Empty
  /// for non-standard scripts — fall back to [script].
  final String address;

  /// Amount in satoshi (8 decimal places). Only meaningful for outputs
  /// in v1 — input amounts would require a per-input prev-txo lookup
  /// which the simulator doesn't perform yet.
  final int amount;

  /// Hex-encoded script pubkey. Non-empty for non-standard scripts.
  final String script;

  /// Previous txid (big-endian hex) — inputs only.
  final String txid;

  /// Previous output index — inputs only.
  final int vout;

  const BitcoinIO({
    this.address = '',
    this.amount = 0,
    this.script = '',
    this.txid = '',
    this.vout = 0,
  });

  factory BitcoinIO.fromJson(Map<String, dynamic> json) => BitcoinIO(
        address: (json['address'] as String?) ?? '',
        amount: (json['amount'] as num?)?.toInt() ?? 0,
        script: (json['script'] as String?) ?? '',
        txid: (json['txid'] as String?) ?? '',
        vout: (json['vout'] as num?)?.toInt() ?? 0,
      );
}
