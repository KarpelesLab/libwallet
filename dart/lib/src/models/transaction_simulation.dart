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

    return TransactionSimulation(
      chain: (json['chain'] as String?) ?? '',
      willRevert: json['willRevert'] == true,
      revertReason: json['revertReason'] as String?,
      decodedMethod: json['decodedMethod'] as String?,
      decodedArgs: json['decodedArgs'] is Map
          ? Map<String, dynamic>.from(json['decodedArgs'] as Map)
          : const <String, dynamic>{},
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
