/// Result of `NetworkApi.testRpc`.
///
/// Shape depends on [type] — fields relevant to the other chain
/// families stay null. Use the boolean getters (`isEvm`, `isSolana`,
/// `isBitcoin`) or switch on [type] to pick the right read-side fields.
class RpcTestResult {
  /// Echoed RPC URL that was tested.
  final String rpc;

  /// Chain family the probe targeted: `evm`, `solana`, or `bitcoin`.
  final String type;

  // ── EVM ────────────────────────────────────────────────────
  /// EVM chain id (from `net_version`). Null for non-EVM probes.
  final int? chainId;

  /// Human-readable chain name (e.g. `Ethereum Mainnet`) when the id
  /// is in the built-in registry.
  final String? name;

  /// Native currency symbol (e.g. `ETH`).
  final String? currencySymbol;

  /// Raw ethereum-lists `chains.json` record, if matched.
  final Map<String, dynamic>? evmInfo;

  // ── Solana ─────────────────────────────────────────────────
  /// `solana-core` version string (from `getVersion`).
  final String? solanaVersion;

  /// Named cluster resolved from `getGenesisHash`: `mainnet-beta`,
  /// `devnet`, `testnet`, or `unknown`.
  final String? solanaCluster;

  // ── Bitcoin-family ─────────────────────────────────────────
  /// `chain` field from `getblockchaininfo` (e.g. `main`, `test`,
  /// `regtest`, `signet` — or fork-specific names).
  final String? bitcoinChain;

  /// Current block height.
  final int? bitcoinBlocks;

  const RpcTestResult({
    required this.rpc,
    required this.type,
    this.chainId,
    this.name,
    this.currencySymbol,
    this.evmInfo,
    this.solanaVersion,
    this.solanaCluster,
    this.bitcoinChain,
    this.bitcoinBlocks,
  });

  factory RpcTestResult.fromJson(Map<String, dynamic> json) => RpcTestResult(
        rpc: json['RPC'] as String? ?? '',
        type: json['Type'] as String? ?? 'evm',
        chainId: (json['ChainId'] as num?)?.toInt(),
        name: json['Name'] as String?,
        currencySymbol: json['CurrencySymbol'] as String?,
        evmInfo: json['EVM_Info'] is Map
            ? Map<String, dynamic>.from(json['EVM_Info'] as Map)
            : null,
        solanaVersion: json['SolanaVersion'] as String?,
        solanaCluster: json['SolanaCluster'] as String?,
        bitcoinChain: json['Chain'] as String?,
        bitcoinBlocks: (json['Blocks'] as num?)?.toInt(),
      );

  bool get isEvm => type == 'evm';
  bool get isSolana => type == 'solana';
  bool get isBitcoin => type == 'bitcoin';
}
