enum NetworkType {
  evm,
  bitcoin,
  solana,
  unknown;

  static NetworkType fromString(String s) {
    switch (s) {
      case 'evm':
        return NetworkType.evm;
      case 'bitcoin':
        return NetworkType.bitcoin;
      case 'solana':
        return NetworkType.solana;
      default:
        return NetworkType.unknown;
    }
  }
}

/// A blockchain network configuration.
class Network {
  /// Unique identifier for this network.
  final String id;

  /// Network family: [NetworkType.evm], [NetworkType.bitcoin], or [NetworkType.solana].
  final NetworkType type;

  /// Chain ID (e.g. `"1"` for Ethereum mainnet).
  final String chainId;

  /// Human-readable network name (e.g. `"Ethereum"`).
  final String name;

  /// JSON-RPC endpoint URL for this network.
  final String rpc;

  /// Ticker symbol of the native currency (e.g. `ETH`).
  final String currencySymbol;

  /// Number of decimal places for the native currency.
  final int currencyDecimals;

  /// Base URL of the block explorer for this network. Raw user-set
  /// value — `"auto"` for the default networks where libwallet picks
  /// the explorer at runtime. Use [resolvedBlockExplorer] (or the
  /// [transactionUrl] / [addressUrl] helpers) to get a usable URL.
  final String blockExplorer;

  /// Block-explorer base URL after libwallet resolves the `"auto"`
  /// sentinel (against the chain registry for EVM, defaults for
  /// Solana). Empty when no canonical explorer is known — typically
  /// custom networks the user added without a [blockExplorer], or
  /// Bitcoin networks that haven't been configured. Hosts that render
  /// "open in explorer" affordances should hide the link when this
  /// (or [transactionUrl] / [addressUrl]) returns empty.
  final String resolvedBlockExplorer;

  /// Whether this is a test network.
  final bool testNet;

  /// Display priority; higher values are shown first.
  final int priority;

  /// Timestamp when the network was created.
  final DateTime created;

  /// Timestamp when the network was last updated.
  final DateTime updated;

  /// Name of the on-chain transaction-history provider libwallet
  /// uses to populate the local Transaction table for this
  /// network, or empty when no provider is implemented yet. Use
  /// this to distinguish "indexer hasn't returned anything yet"
  /// (provider non-empty + Transaction list empty) from "indexer
  /// not implemented on this chain" (provider empty + Transaction
  /// list always empty). Stable values:
  ///
  ///   - `"modchain"`   — EVM (primary), via modchain_historyByAddress
  ///   - `"otterscan"`  — EVM (fallback), via ots_searchTransactionsAfter
  ///   - `"signatures"` — Solana, via getSignaturesForAddress + getTransaction
  ///   - `""`           — no provider (bitcoin family, custom chains, …)
  ///
  /// Hosts that render a "Powered by …" badge can read this; UIs
  /// that want to hide the tx tab on chains without an indexer
  /// should check for `txHistoryProvider.isEmpty`.
  final String txHistoryProvider;

  const Network({
    required this.id,
    required this.type,
    required this.chainId,
    required this.name,
    required this.rpc,
    required this.currencySymbol,
    required this.currencyDecimals,
    required this.blockExplorer,
    this.resolvedBlockExplorer = '',
    required this.testNet,
    required this.priority,
    required this.created,
    required this.updated,
    this.txHistoryProvider = '',
  });

  factory Network.fromJson(Map<String, dynamic> json) {
    return Network(
      id: json['Id'] as String,
      type: NetworkType.fromString(json['Type'] as String? ?? ''),
      chainId: json['ChainId'] as String? ?? '',
      name: json['Name'] as String? ?? '',
      rpc: json['RPC'] as String? ?? '',
      currencySymbol: json['CurrencySymbol'] as String? ?? '',
      currencyDecimals: json['CurrencyDecimals'] as int? ?? 18,
      blockExplorer: json['BlockExplorer'] as String? ?? '',
      resolvedBlockExplorer:
          json['ResolvedBlockExplorer'] as String? ?? '',
      testNet: json['TestNet'] as bool? ?? false,
      priority: json['Priority'] as int? ?? 0,
      created: DateTime.parse(json['Created'] as String),
      updated: DateTime.parse(json['Updated'] as String),
      txHistoryProvider: json['TxHistoryProvider'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Type': type.name,
        'ChainId': chainId,
        'Name': name,
        'RPC': rpc,
        'CurrencySymbol': currencySymbol,
        'CurrencyDecimals': currencyDecimals,
        'BlockExplorer': blockExplorer,
        if (resolvedBlockExplorer.isNotEmpty)
          'ResolvedBlockExplorer': resolvedBlockExplorer,
        'TestNet': testNet,
        'Priority': priority,
        'Created': created.toIso8601String(),
        'Updated': updated.toIso8601String(),
        if (txHistoryProvider.isNotEmpty)
          'TxHistoryProvider': txHistoryProvider,
      };

  /// Block-explorer URL for [txHash] on this network. Returns `""`
  /// when the network has no resolvable explorer (custom chain, no
  /// `blockExplorer` configured). Hosts should hide the affordance
  /// when this returns empty.
  ///
  /// On Solana devnet/testnet the result carries `?cluster=<chainId>`
  /// — required to make explorer.solana.com / solscan.io / solana.fm
  /// query the right cluster. Mainnet stays bare.
  String transactionUrl(String txHash) {
    if (resolvedBlockExplorer.isEmpty) return '';
    return '$resolvedBlockExplorer/tx/$txHash${_solanaClusterSuffix()}';
  }

  /// Block-explorer URL for an account or contract [address] on this
  /// network. Symmetric with [transactionUrl] — same nullability,
  /// same per-chain branching (Solana cluster suffix on non-mainnet).
  ///
  /// Use for "tap address → open in explorer" affordances. Returns
  /// `""` when the network has no resolvable explorer; hosts should
  /// hide the link in that case.
  String addressUrl(String address) {
    if (resolvedBlockExplorer.isEmpty) return '';
    return '$resolvedBlockExplorer/address/$address${_solanaClusterSuffix()}';
  }

  String _solanaClusterSuffix() {
    if (type != NetworkType.solana) return '';
    if (chainId.isEmpty || chainId == 'mainnet' || chainId == 'mainnet-beta') {
      return '';
    }
    return '?cluster=$chainId';
  }
}
