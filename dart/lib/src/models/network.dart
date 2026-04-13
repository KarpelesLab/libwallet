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

  /// Base URL of the block explorer for this network.
  final String blockExplorer;

  /// Whether this is a test network.
  final bool testNet;

  /// Display priority; higher values are shown first.
  final int priority;

  /// Timestamp when the network was created.
  final DateTime created;

  /// Timestamp when the network was last updated.
  final DateTime updated;

  const Network({
    required this.id,
    required this.type,
    required this.chainId,
    required this.name,
    required this.rpc,
    required this.currencySymbol,
    required this.currencyDecimals,
    required this.blockExplorer,
    required this.testNet,
    required this.priority,
    required this.created,
    required this.updated,
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
      testNet: json['TestNet'] as bool? ?? false,
      priority: json['Priority'] as int? ?? 0,
      created: DateTime.parse(json['Created'] as String),
      updated: DateTime.parse(json['Updated'] as String),
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
        'TestNet': testNet,
        'Priority': priority,
        'Created': created.toIso8601String(),
        'Updated': updated.toIso8601String(),
      };
}
