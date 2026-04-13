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
  final String id;
  final NetworkType type;
  final String chainId;
  final String name;
  final String rpc;
  final String currencySymbol;
  final int currencyDecimals;
  final String blockExplorer;
  final bool testNet;
  final int priority;
  final DateTime created;
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
