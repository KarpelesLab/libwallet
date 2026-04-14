/// Result of `NetworkApi.testRpc` — metadata about an EVM RPC endpoint.
class RpcTestResult {
  /// Echoed RPC URL that was tested.
  final String rpc;

  /// EVM chain ID returned by `net_version`.
  final int chainId;

  /// Human-readable chain name (e.g. `Ethereum Mainnet`). Null if the
  /// chain ID is not in the built-in registry.
  final String? name;

  /// Native currency symbol (e.g. `ETH`). Null if unknown.
  final String? currencySymbol;

  /// Raw EVM chain info record (from the built-in chains registry), if
  /// a match was found. The shape is the ethereum-lists `chains` JSON.
  final Map<String, dynamic>? evmInfo;

  const RpcTestResult({
    required this.rpc,
    required this.chainId,
    this.name,
    this.currencySymbol,
    this.evmInfo,
  });

  factory RpcTestResult.fromJson(Map<String, dynamic> json) => RpcTestResult(
        rpc: json['RPC'] as String? ?? '',
        chainId: (json['ChainId'] as num?)?.toInt() ?? 0,
        name: json['Name'] as String?,
        currencySymbol: json['CurrencySymbol'] as String?,
        evmInfo: json['EVM_Info'] is Map
            ? Map<String, dynamic>.from(json['EVM_Info'] as Map)
            : null,
      );
}
