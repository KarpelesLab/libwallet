import '../client/transport.dart';
import '../models/network.dart';
import '../models/rpc_test.dart';

/// Network CRUD and management.
class NetworkApi {
  final Transport _conn;

  NetworkApi(this._conn);

  /// List all networks. Optionally exclude testnets.
  Future<List<Network>> list({bool? testNet}) async {
    final params = <String, dynamic>{};
    if (testNet != null) params['TestNet'] = testNet;
    final data = await _conn.request('Network', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    return (data as List)
        .map((e) => Network.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a network by ID. Use `"@"` for the current network.
  Future<Network> get(String id) async {
    final data = await _conn.request('Network/$id', 'GET');
    return Network.fromJson(data as Map<String, dynamic>);
  }

  /// Get the current network.
  Future<Network> getCurrent() => get('@');

  /// Add a new network.
  Future<Network> create({
    required String type,
    required String chainId,
    required String name,
    String? rpc,
    required String currencySymbol,
    String? blockExplorer,
    bool testNet = false,
    int priority = 0,
  }) async {
    final data = await _conn.request('Network', 'POST', {
      'Type': type,
      'ChainId': chainId,
      'Name': name,
      if (rpc != null) 'RPC': rpc,
      'CurrencySymbol': currencySymbol,
      if (blockExplorer != null) 'BlockExplorer': blockExplorer,
      'TestNet': testNet,
      'Priority': priority,
    });
    return Network.fromJson(data as Map<String, dynamic>);
  }

  /// Set a network as the current network.
  Future<void> setCurrent(String id) async {
    await _conn.request('Network/$id:setCurrent', 'POST');
  }

  /// Update a network. Only non-null fields are sent.
  Future<Network> update(
    String id, {
    String? name,
    String? rpc,
    String? currencySymbol,
    int? currencyDecimals,
    String? blockExplorer,
    bool? testNet,
    int? priority,
  }) async {
    final fields = <String, dynamic>{};
    if (name != null) fields['Name'] = name;
    if (rpc != null) fields['RPC'] = rpc;
    if (currencySymbol != null) fields['CurrencySymbol'] = currencySymbol;
    if (currencyDecimals != null) fields['CurrencyDecimals'] = currencyDecimals;
    if (blockExplorer != null) fields['BlockExplorer'] = blockExplorer;
    if (testNet != null) fields['TestNet'] = testNet;
    if (priority != null) fields['Priority'] = priority;
    final data = await _conn.request('Network/$id', 'PATCH', fields);
    return Network.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a network.
  Future<void> delete(String id) async {
    await _conn.request('Network/$id', 'DELETE');
  }

  /// Test an EVM RPC URL. Returns the chain ID and (if known) metadata
  /// from the built-in chain registry.
  Future<RpcTestResult> testRpc(String url) async {
    final data = await _conn.request('Network:testRPC', 'POST', {'URL': url});
    return RpcTestResult.fromJson(data as Map<String, dynamic>);
  }
}
