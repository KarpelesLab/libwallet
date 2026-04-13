import '../client/transport.dart';
import '../models/network.dart';

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

  /// Update a network.
  Future<Network> update(String id, Map<String, dynamic> fields) async {
    final data = await _conn.request('Network/$id', 'PATCH', fields);
    return Network.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a network.
  Future<void> delete(String id) async {
    await _conn.request('Network/$id', 'DELETE');
  }

  /// Test an RPC URL.
  Future<dynamic> testRpc(String url) async {
    return await _conn.request('Network:testRPC', 'POST', {'URL': url});
  }
}
