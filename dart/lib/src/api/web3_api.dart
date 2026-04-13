import '../client/transport.dart';

/// Web3 JSON-RPC proxy.
class Web3Api {
  final Transport _conn;

  Web3Api(this._conn);

  /// Send a Web3 JSON-RPC request.
  Future<dynamic> request({
    required String url,
    required Map<String, dynamic> query,
  }) async {
    return await _conn.request('Web3:request', 'POST', {
      'url': url,
      'query': query,
    });
  }
}
