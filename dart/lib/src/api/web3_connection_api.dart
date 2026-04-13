import '../client/transport.dart';
import '../models/web3_connection.dart';

/// Web3/Connection management.
class Web3ConnectionApi {
  final Transport _conn;

  Web3ConnectionApi(this._conn);

  /// List all Web3 connections. Optionally filter by host.
  Future<List<Web3Connection>> list({String? host}) async {
    final params = <String, dynamic>{};
    if (host != null) params['Host'] = host;
    final data = await _conn.request(
        'Web3/Connection', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    return (data as List)
        .map((e) => Web3Connection.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a connection by ID.
  Future<Web3Connection> get(String id) async {
    final data = await _conn.request('Web3/Connection/$id', 'GET');
    return Web3Connection.fromJson(data as Map<String, dynamic>);
  }

  /// Create a new Web3 connection.
  Future<Web3Connection> create({
    required String host,
    required String account,
  }) async {
    final data = await _conn.request('Web3/Connection', 'POST', {
      'Host': host,
      'Account': account,
    });
    return Web3Connection.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a Web3 connection.
  Future<void> delete(String id) async {
    await _conn.request('Web3/Connection/$id', 'DELETE');
  }
}
