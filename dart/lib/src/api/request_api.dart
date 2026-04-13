import '../client/transport.dart';
import '../models/request_event.dart';

/// Request approval/rejection for Web3 interactions.
class RequestApi {
  final Transport _conn;

  RequestApi(this._conn);

  /// Get a pending request by ID.
  Future<PendingRequest> get(String id) async {
    final data = await _conn.request('Request/$id', 'GET');
    return PendingRequest.fromJson(data as Map<String, dynamic>);
  }

  /// Fire a test request event.
  Future<dynamic> test() => _conn.request('Request:test', 'GET');

  /// Approve a request. For "connect" type, pass account IDs.
  Future<dynamic> approve(String id, {List<String>? accounts}) async {
    final params = <String, dynamic>{};
    if (accounts != null) params['Accounts'] = accounts;
    return await _conn.request(
        'Request/$id:approve', 'POST', params.isNotEmpty ? params : null);
  }

  /// Reject a request.
  Future<dynamic> reject(String id) async {
    return await _conn.request('Request/$id:reject', 'POST');
  }
}
