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

  /// Fire a test request event (emits a synthetic pending request for
  /// debugging/UI testing). Returns the synthetic request.
  Future<PendingRequest> test() async {
    final data = await _conn.request('Request:test', 'GET');
    return PendingRequest.fromJson(data as Map<String, dynamic>);
  }

  /// Approve a request. For `connect` type, pass the account IDs to expose.
  /// Returns the request with its populated result field.
  Future<PendingRequest> approve(String id, {List<String>? accounts}) async {
    final params = <String, dynamic>{};
    if (accounts != null) params['Accounts'] = accounts;
    final data = await _conn.request(
        'Request/$id:approve', 'POST', params.isNotEmpty ? params : null);
    return PendingRequest.fromJson(data as Map<String, dynamic>);
  }

  /// Reject a request. Returns the request with status `rejected`.
  Future<PendingRequest> reject(String id) async {
    final data = await _conn.request('Request/$id:reject', 'POST');
    return PendingRequest.fromJson(data as Map<String, dynamic>);
  }
}
