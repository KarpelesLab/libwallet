import '../client/transport.dart';
import '../models/key_description.dart';
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

  /// Approve a request. Returns the request with its populated result field.
  ///
  /// - For `connect` types, pass [accounts] — the IDs the dApp is allowed
  ///   to see.
  /// - For signing types (`personal_sign`, `sign_typed_data`,
  ///   `mpurse_sign_message`, `solana_sign_*`, `sign`), pass [keys] — the
  ///   wallet key shares that unlock the TSS signer (typically the user's
  ///   password + remote key + store key).
  Future<PendingRequest> approve(
    String id, {
    List<String>? accounts,
    List<SigningKey>? keys,
  }) async {
    final params = <String, dynamic>{};
    if (accounts != null) params['Accounts'] = accounts;
    if (keys != null) params['Keys'] = keys.map((k) => k.toJson()).toList();
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
