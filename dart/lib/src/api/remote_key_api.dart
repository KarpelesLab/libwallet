import '../client/transport.dart';

/// RemoteKey management for phone-based 2FA recovery keys.
class RemoteKeyApi {
  final Transport _conn;

  RemoteKeyApi(this._conn);

  /// Start a new remote key setup. Returns a session ID.
  Future<dynamic> create({required String number}) async {
    return await _conn.request('RemoteKey:new', 'POST', {
      'number': number,
    });
  }

  /// Start a key reshare for an existing remote key. Returns a session ID.
  Future<dynamic> reshare({
    required String key,
    required String curve,
  }) async {
    return await _conn.request('RemoteKey:reshare', 'POST', {
      'key': key,
      'curve': curve,
    });
  }

  /// Validate an SMS code to complete remote key setup.
  Future<dynamic> validate({
    required String session,
    required String code,
  }) async {
    return await _conn.request('RemoteKey:validate', 'POST', {
      'session': session,
      'code': code,
    });
  }
}
