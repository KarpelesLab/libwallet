import '../client/transport.dart';

/// RemoteKey management for 2FA recovery keys.
///
/// Supports both phone numbers (SMS verification) and email addresses
/// (email verification). The Crypto/WalletSign backend routes based on
/// whether the identifier contains an `@`.
class RemoteKeyApi {
  final Transport _conn;

  RemoteKeyApi(this._conn);

  /// Start a new remote key setup. Returns a session ID.
  ///
  /// Pass either [number] (phone, international format like `+14045551234`)
  /// or [email] (e.g. `alice@example.com`). Exactly one must be provided.
  ///
  /// A verification code will be sent via SMS or email respectively; complete
  /// setup by calling [validate] with the code.
  Future<dynamic> create({String? number, String? email}) async {
    final target = number ?? email;
    if (target == null || target.isEmpty) {
      throw ArgumentError('RemoteKey.create requires either number or email');
    }
    return await _conn.request('RemoteKey:new', 'POST', {
      'number': target,
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

  /// Validate an SMS or email verification code to complete remote key setup.
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
