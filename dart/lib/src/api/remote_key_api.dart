import '../client/transport.dart';
import '../models/remote_key_session.dart';

/// RemoteKey management for 2FA recovery keys.
///
/// Supports both phone numbers (SMS verification) and email addresses
/// (email verification). The Crypto/WalletSign backend routes based on
/// whether the identifier contains an `@`.
class RemoteKeyApi {
  final Transport _conn;

  RemoteKeyApi(this._conn);

  /// Start a new remote key setup. Returns a session descriptor.
  ///
  /// Pass either [number] (phone, international format like `+14045551234`)
  /// or [email] (e.g. `alice@example.com`). Exactly one must be provided.
  ///
  /// A verification code will be sent via SMS or email respectively; complete
  /// setup by calling [validate] with the code.
  Future<RemoteKeySession> create({String? number, String? email}) async {
    final target = number ?? email;
    if (target == null || target.isEmpty) {
      throw ArgumentError('RemoteKey.create requires either number or email');
    }
    final data = await _conn.request('RemoteKey:new', 'POST', {
      'number': target,
    });
    return RemoteKeySession.fromJson(data as Map<String, dynamic>);
  }

  /// Start a key reshare for an existing remote key. Returns a session
  /// descriptor; complete the reshare by calling [validate].
  Future<RemoteKeySession> reshare({
    required String key,
    required String curve,
  }) async {
    final data = await _conn.request('RemoteKey:reshare', 'POST', {
      'key': key,
      'curve': curve,
    });
    return RemoteKeySession.fromJson(data as Map<String, dynamic>);
  }

  /// Validate an SMS or email verification code to complete remote key setup
  /// or reshare. Returns the newly-created (or resharded) remote key
  /// identifier.
  Future<RemoteKeyValidation> validate({
    required String session,
    required String code,
  }) async {
    final data = await _conn.request('RemoteKey:validate', 'POST', {
      'session': session,
      'code': code,
    });
    return RemoteKeyValidation.fromJson(data as Map<String, dynamic>);
  }
}
