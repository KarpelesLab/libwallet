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
  /// descriptor (SMS/email code sent to the user); complete the
  /// reshare by calling [validate] with the code the user entered.
  ///
  /// **CRITICAL**: [key] is the value of `WalletKey.key` on the
  /// RemoteKey-typed share — the `crws-…:crwsv-…` server resource
  /// identifier — **NOT** `WalletKey.id` (the `wkey-…` wallet share
  /// uuid). The server rejects `wkey-…` with `[rest] error from
  /// server: Invalid key` because it only understands resource ids;
  /// the share uuid is purely a libwallet-local identifier.
  ///
  /// The act of calling this endpoint transitions the *old* session
  /// to `done` on the server and mints a fresh session. The new
  /// session's identifier is returned by [validate] as
  /// `RemoteKeyValidation.remoteKey`; see that field's docstring
  /// for how to thread it into `Wallet:reshare`.
  ///
  /// As of 0.4.41 this no longer takes a `curve` argument — the
  /// server records the remote key's curve at issue time so the
  /// caller doesn't need to (and shouldn't) pass it back in.
  /// Previously a host-side defaulted `wallet.curve` could mis-route
  /// the reshare into the wrong ceremony.
  Future<RemoteKeySession> reshare({required String key}) async {
    final data = await _conn.request('RemoteKey:reshare', 'POST', {
      'key': key,
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
