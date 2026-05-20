/// Result of `RemoteKeyApi.create` / `RemoteKeyApi.reshare`.
///
/// The user must enter the `length`-digit code (format described in
/// [format]) sent via SMS/email, then pass it to [RemoteKeyApi.validate]
/// together with [session] to complete the flow.
class RemoteKeySession {
  /// Opaque session identifier to pass back to `validate`.
  final String session;

  /// Expected code format (currently always `"all-digits"`).
  final String format;

  /// Expected code length in characters.
  final int length;

  const RemoteKeySession({
    required this.session,
    required this.format,
    required this.length,
  });

  factory RemoteKeySession.fromJson(Map<String, dynamic> json) =>
      RemoteKeySession(
        session: json['session'] as String,
        format: json['format'] as String? ?? 'all-digits',
        length: json['length'] as int? ?? 6,
      );
}

/// Result of `RemoteKeyApi.validate` — the new RemoteKey identifier.
class RemoteKeyValidation {
  /// Identifier of the newly-created (or resharded) remote key —
  /// a `crws-…:crwsv-…` server resource id. Pass this into
  /// `KeyDescription.remoteKey(...)` when calling wallet operations.
  ///
  /// **For reshare flows** (e.g., rotating the 2FA share, or
  /// recovering a wallet on a fresh device after JSON restore):
  /// the original `crwsv-…` session that lived in
  /// `WalletKey.key` is `done` on the server after
  /// [RemoteKeyApi.reshare] runs — it can't be reused. This new
  /// [remoteKey] supersedes it for the upcoming `Wallet:reshare`
  /// ceremony, and **must be passed as the `key` on BOTH the
  /// old-committee AND new-committee RemoteKey
  /// `KeyDescription`s**:
  ///
  /// ```dart
  /// // After RemoteKeyApi.reshare + .validate:
  /// final newKey = validation.remoteKey;
  ///
  /// await client.wallets.reshare(
  ///   walletId: wallet.id,
  ///   old: [
  ///     KeyDescription(id: oldStoreKey.id),                         // local share — id is enough
  ///     KeyDescription(id: oldRemoteKey.id,
  ///                    key: newKey,        // ← NEW id, NOT oldRemoteKey.key
  ///                    type: 'RemoteKey'),
  ///     KeyDescription(id: oldPassword.id, key: oldPasswordPub, type: 'Password'),
  ///   ],
  ///   newKeys: [
  ///     KeyDescription(type: 'StoreKey',  key: newStorePair.publicKey),
  ///     KeyDescription(type: 'RemoteKey', key: newKey),             // ← same NEW id
  ///     KeyDescription(type: 'Password',  key: newPasswordPub),
  ///   ],
  /// );
  /// ```
  ///
  /// Passing the wallet's stored `WalletKey.key` (the old
  /// `crwsv-OLD`) trips
  /// `failed to start remote peer …: failed to init remote:
  /// invalid status for wallet sign session: done` — the server
  /// is correctly refusing to engage on a retired session. The
  /// fix is always "use [remoteKey] from the latest validate
  /// response."
  final String remoteKey;

  const RemoteKeyValidation({required this.remoteKey});

  factory RemoteKeyValidation.fromJson(Map<String, dynamic> json) =>
      RemoteKeyValidation(remoteKey: json['RemoteKey'] as String);
}
