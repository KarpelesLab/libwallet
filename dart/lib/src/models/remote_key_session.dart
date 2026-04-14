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
  /// Identifier of the newly-created (or resharded) remote key. Pass this
  /// into `KeyDescription.remoteKey(...)` when calling wallet operations.
  final String remoteKey;

  const RemoteKeyValidation({required this.remoteKey});

  factory RemoteKeyValidation.fromJson(Map<String, dynamic> json) =>
      RemoteKeyValidation(remoteKey: json['RemoteKey'] as String);
}
