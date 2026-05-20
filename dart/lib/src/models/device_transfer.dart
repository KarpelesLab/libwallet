// Models for the Wallet:exportToDevice / Wallet:importFromDevice
// device-transfer flow. See `doc/device_share.md` for the full
// protocol; these classes mirror the Go-side wire shapes verbatim.

/// One open device-transfer session, returned by
/// [WalletApi.exportToDevice]. The host paints [pairingCode] as a
/// QR code on the OLD device's screen; the user scans it on the
/// NEW device which then calls [WalletApi.importFromDevice] with
/// the same string.
class DeviceTransferSession {
  /// Server-issued session id. Pass it to
  /// [WalletApi.exportToDeviceConfirm] /
  /// [WalletApi.exportToDeviceCancel] to drive the confirmation
  /// step from the host UI.
  final String sid;

  /// Opaque pairing code — DO NOT attempt to parse this string.
  /// Render it verbatim into a QR code on the old device. The new
  /// device scans the QR and passes the resulting string to
  /// [WalletApi.importFromDevice].
  ///
  /// The encoding (currently a `tibane://device-transfer?…` URL)
  /// is an internal detail and may change without a wire-format
  /// bump; treating the string as opaque keeps the host code
  /// future-proof.
  final String pairingCode;

  /// Wall-clock deadline after which the session expires and the
  /// pairing code stops working. Default lifetime is 5 minutes,
  /// matching the ClawdWallet pairing flow.
  final DateTime expiresAt;

  const DeviceTransferSession({
    required this.sid,
    required this.pairingCode,
    required this.expiresAt,
  });

  factory DeviceTransferSession.fromJson(Map<String, dynamic> json) =>
      DeviceTransferSession(
        sid: (json['sid'] as String?) ?? '',
        pairingCode: (json['pairingCode'] as String?) ?? '',
        expiresAt: DateTime.parse(json['expiresAt'] as String),
      );

  /// True once `DateTime.now()` is past [expiresAt]. Convenience
  /// for UIs that hide stale QRs without re-querying the backend.
  bool get isExpired => DateTime.now().isAfter(expiresAt);
}

/// One StoreKey-typed share's private key, paired with the
/// WalletKey id that owns it. The host produces this from its
/// platform keystore at confirm time (old device); the host
/// consumes it from [DeviceTransferImportResult.deviceShares] at
/// import time (new device).
///
/// [privateKey] is the same base64url-encoded blob
/// `StoreKey:create` returns in its `private` field. Hosts MUST
/// re-derive the public half from this and verify it against the
/// WalletKey's stored [Key] field before writing to platform
/// storage — a mismatched private key would let the wallet appear
/// to load but produce unverifiable signatures.
class DeviceShareEntry {
  /// WalletKey id this share belongs to (matches `WalletKey.id`).
  final String walletKeyId;

  /// 64-byte StoreKey blob, base64url-encoded (no padding).
  /// Identical shape to `StoreKey:create`'s `private` field.
  final String privateKey;

  const DeviceShareEntry({
    required this.walletKeyId,
    required this.privateKey,
  });

  factory DeviceShareEntry.fromJson(Map<String, dynamic> json) =>
      DeviceShareEntry(
        walletKeyId: (json['wallet_key_id'] as String?) ?? '',
        privateKey: (json['private_key'] as String?) ?? '',
      );

  Map<String, dynamic> toJson() => {
        'wallet_key_id': walletKeyId,
        'private_key': privateKey,
      };
}

/// Result of [WalletApi.importFromDevice] on the NEW device. The
/// wallet has already been written to libwallet's local store by
/// the time the future resolves; [walletId] is the canonical id
/// the host uses to fetch the wallet via [WalletApi.get].
///
/// [deviceShares] carries one entry per StoreKey-typed share on
/// the wallet (currently always exactly one in the 1-of-3
/// committee shape libwallet ships). The host MUST write each
/// entry's [privateKey] to its platform keystore BEFORE the next
/// unlock-against-wallet call; otherwise the host's
/// "Device share not found on this device" guard fires and the
/// import looks like it succeeded but the wallet can't sign.
class DeviceTransferImportResult {
  final String walletId;
  final List<DeviceShareEntry> deviceShares;

  const DeviceTransferImportResult({
    required this.walletId,
    required this.deviceShares,
  });

  factory DeviceTransferImportResult.fromJson(Map<String, dynamic> json) {
    final raw = json['deviceShares'];
    final shares = raw is List
        ? raw
            .whereType<Map>()
            .map((m) => DeviceShareEntry.fromJson(Map<String, dynamic>.from(m)))
            .toList()
        : <DeviceShareEntry>[];
    return DeviceTransferImportResult(
      walletId: (json['walletId'] as String?) ?? '',
      deviceShares: shares,
    );
  }
}
