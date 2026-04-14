/// One entry in a wallet backup bundle — a single encrypted wallet file.
class WalletBackupEntry {
  /// Suggested filename (e.g. `wallet_<id>.dat`).
  final String filename;

  /// Base64url-encoded encrypted wallet payload. Pass this back through
  /// `WalletApi.restore` together with the [filename] to restore.
  final String data;

  const WalletBackupEntry({required this.filename, required this.data});

  factory WalletBackupEntry.fromJson(Map<String, dynamic> json) =>
      WalletBackupEntry(
        filename: json['filename'] as String,
        data: json['data'] as String,
      );

  Map<String, String> toJson() => {'filename': filename, 'data': data};
}
