/// The secret of a single-key imported wallet, as returned by
/// `WalletApi.exportSecret`. Treat every field as highly sensitive: show it
/// once, never log or persist it.
class WalletSecret {
  /// `'mnemonic'` (wallet imported from a recovery phrase) or `'privateKey'`.
  final String type;

  /// `'secp256k1'` or `'ed25519'`.
  final String curve;

  /// The BIP-39 recovery phrase (type `mnemonic`).
  final String? mnemonic;

  /// The BIP-39 passphrase ("25th word") imported with [mnemonic]; empty if
  /// none was set.
  final String? passphrase;

  /// Wordlist language of [mnemonic].
  final String? language;

  /// The private key (type `privateKey`), encoded per [format].
  final String? privateKey;

  /// Encoding of [privateKey]:
  /// - `'hex'` — secp256k1, `0x`-prefixed 32 bytes (also see [wif]);
  /// - `'keypair'` — ed25519, base58 `seed ‖ pubkey`: the form Phantom /
  ///   Solflare import;
  /// - `'scalar'` — ed25519 raw secret scalar, `0x`-hex. Only libwallet can
  ///   re-import it (`importPrivateKey(curve: 'ed25519')`); other Solana
  ///   wallets cannot. Keys imported before libwallet 0.5.5, or imported as
  ///   a scalar, export this way.
  final String? format;

  /// secp256k1 only: the key as a compressed mainnet WIF.
  final String? wif;

  const WalletSecret({
    required this.type,
    required this.curve,
    this.mnemonic,
    this.passphrase,
    this.language,
    this.privateKey,
    this.format,
    this.wif,
  });

  bool get isMnemonic => type == 'mnemonic';

  factory WalletSecret.fromJson(Map<String, dynamic> json) => WalletSecret(
        type: json['type'] as String,
        curve: json['curve'] as String? ?? '',
        mnemonic: json['mnemonic'] as String?,
        passphrase: json['passphrase'] as String?,
        language: json['language'] as String?,
        privateKey: json['privateKey'] as String?,
        format: json['format'] as String?,
        wif: json['wif'] as String?,
      );
}
