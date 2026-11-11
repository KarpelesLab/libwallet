/// Result of `AccountApi.signMessage`.
class SignedMessage {
  /// Encoded signature. Format depends on the signing mode:
  /// - `solana` → base58
  /// - `evm`/`personal_sign` → 0x-prefixed hex
  /// - `raw` → base64
  final String signature;

  /// Base58-encoded public key of the signer (Solana mode only; null for EVM).
  final String? publicKey;

  /// The bytes the signature is over (base64), when they are not the message
  /// itself: a Ledger signs a Solana message wrapped as an off-chain message.
  final String? signedMessage;

  const SignedMessage(
      {required this.signature, this.publicKey, this.signedMessage});

  factory SignedMessage.fromJson(Map<String, dynamic> json) => SignedMessage(
        signature: json['signature'] as String,
        publicKey: json['publicKey'] as String?,
        signedMessage: json['signedMessage'] as String?,
      );
}
