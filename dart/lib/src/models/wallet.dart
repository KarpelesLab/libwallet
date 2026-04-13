/// A TSS wallet with distributed key management.
class Wallet {
  /// Unique identifier for this wallet.
  final String id;

  /// Human-readable wallet name.
  final String name;

  /// Elliptic curve used by this wallet (`secp256k1` or `ed25519`).
  final String curve;

  /// Minimum number of key shares required to sign a transaction.
  final int threshold;

  /// Key generation number, incremented on each key rotation.
  final int gen;

  /// Hex-encoded master public key of the wallet.
  final String pubkey;

  /// Hex-encoded BIP-32 chain code for key derivation.
  final String chaincode;

  /// Timestamp when the wallet was created.
  final DateTime created;

  /// Timestamp when the wallet was last modified.
  final DateTime modified;

  /// Key shares that belong to this wallet.
  final List<WalletKey> keys;

  const Wallet({
    required this.id,
    required this.name,
    required this.curve,
    required this.threshold,
    required this.gen,
    required this.pubkey,
    required this.chaincode,
    required this.created,
    required this.modified,
    required this.keys,
  });

  factory Wallet.fromJson(Map<String, dynamic> json) {
    return Wallet(
      id: json['Id'] as String,
      name: json['Name'] as String? ?? '',
      curve: json['Curve'] as String? ?? 'secp256k1',
      threshold: json['Threshold'] as int? ?? 0,
      gen: json['Gen'] as int? ?? 0,
      pubkey: json['Pubkey'] as String? ?? '',
      chaincode: json['Chaincode'] as String? ?? '',
      created: DateTime.parse(json['Created'] as String),
      modified: DateTime.parse(json['Modified'] as String),
      keys: (json['Keys'] as List?)
              ?.map((k) => WalletKey.fromJson(k as Map<String, dynamic>))
              .toList() ??
          [],
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Name': name,
        'Curve': curve,
        'Threshold': threshold,
        'Gen': gen,
        'Pubkey': pubkey,
        'Chaincode': chaincode,
        'Created': created.toIso8601String(),
        'Modified': modified.toIso8601String(),
        'Keys': keys.map((k) => k.toJson()).toList(),
      };

  bool get isUnsafe => keys.every((k) => k.isPassword);
}

/// An individual key share in a TSS wallet.
class WalletKey {
  /// Unique identifier for this key share.
  final String id;

  /// ID of the parent wallet this key belongs to.
  final String wallet;

  /// Key type: `StoreKey`, `RemoteKey`, `Password`, or `Plain`.
  final String type;

  /// Key material (encrypted or plaintext depending on [type]).
  final String key;

  /// Generation number this key share was created in.
  final int gen;

  const WalletKey({
    required this.id,
    required this.wallet,
    required this.type,
    required this.key,
    required this.gen,
  });

  factory WalletKey.fromJson(Map<String, dynamic> json) {
    return WalletKey(
      id: json['Id'] as String,
      wallet: json['Wallet'] as String? ?? '',
      type: json['Type'] as String,
      key: json['Key'] as String? ?? '',
      gen: json['Gen'] as int? ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Wallet': wallet,
        'Type': type,
        'Key': key,
        'Gen': gen,
      };

  bool get isPassword => type == 'Password';
  bool get isStoreKey => type == 'StoreKey';
  bool get isRemoteKey => type == 'RemoteKey';
}
