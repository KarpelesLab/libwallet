/// A TSS wallet with distributed key management.
class Wallet {
  final String id;
  final String name;
  final String curve;
  final int threshold;
  final int gen;
  final String pubkey;
  final String chaincode;
  final DateTime created;
  final DateTime modified;
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
  final String id;
  final String wallet;
  final String type;
  final String key;
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
