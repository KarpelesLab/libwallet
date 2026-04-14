/// A blockchain account derived from a wallet.
class Account {
  /// Unique identifier for this account.
  final String id;

  /// ID of the parent wallet this account was derived from.
  final String wallet;

  /// Human-readable account name.
  final String name;

  /// Account index used in key derivation.
  final int index;

  /// Blockchain type: `ethereum`, `bitcoin`, or `solana`.
  final String type;

  /// BIP-44 derivation path (e.g. `m/44'/60'/0'/0/0`).
  final String path;

  /// On-chain address for this account.
  final String address;

  /// URI representation of the address (e.g. `ethereum:0x...`).
  final String uri;

  /// Hex-encoded public key for this account.
  final String pubkey;

  /// Hex-encoded BIP-32 chain code for child key derivation.
  final String chaincode;

  /// Timestamp when the account was created.
  final DateTime created;

  /// Timestamp when the account was last updated.
  final DateTime updated;

  const Account({
    required this.id,
    required this.wallet,
    required this.name,
    required this.index,
    required this.type,
    required this.path,
    required this.address,
    required this.uri,
    required this.pubkey,
    required this.chaincode,
    required this.created,
    required this.updated,
  });

  factory Account.fromJson(Map<String, dynamic> json) {
    return Account(
      id: json['Id'] as String,
      wallet: json['Wallet'] as String? ?? '',
      name: json['Name'] as String? ?? '',
      index: json['Index'] as int? ?? 0,
      type: json['Type'] as String? ?? '',
      path: json['Path'] as String? ?? '',
      address: json['Address'] as String? ?? '',
      uri: json['URI'] as String? ?? '',
      pubkey: json['Pubkey'] as String? ?? '',
      chaincode: json['Chaincode'] as String? ?? '',
      created: DateTime.parse(json['Created'] as String),
      updated: DateTime.parse(json['Updated'] as String),
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Wallet': wallet,
        'Name': name,
        'Index': index,
        'Type': type,
        'Path': path,
        'Address': address,
        'URI': uri,
        'Pubkey': pubkey,
        'Chaincode': chaincode,
        'Created': created.toIso8601String(),
        'Updated': updated.toIso8601String(),
      };

  /// True when this account has no backing wallet (created via
  /// `AccountApi.createView`). View-only accounts can query balance and NFT
  /// holdings but cannot sign transactions or messages.
  bool get isViewOnly => wallet.isEmpty;
}
