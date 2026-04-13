/// A blockchain account derived from a wallet.
class Account {
  final String id;
  final String wallet;
  final String name;
  final int index;
  final String type;
  final String path;
  final String address;
  final String uri;
  final String pubkey;
  final String chaincode;
  final DateTime created;
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
}
