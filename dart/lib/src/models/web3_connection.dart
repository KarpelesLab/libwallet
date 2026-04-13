/// A Web3 site connection to a wallet account.
class Web3Connection {
  final String id;
  final String host;
  final String account;
  final DateTime created;

  const Web3Connection({
    required this.id,
    required this.host,
    required this.account,
    required this.created,
  });

  factory Web3Connection.fromJson(Map<String, dynamic> json) {
    return Web3Connection(
      id: json['Id'] as String,
      host: json['Host'] as String? ?? '',
      account: json['Account'] as String? ?? '',
      created: DateTime.parse(json['Created'] as String),
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Host': host,
        'Account': account,
        'Created': created.toIso8601String(),
      };
}
