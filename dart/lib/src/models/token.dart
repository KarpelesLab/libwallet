/// A registered token (ERC-20, SPL, etc.).
class Token {
  final String id;
  final String name;
  final String symbol;
  final String address;
  final int decimals;
  final String type;
  final String network;
  final String? logo;
  final String? memo;
  final DateTime created;
  final DateTime updated;

  const Token({
    required this.id,
    required this.name,
    required this.symbol,
    required this.address,
    required this.decimals,
    required this.type,
    required this.network,
    this.logo,
    this.memo,
    required this.created,
    required this.updated,
  });

  factory Token.fromJson(Map<String, dynamic> json) {
    return Token(
      id: json['Id'] as String,
      name: json['Name'] as String? ?? '',
      symbol: json['Symbol'] as String? ?? '',
      address: json['Address'] as String? ?? '',
      decimals: json['Decimals'] as int? ?? 0,
      type: json['Type'] as String? ?? '',
      network: json['Network'] as String? ?? '',
      logo: json['Logo'] as String?,
      memo: json['Memo'] as String?,
      created: DateTime.parse(json['Created'] as String),
      updated: DateTime.parse(json['Updated'] as String),
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Name': name,
        'Symbol': symbol,
        'Address': address,
        'Decimals': decimals,
        'Type': type,
        'Network': network,
        if (logo != null) 'Logo': logo,
        if (memo != null) 'Memo': memo,
        'Created': created.toIso8601String(),
        'Updated': updated.toIso8601String(),
      };
}

/// Result of Token:discoverToken.
class DiscoveredToken {
  final String name;
  final String symbol;
  final int decimals;
  final String? totalSupply;
  final String address;
  final String type;

  const DiscoveredToken({
    required this.name,
    required this.symbol,
    required this.decimals,
    this.totalSupply,
    required this.address,
    required this.type,
  });

  factory DiscoveredToken.fromJson(Map<String, dynamic> json) {
    return DiscoveredToken(
      name: json['name'] as String? ?? '',
      symbol: json['symbol'] as String? ?? '',
      decimals: json['decimals'] as int? ?? 0,
      totalSupply: json['total_supply'] as String?,
      address: json['address'] as String? ?? '',
      type: json['type'] as String? ?? '',
    );
  }
}
