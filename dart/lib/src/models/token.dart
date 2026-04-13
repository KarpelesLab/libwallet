/// A registered token (ERC-20, SPL, etc.).
class Token {
  /// Unique identifier for this token.
  final String id;

  /// Human-readable token name (e.g. `"USD Coin"`).
  final String name;

  /// Ticker symbol (e.g. `USDC`).
  final String symbol;

  /// Contract address (ERC-20) or mint address (SPL token).
  final String address;

  /// Number of decimal places for this token.
  final int decimals;

  /// Token standard: `erc20`, `spl-token`, etc.
  final String type;

  /// Network ID this token is deployed on.
  final String network;

  /// URL to the token logo image.
  final String? logo;

  /// Optional memo or tag required for transfers.
  final String? memo;

  /// Timestamp when the token was registered.
  final DateTime created;

  /// Timestamp when the token was last updated.
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
  /// Token name read from the on-chain contract.
  final String name;

  /// Ticker symbol read from the on-chain contract.
  final String symbol;

  /// Number of decimal places for this token.
  final int decimals;

  /// Total supply as a decimal string, if available.
  final String? totalSupply;

  /// Contract or mint address of the discovered token.
  final String address;

  /// Token standard: `erc20`, `spl-token`, etc.
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
