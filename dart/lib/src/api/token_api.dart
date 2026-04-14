import '../client/transport.dart';
import '../models/token.dart';

/// Token CRUD and discovery.
class TokenApi {
  final Transport _conn;

  TokenApi(this._conn);

  /// List all registered tokens. Searchable by Name, Symbol, Address, Type.
  Future<List<Token>> list({String? search}) async {
    final params = <String, dynamic>{};
    if (search != null) params['search'] = search;
    final data = await _conn.request(
        'Token', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    return (data as List)
        .map((e) => Token.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a token by ID.
  Future<Token> get(String id) async {
    final data = await _conn.request('Token/$id', 'GET');
    return Token.fromJson(data as Map<String, dynamic>);
  }

  /// Register a custom token.
  Future<Token> create({
    required String name,
    required String symbol,
    required String address,
    required int decimals,
    required String network,
    String? type,
    String? logo,
    String? memo,
  }) async {
    final data = await _conn.request('Token', 'POST', {
      'Name': name,
      'Symbol': symbol,
      'Address': address,
      'Decimals': decimals,
      'Network': network,
      if (type != null) 'Type': type,
      if (logo != null) 'Logo': logo,
      if (memo != null) 'Memo': memo,
    });
    return Token.fromJson(data as Map<String, dynamic>);
  }

  /// Update a token. Only non-null fields are sent.
  Future<Token> update(
    String id, {
    String? name,
    String? symbol,
    int? decimals,
    String? type,
    String? logo,
    String? memo,
  }) async {
    final fields = <String, dynamic>{};
    if (name != null) fields['Name'] = name;
    if (symbol != null) fields['Symbol'] = symbol;
    if (decimals != null) fields['Decimals'] = decimals;
    if (type != null) fields['Type'] = type;
    if (logo != null) fields['Logo'] = logo;
    if (memo != null) fields['Memo'] = memo;
    final data = await _conn.request('Token/$id', 'PATCH', fields);
    return Token.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a token.
  Future<void> delete(String id) async {
    await _conn.request('Token/$id', 'DELETE');
  }

  /// Auto-detect token metadata from on-chain data.
  Future<DiscoveredToken> discover({
    required String network,
    required String address,
  }) async {
    final data = await _conn.request('Token:discoverToken', 'POST', {
      'Network': network,
      'Address': address,
    });
    return DiscoveredToken.fromJson(data as Map<String, dynamic>);
  }
}
