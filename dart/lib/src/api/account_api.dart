import '../client/transport.dart';
import '../models/account.dart';

/// Account CRUD and management.
class AccountApi {
  final Transport _conn;

  AccountApi(this._conn);

  /// List all accounts. Optionally filter by wallet ID.
  Future<List<Account>> list({String? wallet}) async {
    final params = <String, dynamic>{};
    if (wallet != null) params['Wallet'] = wallet;
    final data = await _conn.request('Account', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    return (data as List)
        .map((e) => Account.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get an account by ID. Use `"@"` for the current account.
  Future<Account> get(String id) async {
    final data = await _conn.request('Account/$id', 'GET');
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Get the current account.
  Future<Account> getCurrent() => get('@');

  /// Create a new account.
  Future<Account> create({
    required String name,
    required String wallet,
    required String type,
    required int index,
  }) async {
    final data = await _conn.request('Account', 'POST', {
      'Name': name,
      'Wallet': wallet,
      'Type': type,
      'Index': index,
    });
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Update an account's name.
  Future<Account> update(String id, {required String name}) async {
    final data = await _conn.request('Account/$id', 'PATCH', {'Name': name});
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Delete an account.
  Future<void> delete(String id) async {
    await _conn.request('Account/$id', 'DELETE');
  }

  /// Set an account as the current account.
  Future<void> setCurrent(String id) async {
    await _conn.request('Account/$id:setCurrent', 'POST');
  }
}
