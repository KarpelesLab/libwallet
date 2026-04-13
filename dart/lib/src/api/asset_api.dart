import '../client/transport.dart';
import '../models/asset.dart';

/// Asset listing and balance queries.
class AssetApi {
  final Transport _conn;

  AssetApi(this._conn);

  /// List all assets. Optionally convert to a fiat currency (USD, EUR, GBP, JPY).
  Future<List<Asset>> list({String? convert}) async {
    final params = <String, dynamic>{};
    if (convert != null) params['_convert'] = convert;
    final data = await _conn.request('Asset', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    // The API may return a List directly or a Map with an embedded list
    if (data is List) {
      return data
          .map((e) => Asset.fromJson(e as Map<String, dynamic>))
          .toList();
    }
    if (data is Map) {
      // Try common wrapper keys
      final list = data['assets'] ?? data['data'] ?? data['result'];
      if (list is List) {
        return list
            .map((e) => Asset.fromJson(e as Map<String, dynamic>))
            .toList();
      }
    }
    return [];
  }
}
