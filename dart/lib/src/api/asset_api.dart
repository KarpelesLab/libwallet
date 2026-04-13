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
    return (data as List)
        .map((e) => Asset.fromJson(e as Map<String, dynamic>))
        .toList();
  }
}
