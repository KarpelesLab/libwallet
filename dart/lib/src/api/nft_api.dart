import '../client/transport.dart';
import '../models/nft.dart';

/// NFT listing and fetching.
class NftApi {
  final Transport _conn;

  NftApi(this._conn);

  /// List NFTs for the current or specified account/network.
  Future<Map<String, dynamic>> list({
    String? network,
    String? account,
  }) async {
    final params = <String, dynamic>{};
    if (network != null) params['Network'] = network;
    if (account != null) params['Account'] = account;
    final data = await _conn.request('Nft', 'GET', params.isNotEmpty ? params : null);
    return data as Map<String, dynamic>;
  }

  /// Get a specific NFT by ID.
  Future<Nft> get(String id) async {
    final data = await _conn.request('Nft/$id', 'GET');
    return Nft.fromJson(data as Map<String, dynamic>);
  }
}
