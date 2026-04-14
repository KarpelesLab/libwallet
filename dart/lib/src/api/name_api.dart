import '../client/transport.dart';
import '../models/name_resolution.dart';

/// ENS (`.eth`) and SNS (`.sol`) name resolution.
class NameApi {
  final Transport _conn;

  NameApi(this._conn);

  /// Resolve an ENS or SNS name to an on-chain address.
  ///
  /// Names ending in `.eth` are resolved via ENS on Ethereum mainnet.
  /// Names ending in `.sol` are resolved via SNS on Solana mainnet.
  Future<NameResolution> resolve(String name) async {
    final data = await _conn.request('Names:resolve', 'POST', {'Name': name});
    return NameResolution.fromJson(data as Map<String, dynamic>);
  }
}
