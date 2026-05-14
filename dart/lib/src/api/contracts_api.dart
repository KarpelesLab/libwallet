import '../client/transport.dart';

/// Curated contract-label registry — known smart contracts (swap
/// routers, marketplaces, lending pools, AMM vaults) baked into
/// libwallet with stable display labels.
///
/// Use [lookup] at any address-render site (signing sheets,
/// transaction-effect rows, watch_asset prompts) to prepend a
/// friendly name above the raw `0x…` when libwallet recognises the
/// contract. Returns `null` for custom contracts and chains the
/// registry hasn't covered yet — host falls back to the raw address
/// in that case.
///
/// EIP-712 typed-data sign requests get the label resolved
/// automatically — see [MessageSignRequest.verifyingContractLabel].
/// This API is for everything else.
class ContractsApi {
  final Transport _conn;
  ContractsApi(this._conn);

  /// Resolve a contract address to its curated label, or null when
  /// the address isn't on the registry for [chainKey].
  ///
  /// - [chainKey] is the canonical `"<type>.<chainId>"` form, matching
  ///   `Network.toString()` / the `network` field on assets. Examples:
  ///   `"evm.1"` (Ethereum mainnet), `"evm.8453"` (Base).
  /// - [address] is case-insensitive — lowercased and EIP-55-cased
  ///   forms both resolve.
  Future<ContractLabel?> lookup({
    required String chainKey,
    required String address,
  }) async {
    final data = await _conn.request('Contracts:lookup', 'POST', {
      'chainKey': chainKey,
      'address': address,
    });
    if (data == null) return null;
    return ContractLabel.fromJson(Map<String, dynamic>.from(data as Map));
  }
}

/// One curated registry entry. Mirrors the Go-side `wltcontract.Entry`.
class ContractLabel {
  /// Canonical `"<type>.<chainId>"` chain key.
  final String chainKey;

  /// Contract address, lowercased.
  final String address;

  /// Display label, e.g. `"Uniswap V3: SwapRouter02"`. Short enough to
  /// fit a typed-data approval sheet header.
  final String label;

  /// Informational category — `"router" | "permit2" | "lending_pool"
  /// | "marketplace" | "amm_vault" | "permit_target"`. Hosts may filter
  /// or icon on this; libwallet doesn't branch on the value.
  final String kind;

  /// Upstream brand grouping (`"uniswap"`, `"aave"`, `"opensea"`, …).
  /// Useful for picking a per-project icon next to [label].
  final String project;

  const ContractLabel({
    required this.chainKey,
    required this.address,
    required this.label,
    this.kind = '',
    this.project = '',
  });

  factory ContractLabel.fromJson(Map<String, dynamic> json) => ContractLabel(
        chainKey: (json['chainKey'] as String?) ?? '',
        address: (json['address'] as String?) ?? '',
        label: (json['label'] as String?) ?? '',
        kind: (json['kind'] as String?) ?? '',
        project: (json['project'] as String?) ?? '',
      );

  @override
  String toString() => label.isNotEmpty ? label : address;
}
