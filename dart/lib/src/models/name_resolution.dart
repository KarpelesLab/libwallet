/// Result of resolving an ENS or SNS name to a blockchain address.
class NameResolution {
  /// The original name that was resolved (e.g. `vitalik.eth`).
  final String name;

  /// The resolved on-chain address.
  final String address;

  /// The network family: `ethereum` (ENS) or `solana` (SNS).
  final String network;

  const NameResolution({
    required this.name,
    required this.address,
    required this.network,
  });

  factory NameResolution.fromJson(Map<String, dynamic> json) {
    return NameResolution(
      name: json['name'] as String,
      address: json['address'] as String,
      network: json['network'] as String,
    );
  }
}
