import 'account.dart';
import 'network.dart';
import 'nft.dart';

/// Result of `NftApi.list` — NFTs plus the network/account context they
/// belong to (so the caller can render them without re-fetching).
class NftListing {
  /// Network the listing was queried against.
  final Network network;

  /// Account the listing was queried against.
  final Account account;

  /// NFTs owned by [account] on [network]. Empty when the account has
  /// no valid address on the network (e.g. an ed25519 wallet on EVM).
  final List<Nft> nfts;

  const NftListing({
    required this.network,
    required this.account,
    required this.nfts,
  });

  factory NftListing.fromJson(Map<String, dynamic> json) {
    final n = json['network'] ?? json['Network'];
    final a = json['account'] ?? json['Account'];
    final nftList = json['nfts'] ?? json['Nfts'];
    return NftListing(
      network: Network.fromJson(n as Map<String, dynamic>),
      account: Account.fromJson(a as Map<String, dynamic>),
      nfts: (nftList as List?)
              ?.map((e) => Nft.fromJson(e as Map<String, dynamic>))
              .toList() ??
          [],
    );
  }
}
