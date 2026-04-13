/// A non-fungible token.
class Nft {
  final String id;
  final String key;
  final String contractAddress;
  final String contractName;
  final String tokenId;
  final String name;
  final String description;
  final String? image;
  final String? imageUrl;
  final String? animationUrl;
  final String? externalUrl;
  final String? youtubeUrl;
  final String? backgroundColor;
  final String? decimals;
  final List<NftAttribute> attributes;
  final String network;
  final DateTime created;
  final DateTime updated;

  const Nft({
    required this.id,
    required this.key,
    required this.contractAddress,
    required this.contractName,
    required this.tokenId,
    required this.name,
    required this.description,
    this.image,
    this.imageUrl,
    this.animationUrl,
    this.externalUrl,
    this.youtubeUrl,
    this.backgroundColor,
    this.decimals,
    required this.attributes,
    required this.network,
    required this.created,
    required this.updated,
  });

  factory Nft.fromJson(Map<String, dynamic> json) {
    return Nft(
      id: json['Id'] as String? ?? '',
      key: json['Key'] as String? ?? '',
      contractAddress: json['ContractAddress'] as String? ?? '',
      contractName: json['ContractName'] as String? ?? '',
      tokenId: json['TokenId'] as String? ?? '',
      name: json['Name'] as String? ?? '',
      description: json['Description'] as String? ?? '',
      image: json['Image'] as String?,
      imageUrl: json['ImageUrl'] as String?,
      animationUrl: json['AnimationUrl'] as String?,
      externalUrl: json['ExternalUrl'] as String?,
      youtubeUrl: json['YoutubeUrl'] as String?,
      backgroundColor: json['BackgroundColor'] as String?,
      decimals: json['Decimals'] as String?,
      attributes: (json['Attributes'] as List?)
              ?.map((a) => NftAttribute.fromJson(a as Map<String, dynamic>))
              .toList() ??
          [],
      network: json['Network'] as String? ?? '',
      created: DateTime.parse(
          json['Created'] as String? ?? DateTime.now().toIso8601String()),
      updated: DateTime.parse(
          json['Updated'] as String? ?? DateTime.now().toIso8601String()),
    );
  }
}

/// An NFT metadata attribute.
class NftAttribute {
  final String traitType;
  final String? displayType;
  final dynamic value;

  const NftAttribute({
    required this.traitType,
    this.displayType,
    this.value,
  });

  factory NftAttribute.fromJson(Map<String, dynamic> json) {
    return NftAttribute(
      traitType: json['TraitType'] as String? ?? json['trait_type'] as String? ?? '',
      displayType: json['DisplayType'] as String? ?? json['display_type'] as String?,
      value: json['Value'] ?? json['value'],
    );
  }
}
