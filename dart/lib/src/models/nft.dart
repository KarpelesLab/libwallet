/// A non-fungible token.
class Nft {
  /// Unique identifier for this NFT record.
  final String id;

  /// Composite key (contract + token ID) for deduplication.
  final String key;

  /// Address of the NFT contract.
  final String contractAddress;

  /// Name of the NFT collection/contract.
  final String contractName;

  /// Token ID within the contract.
  final String tokenId;

  /// Name of this individual NFT.
  final String name;

  /// Human-readable description from the NFT metadata.
  final String description;

  /// Primary image data or URI from the metadata.
  final String? image;

  /// Resolved HTTP URL for the NFT image.
  final String? imageUrl;

  /// URL to an animation or video asset.
  final String? animationUrl;

  /// External link from the NFT metadata.
  final String? externalUrl;

  /// YouTube video URL from the NFT metadata.
  final String? youtubeUrl;

  /// CSS-compatible background color (hex without `#`).
  final String? backgroundColor;

  /// Decimal places for semi-fungible tokens (ERC-1155).
  final String? decimals;

  /// Metadata attributes (trait type / value pairs).
  final List<NftAttribute> attributes;

  /// Network ID this NFT exists on.
  final String network;

  /// Timestamp when the NFT was first indexed.
  final DateTime created;

  /// Timestamp when the NFT metadata was last refreshed.
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
  /// Attribute name (e.g. `"Background"`, `"Rarity"`).
  final String traitType;

  /// Optional display hint (e.g. `"number"`, `"date"`).
  final String? displayType;

  /// Attribute value (string, number, or other JSON-compatible type).
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
