/// A saved contact address.
class Contact {
  /// Unique identifier for this contact.
  final String id;

  /// Display name of the contact.
  final String name;

  /// Blockchain address of the contact.
  final String address;

  /// Address type: `ethereum`, `bitcoin`, or `solana`.
  final String type;

  /// Contact flags (e.g. `verified`, `favorite`).
  final List<String> flags;

  /// Optional note or memo for this contact.
  final String memo;

  /// Timestamp when the contact was created.
  final DateTime created;

  /// Timestamp when the contact was last updated.
  final DateTime updated;

  const Contact({
    required this.id,
    required this.name,
    required this.address,
    required this.type,
    required this.flags,
    required this.memo,
    required this.created,
    required this.updated,
  });

  factory Contact.fromJson(Map<String, dynamic> json) {
    return Contact(
      id: json['Id'] as String,
      name: json['Name'] as String? ?? '',
      address: json['Address'] as String? ?? '',
      type: json['Type'] as String? ?? '',
      flags: (json['Flags'] as List?)?.cast<String>() ?? [],
      memo: json['Memo'] as String? ?? '',
      created: DateTime.parse(json['Created'] as String),
      updated: DateTime.parse(json['Updated'] as String),
    );
  }

  Map<String, dynamic> toJson() => {
        'Id': id,
        'Name': name,
        'Address': address,
        'Type': type,
        'Flags': flags,
        'Memo': memo,
        'Created': created.toIso8601String(),
        'Updated': updated.toIso8601String(),
      };
}
