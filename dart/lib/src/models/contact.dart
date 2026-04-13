/// A saved contact address.
class Contact {
  final String id;
  final String name;
  final String address;
  final String type;
  final List<String> flags;
  final String memo;
  final DateTime created;
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
