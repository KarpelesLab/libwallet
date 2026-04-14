import '../client/transport.dart';
import '../models/contact.dart';

/// Contact CRUD.
class ContactApi {
  final Transport _conn;

  ContactApi(this._conn);

  /// List all contacts.
  Future<List<Contact>> list() async {
    final data = await _conn.request('Contact', 'GET');
    if (data == null) return [];
    return (data as List)
        .map((e) => Contact.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a contact by ID.
  Future<Contact> get(String id) async {
    final data = await _conn.request('Contact/$id', 'GET');
    return Contact.fromJson(data as Map<String, dynamic>);
  }

  /// Create a new contact.
  Future<Contact> create({
    required String name,
    required String address,
    required String type,
    String memo = '',
  }) async {
    final data = await _conn.request('Contact', 'POST', {
      'Name': name,
      'Address': address,
      'Type': type,
      'Memo': memo,
    });
    return Contact.fromJson(data as Map<String, dynamic>);
  }

  /// Update a contact. Only non-null fields are sent.
  Future<Contact> update(
    String id, {
    String? name,
    String? address,
    String? type,
    String? memo,
  }) async {
    final fields = <String, dynamic>{};
    if (name != null) fields['Name'] = name;
    if (address != null) fields['Address'] = address;
    if (type != null) fields['Type'] = type;
    if (memo != null) fields['Memo'] = memo;
    final data = await _conn.request('Contact/$id', 'PATCH', fields);
    return Contact.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a contact.
  Future<void> delete(String id) async {
    await _conn.request('Contact/$id', 'DELETE');
  }
}
