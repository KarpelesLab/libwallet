import '../client/transport.dart';
import '../models/crash.dart';

/// Crash event listing and management.
class CrashApi {
  final Transport _conn;

  CrashApi(this._conn);

  /// List all crash events.
  Future<List<Crash>> list() async {
    final data = await _conn.request('Crash', 'GET');
    if (data == null) return [];
    return (data as List)
        .map((e) => Crash.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a crash event by ID.
  Future<Crash> get(String id) async {
    final data = await _conn.request('Crash/$id', 'GET');
    return Crash.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a crash event.
  Future<void> delete(String id) async {
    await _conn.request('Crash/$id', 'DELETE');
  }
}
