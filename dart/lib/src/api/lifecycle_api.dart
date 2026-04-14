import '../client/transport.dart';

/// Lifecycle management — informs libwallet about the host app's
/// foreground/background/resumed state so long-running TSS operations
/// can pause or resume safely.
class LifecycleApi {
  final Transport _conn;

  LifecycleApi(this._conn);

  /// Report the host's current lifecycle status. Typical values are
  /// `foreground`, `background`, `paused`, `resumed`. Returns the
  /// acknowledged status string.
  Future<String> update(String status) async {
    final data = await _conn.request('Lifecycle:update', 'POST', {
      'status': status,
    });
    return (data as Map<String, dynamic>)['status'] as String? ?? status;
  }
}
