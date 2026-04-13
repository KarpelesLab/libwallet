import '../client/transport.dart';

/// Lifecycle management.
class LifecycleApi {
  final Transport _conn;

  LifecycleApi(this._conn);

  /// Trigger a lifecycle update.
  Future<dynamic> update() => _conn.request('Lifecycle:update', 'POST');
}
