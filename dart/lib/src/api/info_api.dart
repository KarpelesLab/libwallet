import '../client/transport.dart';
import '../models/onboarding.dart';

/// Info endpoints: ping, version, paths, first_run, onboarding.
class InfoApi {
  final Transport _conn;

  InfoApi(this._conn);

  /// Ping the library to check if it's running. Returns `"pong"`.
  Future<String> ping() async {
    final data = await _conn.request('Info:ping', 'GET');
    return data as String? ?? '';
  }

  /// Get the library version.
  Future<String> version() async {
    final data = await _conn.request('Info:version', 'GET');
    if (data is String) return data;
    if (data is Map) return data['version'] as String? ?? data.toString();
    return data.toString();
  }

  /// Get system paths information.
  Future<Map<String, dynamic>> paths() async {
    final data = await _conn.request('Info:paths', 'GET');
    return data as Map<String, dynamic>;
  }

  /// Get an opaque identifier for the first-run time of this install.
  /// Format is `<type>:<unix>:<nano>:<index>` (Go's wltobj.TimeId).
  /// Returns null if this is the first run and the identifier hasn't
  /// been persisted yet.
  Future<String?> firstRun() async {
    final data = await _conn.request('Info:first_run', 'GET');
    return data as String?;
  }

  /// Get the onboarding state.
  Future<OnboardingState> onboarding() async {
    final data = await _conn.request('Info:onboarding', 'GET');
    return OnboardingState.fromJson(data as Map<String, dynamic>);
  }
}
