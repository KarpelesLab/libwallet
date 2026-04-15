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

  /// Register the host wallet's identity block. Call once at startup
  /// (before any `RemoteKey` flow).
  ///
  /// - [clientId] maps to the `Sec-ClientId` HTTP header sent with
  ///   every `Crypto/WalletSign:*` call. The WalletSign backend uses
  ///   it to pick branded SMS / email copy, apply per-app rate
  ///   limits, and tag audit logs. Pre-register the value with your
  ///   WalletSign backend operator.
  /// - [name] / [version] are stored for future use (untrusted
  ///   display strings on approval prompts, diagnostics). Optional.
  ///
  /// Pass empty strings to clear.
  Future<WalletInfo> setWalletInfo({
    required String clientId,
    String name = '',
    String version = '',
  }) async {
    final data = await _conn.request('Info:setWalletInfo', 'POST', {
      'ClientId': clientId,
      'Name': name,
      'Version': version,
    });
    return WalletInfo.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Return the currently registered host-wallet identity block.
  Future<WalletInfo> getWalletInfo() async {
    final data = await _conn.request('Info:getWalletInfo', 'GET');
    return WalletInfo.fromJson(Map<String, dynamic>.from(data as Map));
  }
}

/// Host-wallet identity block sent to libwallet via [InfoApi.setWalletInfo].
class WalletInfo {
  /// Sec-ClientId header value sent with every Crypto/WalletSign:* call.
  final String clientId;

  /// Short human-readable wallet name (e.g. `MyWallet`).
  final String name;

  /// Host app version (e.g. `1.4.2`). Diagnostic only.
  final String version;

  const WalletInfo({
    this.clientId = '',
    this.name = '',
    this.version = '',
  });

  factory WalletInfo.fromJson(Map<String, dynamic> json) => WalletInfo(
        clientId: (json['clientId'] as String?) ?? '',
        name: (json['name'] as String?) ?? '',
        version: (json['version'] as String?) ?? '',
      );
}
