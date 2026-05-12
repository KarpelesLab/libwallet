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

  /// Tagged release the loaded native binary was built from
  /// (e.g. `"0.3.30"`). Empty string when the binary was built from a
  /// non-tagged commit (local dev / master CI mid-merge).
  ///
  /// Use [LibwalletClient]'s startup mismatch check to detect when this
  /// disagrees with the Dart package version — the symptom you'd see is
  /// post-upgrade events arriving in the previous release's wire shape.
  Future<String> version() async {
    final data = await _conn.request('Info:version', 'GET');
    if (data is String) return data;
    if (data is Map) return (data['version'] as String?) ?? '';
    return '';
  }

  /// Full version metadata (release version + commit SHA + commit
  /// timestamp). Useful for support diagnostics; most apps just want
  /// [version].
  Future<VersionInfo> versionInfo() async {
    final data = await _conn.request('Info:version', 'GET');
    if (data is Map) {
      final m = Map<String, dynamic>.from(data);
      return VersionInfo(
        version: (m['version'] as String?) ?? '',
        gitTag: (m['gitTag'] as String?) ?? '',
        dateTag: (m['dateTag'] as String?) ?? '',
      );
    }
    return const VersionInfo(version: '', gitTag: '', dateTag: '');
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
  /// - [logLevel] controls libwallet's leveled logging. Valid values:
  ///   `"debug"`, `"info"`, `"warn"`, `"error"`, `"off"`. Empty
  ///   resolves to libwallet's auto-default (`"debug"` on dev
  ///   binaries, `"info"` on release binaries). A common pattern is
  ///   `logLevel: kDebugMode ? "debug" : "off"`.
  ///
  /// Pass empty strings to clear.
  Future<WalletInfo> setWalletInfo({
    required String clientId,
    String name = '',
    String version = '',
    String logLevel = '',
  }) async {
    final data = await _conn.request('Info:setWalletInfo', 'POST', {
      'ClientId': clientId,
      'Name': name,
      'Version': version,
      'LogLevel': logLevel,
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

  /// Requested log level. Empty means "auto" (debug on dev binaries,
  /// info on release binaries).
  final String logLevel;

  /// The log level libwallet is actually using, after resolving
  /// [logLevel] against the auto-default. Echoed by the Go side on
  /// every `setWalletInfo` / `getWalletInfo` so the host doesn't have
  /// to recompute the mapping.
  final String effectiveLogLevel;

  const WalletInfo({
    this.clientId = '',
    this.name = '',
    this.version = '',
    this.logLevel = '',
    this.effectiveLogLevel = '',
  });

  factory WalletInfo.fromJson(Map<String, dynamic> json) => WalletInfo(
        clientId: (json['clientId'] as String?) ?? '',
        name: (json['name'] as String?) ?? '',
        version: (json['version'] as String?) ?? '',
        logLevel: (json['logLevel'] as String?) ?? '',
        effectiveLogLevel: (json['effectiveLogLevel'] as String?) ?? '',
      );
}

/// Full version metadata returned by [InfoApi.versionInfo].
class VersionInfo {
  /// Tagged release (e.g. `"0.3.30"`). Empty for non-tagged builds.
  final String version;

  /// Short git SHA the binary was built from (e.g. `"a1b2c3d"`).
  final String gitTag;

  /// UTC commit timestamp of [gitTag], formatted YYYYMMDDhhmmss.
  final String dateTag;

  const VersionInfo({
    required this.version,
    required this.gitTag,
    required this.dateTag,
  });

  @override
  String toString() => version.isNotEmpty
      ? 'libwallet $version ($gitTag, $dateTag)'
      : 'libwallet dev ($gitTag, $dateTag)';
}
