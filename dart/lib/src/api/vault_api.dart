import '../client/transport.dart';

/// Secrets libwallet keeps for the app, so the app never has to.
///
/// An entry holds a StoreKey, a wallet password, or opaque data. It is
/// sealed either by the device's secure storage (`secure`: Secure Enclave or
/// Keychain on iOS/macOS, Keystore on Android — optionally behind Face ID /
/// Touch ID / fingerprint / passcode), or by a password (`password`: an
/// Argon2id-sealed blob, for hosts without secure storage).
///
/// Use an entry by reference wherever libwallet takes keys —
/// [KeyDescription.vault] / [SigningKey.vault]. Its secret is unsealed
/// inside libwallet at the moment of use and wiped right after; it never
/// crosses into Dart (Dart strings cannot be wiped). The one exception is
/// [export], for entries created with `exportable: true`.
///
/// See `docs/secret-storage.md` for the full guide.
class VaultApi {
  final Transport _conn;

  VaultApi(this._conn);

  /// What this device offers. Check [VaultCapabilities.secure] before
  /// creating `secure` entries; fall back to the `password` backend.
  Future<VaultCapabilities> capabilities() async {
    final data = await _conn.request('Vault:capabilities', 'GET');
    return VaultCapabilities.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Create an entry whose secret is generated inside libwallet — the
  /// preferred way: the secret exists nowhere else.
  ///
  /// - [kind]: `storekey` (to protect wallet shares as a StoreKey —
  ///   pass the entry as a [KeyDescription.vault] recipient at wallet
  ///   creation), `password` (a random password for `Password` shares), or
  ///   `data`.
  /// - [backend]: `secure` (default) or `password`.
  /// - [password]: required for the `password` backend (8+ characters).
  Future<VaultEntry> create({
    String kind = 'storekey',
    String backend = 'secure',
    String label = '',
    VaultPolicy policy = const VaultPolicy(),
    String? password,
  }) async {
    final data = await _conn.request('Vault:create', 'POST', {
      'Kind': kind,
      'Backend': backend,
      'Label': label,
      'Policy': policy.toJson(),
      if (password != null) 'Password': password,
    });
    return VaultEntry.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Move an existing secret into the vault — the one-time migration path
  /// for apps that kept a StoreKey or wallet password themselves (e.g. in
  /// flutter_secure_storage). Delete the app's own copy once this returns.
  ///
  /// [secret] uses the format libwallet used before: a StoreKey as
  /// returned by `StoreKey:create` (base64url), a password as-is, data as
  /// base64url — or set [encoding] (`utf8`, `base64`, `base64url`, `hex`).
  Future<VaultEntry> import({
    required String kind,
    required String secret,
    String? encoding,
    String backend = 'secure',
    String label = '',
    VaultPolicy policy = const VaultPolicy(),
    String? password,
  }) async {
    final data = await _conn.request('Vault:import', 'POST', {
      'Kind': kind,
      'Secret': secret,
      if (encoding != null) 'Encoding': encoding,
      'Backend': backend,
      'Label': label,
      'Policy': policy.toJson(),
      if (password != null) 'Password': password,
    });
    return VaultEntry.fromJson(Map<String, dynamic>.from(data as Map));
  }

  Future<List<VaultEntry>> list() async {
    final data = await _conn.request('Vault', 'GET');
    return (data as List)
        .map((e) => VaultEntry.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  Future<VaultEntry> get(String id) async {
    final data = await _conn.request('Vault/$id', 'GET');
    return VaultEntry.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Delete an entry and destroy its device key. Wallet shares sealed only
  /// to it become unrecoverable — make sure another share or a backup
  /// exists.
  Future<bool> delete(String id) async {
    final data = await _conn.request('Vault/$id', 'DELETE');
    return (data as Map)['Deleted'] == true;
  }

  /// Unseal now (prompting if required) and keep the secret in libwallet's
  /// memory for the entry's `cacheSeconds`, so the next uses don't prompt.
  /// Refused for entries with `cacheSeconds: 0`. Returns the expiry, or
  /// null when it lasts until [lock].
  Future<DateTime?> unlock(String id, {String? password, String? reason}) async {
    final data = await _conn.request('Vault/$id:unlock', 'POST', {
      if (password != null) 'Password': password,
      if (reason != null) 'Reason': reason,
    });
    final exp = (data as Map)['Expires'];
    return exp is num
        ? DateTime.fromMillisecondsSinceEpoch(exp.toInt(), isUtc: true)
        : null;
  }

  /// Wipe cached secrets: one entry, or all of them. libwallet also does
  /// this when `lifecycle.update` reports the app left the foreground.
  Future<void> lock([String? id]) async {
    await _conn.request('Vault:lock', 'POST', {if (id != null) 'Id': id});
  }

  Future<bool> isUnlocked(String id) async {
    final data = await _conn.request('Vault/$id:status', 'GET');
    return (data as Map)['Unlocked'] == true;
  }

  /// Hand the secret to Dart. Only for entries created with
  /// `exportable: true`; gate it behind an explicit user action.
  Future<String> export(String id, {String? password, String? reason}) async {
    final data = await _conn.request('Vault/$id:export', 'POST', {
      if (password != null) 'Password': password,
      if (reason != null) 'Reason': reason,
    });
    return (data as Map)['Secret'] as String;
  }

  /// A password entry's portable sealed blob, for hosts that persist
  /// storage themselves (a browser extension). Only libwallet, given the
  /// password, can open it.
  Future<String> blob(String id) async {
    final data = await _conn.request('Vault/$id:blob', 'GET');
    return (data as Map)['Blob'] as String;
  }

  /// Register a blob from [blob] (e.g. after a restart). No password needed
  /// until the entry is used or unlocked.
  Future<VaultEntry> load(String blob) async {
    final data = await _conn.request('Vault:load', 'POST', {'Blob': blob});
    return VaultEntry.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Re-seal a password entry under [newPassword]. Store the new [blob]
  /// afterwards if the host persists blobs itself.
  Future<VaultEntry> changePassword(
      String id, String password, String newPassword) async {
    final data = await _conn.request('Vault/$id:changePassword', 'POST', {
      'Password': password,
      'NewPassword': newPassword,
    });
    return VaultEntry.fromJson(Map<String, dynamic>.from(data as Map));
  }
}

/// How an entry may be used. Fixed at creation (it is sealed with the
/// entry).
class VaultPolicy {
  /// Require Face ID / Touch ID / fingerprint / passcode for each unseal
  /// (`secure` backend; enforced by the OS).
  final bool userPresence;

  /// Keep an unsealed secret in libwallet's memory for reuse: 0 = unseal on
  /// every use (default), N = N seconds, -1 = until [VaultApi.lock] or the
  /// app is backgrounded.
  final int cacheSeconds;

  /// Allow [VaultApi.export]. Off by default.
  final bool exportable;

  const VaultPolicy(
      {this.userPresence = true, this.cacheSeconds = 0, this.exportable = false});

  factory VaultPolicy.fromJson(Map<String, dynamic> j) => VaultPolicy(
        userPresence: j['UserPresence'] as bool? ?? true,
        cacheSeconds: (j['CacheSeconds'] as num?)?.toInt() ?? 0,
        exportable: j['Exportable'] as bool? ?? false,
      );

  Map<String, dynamic> toJson() => {
        'UserPresence': userPresence,
        'CacheSeconds': cacheSeconds,
        'Exportable': exportable,
      };
}

class VaultEntry {
  final String id;
  final String label;

  /// `storekey`, `password` or `data`.
  final String kind;

  /// `secure` or `password`.
  final String backend;

  /// `apple-se`, `apple-keychain`, `android-keystore`, `argon2id`, …
  final String provider;

  /// StoreKey entries: the public key wallet shares are sealed to.
  final String? publicKey;
  final VaultPolicy policy;
  final DateTime? created;

  /// `create` / `import` of a password entry: its portable blob.
  final String? blob;

  const VaultEntry({
    required this.id,
    required this.label,
    required this.kind,
    required this.backend,
    required this.provider,
    required this.policy,
    this.publicKey,
    this.created,
    this.blob,
  });

  factory VaultEntry.fromJson(Map<String, dynamic> j) => VaultEntry(
        id: j['Id'] as String,
        label: j['Label'] as String? ?? '',
        kind: j['Kind'] as String,
        backend: j['Backend'] as String,
        provider: j['Provider'] as String? ?? '',
        publicKey: j['Public'] as String?,
        policy: VaultPolicy.fromJson(
            Map<String, dynamic>.from(j['Policy'] as Map? ?? const {})),
        created: DateTime.tryParse(j['Created'] as String? ?? ''),
        blob: j['Blob'] as String?,
      );
}

class VaultCapabilities {
  /// `secure` entries can be created on this device.
  final bool secure;

  /// Keys live in dedicated hardware (Secure Enclave, StrongBox/TEE).
  final bool hardware;

  /// `faceID`, `touchID`, `opticID`, `biometric`, `passcode` or `none`.
  final String biometry;
  final String provider;

  /// Why [secure] is false, when it is.
  final String? reason;

  const VaultCapabilities({
    required this.secure,
    required this.hardware,
    required this.biometry,
    required this.provider,
    this.reason,
  });

  factory VaultCapabilities.fromJson(Map<String, dynamic> j) =>
      VaultCapabilities(
        secure: j['Secure'] as bool? ?? false,
        hardware: j['Hardware'] as bool? ?? false,
        biometry: j['Biometry'] as String? ?? 'none',
        provider: j['Provider'] as String? ?? '',
        reason: j['Reason'] as String?,
      );
}
