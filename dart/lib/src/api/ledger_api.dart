import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../client/transport.dart';
import '../models/account.dart';
import '../models/wallet.dart';
import 'airgap_api.dart' show AirgapKey;

/// Ledger hardware wallets (Nano S / S Plus / X, Stax, Flex).
///
/// A Ledger wallet (`Protocol: ledger`) holds watch-only accounts whose keys
/// were read from the device; signing happens on the device, after the user
/// reviews the transaction on its screen.
///
/// **Reaching the device.** Every call takes the link to use:
///
/// - `hid` — USB, opened by libwallet itself (desktop: macOS, Linux, Windows).
/// - `webhid` — the browser build.
/// - `bridge` — *your app* carries the APDUs. This is the only option on iOS
///   and Android, where the device is reached over Bluetooth (or USB-OTG) with
///   a platform plugin. Install the relay once with [bridge]:
///   ```dart
///   final sub = client.ledger.bridge((apdu) => myBleDevice.exchange(apdu));
///   ```
///
/// With no [LedgerLink] the platform's built-in transport is used where there
/// is one, the bridge elsewhere.
///
/// **Typical flow.** The device runs one app at a time and each app knows one
/// chain, so keys are read app by app into the same wallet:
/// ```dart
/// // user opens the Ethereum app on the device
/// final eth = await client.ledger.getKeys();
/// final w = await client.ledger.importKeys(eth, name: 'My Nano');
/// // user opens the Bitcoin app
/// final btc = await client.ledger.getKeys();
/// await client.ledger.importKeys(btc, wallet: w.wallet.id);
///
/// final tx = await client.ledger.signTransaction(
///     account: w.accounts.first.id,
///     transaction: {'to': '0x…', 'value': '1000000000000000'},
///     broadcast: true);
/// ```
/// libwallet only returns a signature that verifies under the account's key
/// over exactly what was requested; a device holding other keys is refused.

class LedgerApi {
  final Transport _conn;

  LedgerApi(this._conn);

  /// The devices the built-in transport can see, the transports this build
  /// offers, and the default one.
  Future<LedgerDevices> list() async {
    final data = await _conn.request('Ledger:list', 'POST', {});
    return LedgerDevices.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// What the device is running. On the dashboard ([LedgerInfo.dashboard])
  /// the model and firmware version are reported as well.
  Future<LedgerInfo> info({LedgerLink? link}) async {
    final data = await _conn.request('Ledger:info', 'POST', _link(link));
    return LedgerInfo.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Open an installed app by [name] (`Ethereum`, `Bitcoin`, `Solana`) from
  /// the dashboard. The device may ask for confirmation, and over USB it
  /// reconnects when the app starts: wait a moment before the next call.
  Future<void> openApp(String name, {LedgerLink? link}) =>
      _conn.request('Ledger:openApp', 'POST', {..._link(link), 'Name': name});

  /// Close the open app and return to the dashboard (the device reconnects).
  Future<void> quitApp({LedgerLink? link}) =>
      _conn.request('Ledger:quitApp', 'POST', _link(link));

  // ── Device management (the device must be on the dashboard) ──────────────

  /// Model, firmware version and whether a firmware update is available.
  Future<LedgerStatus> status({LedgerLink? link}) async {
    final data = await _conn.request('Ledger:status', 'POST', _link(link));
    return LedgerStatus.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Whether the manufacturer vouches for the device. The device asks the
  /// user to allow the check.
  Future<bool> genuineCheck({LedgerLink? link}) async {
    final data = await _conn.request('Ledger:genuineCheck', 'POST', _link(link));
    return (data as Map)['genuine'] as bool? ?? false;
  }

  /// The installed apps. The device asks the user to allow the listing.
  Future<List<LedgerApp>> installedApps({LedgerLink? link}) async {
    final data = await _conn.request('Ledger:apps', 'POST', _link(link));
    return (data as List)
        .map((a) => LedgerApp.fromJson(Map<String, dynamic>.from(a as Map)))
        .toList();
  }

  /// The apps available for this device and firmware.
  Future<List<LedgerApp>> catalog({LedgerLink? link}) async {
    final data = await _conn.request('Ledger:catalog', 'POST', _link(link));
    return (data as List)
        .map((a) => LedgerApp.fromJson(Map<String, dynamic>.from(a as Map)))
        .toList();
  }

  /// Install the app [name] (and the app it depends on). Progress arrives as
  /// `ledger:progress` events on `client.events`.
  Future<void> installApp(String name, {LedgerLink? link}) => _conn
      .request('Ledger:installApp', 'POST', {..._link(link), 'Name': name});

  /// Remove the app [name]. Keys and funds are unaffected.
  Future<void> uninstallApp(String name, {LedgerLink? link}) => _conn
      .request('Ledger:uninstallApp', 'POST', {..._link(link), 'Name': name});

  /// Step 1 of a firmware update: install the updater for [update] (from
  /// [status]). The user confirms on the device, which then restarts — the
  /// link has to be reopened. Returns whether [firmwareFlash] must follow.
  Future<bool> firmwareUpdate(LedgerFirmwareUpdate update,
      {LedgerLink? link}) async {
    final data = await _conn.request('Ledger:firmwareUpdate', 'POST',
        {..._link(link), 'Update': update.handle});
    return (data as Map)['flashMcu'] as bool? ?? false;
  }

  /// With the device in bootloader mode, flash the MCU or bootloader the new
  /// firmware needs; repeat while [status] reports `bootloader`. Without
  /// [update] (an interrupted update) the requirement is derived from the
  /// device. Returns `mcu`, `bootloader`, or null when there was nothing to do.
  Future<String?> firmwareFlash(
      {LedgerFirmwareUpdate? update, LedgerLink? link}) async {
    final data = await _conn.request('Ledger:firmwareFlash', 'POST',
        {..._link(link), if (update != null) 'Update': update.handle});
    return (data as Map)['flashed'] as String?;
  }

  /// Read the keys of the app that is open on the device, for [count]
  /// accounts starting at [account]. Bitcoin: [scripts] selects the account
  /// types (`p2wpkh` by default; `p2sh:p2wpkh`, `p2pkh`). Ethereum / Solana:
  /// [paths] reads explicit derivation paths instead.
  Future<LedgerKeys> getKeys({
    int account = 0,
    int count = 1,
    List<String>? scripts,
    List<String>? paths,
    LedgerLink? link,
  }) async {
    final data = await _conn.request('Ledger:getKeys', 'POST', {
      ..._link(link),
      'Account': account,
      'Count': count,
      if (scripts != null) 'Scripts': scripts,
      if (paths != null) 'Paths': paths,
    });
    return LedgerKeys.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Persist [keys] as a new Ledger wallet named [name], or add them to the
  /// existing Ledger wallet [wallet] (keys it already holds are skipped).
  /// The device is not needed for this call.
  Future<LedgerImportResult> importKeys(
    LedgerKeys keys, {
    String? name,
    String? wallet,
    List<String>? selectPaths,
  }) async {
    final data = await _conn.request('Ledger:import', 'POST', {
      'Keys': keys.raw,
      if (keys.masterFingerprint != null)
        'MasterFingerprint': keys.masterFingerprint,
      if (name != null) 'Name': name,
      if (wallet != null) 'Wallet': wallet,
      if (selectPaths != null) 'Select': selectPaths,
    });
    return LedgerImportResult.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Show [account]'s address on the device for the user to compare, and
  /// check the device derives the address libwallet holds. Throws when it
  /// does not (another device, or another passphrase).
  Future<String> showAddress(String account, {LedgerLink? link}) async {
    final data = await _conn.request(
        'Ledger:showAddress', 'POST', {..._link(link), 'Account': account});
    return (data as Map)['address'] as String;
  }

  /// Sign [message] with [account] on the device: Ethereum `personal_sign`
  /// or a Tron `signMessageV2` (returns `0x` + 65-byte r‖s‖v hex), a Bitcoin
  /// message signature (base64), or — for a Solana account — the signature
  /// (base58) over the off-chain message wrapping the text; use
  /// [signSolanaMessage] to also get those signed bytes.
  Future<String> signMessage({
    required String account,
    required Uint8List message,
    LedgerLink? link,
  }) async {
    final data = await _conn.request('Ledger:signMessage', 'POST', {
      ..._link(link),
      'Account': account,
      'Message': base64.encode(message),
    });
    return (data as Map)['signature'] as String;
  }

  /// Sign the text [message] with a Solana [account]. The Solana app does not
  /// sign bare bytes: it signs the off-chain message that wraps the text
  /// (signing domain, version, the signer, the length). A verifier must check
  /// the signature over `signedMessage`, not over [message].
  Future<({String signature, Uint8List signedMessage})> signSolanaMessage({
    required String account,
    required Uint8List message,
    LedgerLink? link,
  }) async {
    final data = await _conn.request('Ledger:signMessage', 'POST', {
      ..._link(link),
      'Account': account,
      'Message': base64.encode(message),
    }) as Map;
    return (
      signature: data['signature'] as String,
      signedMessage: base64.decode(data['signedMessage'] as String),
    );
  }

  /// Sign EIP-712 [typedData] (the JSON) with an Ethereum [account]: `0x` +
  /// 65-byte r‖s‖v hex. The device is given the domain separator and the
  /// message hash and shows those — it cannot display the typed data itself
  /// (the Ethereum app's blind-signing setting must allow it).
  Future<String> signTypedData({
    required String account,
    required String typedData,
    LedgerLink? link,
  }) async {
    final data = await _conn.request('Ledger:signTypedData', 'POST', {
      ..._link(link),
      'Account': account,
      'TypedData': typedData,
    });
    return (data as Map)['signature'] as String;
  }

  /// Build [transaction] for [account], have the device sign it, and — with
  /// [broadcast] — send it.
  ///
  /// The `Transaction` object is the one `Account:signAndSendTransaction`
  /// takes: Ethereum `{to, value, data?}` (nonce, gas and fees are filled
  /// from the node; the chain id always comes from the network, never the
  /// node), Solana `{to, amount, asset?}` or a ready `{message}`, Bitcoin
  /// `{To, Amount, FeeRate?}`. [network] picks the network (default: the
  /// account chain's current/default one); [offline] skips the node, in which
  /// case the transaction must be complete and cannot be broadcast.
  Future<LedgerSignedTransaction> signTransaction({
    required String account,
    required Map<String, dynamic> transaction,
    String? network,
    String? rpc,
    bool offline = false,
    bool broadcast = false,
    LedgerLink? link,
  }) async {
    final data = await _conn.request('Ledger:signTransaction', 'POST', {
      ..._link(link),
      'Account': account,
      'Transaction': transaction,
      if (network != null) 'Network': network,
      if (rpc != null) 'RPC': rpc,
      if (offline) 'Offline': true,
      if (broadcast) 'Broadcast': true,
    });
    return LedgerSignedTransaction.fromJson(
        Map<String, dynamic>.from(data as Map));
  }

  /// Relay APDUs for the `bridge` transport: [exchange] sends one APDU to the
  /// device (over Bluetooth, USB-OTG, …) and returns its full response,
  /// status word included. Keep the subscription for as long as Ledger calls
  /// may run, and cancel it when done. An exception from [exchange] fails the
  /// Ledger call that needed the device.
  StreamSubscription<void> bridge(
      Future<Uint8List> Function(Uint8List apdu) exchange) {
    return _conn.events.where((e) => e.event == 'ledger:apdu').asyncMap((e) async {
      final id = e.data['id'] as String? ?? '';
      if (id.isEmpty) return;
      Map<String, dynamic> answer;
      try {
        final reply = await exchange(_unhex(e.data['apdu'] as String? ?? ''));
        answer = {'Id': id, 'Data': _hex(reply)};
      } catch (err) {
        answer = {'Id': id, 'Error': err.toString()};
      }
      try {
        await _conn.request('Ledger:apduResponse', 'POST', answer);
      } catch (_) {
        // The exchange timed out or was abandoned; nothing is waiting.
      }
    }).listen((_) {});
  }

  static Map<String, dynamic> _link(LedgerLink? link) => link?.toParams() ?? {};

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  static Uint8List _unhex(String s) {
    final out = Uint8List(s.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(s.substring(2 * i, 2 * i + 2), radix: 16);
    }
    return out;
  }
}

/// Which link a Ledger call uses to reach the device.
class LedgerLink {
  /// `hid` | `webhid` | `bridge`; null = the platform default.
  final String? transport;

  /// A USB device path from [LedgerApi.list] (`hid`); null = the first one.
  final String? device;

  /// `webhid`: show the browser's device picker (needs a user gesture)
  /// instead of reusing a device already granted to the page.
  final bool request;

  const LedgerLink({this.transport, this.device, this.request = false});

  /// The app relays the APDUs (see [LedgerApi.bridge]).
  const LedgerLink.bridge() : this(transport: 'bridge');

  /// A USB device, by its [LedgerApi.list] path (or the first one found).
  const LedgerLink.usb([String? device])
      : this(transport: 'hid', device: device);

  Map<String, dynamic> toParams() => {
        if (transport != null) 'Transport': transport,
        if (device != null) 'Device': device,
        if (request) 'Request': true,
      };
}

/// A device seen by the built-in transport.
class LedgerDevice {
  final String transport;
  final String? path;
  final int productId;
  final String? model;
  final String? product;
  final String? serial;

  /// The device is in bootloader mode (a firmware update is in progress).
  final bool bootloader;

  LedgerDevice.fromJson(Map<String, dynamic> j)
      : transport = j['transport'] as String? ?? '',
        path = j['path'] as String?,
        productId = (j['productId'] as num?)?.toInt() ?? 0,
        model = j['model'] as String?,
        product = j['product'] as String?,
        serial = j['serial'] as String?,
        bootloader = j['bootloader'] as bool? ?? false;
}

/// Result of [LedgerApi.list].
class LedgerDevices {
  final List<LedgerDevice> devices;

  /// The transports this build can open (`hid`/`webhid`, `bridge`).
  final List<String> transports;

  /// The transport used when a call names none.
  final String defaultTransport;

  LedgerDevices.fromJson(Map<String, dynamic> j)
      : devices = ((j['devices'] as List?) ?? const [])
            .map((d) => LedgerDevice.fromJson(Map<String, dynamic>.from(d as Map)))
            .toList(),
        transports = List<String>.from((j['transports'] as List?) ?? const []),
        defaultTransport = j['default'] as String? ?? '';
}

/// What a device is running.
class LedgerInfo {
  /// The open app (`Ethereum`, `Bitcoin`, `Solana`, …) or `BOLOS` on the
  /// dashboard.
  final String appName;
  final String appVersion;

  /// No app is open.
  final bool dashboard;

  /// Device model and firmware version — only known on the dashboard.
  final String? model;
  final String? firmware;

  LedgerInfo.fromJson(Map<String, dynamic> j)
      : appName = ((j['app'] as Map?)?['name'] as String?) ?? '',
        appVersion = ((j['app'] as Map?)?['version'] as String?) ?? '',
        dashboard = j['dashboard'] as bool? ?? false,
        model = j['model'] as String?,
        firmware = j['firmware'] as String?;
}

/// An available firmware update.
class LedgerFirmwareUpdate {
  final String version;

  /// The MCU / bootloader must be flashed after the updater (older models).
  final bool flashMcu;

  /// Opaque description passed back to libwallet.
  final Map<String, dynamic> handle;

  LedgerFirmwareUpdate.fromJson(Map<String, dynamic> j)
      : version = j['version'] as String? ?? '',
        flashMcu = j['flashMcu'] as bool? ?? false,
        handle = Map<String, dynamic>.from((j['handle'] as Map?) ?? const {});
}

/// Result of [LedgerApi.status].
class LedgerStatus {
  final String? model;
  final String firmware;

  /// A firmware update is in progress: the device is in bootloader mode, or
  /// running the updater.
  final bool bootloader;
  final bool updater;

  /// The update available, if any.
  final LedgerFirmwareUpdate? update;

  /// Why the update check failed, when it did.
  final String? updateError;

  LedgerStatus.fromJson(Map<String, dynamic> j)
      : model = j['model'] as String?,
        firmware = j['firmware'] as String? ?? '',
        bootloader = j['bootloader'] as bool? ?? false,
        updater = j['updater'] as bool? ?? false,
        update = j['update'] is Map
            ? LedgerFirmwareUpdate.fromJson(
                Map<String, dynamic>.from(j['update'] as Map))
            : null,
        updateError = j['updateError'] as String?;
}

/// An app, installed ([LedgerApi.installedApps]) or available
/// ([LedgerApi.catalog]).
class LedgerApp {
  /// The name to pass to `openApp` / `installApp` / `uninstallApp`.
  final String name;
  final String? displayName;
  final String? version;
  final String? description;

  /// The app this one needs installed first (catalog only).
  final String? requires;

  LedgerApp.fromJson(Map<String, dynamic> j)
      : name = j['name'] as String? ?? '',
        displayName = j['displayName'] as String?,
        version = j['version'] as String?,
        description = j['description'] as String?,
        requires = j['requires'] as String?;
}

/// Keys read from the open app, ready for [LedgerApi.importKeys].
class LedgerKeys {
  /// The device's master fingerprint (hex) — reported by the Bitcoin app only.
  final String? masterFingerprint;

  /// The app the keys were read from, with its version (`Ethereum 1.2.3`).
  final String? app;
  final List<AirgapKey> keys;

  /// The keys as returned by libwallet, passed back verbatim on import.
  final List<dynamic> raw;

  LedgerKeys.fromJson(Map<String, dynamic> j)
      : masterFingerprint = j['master_fingerprint'] as String?,
        app = j['version'] as String?,
        raw = List<dynamic>.from((j['keys'] as List?) ?? const []),
        keys = ((j['keys'] as List?) ?? const [])
            .map((k) => AirgapKey.fromJson(Map<String, dynamic>.from(k as Map)))
            .toList();
}

/// Result of [LedgerApi.importKeys].
class LedgerImportResult {
  final Wallet wallet;

  /// The accounts created by this import (not the wallet's earlier ones).
  final List<Account> accounts;

  LedgerImportResult.fromJson(Map<String, dynamic> j)
      : wallet = Wallet.fromJson(Map<String, dynamic>.from(j['wallet'] as Map)),
        accounts = ((j['accounts'] as List?) ?? const [])
            .map((a) => Account.fromJson(Map<String, dynamic>.from(a as Map)))
            .toList();
}

/// A transaction signed on the device.
class LedgerSignedTransaction {
  /// `ethereum` | `bitcoin` | `solana`.
  final String chain;
  final String account;

  /// The signed transaction: `0x` hex (ethereum, bitcoin) or base58 (solana).
  final String raw;

  /// Its id: tx hash (ethereum), txid (bitcoin) or signature (solana).
  final String id;

  /// The node's answer when the transaction was broadcast.
  final dynamic broadcast;

  LedgerSignedTransaction.fromJson(Map<String, dynamic> j)
      : chain = j['chain'] as String? ?? '',
        account = j['account'] as String? ?? '',
        raw = j['raw'] as String? ?? '',
        id = j['id'] as String? ?? '',
        broadcast = j['broadcast'];
}
