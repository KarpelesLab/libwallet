import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../client/transport.dart';
import '../models/account.dart';
import '../models/wallet.dart';
import 'airgap_api.dart' show AirgapKey;

/// CatCard hardware wallets — our open firmware for Coldcard hardware (mk3,
/// mk4, mk5, Q1), over the device's own USB protocol.
///
/// **The firmware's README says it is not ready for funds.** Treat this as a
/// development integration.
///
/// A CatCard wallet (`Protocol: catcard`) holds watch-only accounts whose keys
/// were read from the device; signing happens on the device, after the user
/// reviews the transaction on its screen.
///
/// **Reaching the device.** Every call takes the link to use:
///
/// - `hid` — USB, opened by libwallet itself (desktop: macOS, Linux, Windows).
/// - `webhid` — the browser build.
/// - `bridge` — *your app* carries the messages. This is the only option on
///   iOS and Android: a phone cannot open the device's HID interface, but it
///   can drive its smart-card reader (CryptoTokenKit on iOS), whose one APDU
///   carries exactly the bytes libwallet hands over. Install the relay once
///   with [bridge].
///
/// With no [CatCardLink] the platform's built-in transport is used where there
/// is one, the bridge elsewhere.
///
/// **Pairing.** The device only shares addresses and signs inside an encrypted
/// channel that is paired afresh on every connection, by a six-digit code the
/// user compares on both screens. The first call that needs the channel emits
/// the code; answer it once the user has compared it — never automatically,
/// the comparison is the whole defence against a relay in the middle:
/// ```dart
/// final sub = client.catcard.pairing.listen((p) async {
///   final same = await askUser('Does the CatCard show ${p.code}?');
///   await client.catcard.confirmPairing(p, accept: same);
/// });
/// ```
/// The session is then reused until the device ends it (unplug, logout).
///
/// **Typical flow.** The account is picked *on the device*, not by the app:
/// ```dart
/// final keys = await client.catcard.getKeys(); // the user answers on the device
/// final w = await client.catcard.importKeys(keys, name: 'My CatCard');
/// final eth = w.accounts.firstWhere((a) => a.type == 'ethereum');
/// final tx = await client.catcard.signTransaction(
///     account: eth.id,
///     transaction: {'to': '0x…', 'value': '1000000000000000'},
///     broadcast: true);
/// ```
/// libwallet only returns a signature that verifies under the account's key
/// over exactly what was requested; a device holding other keys is refused.

class CatCardApi {
  final Transport _conn;

  CatCardApi(this._conn);

  /// The devices the built-in transport can see, the transports this build
  /// offers, and the default one.
  Future<CatCardDevices> list() async {
    final data = await _conn.request('CatCard:list', 'POST', {});
    return CatCardDevices.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// What the device says about itself. Needs no pairing, and nothing is
  /// asked of the user.
  Future<CatCardInfo> info({CatCardLink? link}) async {
    final data = await _conn.request('CatCard:info', 'POST', _link(link));
    return CatCardInfo.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Pairing codes waiting for the user: compare [CatCardPairing.code] with
  /// the device's screen, then call [confirmPairing].
  Stream<CatCardPairing> get pairing => _conn.events
      .where((e) => e.event == 'catcard:pair')
      .map((e) => CatCardPairing.fromJson(Map<String, dynamic>.from(e.data)));

  /// The user's answer to a pairing code. Pass `accept: true` only once they
  /// have confirmed the device shows the same code.
  Future<void> confirmPairing(CatCardPairing pairing, {required bool accept}) =>
      _conn.request('CatCard:pairResponse', 'POST',
          {'Id': pairing.id, 'Accept': accept});

  /// What the person at the device is being waited for: `queued` (they are in
  /// another menu) or `deciding`, for `addresses` or a `signature`.
  Stream<CatCardWaiting> get waiting => _conn.events
      .where((e) => e.event == 'catcard:waiting')
      .map((e) => CatCardWaiting.fromJson(Map<String, dynamic>.from(e.data)));

  /// End the paired session (the next call pairs again). Returns whether one
  /// was held.
  Future<bool> disconnect({CatCardLink? link}) async {
    final data = await _conn.request('CatCard:disconnect', 'POST', _link(link));
    return (data as Map)['disconnected'] as bool? ?? false;
  }

  /// Ask the device to share its addresses. The user picks the account (and
  /// the chains) on the device; this returns that account's keys: Bitcoin
  /// account keys for the [scripts] asked (`p2wpkh` by default;
  /// `p2sh:p2wpkh`, `p2pkh`, `p2tr`), the Ethereum key and the Solana key.
  /// Chains the device shares but does not sign for are reported with
  /// `chain: unsupported`.
  ///
  /// [account] is only a check: when given and the user picked another
  /// account on the device, the call fails.
  Future<CatCardKeys> getKeys({
    int? account,
    List<String>? scripts,
    CatCardLink? link,
  }) async {
    final data = await _conn.request('CatCard:getKeys', 'POST', {
      ..._link(link),
      if (account != null) 'Account': account,
      if (scripts != null) 'Scripts': scripts,
    });
    return CatCardKeys.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Persist [keys] as a new CatCard wallet named [name], or add them to the
  /// existing CatCard wallet [wallet] (keys it already holds are skipped).
  /// The device is not needed for this call.
  Future<CatCardImportResult> importKeys(
    CatCardKeys keys, {
    String? name,
    String? wallet,
    List<String>? selectPaths,
  }) async {
    final data = await _conn.request('CatCard:import', 'POST', {
      'Keys': keys.raw,
      if (keys.masterFingerprint != null)
        'MasterFingerprint': keys.masterFingerprint,
      if (name != null) 'Name': name,
      if (wallet != null) 'Wallet': wallet,
      if (selectPaths != null) 'Select': selectPaths,
    });
    return CatCardImportResult.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Build [transaction] for [account], have the user review and sign it on
  /// the device, and — with [broadcast] — send it.
  ///
  /// The `Transaction` object is the one `Account:signAndSendTransaction`
  /// takes: Ethereum `{to, value, data?}` (nonce, gas and fees are filled
  /// from the node; the chain id always comes from the network, never the
  /// node), Solana `{to, amount, asset?}` or a ready `{message}`, Bitcoin
  /// `{To, Amount, FeeRate?}`. [network] picks the network (default: the
  /// account chain's current/default one); [offline] skips the node, in which
  /// case the transaction must be complete and cannot be broadcast.
  ///
  /// The device only signs with keys of an account it shared in the same
  /// session: in a new session the user is first asked to share again, and
  /// must pick the account this one belongs to.
  Future<CatCardSignedTransaction> signTransaction({
    required String account,
    required Map<String, dynamic> transaction,
    String? network,
    String? rpc,
    bool offline = false,
    bool broadcast = false,
    CatCardLink? link,
  }) async {
    final data = await _conn.request('CatCard:signTransaction', 'POST', {
      ..._link(link),
      'Account': account,
      'Transaction': transaction,
      if (network != null) 'Network': network,
      if (rpc != null) 'RPC': rpc,
      if (offline) 'Offline': true,
      if (broadcast) 'Broadcast': true,
    });
    return CatCardSignedTransaction.fromJson(
        Map<String, dynamic>.from(data as Map));
  }

  /// Not available: the firmware's host protocol has no command to display
  /// an address, so this always throws (code 501). The device's own Address
  /// Explorer shows them; [getKeys] checks the device still derives them.
  Future<String> showAddress(String account, {CatCardLink? link}) async {
    final data = await _conn.request(
        'CatCard:showAddress', 'POST', {..._link(link), 'Account': account});
    return (data as Map)['address'] as String;
  }

  /// Not available: the firmware's host protocol signs transactions only, so
  /// this always throws (code 501).
  Future<String> signMessage({
    required String account,
    required Uint8List message,
    CatCardLink? link,
  }) async {
    final data = await _conn.request('CatCard:signMessage', 'POST', {
      ..._link(link),
      'Account': account,
      'Message': base64.encode(message),
    });
    return (data as Map)['signature'] as String;
  }

  /// Relay messages for the `bridge` transport: [exchange] sends one message
  /// to the device and returns its reply.
  ///
  /// A message is `[u16 opcode LE][u32 length LE][payload]` and a reply
  /// `[u16 status LE][u32 length LE][payload]` — exactly the data of the one
  /// APDU the device's smart-card reader answers (`80 CC 00 00`, extended
  /// length; see the firmware's `docs/PHONE-APP.md`), without the APDU header
  /// and status word. Keep the subscription for as long as CatCard calls may
  /// run, and cancel it when done. An exception from [exchange] fails the
  /// call that needed the device.
  StreamSubscription<void> bridge(
      Future<Uint8List> Function(Uint8List message) exchange) {
    return _conn.events
        .where((e) => e.event == 'catcard:packet')
        .asyncMap((e) async {
      final id = e.data['id'] as String? ?? '';
      if (id.isEmpty) return;
      Map<String, dynamic> answer;
      try {
        final reply = await exchange(_unhex(e.data['packet'] as String? ?? ''));
        answer = {'Id': id, 'Data': _hex(reply)};
      } catch (err) {
        answer = {'Id': id, 'Error': err.toString()};
      }
      try {
        await _conn.request('CatCard:packetResponse', 'POST', answer);
      } catch (_) {
        // The exchange timed out or was abandoned; nothing is waiting.
      }
    }).listen((_) {});
  }

  static Map<String, dynamic> _link(CatCardLink? link) =>
      link?.toParams() ?? {};

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

/// Which link a CatCard call uses to reach the device.
class CatCardLink {
  /// `hid` | `webhid` | `bridge`; null = the platform default.
  final String? transport;

  /// A USB device path from [CatCardApi.list] (`hid`); null = the first one.
  final String? device;

  /// `webhid`: show the browser's device picker (needs a user gesture)
  /// instead of reusing a device already granted to the page.
  final bool request;

  const CatCardLink({this.transport, this.device, this.request = false});

  /// The app relays the messages (see [CatCardApi.bridge]).
  const CatCardLink.bridge() : this(transport: 'bridge');

  /// A USB device, by its [CatCardApi.list] path (or the first one found).
  const CatCardLink.usb([String? device])
      : this(transport: 'hid', device: device);

  Map<String, dynamic> toParams() => {
        if (transport != null) 'Transport': transport,
        if (device != null) 'Device': device,
        if (request) 'Request': true,
      };
}

/// A device seen by the built-in transport.
class CatCardDevice {
  final String transport;
  final String? path;
  final int productId;
  final String? product;
  final String? serial;

  CatCardDevice.fromJson(Map<String, dynamic> j)
      : transport = j['transport'] as String? ?? '',
        path = j['path'] as String?,
        productId = (j['productId'] as num?)?.toInt() ?? 0,
        product = j['product'] as String?,
        serial = j['serial'] as String?;
}

/// Result of [CatCardApi.list].
class CatCardDevices {
  final List<CatCardDevice> devices;

  /// The transports this build can open (`hid`/`webhid`, `bridge`).
  final List<String> transports;

  /// The transport used when a call names none.
  final String defaultTransport;

  CatCardDevices.fromJson(Map<String, dynamic> j)
      : devices = ((j['devices'] as List?) ?? const [])
            .map((d) =>
                CatCardDevice.fromJson(Map<String, dynamic>.from(d as Map)))
            .toList(),
        transports = List<String>.from((j['transports'] as List?) ?? const []),
        defaultTransport = j['default'] as String? ?? '';
}

/// What a device says about itself.
class CatCardInfo {
  /// `mk3`, `mk4`, `mk5` or `q1`.
  final String board;
  final String firmware;

  /// The protocol version the device speaks (this library speaks 2).
  final int protocol;

  /// The PIN has been entered. Nothing but [CatCardApi.info] works before.
  final bool unlocked;

  /// No PIN has been set yet.
  final bool blank;

  /// The firmware offers the paired channel and the wallet commands.
  final bool pairing;
  final bool hostWallet;

  /// A development image whose host can press keys or read memory: warn the
  /// user, no owner should be running one.
  final bool bench;

  /// A session from an earlier call is held for this link.
  final bool paired;

  CatCardInfo.fromJson(Map<String, dynamic> j)
      : board = j['board'] as String? ?? '',
        firmware = j['firmware'] as String? ?? '',
        protocol = (j['protocol'] as num?)?.toInt() ?? 0,
        unlocked = j['unlocked'] as bool? ?? false,
        blank = j['blank'] as bool? ?? false,
        pairing = j['pairing'] as bool? ?? false,
        hostWallet = j['hostWallet'] as bool? ?? false,
        bench = j['bench'] as bool? ?? false,
        paired = j['paired'] as bool? ?? false;
}

/// A pairing code waiting for the user ([CatCardApi.pairing]).
class CatCardPairing {
  final String id;

  /// The six digits, as both screens show them: `123 456`.
  final String code;
  final String board;
  final String firmware;

  /// The device runs a development image (see [CatCardInfo.bench]).
  final bool bench;

  CatCardPairing.fromJson(Map<String, dynamic> j)
      : id = j['id'] as String? ?? '',
        code = j['code'] as String? ?? '',
        board = j['board'] as String? ?? '',
        firmware = j['version'] as String? ?? '',
        bench = j['bench'] as bool? ?? false;
}

/// The person at the device is being waited for ([CatCardApi.waiting]).
class CatCardWaiting {
  /// `addresses` | `signature`.
  final String what;

  /// `queued` (the device will ask once they are back on a menu) |
  /// `deciding` (the question is on its screen).
  final String stage;

  CatCardWaiting.fromJson(Map<String, dynamic> j)
      : what = j['for'] as String? ?? '',
        stage = j['stage'] as String? ?? '';
}

/// Keys shared by the device, ready for [CatCardApi.importKeys].
class CatCardKeys {
  /// The device's master fingerprint (hex).
  final String? masterFingerprint;

  /// The board and firmware the keys were read from (`q1 7.0.0`).
  final String? device;
  final List<AirgapKey> keys;

  /// The keys as returned by libwallet, passed back verbatim on import.
  final List<dynamic> raw;

  CatCardKeys.fromJson(Map<String, dynamic> j)
      : masterFingerprint = j['master_fingerprint'] as String?,
        device = j['version'] as String?,
        raw = List<dynamic>.from((j['keys'] as List?) ?? const []),
        keys = ((j['keys'] as List?) ?? const [])
            .map((k) => AirgapKey.fromJson(Map<String, dynamic>.from(k as Map)))
            .toList();
}

/// Result of [CatCardApi.importKeys].
class CatCardImportResult {
  final Wallet wallet;

  /// The accounts created by this import (not the wallet's earlier ones).
  final List<Account> accounts;

  CatCardImportResult.fromJson(Map<String, dynamic> j)
      : wallet = Wallet.fromJson(Map<String, dynamic>.from(j['wallet'] as Map)),
        accounts = ((j['accounts'] as List?) ?? const [])
            .map((a) => Account.fromJson(Map<String, dynamic>.from(a as Map)))
            .toList();
}

/// A transaction signed on the device.
class CatCardSignedTransaction {
  /// `ethereum` | `bitcoin` | `solana`.
  final String chain;
  final String account;

  /// The signed transaction: `0x` hex (ethereum, bitcoin) or base58 (solana).
  final String raw;

  /// Its id: tx hash (ethereum), txid (bitcoin) or signature (solana).
  final String id;

  /// The node's answer when the transaction was broadcast.
  final dynamic broadcast;

  CatCardSignedTransaction.fromJson(Map<String, dynamic> j)
      : chain = j['chain'] as String? ?? '',
        account = j['account'] as String? ?? '',
        raw = j['raw'] as String? ?? '',
        id = j['id'] as String? ?? '',
        broadcast = j['broadcast'];
}
