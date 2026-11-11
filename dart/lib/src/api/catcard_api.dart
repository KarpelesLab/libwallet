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
/// - `ccid` — *your app* carries APDUs to the device's smart-card reader.
///   This is the way on iOS and Android: a phone cannot open the device's HID
///   interface, but it can drive its reader (CryptoTokenKit on iOS). Install
///   the relay once with [ccidBridge]:
///   ```dart
///   final sub = client.catcard.ccidBridge((apdu) => myCard.transmit(apdu));
///   ```
/// - `bridge` — *your app* carries whole messages, over anything else that
///   reaches the device (see [bridge]).
///
/// With no [CatCardLink] the platform's built-in transport is used where there
/// is one, `ccid` elsewhere (iOS, Android).
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
/// (The one exception is a BIP-322 message signature, see [signMessage].)
///
/// **Firmware versions.** [showAddress], [signMessage] and [getKeys] with
/// `paths` need firmware that has those requests; older firmware answers
/// them with code 501. [CatCardInfo.hostInfo] says which a device has.

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
  ///
  /// [CatCardInfo.hostInfo] — what its firmware can do beyond sharing
  /// accounts and signing transactions — only travels inside the paired
  /// channel: it is there once an earlier call has paired, and null before
  /// (this call never starts a pairing).
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
  /// another menu) or `deciding`, for `addresses`, an `address`, a
  /// `signature` or a `message`.
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
  ///
  /// With [paths] the app names the keys instead (newer firmware only, see
  /// [CatCardHostInfo.addressAt]; code 501 otherwise): each key is asked for
  /// by its derivation path. The user is asked on the device for every one,
  /// unless they tick **Allow during session** at the first. The chain is
  /// read from the path's coin type (`0'`, `60'`, `501'`) unless [chain]
  /// (`bitcoin`, `ethereum`, `solana`) says it; [format] is the Bitcoin
  /// script kind when the path's purpose does not say it. Ethereum and Solana
  /// keys can be imported. A Bitcoin path is a single address key, not an
  /// account — it comes back with `chain: unsupported` and its address, and
  /// [importKeys] skips it.
  Future<CatCardKeys> getKeys({
    int? account,
    List<String>? scripts,
    List<String>? paths,
    String? chain,
    String? format,
    CatCardLink? link,
  }) async {
    final data = await _conn.request('CatCard:getKeys', 'POST', {
      ..._link(link),
      if (account != null) 'Account': account,
      if (scripts != null) 'Scripts': scripts,
      if (paths != null) 'Paths': paths,
      if (chain != null) 'Chain': chain,
      if (format != null) 'Format': format,
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
  /// The device only signs with keys it shared in the same session. In a new
  /// session the user is therefore asked first: for an Ethereum or Solana
  /// account, to share that one key (newer firmware); for a Bitcoin account —
  /// or on older firmware — to share their addresses again, picking the
  /// account this one belongs to.
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

  /// Show [account]'s address on the device ("Same as the computer shows?")
  /// so the user can compare it with the one your app displays, and check
  /// that the device derives the address libwallet holds. For a Bitcoin
  /// account it is the first receive address. Returns the address; fails
  /// (code 409) when the device shows another one.
  ///
  /// Needs newer firmware ([CatCardHostInfo.addressAt]): older firmware has no
  /// such request and this throws with code 501.
  Future<String> showAddress(String account, {CatCardLink? link}) async {
    final data = await _conn.request(
        'CatCard:showAddress', 'POST', {..._link(link), 'Account': account});
    return (data as Map)['address'] as String;
  }

  /// Have the user read [message] on the device and sign it with [account]'s
  /// key. Returns the signature:
  ///
  /// - **Ethereum** — `personal_sign` (EIP-191): `0x` + 65 bytes `r‖s‖v` hex.
  /// - **Bitcoin** — signed with the account's first receive address: BIP-137
  ///   by default, base64. [scheme] `bip322` or `bip322-full` asks for a
  ///   BIP-322 signature instead (base64); a taproot account has those only.
  ///   Not every scheme signs for every address type; the wrong pairing is
  ///   refused (code 400).
  ///
  /// The device signs printable ASCII text only: one line of at most 240
  /// characters for Bitcoin; up to 24 lines and 960 bytes for Ethereum, no
  /// line starting or ending with a space. Anything else is refused (code
  /// 400) with the reason. EIP-712 typed data and Solana messages are not
  /// signed.
  ///
  /// An Ethereum or BIP-137 signature is only returned once it verifies under
  /// the account's key. **A BIP-322 signature is returned as the device gave
  /// it: libwallet does not verify it.** Use [signMessageDetailed] to see
  /// which it was.
  ///
  /// Needs newer firmware ([CatCardHostInfo.signMessage]): older firmware has
  /// no such request and this throws with code 501.
  Future<String> signMessage({
    required String account,
    required Uint8List message,
    String? scheme,
    CatCardLink? link,
  }) async =>
      (await signMessageDetailed(
              account: account, message: message, scheme: scheme, link: link))
          .signature;

  /// [signMessage], with the scheme used, the signing address and whether
  /// libwallet verified the signature.
  Future<CatCardSignedMessage> signMessageDetailed({
    required String account,
    required Uint8List message,
    String? scheme,
    CatCardLink? link,
  }) async {
    final data = await _conn.request('CatCard:signMessage', 'POST', {
      ..._link(link),
      'Account': account,
      'Message': base64.encode(message),
      if (scheme != null) 'Scheme': scheme,
    });
    return CatCardSignedMessage.fromJson(
        Map<String, dynamic>.from(data as Map));
  }

  /// Relay APDUs for the `ccid` transport: [transmit] sends one command APDU
  /// to the card in the device's smart-card reader and returns the response
  /// APDU, status word included — on iOS, `TKSmartCard.transmit(_:)`; on
  /// Android, the reader's transceive. Send the bytes as given (the class
  /// byte is part of the protocol) and return whatever comes back, including
  /// `61 xx`: libwallet does the chaining and the `GET RESPONSE` paging.
  ///
  /// Keep the subscription for as long as CatCard calls may run, and cancel
  /// it when done. An exception from [transmit] fails the call that needed
  /// the device.
  StreamSubscription<void> ccidBridge(
          Future<Uint8List> Function(Uint8List apdu) transmit) =>
      _relay('catcard:apdu', 'apdu', 'CatCard:apduResponse', transmit);

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
          Future<Uint8List> Function(Uint8List message) exchange) =>
      _relay('catcard:packet', 'packet', 'CatCard:packetResponse', exchange);

  StreamSubscription<void> _relay(String event, String field, String route,
      Future<Uint8List> Function(Uint8List) exchange) {
    return _conn.events.where((e) => e.event == event).asyncMap((e) async {
      final id = e.data['id'] as String? ?? '';
      if (id.isEmpty) return;
      Map<String, dynamic> answer;
      try {
        final reply = await exchange(_unhex(e.data[field] as String? ?? ''));
        answer = {'Id': id, 'Data': _hex(reply)};
      } catch (err) {
        answer = {'Id': id, 'Error': err.toString()};
      }
      try {
        await _conn.request(route, 'POST', answer);
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
  /// `hid` | `webhid` | `ccid` | `bridge`; null = the platform default.
  final String? transport;

  /// `ccid`: keep to short APDUs (255 data bytes, replies paged by
  /// `GET RESPONSE`), for a smart-card API without extended ones.
  final bool shortApdu;

  /// A USB device path from [CatCardApi.list] (`hid`); null = the first one.
  final String? device;

  /// `webhid`: show the browser's device picker (needs a user gesture)
  /// instead of reusing a device already granted to the page.
  final bool request;

  const CatCardLink(
      {this.transport,
      this.device,
      this.request = false,
      this.shortApdu = false});

  /// The app relays APDUs to the device's smart-card reader (see
  /// [CatCardApi.ccidBridge]).
  const CatCardLink.ccid({bool shortApdu = false})
      : this(transport: 'ccid', shortApdu: shortApdu);

  /// The app relays the messages (see [CatCardApi.bridge]).
  const CatCardLink.bridge() : this(transport: 'bridge');

  /// A USB device, by its [CatCardApi.list] path (or the first one found).
  const CatCardLink.usb([String? device])
      : this(transport: 'hid', device: device);

  Map<String, dynamic> toParams() => {
        if (transport != null) 'Transport': transport,
        if (device != null) 'Device': device,
        if (request) 'Request': true,
        if (shortApdu) 'ShortApdu': true,
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

  /// The transports this build can open (`hid`/`webhid`, `ccid`, `bridge`).
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

  /// What the firmware can do beyond sharing accounts and signing
  /// transactions. Null until a call has paired with the device: it is only
  /// told inside the paired channel.
  final CatCardHostInfo? hostInfo;

  CatCardInfo.fromJson(Map<String, dynamic> j)
      : board = j['board'] as String? ?? '',
        firmware = j['firmware'] as String? ?? '',
        protocol = (j['protocol'] as num?)?.toInt() ?? 0,
        unlocked = j['unlocked'] as bool? ?? false,
        blank = j['blank'] as bool? ?? false,
        pairing = j['pairing'] as bool? ?? false,
        hostWallet = j['hostWallet'] as bool? ?? false,
        bench = j['bench'] as bool? ?? false,
        paired = j['paired'] as bool? ?? false,
        hostInfo = j['hostInfo'] is Map
            ? CatCardHostInfo.fromJson(
                Map<String, dynamic>.from(j['hostInfo'] as Map))
            : null;
}

/// What a device's firmware can do beyond sharing accounts and signing
/// transactions, and what the current session has been given
/// ([CatCardInfo.hostInfo]).
class CatCardHostInfo {
  /// Older firmware: it shares accounts and signs transactions, nothing more.
  /// [addressAt] and [signMessage] are then false.
  final bool legacy;

  /// It gives one address by its path: [CatCardApi.showAddress] and
  /// [CatCardApi.getKeys] with `paths` work.
  final bool addressAt;

  /// It signs messages: [CatCardApi.signMessage] works (for the chains whose
  /// [CatCardChainInfo.messages] is set).
  final bool signMessage;

  /// The user ticked "Allow during session" on the device: until the session
  /// ends, addresses asked for by their path are given without a question.
  final bool pathsAllowed;

  /// Something was shared in this session, so the device has keys it will
  /// sign with.
  final bool shared;

  /// The longest message, in bytes, the device takes (a chain may allow
  /// less, and a small screen less still).
  final int messageMax;

  /// The chains the firmware carries, and what each can be asked for.
  final List<CatCardChainInfo> chains;

  CatCardHostInfo.fromJson(Map<String, dynamic> j)
      : legacy = j['legacy'] as bool? ?? false,
        addressAt = j['addressAt'] as bool? ?? false,
        signMessage = j['signMessage'] as bool? ?? false,
        pathsAllowed = j['pathsAllowed'] as bool? ?? false,
        shared = j['shared'] as bool? ?? false,
        messageMax = (j['messageMax'] as num?)?.toInt() ?? 0,
        chains = ((j['chains'] as List?) ?? const [])
            .map((c) =>
                CatCardChainInfo.fromJson(Map<String, dynamic>.from(c as Map)))
            .toList();
}

/// One chain of a [CatCardHostInfo].
class CatCardChainInfo {
  /// The firmware's chain number (Bitcoin 1, Ethereum 2, Solana 3, …).
  final int chain;

  /// `Bitcoin`, `Ethereum`, `Solana`, `Litecoin`, …
  final String name;

  /// The device shares this chain's addresses.
  final bool addresses;

  /// It signs this chain's transactions.
  final bool sign;

  /// It signs messages for this chain.
  final bool messages;

  /// The address formats the chain has, most usual first: the Bitcoin script
  /// kinds (`p2wpkh`, `p2sh:p2wpkh`, `p2pkh`, `p2tr`), `evm`, `tron`,
  /// `solana`.
  final List<String> formats;

  CatCardChainInfo.fromJson(Map<String, dynamic> j)
      : chain = (j['chain'] as num?)?.toInt() ?? 0,
        name = j['name'] as String? ?? '',
        addresses = j['addresses'] as bool? ?? false,
        sign = j['sign'] as bool? ?? false,
        messages = j['messages'] as bool? ?? false,
        formats = List<String>.from((j['formats'] as List?) ?? const []);
}

/// A message signed on the device ([CatCardApi.signMessageDetailed]).
class CatCardSignedMessage {
  final String account;

  /// The address the signature speaks for (Bitcoin: the account's first
  /// receive address).
  final String address;

  /// `0x` hex of `r‖s‖v` (`eip191`), or base64 (the Bitcoin schemes).
  final String signature;

  /// `eip191` | `bip137` | `bip322` | `bip322-full`.
  final String scheme;

  /// The signing key's derivation path (Bitcoin).
  final String? path;

  /// libwallet checked the signature against the account's key. False for
  /// BIP-322, which it cannot verify: the signature is the device's word.
  final bool verified;

  CatCardSignedMessage.fromJson(Map<String, dynamic> j)
      : account = j['account'] as String? ?? '',
        address = j['address'] as String? ?? '',
        signature = j['signature'] as String? ?? '',
        scheme = j['scheme'] as String? ?? '',
        path = j['path'] as String?,
        verified = j['verified'] as bool? ?? false;
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
  /// `addresses` | `address` | `signature` | `message`.
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
