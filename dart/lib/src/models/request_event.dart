import 'dart:convert';
import 'dart:typed_data';

import 'network.dart';
import 'transaction.dart';

/// A Web3 request awaiting user action.
///
/// Sealed: pattern-match on the subtype to handle each request kind with a
/// typed payload, or on the `type` string for forward-compat. A request
/// that arrives with a string the Dart layer doesn't recognize yet comes
/// through as [UnknownPendingRequest] — the raw value and result remain
/// accessible on the base class for fallback handling.
sealed class PendingRequest {
  /// Unique request identifier.
  final String id;

  /// Wire-level type discriminator (e.g. `connect`, `personal_sign`,
  /// `solana_sign_transaction`). Exposed for logging / telemetry; for
  /// behaviour, pattern-match on the subtype instead.
  String get type;

  /// Current status: `pending`, `accepted`, `rejected`, or `timedout`.
  final String status;

  /// Hostname of the dApp that initiated the request.
  final String host;

  /// Account ID the dApp is signing as, if specified.
  final String? account;

  /// Raw value payload as delivered by Go. Kept untyped on the base class
  /// because each request type has its own shape; concrete subtypes expose
  /// typed accessors. Consumers generally don't need to touch this.
  final dynamic rawValue;

  /// Result payload once the request has been approved (e.g. signature,
  /// tx hash). Null while pending. Shape depends on the request type;
  /// subtypes may expose typed getters.
  final dynamic result;

  /// EVM transaction attached to the request, if this is a `sign`-type
  /// request representing `eth_sendTransaction`. Null for other types.
  final Transaction? transaction;

  /// Timestamp when the request was created.
  final DateTime? created;

  /// Timestamp when the request was last updated.
  final DateTime? updated;

  const PendingRequest({
    required this.id,
    required this.status,
    required this.host,
    this.account,
    this.rawValue,
    this.result,
    this.transaction,
    this.created,
    this.updated,
  });

  bool get isPending => status == 'pending';
  bool get isAccepted => status == 'accepted';
  bool get isRejected => status == 'rejected';
  bool get isTimedOut => status == 'timedout';

  /// Parse a request from its JSON wire shape. Dispatches to the correct
  /// concrete subtype based on the `Type` field.
  factory PendingRequest.fromJson(Map<String, dynamic> json) {
    final type = (json['Type'] as String?) ?? (json['type'] as String?) ?? '';
    return switch (type) {
      'connect' => ConnectRequest._(json),
      'sign' => SignRequest._(json),
      'personal_sign' => PersonalSignRequest._(json),
      'sign_typed_data' => SignTypedDataRequest._(json),
      'add_network' => AddNetworkRequest._(json),
      'change_network' => ChangeNetworkRequest._(json),
      'watch_asset' => WatchAssetRequest._(json),
      'solana_sign_message' => SolanaSignMessageRequest._(json),
      'solana_sign_transaction' => SolanaSignTransactionRequest._(json),
      'solana_sign_send_transaction' =>
        SolanaSignAndSendTransactionRequest._(json),
      'mpurse_sign_message' => MpurseSignMessageRequest._(json),
      'mpurse_sign_transaction' => MpurseSignTransactionRequest._(json),
      _ => UnknownPendingRequest._(type, json),
    };
  }
}

// ── Shared helpers ────────────────────────────────────────────────────────

DateTime? _parseTime(dynamic v) {
  if (v is String && v.isNotEmpty) {
    try {
      return DateTime.parse(v);
    } catch (_) {}
  }
  return null;
}

String _id(Map<String, dynamic> j) =>
    (j['Id'] as String?) ?? (j['id'] as String?) ?? '';
String _status(Map<String, dynamic> j) =>
    (j['Status'] as String?) ?? (j['status'] as String?) ?? '';
String _host(Map<String, dynamic> j) =>
    (j['Host'] as String?) ?? (j['host'] as String?) ?? '';
String? _account(Map<String, dynamic> j) =>
    (j['Account'] as String?) ?? (j['account'] as String?);
dynamic _value(Map<String, dynamic> j) => j['Value'] ?? j['value'];
dynamic _result(Map<String, dynamic> j) => j['Result'] ?? j['result'];
Transaction? _tx(Map<String, dynamic> j) {
  final raw = j['Transaction'] ?? j['transaction'];
  if (raw is Map) return Transaction.fromJson(Map<String, dynamic>.from(raw));
  return null;
}

/// Decode a `0x`-prefixed hex string (as EVM uses for raw bytes) into bytes.
Uint8List _hex(String s) {
  var h = s.startsWith('0x') || s.startsWith('0X') ? s.substring(2) : s;
  if (h.length.isOdd) h = '0$h';
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

// ── Concrete request types ────────────────────────────────────────────────

/// dApp is requesting access to one or more of the user's accounts
/// (Web3 `eth_requestAccounts` / Solana connect / etc.).
///
/// Approve via `client.requests.approve(req.id, accounts: [accountId, ...])`.
class ConnectRequest extends PendingRequest {
  ConnectRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'connect';
}

/// EVM `eth_sendTransaction` — a full transaction ready to be signed + sent.
/// The typed transaction payload is on [transaction].
class SignRequest extends PendingRequest {
  SignRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          transaction: _tx(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'sign';

  /// Transaction hash set once the signed transaction has been broadcast.
  /// Available via [transaction].hash after approval.
  String? get txHash => transaction?.hash;
}

/// EVM `personal_sign` — sign a raw message as bytes with the EIP-191 prefix.
class PersonalSignRequest extends PendingRequest {
  PersonalSignRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'personal_sign';

  /// Raw message bytes to be signed (the dApp usually wants this rendered
  /// as UTF-8 for user confirmation).
  Uint8List get messageBytes {
    final v = rawValue;
    if (v is String) return _hex(v);
    return Uint8List(0);
  }

  /// Attempt to decode the message as UTF-8 text. Returns null if the bytes
  /// aren't valid UTF-8 — the caller should then display the raw hex or
  /// bytes instead.
  String? get messageAsText {
    try {
      return utf8.decode(messageBytes);
    } catch (_) {
      return null;
    }
  }

  /// `0x`-hex signature, populated after approval. Null while pending.
  String? get signature {
    final r = result;
    if (r is String) return r;
    return null;
  }
}

/// EVM `eth_signTypedData` (v4) — sign an EIP-712 structured message.
class SignTypedDataRequest extends PendingRequest {
  SignTypedDataRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'sign_typed_data';

  /// Parsed EIP-712 typed-data object (`{types, domain, primaryType,
  /// message}`). The dApp sends this as a JSON string; parse it lazily.
  Map<String, dynamic>? get typedData {
    final v = rawValue;
    if (v is Map) return Map<String, dynamic>.from(v);
    if (v is String && v.isNotEmpty) {
      try {
        final decoded = jsonDecode(v);
        if (decoded is Map) return Map<String, dynamic>.from(decoded);
      } catch (_) {}
    }
    return null;
  }

  /// `0x`-hex signature, populated after approval. Null while pending.
  String? get signature {
    final r = result;
    if (r is String) return r;
    return null;
  }
}

/// dApp is asking to add a new network to the user's configuration
/// (`wallet_addEthereumChain`).
class AddNetworkRequest extends PendingRequest {
  AddNetworkRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'add_network';

  /// Proposed network descriptor.
  Network? get network {
    final v = rawValue;
    if (v is Map) return Network.fromJson(Map<String, dynamic>.from(v));
    return null;
  }
}

/// dApp is asking to switch to a different network
/// (`wallet_switchEthereumChain`). Same shape as [AddNetworkRequest].
class ChangeNetworkRequest extends PendingRequest {
  ChangeNetworkRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'change_network';

  /// Target network descriptor.
  Network? get network {
    final v = rawValue;
    if (v is Map) return Network.fromJson(Map<String, dynamic>.from(v));
    return null;
  }
}

/// dApp is asking the wallet to start tracking a custom token
/// (`wallet_watchAsset`).
class WatchAssetRequest extends PendingRequest {
  WatchAssetRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'watch_asset';

  /// Asset descriptor as sent by the dApp. Shape is loose
  /// (typically `{type, options: {address, symbol, decimals, image}}`).
  Map<String, dynamic>? get asset {
    final v = rawValue;
    if (v is Map) return Map<String, dynamic>.from(v);
    return null;
  }
}

/// Solana `signMessage` — sign a raw message with the account's Ed25519 key.
class SolanaSignMessageRequest extends PendingRequest {
  SolanaSignMessageRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'solana_sign_message';

  /// Raw message bytes.
  Uint8List get messageBytes {
    final v = rawValue;
    if (v is String) {
      try {
        return base64.decode(v);
      } catch (_) {}
    }
    return Uint8List(0);
  }

  /// `{signature: base58, publicKey: base58}` after approval. Null while pending.
  Map<String, String>? get signatureResult {
    final r = result;
    if (r is Map) return Map<String, String>.from(r);
    return null;
  }
}

/// Solana `signTransaction` — sign (but do not broadcast) a serialized tx.
class SolanaSignTransactionRequest extends PendingRequest {
  SolanaSignTransactionRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'solana_sign_transaction';

  /// Unsigned / partially-signed transaction bytes (base64-decoded).
  Uint8List get transactionBytes {
    final v = rawValue;
    if (v is String) {
      try {
        return base64.decode(v);
      } catch (_) {}
    }
    return Uint8List(0);
  }

  /// Signed transaction bytes after approval (base64-decoded). Null while pending.
  Uint8List? get signedTransaction {
    final r = result;
    if (r is Map) {
      final s = r['transaction'];
      if (s is String) {
        try {
          return base64.decode(s);
        } catch (_) {}
      }
    }
    return null;
  }
}

/// Solana `signAndSendTransaction` — sign AND broadcast in one step.
class SolanaSignAndSendTransactionRequest extends PendingRequest {
  SolanaSignAndSendTransactionRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'solana_sign_send_transaction';

  /// Unsigned / partially-signed transaction bytes (base64-decoded).
  Uint8List get transactionBytes {
    final v = rawValue;
    if (v is String) {
      try {
        return base64.decode(v);
      } catch (_) {}
    }
    return Uint8List(0);
  }

  /// Broadcast signature (base58) after approval. Null while pending.
  String? get broadcastSignature {
    final r = result;
    if (r is Map) return r['signature'] as String?;
    return null;
  }
}

/// Monacoin (mpurse) `signMessage` — sign a Bitcoin-family message with
/// the standard "\x19Monacoin Signed Message:\n" prefix. Works on any
/// bitcoin-family chain libwallet has a signing prefix for (bitcoin,
/// litecoin, dogecoin, bitcoincash, monacoin).
class MpurseSignMessageRequest extends PendingRequest {
  MpurseSignMessageRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'mpurse_sign_message';

  /// Plain-text message to be signed.
  String get message {
    final v = rawValue;
    return v is String ? v : '';
  }

  /// Base64-encoded 65-byte compact signature after approval. Null while
  /// pending. Matches Bitcoin Core's `signmessage` output format.
  String? get signature {
    final r = result;
    if (r is String) return r;
    return null;
  }
}

/// Monacoin (mpurse) `signRawTransaction` — sign the inputs of a pre-built
/// raw Bitcoin-family transaction that belong to this account's xpub tree.
/// Typical use: dApp built a Counterparty asset transfer, asks the wallet
/// to sign its inputs.
class MpurseSignTransactionRequest extends PendingRequest {
  MpurseSignTransactionRequest._(Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => 'mpurse_sign_transaction';

  /// Unsigned transaction hex provided by the dApp.
  String get unsignedTxHex {
    final v = rawValue;
    return v is String ? v : '';
  }

  /// Signed transaction hex after approval. Null while pending.
  String? get signedTxHex {
    final r = result;
    if (r is String) return r;
    return null;
  }
}

/// Catch-all for request types the Dart layer doesn't know about yet — lets
/// consumers switch exhaustively without losing forward-compatibility when
/// the Go side adds new types.
class UnknownPendingRequest extends PendingRequest {
  final String _type;

  UnknownPendingRequest._(this._type, Map<String, dynamic> j)
      : super(
          id: _id(j),
          status: _status(j),
          host: _host(j),
          account: _account(j),
          rawValue: _value(j),
          result: _result(j),
          created: _parseTime(j['Created']),
          updated: _parseTime(j['Updated']),
        );

  @override
  String get type => _type;
}
