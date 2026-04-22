import 'dart:convert';
import 'dart:typed_data';

import 'account.dart';
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
      'transaction_sign' => TransactionSignRequest._(json),
      'message_sign' => MessageSignRequest._(json),
      'add_network' => AddNetworkRequest._(json),
      'chain_switch' => ChainSwitchRequest._(json),
      'watch_asset' => WatchAssetRequest._(json),
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


// ── Concrete request types ────────────────────────────────────────────────

/// dApp is requesting access to one or more of the user's accounts
/// — `eth_requestAccounts`, `wallet_requestPermissions`,
/// `solana_connect`, `solana_requestAccounts`, `mpurse_getAddress`.
///
/// The rich payload lets a host render the picker without a
/// follow-up `accounts.list()`:
/// - [method] / [family] — which RPC + chain family
/// - [availableAccounts] — accounts curve-compatible with [family]
/// - [alreadyConnectedIds] — account IDs already connected to this
///   host (pre-check in the picker, or render "Reconnect")
/// - [requestedPermissions] — EIP-2255 permission names (currently
///   just `"eth_accounts"`)
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

  Map<String, dynamic>? get _v {
    final v = rawValue;
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// Originating RPC method.
  String get method => _v?['method'] as String? ?? '';

  /// Chain family: `"evm"` / `"solana"` / `"bitcoin"`. Empty when
  /// the connect isn't chain-scoped.
  String get family => _v?['family'] as String? ?? '';

  /// Accounts compatible with [family] — the picker's candidate set.
  List<Account> get availableAccounts {
    final list = _v?['availableAccounts'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => Account.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// Account IDs already connected to this host.
  List<String> get alreadyConnectedIds {
    final list = _v?['alreadyConnected'];
    if (list is! List) return const [];
    return list.whereType<String>().toList();
  }

  /// EIP-2255 permission names the dApp asked for.
  List<String> get requestedPermissions {
    final list = _v?['requestedPermissions'];
    if (list is! List) return const [];
    return list.whereType<String>().toList();
  }
}

/// Unified on-chain transaction-signing request — covers
/// `eth_sendTransaction`, `solana_signTransaction`,
/// `solana_signAndSendTransaction`, `mpurse_signRawTransaction`.
/// The chain family is on [chain]; the original RPC method on
/// [method].
///
/// The payload carries pre-decoded data so the approval sheet can
/// render rich content without a follow-up `Transaction:simulate`
/// round-trip:
/// - [decodedMethod] / [decodedArgs] — recognised top-level
///   operation ("native_transfer", "erc20_transfer",
///   "erc20_approve", …)
/// - [effects] — every transfer / approve at any call depth
/// - [balanceChanges] — signed native-balance deltas per address
/// - [warnings] — stable-coded advisories (recipient_is_contract,
///   erc20_approve_unlimited, …)
/// - [willRevert] / [revertReason]
/// - [feeAmount] / [feeDecimals] / [feeSymbol]
/// - [networkName] for context
/// - [sizeBytes] / [raw] for the developer view
/// - chain-specific extras: [evmTransaction], [solanaUnitsConsumed],
///   [solanaLogs], [bitcoinInputs], [bitcoinOutputs], [bitcoinFeeSats]
class TransactionSignRequest extends PendingRequest {
  TransactionSignRequest._(Map<String, dynamic> j)
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
  String get type => 'transaction_sign';

  Map<String, dynamic>? get _v {
    final v = rawValue;
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// `"evm"` / `"solana"` / `"bitcoin"`.
  String get chain => _v?['chain'] as String? ?? '';

  /// The original RPC method that triggered the prompt
  /// (`"eth_sendTransaction"`, `"solana_signTransaction"`, …).
  String get method => _v?['method'] as String? ?? '';

  /// Signer's address in the chain's native format.
  String get from => _v?['from'] as String? ?? '';

  /// Network info for context (name, currency, etc.). Null if
  /// the payload is malformed.
  Network? get network {
    final v = _v?['network'];
    return v is Map ? Network.fromJson(Map<String, dynamic>.from(v)) : null;
  }

  /// Network identifier (`"<type>.<chainId>"`).
  String get networkId => _v?['networkId'] as String? ?? '';

  /// Network display name.
  String get networkName => _v?['networkName'] as String? ?? '';

  /// Approximate serialized tx size in bytes.
  int get sizeBytes => (_v?['sizeBytes'] as num?)?.toInt() ?? 0;

  /// Raw tx — hex on EVM/Bitcoin, base64 on Solana. For dev-mode
  /// "see raw" panels.
  String get raw => _v?['raw'] as String? ?? '';

  /// Recognised top-level operation: `"native_transfer"` |
  /// `"erc20_transfer"` | `"erc20_approve"` | `"spl_transfer"` |
  /// `"bitcoin_transfer"` | `"unknown"` | `""` (no decoder ran).
  String get decodedMethod => _v?['decodedMethod'] as String? ?? '';

  /// Method-specific arguments (`{to, amount, ...}`).
  Map<String, dynamic> get decodedArgs {
    final v = _v?['decodedArgs'];
    return v is Map ? Map<String, dynamic>.from(v) : const {};
  }

  /// Every transfer / approve effect this tx will cause, at any
  /// call depth. Empty when the chain has no decoder.
  List<TxSignEffect> get effects {
    final list = _v?['effects'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => TxSignEffect.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// Signed native-balance deltas per address.
  List<TxSignBalanceChange> get balanceChanges {
    final list = _v?['balanceChanges'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => TxSignBalanceChange.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// Advisories the approval sheet should surface.
  List<TxSignWarning> get warnings {
    final list = _v?['warnings'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => TxSignWarning.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// True when simulate predicts the tx will revert / fail.
  bool get willRevert => _v?['willRevert'] == true;

  /// Human-readable revert reason, when [willRevert] is true.
  String get revertReason => _v?['revertReason'] as String? ?? '';

  /// Fee amount as a decimal-string in base units. Pair with
  /// [feeDecimals] + [feeSymbol] for display.
  String get feeAmount => _v?['feeAmount'] as String? ?? '';

  /// Decimals for [feeAmount] (18 for ETH, 9 for SOL, 8 for BTC).
  int get feeDecimals => (_v?['feeDecimals'] as num?)?.toInt() ?? 0;

  /// Native currency symbol for the fee.
  String get feeSymbol => _v?['feeSymbol'] as String? ?? '';

  /// EVM-specific: full Transaction record (gas, nonce, data, etc.).
  /// Null on non-EVM chains.
  Transaction? get evmTransaction {
    final v = _v?['evmTransaction'];
    return v is Map ? Transaction.fromJson(Map<String, dynamic>.from(v)) : null;
  }

  /// Solana-specific: simulated compute-unit cost (0 when not run).
  int get solanaUnitsConsumed =>
      (_v?['solanaUnitsConsumed'] as num?)?.toInt() ?? 0;

  /// Solana-specific: program log lines from simulateTransaction.
  List<String> get solanaLogs {
    final list = _v?['solanaLogs'];
    if (list is! List) return const [];
    return list.whereType<String>().toList();
  }

  /// Bitcoin-specific: decoded inputs.
  List<TxSignBitcoinIO> get bitcoinInputs {
    final list = _v?['bitcoinInputs'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => TxSignBitcoinIO.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// Bitcoin-specific: decoded outputs.
  List<TxSignBitcoinIO> get bitcoinOutputs {
    final list = _v?['bitcoinOutputs'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => TxSignBitcoinIO.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// Bitcoin-specific: fee in satoshi (sum(inputs) − sum(outputs)
  /// when input amounts are known; 0 otherwise).
  int get bitcoinFeeSats => (_v?['bitcoinFeeSats'] as num?)?.toInt() ?? 0;

  /// Result hash / signature once the request has been approved.
  /// Shape depends on [method]; see the result-getter helpers below
  /// or fall back to the raw [result] field.
  String? get resultHash {
    if (transaction != null && transaction!.hash != null) {
      return transaction!.hash;
    }
    final r = result;
    if (r is String) return r;
    if (r is Map) {
      final s = r['signature'] ?? r['transaction'];
      if (s is String) return s;
    }
    return null;
  }
}

/// Unified arbitrary-data signature request — covers
/// `personal_sign`, `eth_signTypedData*`, `solana_signMessage`,
/// `mpurse_signMessage`. NOT a transaction; typically used for
/// login (Sign-In With Ethereum/Solana) or off-chain attestations.
///
/// Decoded fields:
/// - [messageBytes] / [messageText] — raw bytes + UTF-8 decode
/// - [structuredData] / [structuredPrimaryType] /
///   [structuredDomain] — for EIP-712 typed data
/// - [isSiwe] / [isSiws] / [siweFields] — auto-detected
///   Sign-In-With-Ethereum / Sign-In-With-Solana pattern
/// - [warnings] — advisories (e.g. message contains a URL)
class MessageSignRequest extends PendingRequest {
  MessageSignRequest._(Map<String, dynamic> j)
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
  String get type => 'message_sign';

  Map<String, dynamic>? get _v {
    final v = rawValue;
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// `"evm"` / `"solana"` / `"bitcoin"`.
  String get chain => _v?['chain'] as String? ?? '';

  /// Original RPC method (`"personal_sign"`,
  /// `"eth_signTypedData_v4"`, `"solana_signMessage"`,
  /// `"mpurse_signMessage"`).
  String get method => _v?['method'] as String? ?? '';

  /// Signer's address in the chain's native format.
  String get from => _v?['from'] as String? ?? '';

  /// Raw message bytes (base64-decoded from the wire form).
  Uint8List get messageBytes {
    final s = _v?['messageBytes'];
    if (s is String && s.isNotEmpty) {
      try {
        return base64.decode(s);
      } catch (_) {}
    }
    return Uint8List(0);
  }

  /// UTF-8 decode of [messageBytes] when the bytes are valid
  /// printable text. Empty otherwise — fall back to [messageBytes]
  /// (hex-encoded display) for binary messages.
  String get messageText => _v?['messageText'] as String? ?? '';

  /// EIP-712 parsed object `{types, domain, primaryType, message}`.
  /// Null for non-typed-data methods.
  Map<String, dynamic>? get structuredData {
    final v = _v?['structuredData'];
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// EIP-712 primary type — the "main" struct the user is signing.
  String get structuredPrimaryType =>
      _v?['structuredPrimaryType'] as String? ?? '';

  /// EIP-712 domain — `{name, version, chainId, verifyingContract}`.
  Map<String, dynamic>? get structuredDomain {
    final v = _v?['structuredDomain'];
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// True when the message matches the EIP-4361 (Sign-In With
  /// Ethereum) pattern. UI can render a friendlier "Login to
  /// example.com" prompt with [siweFields] instead of the raw
  /// message body.
  bool get isSiwe => _v?['isSiwe'] == true;

  /// True for Sign-In With Solana (same pattern as SIWE, different
  /// chain family).
  bool get isSiws => _v?['isSiws'] == true;

  /// Parsed SIWE/SIWS fields when [isSiwe] / [isSiws] is true:
  /// `domain`, `address`, `uri`, `version`, `chainid`, `nonce`,
  /// `issuedat`, `expirationtime`, `notbefore`, `requestid`,
  /// `resources`. Lowercase keys with no spaces.
  Map<String, String> get siweFields {
    final v = _v?['siweFields'];
    if (v is Map) {
      return v.map((k, val) => MapEntry(k.toString(), val.toString()));
    }
    return const {};
  }

  /// Advisories the approval sheet should surface.
  List<TxSignWarning> get warnings {
    final list = _v?['warnings'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => TxSignWarning.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// `0x`-hex signature for EVM, base64 for mpurse, or
  /// `{signature, publicKey}` map for Solana — depends on [method].
  /// Null while pending.
  dynamic get signResult => result;
}

/// One observable transfer or approval — a row in
/// [TransactionSignRequest.effects].
class TxSignEffect {
  /// `native_transfer` | `erc20_transfer` | `erc20_approve` |
  /// `spl_transfer` | `bitcoin_output`.
  final String type;

  /// Token contract / mint address. Empty for native transfers.
  final String token;

  /// Sender address (chain-native format).
  final String from;

  /// Recipient address (chain-native format).
  final String to;

  /// Amount in token base units, as a decimal-integer string.
  final String amount;

  const TxSignEffect({
    required this.type,
    this.token = '',
    this.from = '',
    this.to = '',
    this.amount = '',
  });

  factory TxSignEffect.fromJson(Map<String, dynamic> json) => TxSignEffect(
        type: (json['type'] as String?) ?? '',
        token: (json['token'] as String?) ?? '',
        from: (json['from'] as String?) ?? '',
        to: (json['to'] as String?) ?? '',
        amount: (json['amount'] as String?) ?? '',
      );

  bool get isNative => type == 'native_transfer';
  bool get isErc20Transfer => type == 'erc20_transfer';
  bool get isErc20Approve => type == 'erc20_approve';
  bool get isSplTransfer => type == 'spl_transfer';
  bool get isBitcoinOutput => type == 'bitcoin_output';
}

/// Signed native-balance delta for one address — a row in
/// [TransactionSignRequest.balanceChanges]. Negative = loss.
class TxSignBalanceChange {
  final String address;

  /// Signed decimal integer string (wei / lamports / sats).
  final String delta;

  const TxSignBalanceChange({required this.address, required this.delta});

  factory TxSignBalanceChange.fromJson(Map<String, dynamic> json) =>
      TxSignBalanceChange(
        address: (json['address'] as String?) ?? '',
        delta: (json['delta'] as String?) ?? '0',
      );

  /// True if this address LOST balance.
  bool get isLoss => delta.startsWith('-');
}

/// Advisory finding about a sign request. Stable [code] values
/// drive UI copy; [severity] is `"info"` / `"warn"` / `"block"`.
class TxSignWarning {
  final String code;
  final String severity;
  final String message;
  final String field;

  const TxSignWarning({
    required this.code,
    required this.severity,
    required this.message,
    this.field = '',
  });

  factory TxSignWarning.fromJson(Map<String, dynamic> json) => TxSignWarning(
        code: (json['code'] as String?) ?? '',
        severity: (json['severity'] as String?) ?? 'warn',
        message: (json['message'] as String?) ?? '',
        field: (json['field'] as String?) ?? '',
      );

  bool get isInfo => severity == 'info';
  bool get isWarn => severity == 'warn';
  bool get isBlocking => severity == 'block';
}

/// One input or output of a Bitcoin-family tx.
class TxSignBitcoinIO {
  final String address;
  final int amount;
  final String script;
  final String txid;
  final int vout;

  const TxSignBitcoinIO({
    this.address = '',
    this.amount = 0,
    this.script = '',
    this.txid = '',
    this.vout = 0,
  });

  factory TxSignBitcoinIO.fromJson(Map<String, dynamic> json) =>
      TxSignBitcoinIO(
        address: (json['address'] as String?) ?? '',
        amount: (json['amount'] as num?)?.toInt() ?? 0,
        script: (json['script'] as String?) ?? '',
        txid: (json['txid'] as String?) ?? '',
        vout: (json['vout'] as num?)?.toInt() ?? 0,
      );
}

/// dApp is asking to add a new network to the user's configuration
/// (`wallet_addEthereumChain`). Approval saves the Network without
/// activating it — distinct from `ChainSwitchRequest` which also
/// changes the active network.
///
/// Rich payload flags let the UI warn on suspicious proposals:
/// - [network] — the proposed descriptor
/// - [isKnown] — true when chainId is in libwallet's static chain
///   registry (chainid.network). False = totally novel chain
/// - [knownName] — the name the registry associates with this
///   chainId. Mismatch vs. [network.name] is a phishing vector
///   ("chain 1 with name MyMainnet" = definitely not Ethereum)
/// - [alreadyExists] — true when the chain is already registered;
///   approval is a no-op
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

  Map<String, dynamic>? get _v {
    final v = rawValue;
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// Proposed network descriptor.
  Network? get network {
    final v = _v?['network'];
    if (v is Map) return Network.fromJson(Map<String, dynamic>.from(v));
    // Backward-compat: pre-rich shape stored the Network directly
    // as rawValue.
    if (rawValue is Map) {
      return Network.fromJson(Map<String, dynamic>.from(rawValue as Map));
    }
    return null;
  }

  /// True when the chainId appears in libwallet's static chain
  /// metadata.
  bool get isKnown => _v?['isKnown'] == true;

  /// The registered name for this chainId, when [isKnown]. Compare
  /// to [network.name] — a mismatch is suspicious.
  String get knownName => _v?['knownName'] as String? ?? '';

  /// True when the wallet already has this network registered.
  bool get alreadyExists => _v?['alreadyExists'] == true;

  /// True when [network.name] differs from [knownName] — the dApp
  /// is proposing a different label for a well-known chainId.
  /// Surface as a strong warning.
  bool get nameMismatch {
    if (!isKnown || knownName.isEmpty) return false;
    final n = network?.name ?? '';
    return n.isNotEmpty && n != knownName;
  }
}


/// Every network switch comes through this single request type —
/// whether the dApp explicitly asked for a specific chain
/// (`wallet_switchEthereumChain`) or triggered it implicitly by
/// calling an action method on a chain family that doesn't match
/// the wallet's current network.
///
/// Two shapes distinguished by which fields are populated:
///
/// **Pre-specified target** (dApp named a chain):
/// [targetNetwork] is non-null. Render a simple confirm sheet
/// ("Switch to Polygon?"). When [isNewNetwork] is true, the target
/// isn't in the wallet yet and approval implies Add + Switch —
/// render "Add and switch to Polygon?" with appropriate warning
/// copy. [candidateNetworks] is empty in this shape.
///
/// **Picker** (cross-family action method):
/// [targetNetwork] null, [candidateNetworks] populated. Render a
/// picker so the user chooses one.
///
/// [candidateAccounts] is always populated (accounts whose curve
/// is compatible with [requestedFamily]); the user always picks an
/// account to bind to the dApp on the chosen chain.
///
/// Approve:
///
/// ```dart
/// // Pre-specified target — Network can be omitted:
/// await client.requests.approve(
///   req.id,
///   accounts: [accountId],
/// );
///
/// // Picker — Network is required:
/// await client.requests.approve(
///   req.id,
///   network: pickedNetwork.id,
///   accounts: [pickedAccount.id],
/// );
/// ```
///
/// On approval, libwallet atomically: saves the network if new,
/// calls SetCurrent, and connects the dApp to the chosen account.
/// Hosts do NOT need to call `client.networks.setCurrent(...)`
/// separately.
class ChainSwitchRequest extends PendingRequest {
  ChainSwitchRequest._(Map<String, dynamic> j)
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
  String get type => 'chain_switch';

  Map<String, dynamic>? get _v {
    final v = rawValue;
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// Which chain family the dApp's method requires:
  /// `"evm"` / `"solana"` / `"bitcoin"`.
  String get requestedFamily => _v?['requestedFamily'] as String? ?? '';

  /// The Web3 method that triggered the prompt (e.g.
  /// `"eth_sendTransaction"`, `"wallet_switchEthereumChain"`,
  /// `"solana_signTransaction"`). Useful for UI copy.
  String get requestedMethod => _v?['requestedMethod'] as String? ?? '';

  /// The wallet's currently active network (context for the UI).
  /// Null when the request payload is malformed.
  Network? get currentNetwork {
    final v = _v?['currentNetwork'];
    return v is Map ? Network.fromJson(Map<String, dynamic>.from(v)) : null;
  }

  /// Set when the dApp named a specific chain
  /// (`wallet_switchEthereumChain`). UI shows a single-option
  /// confirm sheet against this network. Null in picker mode.
  Network? get targetNetwork {
    final v = _v?['targetNetwork'];
    return v is Map ? Network.fromJson(Map<String, dynamic>.from(v)) : null;
  }

  /// True when [targetNetwork] is set and not yet saved in the
  /// wallet — approval implies Add + Switch. Render with
  /// appropriate warning copy (user is agreeing to both persist
  /// AND switch to a brand-new chain).
  bool get isNewNetwork => _v?['isNewNetwork'] == true;

  /// Networks of [requestedFamily] the user can choose from when
  /// [targetNetwork] is null (picker mode). Empty in confirm mode.
  List<Network> get candidateNetworks {
    final list = _v?['candidateNetworks'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => Network.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }

  /// Accounts whose key curve is compatible with [requestedFamily]
  /// (secp256k1 for EVM/Bitcoin, ed25519 for Solana). Always
  /// populated; the user picks one.
  List<Account> get candidateAccounts {
    final list = _v?['candidateAccounts'];
    if (list is! List) return const [];
    return list
        .whereType<Map>()
        .map((e) => Account.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }
}

/// dApp is asking the wallet to start tracking a custom token
/// (`wallet_watchAsset`, EIP-747).
///
/// Typed accessors for the standard EIP-747 fields plus wallet-side
/// flags:
/// - [assetType] — `"ERC20"` / `"ERC721"` / `"ERC1155"`
/// - [address] / [symbol] / [decimals] / [image] — display metadata
/// - [tokenId] — only for ERC-721 / ERC-1155 (empty for fungibles)
/// - [addressLooksInvalid] — true when address doesn't parse as an
///   EVM 20-byte hex; phishing heuristic
/// - [raw] — the original params map, for forward-compat
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

  Map<String, dynamic>? get _v {
    final v = rawValue;
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// Asset type as sent by the dApp: `"ERC20"` / `"ERC721"` /
  /// `"ERC1155"`. Defaults to `"ERC20"` per EIP-747.
  String get assetType => _v?['type'] as String? ?? 'ERC20';

  /// Token contract address (0x-prefixed on EVM).
  String get address => _v?['address'] as String? ?? '';

  /// Display symbol (e.g. `"USDC"`).
  String get symbol => _v?['symbol'] as String? ?? '';

  /// Token decimals (fungibles). 0 for NFTs.
  int get decimals => (_v?['decimals'] as num?)?.toInt() ?? 0;

  /// Image URL for the token icon. May be empty.
  String get image => _v?['image'] as String? ?? '';

  /// Token id — only set for ERC-721 / ERC-1155.
  String get tokenId => _v?['tokenId'] as String? ?? '';

  /// True when [address] doesn't parse as a valid EVM address.
  /// Surface as a strong warning.
  bool get addressLooksInvalid => _v?['addressLooksInvalid'] == true;

  /// True when libwallet already tracks this (network, address).
  /// Approval would be a no-op.
  bool get isAlreadyTracked => _v?['isAlreadyTracked'] == true;

  /// Original params object — preserved for fields EIP-747 adds
  /// later. Most UIs won't need this.
  Map<String, dynamic>? get raw {
    final v = _v?['raw'];
    return v is Map ? Map<String, dynamic>.from(v) : null;
  }

  /// Legacy asset getter — returns [raw] for backward-compat.
  Map<String, dynamic>? get asset => raw ?? _v;
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
