import 'dart:convert';
import 'dart:typed_data';

import '../client/transport.dart';
import '../models/account.dart';
import '../models/wallet.dart';

/// Interop with air-gapped signers (Keystone, Coldcard, Passport, SeedSigner…)
/// over QR codes: BC-UR (`ur:…`, fountain-coded animated QRs) and BBQr
/// (`B$…`). libwallet handles only the *strings*; the app renders them as QR
/// codes and scans the signer's answer.
///
/// Typical flow:
///
/// 1. **Add the signer's accounts** — scan its key export (Keystone
///    `crypto-multi-accounts`, Coldcard JSON, a zpub…):
///    ```dart
///    final scan = await client.airgap.newDecoder();
///    // for each camera frame:
///    final p = await scan.feed(frameText);
///    showProgress(p.percent);
///    if (p.complete) {
///      final preview = await client.airgap.parseKeys(decoderId: scan.id);
///      final imported = await client.airgap.importKeys(decoderId: scan.id);
///    }
///    ```
/// 2. **Send** from one of those accounts — build the unsigned request, show
///    its frames (loop them), scan the signer's answer, submit:
///    ```dart
///    final req = await client.airgap.signRequest(account: id,
///        transaction: {'To': addr, 'Amount': 50000});
///    animateQr(req.parts);
///    final scan = await client.airgap.newDecoder();
///    … feed frames until complete …
///    final tx = await client.airgap.submitSignature(
///        decoderId: scan.id, requestId: req.requestId, broadcast: true);
///    ```
/// The signer only ever returns the signature (eth/sol) or the signed PSBT
/// (bitcoin); libwallet assembles and (optionally) broadcasts the transaction.
class AirgapApi {
  final Transport _conn;

  AirgapApi(this._conn);

  // ── Scanning ──────────────────────────────────────────────────────────────

  /// Create a decoder context: feed it one scanned frame at a time.
  Future<AirgapDecoder> newDecoder() async {
    final data = await _conn.request('Airgap:decoderNew', 'POST', {});
    return AirgapDecoder._(this, (data as Map)['Id'] as String);
  }

  Future<AirgapProgress> decoderFeed(String id, String frame) async {
    final data = await _conn
        .request('Airgap:decoderFeed', 'POST', {'Id': id, 'Part': frame});
    return AirgapProgress.fromJson(Map<String, dynamic>.from(data as Map));
  }

  Future<AirgapProgress> decoderStatus(String id) async {
    final data = await _conn.request('Airgap:decoderStatus', 'POST', {'Id': id});
    return AirgapProgress.fromJson(Map<String, dynamic>.from(data as Map));
  }

  Future<void> decoderDelete(String id) =>
      _conn.request('Airgap:decoderDelete', 'POST', {'Id': id});

  /// Decode a complete set of frames in one call (all frames already in hand).
  Future<AirgapProgress> decode(List<String> frames) async {
    final data = await _conn.request('Airgap:decode', 'POST', {'Parts': frames});
    return AirgapProgress.fromJson(Map<String, dynamic>.from(data as Map));
  }

  // ── Displaying ────────────────────────────────────────────────────────────

  /// Frame an arbitrary payload for display. UR: [urType] + [cbor] (or
  /// [bytes] for the `bytes` type). BBQr: [bytes] + [fileType] letter
  /// (`P` psbt, `T` tx, `J` json, `C` cbor, `U` text, `B` binary).
  /// Frames come back uppercase, ready for QR alphanumeric mode.
  Future<List<String>> encode({
    String transport = 'ur',
    String? urType,
    Uint8List? cbor,
    Uint8List? bytes,
    String? fileType,
    int? maxFragmentLen,
    int? maxPartLen,
    int? extraParts,
    bool compress = true,
  }) async {
    final data = await _conn.request('Airgap:encode', 'POST', {
      'Transport': transport,
      if (urType != null) 'Type': urType,
      if (cbor != null) 'Cbor': _hex(cbor),
      if (bytes != null) 'Bytes': base64.encode(bytes),
      if (fileType != null) 'FileType': fileType,
      if (maxFragmentLen != null) 'MaxFragmentLen': maxFragmentLen,
      if (maxPartLen != null) 'MaxPartLen': maxPartLen,
      if (extraParts != null) 'ExtraParts': extraParts,
      'Compress': compress,
    });
    return List<String>.from((data as Map)['parts'] as List);
  }

  // ── Keys ──────────────────────────────────────────────────────────────────

  /// Preview the keys in a scanned export without persisting anything. Pass
  /// exactly one of [decoderId] (a completed context), [frames], or [payload]
  /// (a pasted string: zpub, descriptor, JSON export, single UR).
  Future<AirgapExport> parseKeys({
    String? decoderId,
    List<String>? frames,
    String? payload,
  }) async {
    final data = await _conn.request('Airgap:parseKeys', 'POST',
        _payloadParams(decoderId, frames, payload));
    return AirgapExport.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Import the keys as a signer wallet (`Protocol: airgap`) with one
  /// watch-only account per usable key. [ethAccounts] = how many …/0/i leaf
  /// accounts to derive from an ethereum xpub (default 1). [selectPaths]
  /// limits the import to those key paths (as reported by [parseKeys]).
  Future<AirgapImportResult> importKeys({
    String? decoderId,
    List<String>? frames,
    String? payload,
    String? name,
    int? ethAccounts,
    List<String>? selectPaths,
  }) async {
    final params = _payloadParams(decoderId, frames, payload);
    if (name != null) params['Name'] = name;
    if (ethAccounts != null) params['EthAccounts'] = ethAccounts;
    if (selectPaths != null) params['Select'] = selectPaths;
    final data = await _conn.request('Airgap:importKeys', 'POST', params);
    return AirgapImportResult.fromJson(Map<String, dynamic>.from(data as Map));
  }

  // ── Signing ───────────────────────────────────────────────────────────────

  /// Build the unsigned request for [account] (an airgap account). [transaction]
  /// uses the same shape as `TransactionApi.signAndSend`: bitcoin `{To, Amount
  /// (sats), FeeRate?, ChainId?, UTXOs?}`, ethereum `{to, value, data?, nonce?,
  /// gas?, gasPrice? | maxFeePerGas?+maxPriorityFeePerGas?, chainId?}`, solana
  /// `{to, value (lamports), recentBlockhash?}` or `{message}` (base58/base64).
  ///
  /// Missing nonce/gas/fees/blockhash/UTXOs are filled from the node ([rpc] or
  /// [network], else the account chain's current/default network) unless
  /// [offline] is true, in which case the transaction must be complete.
  Future<AirgapSignRequest> signRequest({
    required String account,
    required Map<String, dynamic> transaction,
    String transport = 'ur',
    String? rpc,
    String? network,
    bool offline = false,
    int? maxFragmentLen,
    int? maxPartLen,
    int? extraParts,
  }) async {
    final data = await _conn.request('Airgap:signRequest', 'POST', {
      'Account': account,
      'Transaction': transaction,
      'Transport': transport,
      if (rpc != null) 'RPC': rpc,
      if (network != null) 'Network': network,
      if (offline) 'Offline': true,
      if (maxFragmentLen != null) 'MaxFragmentLen': maxFragmentLen,
      if (maxPartLen != null) 'MaxPartLen': maxPartLen,
      if (extraParts != null) 'ExtraParts': extraParts,
    });
    return AirgapSignRequest.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Turn the signer's answer (`eth-signature`, `sol-signature`, a signed
  /// `crypto-psbt`/BBQr PSBT, or a bare hex/base64 signature) into a signed
  /// transaction. [requestId] is required when the answer carries none
  /// (signed PSBTs, bare signatures). With [broadcast], the tx is sent through
  /// [rpc]/[network] (or the chain's current network).
  Future<AirgapSignedTransaction> submitSignature({
    String? decoderId,
    List<String>? frames,
    String? payload,
    String? requestId,
    bool broadcast = false,
    String? rpc,
    String? network,
  }) async {
    final params = _payloadParams(decoderId, frames, payload);
    if (requestId != null) params['RequestId'] = requestId;
    if (broadcast) params['Broadcast'] = true;
    if (rpc != null) params['RPC'] = rpc;
    if (network != null) params['Network'] = network;
    final data = await _conn.request('Airgap:submitSignature', 'POST', params);
    return AirgapSignedTransaction.fromJson(
        Map<String, dynamic>.from(data as Map));
  }

  /// An outstanding request (requests expire after 24h).
  Future<Map<String, dynamic>> pending(String requestId) async {
    final data =
        await _conn.request('Airgap:pending', 'POST', {'RequestId': requestId});
    return Map<String, dynamic>.from(data as Map);
  }

  Map<String, dynamic> _payloadParams(
      String? decoderId, List<String>? frames, String? payload) {
    final n = [decoderId, frames, payload].where((x) => x != null).length;
    if (n != 1) {
      throw ArgumentError(
          'pass exactly one of decoderId, frames or payload (got $n)');
    }
    return {
      if (decoderId != null) 'DecoderId': decoderId,
      if (frames != null) 'Parts': frames,
      if (payload != null) 'Payload': payload,
    };
  }

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

/// A scanning session: feed frames as the camera delivers them.
class AirgapDecoder {
  final AirgapApi _api;
  final String id;
  AirgapProgress? last;

  AirgapDecoder._(this._api, this.id);

  /// Feed one frame; returns the updated progress. Duplicate frames are
  /// ignored; a frame from another payload throws.
  Future<AirgapProgress> feed(String frame) async {
    last = await _api.decoderFeed(id, frame);
    return last!;
  }

  bool get complete => last?.complete ?? false;

  Future<void> close() => _api.decoderDelete(id);
}

/// Reassembly progress after a frame.
class AirgapProgress {
  /// `ur` | `bbqr` | `raw`, once the first frame set it.
  final String? kind;
  /// Payload fragments recovered / needed. For a UR the decoder may need a few
  /// more frames than `expected` when early frames were missed.
  final int received;
  final int expected;
  /// Distinct frames fed.
  final int frames;
  /// 0–100.
  final int percent;
  final bool complete;
  /// UR type (`crypto-psbt`, `eth-signature`…) once known.
  final String? urType;
  /// BBQr file type letter once known.
  final String? fileType;
  /// Only when complete: `{ur_type, cbor, decoded}` / `{file_type, data,
  /// text}` / `{text}`.
  final Map<String, dynamic>? payload;

  AirgapProgress({
    required this.kind,
    required this.received,
    required this.expected,
    required this.frames,
    required this.percent,
    required this.complete,
    this.urType,
    this.fileType,
    this.payload,
  });

  factory AirgapProgress.fromJson(Map<String, dynamic> j) => AirgapProgress(
        kind: j['kind'] as String?,
        received: (j['received'] as num?)?.toInt() ?? 0,
        expected: (j['expected'] as num?)?.toInt() ?? 0,
        frames: (j['frames'] as num?)?.toInt() ?? 0,
        percent: (j['percent'] as num?)?.toInt() ?? 0,
        complete: j['complete'] == true,
        urType: j['ur_type'] as String?,
        fileType: j['file_type'] as String?,
        payload: j['payload'] == null
            ? null
            : Map<String, dynamic>.from(j['payload'] as Map),
      );
}

/// One key found in a signer export.
class AirgapKey {
  /// `bitcoin` | `ethereum` | `solana` | `unsupported`.
  final String chain;
  final String curve;
  final int? coinType;
  /// Full path from the signer's master, e.g. `m/84'/0'/0'`.
  final String path;
  final String? masterFingerprint;
  final String pubkey;
  final String? chainCode;
  /// Bitcoin script kind (`p2wpkh`, `p2sh:p2wpkh`, `p2pkh`, `p2tr`).
  final String script;
  /// The address this key maps to (first receive address for an xpub).
  final String address;
  final String? name;
  final String? note;
  /// Why the key is `unsupported`, when it is.
  final String? reason;

  AirgapKey.fromJson(Map<String, dynamic> j)
      : chain = j['chain'] as String,
        curve = j['curve'] as String,
        coinType = (j['coin_type'] as num?)?.toInt(),
        path = j['path'] as String,
        masterFingerprint = j['master_fingerprint'] as String?,
        pubkey = j['pubkey'] as String,
        chainCode = j['chain_code'] as String?,
        script = j['script'] as String? ?? '',
        address = j['address'] as String? ?? '',
        name = j['name'] as String?,
        note = j['note'] as String?,
        reason = j['reason'] as String?;

  bool get usable => chain != 'unsupported';
}

/// A parsed key export.
class AirgapExport {
  /// `crypto-multi-accounts` | `crypto-account` | `crypto-hdkey` | `json` |
  /// `xpub` | `descriptor`.
  final String format;
  final String? masterFingerprint;
  final String? device;
  final String? deviceId;
  final String? version;
  final List<AirgapKey> keys;

  AirgapExport.fromJson(Map<String, dynamic> j)
      : format = j['format'] as String,
        masterFingerprint = j['master_fingerprint'] as String?,
        device = j['device'] as String?,
        deviceId = j['device_id'] as String?,
        version = j['version'] as String?,
        keys = (j['keys'] as List)
            .map((k) => AirgapKey.fromJson(Map<String, dynamic>.from(k as Map)))
            .toList();
}

class AirgapImportResult {
  final Wallet wallet;
  final List<Account> accounts;
  /// Keys that were not imported (unsupported chain), with reasons.
  final List<AirgapKey> skipped;

  AirgapImportResult.fromJson(Map<String, dynamic> j)
      : wallet = Wallet.fromJson(Map<String, dynamic>.from(j['wallet'] as Map)),
        accounts = (j['accounts'] as List)
            .map((a) => Account.fromJson(Map<String, dynamic>.from(a as Map)))
            .toList(),
        skipped = ((j['skipped'] as List?) ?? const [])
            .map((k) => AirgapKey.fromJson(Map<String, dynamic>.from(k as Map)))
            .toList();
}

/// An unsigned request to display to the signer.
class AirgapSignRequest {
  final String requestId;
  final String chain;
  final String account;
  /// `ur` | `bbqr`.
  final String transport;
  /// UR type (`crypto-psbt`, `eth-sign-request`, `sol-sign-request`) or the
  /// BBQr file type letter.
  final String format;
  /// The QR frames in display order — loop them as an animated QR.
  final List<String> parts;
  /// The unsigned material for other channels: `psbt` (base64), `signData`
  /// (hex), `message` (base58), plus a `summary`.
  final Map<String, dynamic> payload;

  AirgapSignRequest.fromJson(Map<String, dynamic> j)
      : requestId = j['request_id'] as String,
        chain = j['chain'] as String,
        account = j['account'] as String,
        transport = j['transport'] as String,
        format = j['format'] as String,
        parts = List<String>.from(j['parts'] as List),
        payload = Map<String, dynamic>.from(j['payload'] as Map);
}

/// A signed, assembled transaction.
class AirgapSignedTransaction {
  final String? requestId;
  final String chain;
  final String account;
  /// bitcoin/ethereum: `0x`-hex raw tx; solana: base58 raw tx.
  final String raw;
  /// bitcoin txid / ethereum tx hash / solana signature.
  final String id;
  /// The signature as received (hex), when the signer returned one.
  final String signature;
  /// bitcoin: the finalized PSBT (base64).
  final String? psbt;
  /// The node's broadcast result when `broadcast` was requested.
  final dynamic broadcast;

  AirgapSignedTransaction.fromJson(Map<String, dynamic> j)
      : requestId = j['request_id'] as String?,
        chain = j['chain'] as String,
        account = j['account'] as String? ?? '',
        raw = j['raw'] as String,
        id = j['id'] as String,
        signature = j['signature'] as String? ?? '',
        psbt = j['psbt'] as String?,
        broadcast = j['broadcast'];
}
