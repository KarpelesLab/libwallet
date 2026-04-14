/// A WalletConnect v2 session record (pairing, proposed, or active).
class WcSession {
  /// Local database ID (xuid `wcs-...`).
  final String id;

  /// The relay subscription topic currently bound to this record.
  /// Pairing topic while proposing, session topic once settled.
  final String topic;

  /// The original pairing topic (stays the same across the lifecycle).
  final String pairingTopic;

  /// `pairing` / `proposed` / `active` / `disconnected`.
  final String state;

  /// dApp metadata (name, description, url, icons). May be empty
  /// before the `wc_sessionPropose` arrives.
  final Map<String, dynamic> peerMetadata;

  /// Approved namespaces, e.g.
  /// `{eip155: {accounts: [...], methods: [...], events: [...]}}`.
  /// Empty until the session is active.
  final Map<String, dynamic> namespaces;

  /// Session expiry (default 7 days from approval for WC v2).
  final DateTime? expiry;

  final DateTime? created;
  final DateTime? updated;

  const WcSession({
    required this.id,
    required this.topic,
    required this.pairingTopic,
    required this.state,
    required this.peerMetadata,
    required this.namespaces,
    this.expiry,
    this.created,
    this.updated,
  });

  factory WcSession.fromJson(Map<String, dynamic> json) {
    DateTime? parseTime(dynamic v) {
      if (v is String && v.isNotEmpty) {
        try {
          return DateTime.parse(v);
        } catch (_) {}
      }
      return null;
    }

    return WcSession(
      id: (json['Id'] as String?) ?? '',
      topic: (json['Topic'] as String?) ?? '',
      pairingTopic: (json['PairingTopic'] as String?) ?? '',
      state: (json['State'] as String?) ?? '',
      peerMetadata: json['PeerMetadata'] is Map
          ? Map<String, dynamic>.from(json['PeerMetadata'] as Map)
          : const <String, dynamic>{},
      namespaces: json['Namespaces'] is Map
          ? Map<String, dynamic>.from(json['Namespaces'] as Map)
          : const <String, dynamic>{},
      expiry: parseTime(json['Expiry']),
      created: parseTime(json['Created']),
      updated: parseTime(json['Updated']),
    );
  }

  bool get isPairing => state == 'pairing';
  bool get isProposed => state == 'proposed';
  bool get isActive => state == 'active';
  bool get isDisconnected => state == 'disconnected';

  /// Convenience — dApp name from peerMetadata.
  String get peerName => (peerMetadata['name'] as String?) ?? '';
}

/// A pending `wc_sessionPropose` delivered via the `wc_session_propose`
/// event. Fields come straight from the broadcast event data.
class WcSessionProposal {
  /// Pairing topic the proposal arrived on — pass to
  /// `approveSession` / `rejectSession`.
  final String pairingTopic;

  /// dApp-chosen proposal id (echoed in the JSON-RPC response).
  final int proposalId;

  /// dApp metadata (name, description, url, icons).
  final Map<String, dynamic> proposer;

  /// Full proposal payload — `{requiredNamespaces, optionalNamespaces,
  /// sessionProperties, …}`. Useful to show the user which chains and
  /// methods the dApp is asking for.
  final Map<String, dynamic> proposal;

  const WcSessionProposal({
    required this.pairingTopic,
    required this.proposalId,
    required this.proposer,
    required this.proposal,
  });

  factory WcSessionProposal.fromJson(Map<String, dynamic> json) => WcSessionProposal(
        pairingTopic: (json['pairingTopic'] as String?) ?? '',
        proposalId: (json['proposalId'] as num?)?.toInt() ?? 0,
        proposer: json['proposer'] is Map
            ? Map<String, dynamic>.from(json['proposer'] as Map)
            : const <String, dynamic>{},
        proposal: json['proposal'] is Map
            ? Map<String, dynamic>.from(json['proposal'] as Map)
            : const <String, dynamic>{},
      );

  String get name => (proposer['name'] as String?) ?? '';
  String get url => (proposer['url'] as String?) ?? '';
  List<String> get icons =>
      (proposer['icons'] as List?)?.whereType<String>().toList() ?? const [];
}

/// A pending `wc_sessionRequest` delivered via the `wc_session_request`
/// event — a JSON-RPC call the dApp wants the wallet to handle.
class WcSessionRequest {
  /// Session topic the request arrived on — pass to `respond` /
  /// `respondError`.
  final String topic;

  /// JSON-RPC id, also needed for the response.
  final int id;

  /// Method name (EIP-1193-style, e.g. `personal_sign`,
  /// `eth_sendTransaction`, `solana_signTransaction`).
  final String method;

  /// CAIP-2 chain id the dApp is calling against, e.g. `eip155:1`.
  final String chainId;

  /// Method-specific parameters (shape depends on [method]).
  final dynamic params;

  /// Peer metadata copied from the session for convenience.
  final Map<String, dynamic> peerMetadata;

  const WcSessionRequest({
    required this.topic,
    required this.id,
    required this.method,
    required this.chainId,
    required this.params,
    required this.peerMetadata,
  });

  factory WcSessionRequest.fromJson(Map<String, dynamic> json) => WcSessionRequest(
        topic: (json['topic'] as String?) ?? '',
        id: (json['id'] as num?)?.toInt() ?? 0,
        method: (json['method'] as String?) ?? '',
        chainId: (json['chainId'] as String?) ?? '',
        params: json['params'],
        peerMetadata: json['peerMetadata'] is Map
            ? Map<String, dynamic>.from(json['peerMetadata'] as Map)
            : const <String, dynamic>{},
      );
}
