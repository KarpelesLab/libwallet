/// Verified agent identity returned by `ClawdWallet:pair`.
///
/// Comes from the Spot pair-response after libwallet has confirmed
/// `agentSpotId` matches the `agent` parameter in the pairing URL — at the
/// point this object reaches the host app, the identity is already
/// cryptographically tied to the URL the user opened.
///
/// Pass [agentSpotId] into the subsequent `Crypto/WalletSign:newAgent` call
/// as the canonical agent peer id for the keygen ceremony. The other fields
/// are presentational (default name + agent version banner) and forward-
/// compatibility ([capabilities]).
class AgentIdentity {
  /// Agent's Spot identity in the standard `k.<base64url>` form. Already
  /// verified equal to the `agent` query parameter in the pairing URL.
  final String agentSpotId;

  /// Default wallet name proposed by the agent (e.g. its `moniker`).
  /// May be empty — show the user a regular blank field if so.
  final String suggestedName;

  /// Informational version string the agent identifies as. Show on the
  /// confirmation screen so the user can sanity-check what they're
  /// pairing with. May be empty.
  final String agentVersion;

  /// Forward-compatibility object. Stage 1 callers should treat this as
  /// opaque and pass it through unchanged. Tolerate unknown keys.
  final Map<String, dynamic> capabilities;

  const AgentIdentity({
    required this.agentSpotId,
    this.suggestedName = '',
    this.agentVersion = '',
    this.capabilities = const {},
  });

  factory AgentIdentity.fromJson(Map<String, dynamic> json) {
    final caps = json['capabilities'];
    return AgentIdentity(
      agentSpotId: (json['agent_spot_id'] as String?) ?? '',
      suggestedName: (json['suggested_name'] as String?) ?? '',
      agentVersion: (json['agent_version'] as String?) ?? '',
      capabilities: caps is Map ? Map<String, dynamic>.from(caps) : const {},
    );
  }

  @override
  String toString() => 'AgentIdentity($agentSpotId'
      '${suggestedName.isNotEmpty ? ', "$suggestedName"' : ''}'
      '${agentVersion.isNotEmpty ? ', $agentVersion' : ''})';
}
