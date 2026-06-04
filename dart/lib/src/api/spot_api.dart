import '../client/transport.dart';

/// Spot transport status — lets hosts positively poll connectivity
/// state instead of relying on the edge-triggered `online_status`
/// event (which is missed when Spot comes online before the host
/// subscribes to events).
class SpotApi {
  final Transport _conn;

  SpotApi(this._conn);

  /// Current Spot client state. Useful before [WalletApi.exportToDevice]
  /// to fail fast — a source whose Spot isn't online can't receive a
  /// pair request, so painting a pairing QR is pointless.
  ///
  /// As of libwallet 0.4.48, `exportToDevice` itself refuses to mint
  /// a pairing code when Spot isn't online (throws `local_offline`),
  /// so calling [status] beforehand is purely diagnostic.
  Future<SpotStatus> status() async {
    final data = await _conn.request('Spot:status', 'POST', const {});
    return SpotStatus.fromJson(Map<String, dynamic>.from(data as Map));
  }
}

/// Snapshot of the Spot client's connectivity.
class SpotStatus {
  /// True iff at least one Spot connection has completed its broker
  /// handshake — i.e. this node is reachable from peers.
  final bool online;

  /// Local node id (`k.<base64url>`). Stable across restarts because
  /// it's derived from the keys, so it's safe to display/log.
  final String targetId;

  /// Number of Spot broker connections this client has attempted.
  final int connectionsTotal;

  /// Subset of [connectionsTotal] that finished handshaking. Must be
  /// > 0 for [online] to be true.
  final int connectionsOnline;

  SpotStatus({
    required this.online,
    required this.targetId,
    required this.connectionsTotal,
    required this.connectionsOnline,
  });

  factory SpotStatus.fromJson(Map<String, dynamic> json) {
    final connections =
        Map<String, dynamic>.from(json['connections'] as Map? ?? const {});
    return SpotStatus(
      online: json['online'] as bool? ?? false,
      targetId: json['target_id'] as String? ?? '',
      connectionsTotal: (connections['total'] as num?)?.toInt() ?? 0,
      connectionsOnline: (connections['online'] as num?)?.toInt() ?? 0,
    );
  }
}
