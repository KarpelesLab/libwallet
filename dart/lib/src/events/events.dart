import '../models/account.dart';
import '../models/asset.dart';
import '../models/network.dart';
import '../models/request_event.dart' show PendingRequest;

/// Base class for events pushed from libwallet.
sealed class LibwalletEvent {
  final String event;
  final Map<String, dynamic> data;

  const LibwalletEvent(this.event, this.data);

  factory LibwalletEvent.fromJson(Map<String, dynamic> json) {
    final event = json['event'] as String? ?? '';
    final rawData = json['data'];
    final data = rawData is Map
        ? Map<String, dynamic>.from(rawData)
        : <String, dynamic>{};
    if (event == 'request') return RequestEvent(data);
    if (event == 'balances_changed') return BalancesChangedEvent(data);
    if (event == 'tx:history_updated') return TxHistoryUpdatedEvent(data);
    if (event == 'online_status') return OnlineStatusEvent(data);
    if (event.startsWith('js:')) return JsEvent(event, data);
    return UnknownEvent(event, data);
  }
}

/// A Web3 request pending user action. The event carries the full request
/// payload so the UI can render the prompt immediately without a follow-up
/// `Request/<id>` round-trip.
class RequestEvent extends LibwalletEvent {
  RequestEvent(Map<String, dynamic> data) : super('request', data);

  /// Unique request identifier. Present on every request event.
  String get requestId => data['request_id'] as String? ?? '';

  /// Fully-parsed request. Returns null only if the backend is older than
  /// the event-payload expansion (emits `request_id` only, no `request`).
  /// In that case the caller must fall back to `client.requests.get(id)`.
  PendingRequest? get request {
    final raw = data['request'];
    if (raw is Map) return PendingRequest.fromJson(Map<String, dynamic>.from(raw));
    return null;
  }
}

/// Balances changed on the current account / network. Fired by the
/// background poller every 60 s when anything differs from the
/// previous snapshot (or immediately on app resume from background).
class BalancesChangedEvent extends LibwalletEvent {
  BalancesChangedEvent(Map<String, dynamic> data)
      : super('balances_changed', data);

  /// Network the snapshot was taken against.
  Network? get network {
    final n = data['network'];
    if (n is Map) return Network.fromJson(Map<String, dynamic>.from(n));
    return null;
  }

  /// Account the snapshot was taken for.
  Account? get account {
    final a = data['account'];
    if (a is Map) return Account.fromJson(Map<String, dynamic>.from(a));
    return null;
  }

  /// Updated asset list — one entry per asset (native + any tokens the
  /// poller could enumerate on this chain family).
  List<Asset> get assets {
    final v = data['assets'];
    if (v is! List) return const [];
    return v
        .whereType<Map>()
        .map((e) => Asset.fromJson(Map<String, dynamic>.from(e)))
        .toList();
  }
}

/// Fires after a background sweep inserted new on-chain transactions
/// into the local Transaction table for the current (account, network).
/// The payload reports how many rows were added; the host can then
/// re-query `client.transactions.list()` to render them.
class TxHistoryUpdatedEvent extends LibwalletEvent {
  TxHistoryUpdatedEvent(Map<String, dynamic> data)
      : super('tx:history_updated', data);

  /// Account ID the backfill targeted (matches `Account.id`).
  String get accountId => (data['account'] as String?) ?? '';

  /// Network ID the backfill targeted (matches `Network.id`).
  String get networkId => (data['network'] as String?) ?? '';

  /// Number of new transactions inserted in this sweep.
  int get count => (data['count'] as num?)?.toInt() ?? 0;
}

/// Network connectivity status changed.
class OnlineStatusEvent extends LibwalletEvent {
  OnlineStatusEvent(Map<String, dynamic> data) : super('online_status', data);

  bool get isOnline => data['online'] == true;
}

/// A JavaScript-originated event (chainChanged, accountsChanged, etc.).
class JsEvent extends LibwalletEvent {
  JsEvent(super.event, super.data);

  String get jsEventName => event.substring(3); // strip "js:" prefix
}

/// An unrecognized event type.
class UnknownEvent extends LibwalletEvent {
  const UnknownEvent(super.event, super.data);
}
