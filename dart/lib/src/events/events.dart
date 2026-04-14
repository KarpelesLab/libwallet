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
