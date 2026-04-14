import '../client/transport.dart';
import '../models/wc_session.dart';

/// WalletConnect v2 integration.
///
/// Covers the full lifecycle: start the relay connection, pair with a
/// dApp via a `wc:...` URI, approve/reject the resulting session
/// proposal, respond to incoming `wc_sessionRequest` messages, push
/// chain/account updates, and disconnect.
///
/// Session proposals arrive as `wc_session_propose` events on
/// `client.events` (or via the sugar `client.walletConnect.proposals`
/// stream). Each in-flight signing/send request arrives as a
/// `wc_session_request` event (see `client.walletConnect.requests`).
///
/// Typical host flow:
///
/// 1. `await client.walletConnect.start(projectId: '…');`
/// 2. User pastes a QR-scanned URI, host calls `pair(uri)`.
/// 3. A proposal arrives on `proposals` — host shows a sheet, user
///    picks accounts, then host calls `approveSession(...)` or
///    `rejectSession(...)`.
/// 4. Requests arrive on `requests`. For signing methods, either
///    route through `client.web3.request(...)` and call `respond(...)`,
///    or let the built-in `autoRouteRequests(...)` helper do it.
/// 5. When the user changes the current network or connected accounts,
///    call `emitEvent(...)` on each active session so dApps see the
///    update in real time.
class WalletConnectApi {
  final Transport _conn;

  WalletConnectApi(this._conn);

  /// Open the relay WebSocket. [projectId] is the WalletConnect Cloud
  /// project id for your wallet. [relayUrl] defaults to
  /// `wss://relay.walletconnect.com`. Safe to call multiple times —
  /// subsequent calls after a successful start return an error.
  Future<void> start({
    required String projectId,
    String? relayUrl,
  }) async {
    await _conn.request('WalletConnect:start', 'POST', {
      'ProjectID': projectId,
      if (relayUrl != null) 'RelayURL': relayUrl,
    });
  }

  /// Close the relay connection. In-flight proposals/requests are dropped.
  Future<void> stop() async {
    await _conn.request('WalletConnect:stop', 'POST');
  }

  /// Start pairing from a `wc:TOPIC@2?relay-protocol=irn&symKey=...` URI.
  /// Returns the pairing topic. A `wc_session_propose` event will arrive
  /// shortly with the dApp's metadata.
  Future<String> pair(String uri) async {
    final data = await _conn.request('WalletConnect:pair', 'POST', {
      'URI': uri,
    });
    return (data as Map)['pairingTopic'] as String;
  }

  /// List all non-disconnected WalletConnect sessions (pairing +
  /// proposed + active).
  Future<List<WcSession>> sessions() async {
    final data = await _conn.request('WalletConnect:sessions', 'POST');
    if (data == null) return [];
    return (data as List)
        .map((e) => WcSession.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Approve a session proposal. [accounts] is a CAIP-10 list, e.g.
  /// `['eip155:1:0xabc...', 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:someBase58']`.
  /// [methods] and [events] let the host restrict the approved surface;
  /// leave empty to echo the dApp's request verbatim.
  Future<void> approveSession(
    String pairingTopic, {
    required List<String> accounts,
    List<String>? methods,
    List<String>? events,
  }) async {
    await _conn.request('WalletConnect:approveSession', 'POST', {
      'PairingTopic': pairingTopic,
      'Accounts': accounts,
      if (methods != null) 'Methods': methods,
      if (events != null) 'Events': events,
    });
  }

  /// Reject a session proposal with a JSON-RPC error.
  Future<void> rejectSession(
    String pairingTopic, {
    int code = 5000,
    String message = 'User rejected',
  }) async {
    await _conn.request('WalletConnect:rejectSession', 'POST', {
      'PairingTopic': pairingTopic,
      'Code': code,
      'Message': message,
    });
  }

  /// Respond to an incoming `wc_sessionRequest` with a successful result.
  Future<void> respond(String topic, int id, dynamic result) async {
    await _conn.request('WalletConnect:respond', 'POST', {
      'Topic': topic,
      'ID': id,
      'Result': result,
    });
  }

  /// Respond to an incoming `wc_sessionRequest` with a JSON-RPC error.
  Future<void> respondError(
    String topic,
    int id, {
    int code = 5000,
    String message = 'User rejected',
  }) async {
    await _conn.request('WalletConnect:respondError', 'POST', {
      'Topic': topic,
      'ID': id,
      'Code': code,
      'Message': message,
    });
  }

  /// Push a `wc_sessionEvent` on [topic] — used for `chainChanged` and
  /// `accountsChanged` notifications (CAIP-2 chain id, e.g. `eip155:1`).
  Future<void> emitEvent({
    required String topic,
    required String name,
    required dynamic data,
    required String chainId,
  }) async {
    await _conn.request('WalletConnect:emitEvent', 'POST', {
      'Topic': topic,
      'Name': name,
      'Data': data,
      'ChainID': chainId,
    });
  }

  /// Disconnect a session (sends `wc_sessionDelete` to the peer and
  /// marks it disconnected locally).
  Future<void> disconnect(String topic) async {
    await _conn.request('WalletConnect:disconnect', 'POST', {
      'Topic': topic,
    });
  }
}
