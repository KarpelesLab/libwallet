import 'dart:async';
import 'dart:ffi';

import '../api/account_api.dart';
import '../api/asset_api.dart';
import '../api/contact_api.dart';
import '../api/crash_api.dart';
import '../api/info_api.dart';
import '../api/lifecycle_api.dart';
import '../api/name_api.dart';
import '../api/network_api.dart';
import '../api/nft_api.dart';
import '../api/remote_key_api.dart';
import '../api/request_api.dart';
import '../api/store_key_api.dart';
import '../api/token_api.dart';
import '../api/transaction_api.dart';
import '../api/wallet_api.dart';
import '../api/wallet_key_api.dart';
import '../api/wallet_connect_api.dart';
import '../api/web3_api.dart';
import '../api/web3_connection_api.dart';
import '../models/wc_session.dart';
import '../events/events.dart';
import '../models/request_event.dart';
import 'ffi_transport.dart';
import 'response.dart';
import 'transport.dart';

/// Main client for interacting with the libwallet Go library.
///
/// Provides typed API namespaces, event streams, and manages the underlying
/// FFI transport (direct Go function calls via `dart:ffi`).
///
/// ## Usage
///
/// ```dart
/// final client = LibwalletClient.initialize('/path/to/data');
/// final wallets = await client.wallets.list();
/// ```
class LibwalletClient {
  final Transport _transport;

  // API namespaces
  late final InfoApi info = InfoApi(_transport);
  late final LifecycleApi lifecycle = LifecycleApi(_transport);
  late final NameApi names = NameApi(_transport);
  late final StoreKeyApi storeKeys = StoreKeyApi(_transport);
  late final RemoteKeyApi remoteKeys = RemoteKeyApi(_transport);
  late final WalletApi wallets = WalletApi(_transport);
  late final WalletKeyApi walletKeys = WalletKeyApi(_transport);
  late final NetworkApi networks = NetworkApi(_transport);
  late final AccountApi accounts = AccountApi(_transport);
  late final AssetApi assets = AssetApi(_transport);
  late final NftApi nfts = NftApi(_transport);
  late final TransactionApi transactions = TransactionApi(_transport);
  late final TokenApi tokens = TokenApi(_transport);
  late final ContactApi contacts = ContactApi(_transport);
  late final Web3Api web3 = Web3Api(_transport);
  late final Web3ConnectionApi web3Connections =
      Web3ConnectionApi(_transport);
  late final RequestApi requests = RequestApi(_transport);
  late final WalletConnectApi walletConnect = WalletConnectApi(_transport);
  late final CrashApi crashes = CrashApi(_transport);

  LibwalletClient._(this._transport);

  /// Initialize the Go library via FFI.
  ///
  /// Loads the Go shared library and communicates via direct function
  /// calls — no sockets, no background-disconnection issues, no IPC.
  ///
  /// If [library] is provided, uses that DynamicLibrary. Otherwise loads
  /// the default platform library (`liblibwallet.so` / `.dylib` /
  /// `libwallet.framework` depending on OS).
  static LibwalletClient initialize(
    String dataDir, {
    DynamicLibrary? library,
  }) {
    final transport = FfiTransport.initialize(dataDir, library: library);
    return LibwalletClient._(transport);
  }

  /// Stream of all server-pushed events.
  Stream<LibwalletEvent> get events => _transport.events;

  /// Stream of raw Web3 request events. Prefer [pendingRequests] for a
  /// fully-parsed view; this stream is kept for advanced use cases that
  /// want access to the raw event payload.
  Stream<RequestEvent> get requestEvents =>
      events.where((e) => e is RequestEvent).cast<RequestEvent>();

  /// Stream of pending Web3 requests, fully parsed and ready to render.
  ///
  /// The push event now carries the full request payload, so consumers do
  /// NOT need to call `requests.get(id)` before deciding to approve or
  /// reject. If the backend is older and omits the payload, falls back
  /// to a one-time fetch per event.
  ///
  /// ```dart
  /// client.pendingRequests.listen((req) async {
  ///   switch (req) {
  ///     case ConnectRequest():
  ///       if (await showConnectSheet(req.host)) {
  ///         await client.requests.approve(req.id, accounts: [myAccount.id]);
  ///       } else {
  ///         await client.requests.reject(req.id);
  ///       }
  ///     case PersonalSignRequest():
  ///       final ok = await showSignSheet(req.messageAsText ?? 'binary data');
  ///       ok
  ///           ? await client.requests.approve(req.id)
  ///           : await client.requests.reject(req.id);
  ///     default:
  ///       await client.requests.reject(req.id);
  ///   }
  /// });
  /// ```
  Stream<PendingRequest> get pendingRequests async* {
    await for (final event in requestEvents) {
      final embedded = event.request;
      if (embedded != null) {
        yield embedded;
        continue;
      }
      // Backward-compat fallback: older backend emits only request_id.
      try {
        yield await requests.get(event.requestId);
      } catch (_) {
        // Skip requests we can't fetch (expired, deleted, etc.).
      }
    }
  }

  /// Stream of incoming WalletConnect v2 session proposals — one per
  /// inbound `wc_sessionPropose`. Call
  /// `client.walletConnect.approveSession(proposal.pairingTopic, …)` or
  /// `rejectSession(proposal.pairingTopic)` in response.
  Stream<WcSessionProposal> get walletConnectProposals => events
      .where((e) => e.event == 'wc_session_propose')
      .map((e) => WcSessionProposal.fromJson(e.data));

  /// Stream of incoming WalletConnect v2 `wc_sessionRequest` events —
  /// JSON-RPC calls a connected dApp wants the wallet to execute. Route
  /// through `client.web3.request(...)` and reply with
  /// `client.walletConnect.respond(...)`.
  Stream<WcSessionRequest> get walletConnectRequests => events
      .where((e) => e.event == 'wc_session_request')
      .map((e) => WcSessionRequest.fromJson(e.data));

  /// Stream of online/offline status events.
  Stream<OnlineStatusEvent> get onlineStatusEvents =>
      events.where((e) => e is OnlineStatusEvent).cast<OnlineStatusEvent>();

  /// Stream of tx-history backfill events. Fires after libwallet
  /// pulls on-chain activity (via `modchain_historyByAddress` or
  /// Otterscan `ots_searchTransactionsAfter`) for the current account
  /// + network and inserts new rows into the local Transaction table.
  /// The host can rebind its transaction list via
  /// `client.transactions.list()` on each event.
  Stream<TxHistoryUpdatedEvent> get txHistoryUpdates => events
      .where((e) => e is TxHistoryUpdatedEvent)
      .cast<TxHistoryUpdatedEvent>();

  /// Stream of balance-change snapshots for the current account /
  /// network. Fired by a background poller every 60 s (paused while the
  /// app reports `lifecycle.update('background')`, resumed immediately
  /// on `foreground`). The snapshot always contains the full asset list
  /// — not a delta — so the UI can do a straight replace.
  Stream<BalancesChangedEvent> get balanceChanges => events
      .where((e) => e is BalancesChangedEvent)
      .cast<BalancesChangedEvent>();

  /// Stream of JavaScript-originated events (chainChanged, accountsChanged).
  Stream<JsEvent> get jsEvents =>
      events.where((e) => e is JsEvent).cast<JsEvent>();

  /// Send a raw request. For advanced use when the typed APIs are insufficient.
  Future<dynamic> rawRequest(
    String path, {
    String verb = 'GET',
    Map<String, dynamic>? params,
  }) {
    return _transport.request(path, verb, params);
  }

  /// Send a raw request that may yield progress updates.
  Stream<LibwalletResponse> rawRequestWithProgress(
    String path, {
    String verb = 'GET',
    Map<String, dynamic>? params,
  }) {
    return _transport.send(path, verb, params);
  }

  /// Close the transport and clean up resources.
  void dispose() {
    _transport.dispose();
  }
}
