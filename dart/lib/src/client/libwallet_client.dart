import 'dart:async';
import 'dart:developer' as developer;
import 'dart:ffi';

import '../api/account_api.dart';
import '../api/asset_api.dart';
import '../api/clawdwallet_api.dart';
import '../api/contact_api.dart';
import '../api/contracts_api.dart';
import '../api/crash_api.dart';
import '../api/info_api.dart';
import '../api/lifecycle_api.dart';
import '../api/name_api.dart';
import '../api/network_api.dart';
import '../api/nft_api.dart';
import '../api/remote_key_api.dart';
import '../api/request_api.dart';
import '../api/store_key_api.dart';
import '../api/swap_api.dart';
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
import '../version.dart';
import 'ffi_transport.dart';
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
  late final SwapApi swap = SwapApi(_transport);
  late final TokenApi tokens = TokenApi(_transport);
  late final ContactApi contacts = ContactApi(_transport);
  late final Web3Api web3 = Web3Api(_transport);
  late final Web3ConnectionApi web3Connections =
      Web3ConnectionApi(_transport);
  late final RequestApi requests = RequestApi(_transport);
  late final WalletConnectApi walletConnect = WalletConnectApi(_transport);
  late final CrashApi crashes = CrashApi(_transport);
  late final ClawdWalletApi clawdWallet = ClawdWalletApi(_transport);
  late final ContractsApi contracts = ContractsApi(_transport);

  LibwalletClient._(this._transport) {
    ready = _verifyVersionMatch();
    // Swallow the unawaited rejection so callers that don't await
    // [ready] don't crash the isolate (Dart's "unhandled async error"
    // path). The error is still surfaced two ways: via dart:developer
    // log (for live debugging) and via the [ready] Future itself
    // (for apps that gate their startup on `await client.ready`).
    ready.then((_) {}, onError: (Object _, StackTrace __) {});
  }

  /// Completes once the post-`initialize` runtime check has finished.
  /// In **release** Dart builds (`-Ddart.vm.product=true`, AOT
  /// compilation), this future **rejects** with a [StateError] if the
  /// loaded native binary's release tag does not match the Dart
  /// package's [libwalletPackageVersion] — the post-upgrade footgun
  /// where the .a / .so / .dylib stayed pinned to the previous version.
  /// In debug builds the same condition logs a warning via
  /// `dart:developer` but the future completes normally, so debug
  /// runs of the in-tree test app can iterate against a locally-built
  /// binary without ceremony.
  ///
  /// Release apps should gate their startup on this:
  ///
  /// ```dart
  /// final client = LibwalletClient.initialize(dataDir);
  /// try {
  ///   await client.ready;
  /// } on StateError catch (e) {
  ///   showFatalDialog(e.message); // unrecoverable: rebuild needed
  ///   return;
  /// }
  /// runApp(MyApp(client));
  /// ```
  late final Future<void> ready;

  /// Initialize the Go library via FFI.
  ///
  /// Loads the Go shared library and communicates via direct function
  /// calls — no sockets, no background-disconnection issues, no IPC.
  ///
  /// If [library] is provided, uses that DynamicLibrary. Otherwise loads
  /// the default platform library (`liblibwallet.so` / `.dylib` /
  /// `libwallet.framework` depending on OS).
  ///
  /// Release apps should `await client.ready` after `initialize` —
  /// it rejects on a version mismatch between the Dart package and
  /// the loaded native binary, which would otherwise corrupt every
  /// wire-shape-sensitive call further down.
  static LibwalletClient initialize(
    String dataDir, {
    DynamicLibrary? library,
  }) {
    final transport = FfiTransport.initialize(dataDir, library: library);
    return LibwalletClient._(transport);
  }

  /// Compare the loaded native binary's release tag (set by ldflags
  /// at build time) against the Dart package's `libwalletPackageVersion`
  /// constant. Same release → silent. Native version empty → dev/CI
  /// build, skip the check (the developer knows what they're loading).
  /// Mismatch → log the actionable fix; on release Dart builds also
  /// throw a StateError so [ready] rejects.
  Future<void> _verifyVersionMatch() async {
    String nativeVersion;
    try {
      nativeVersion = await info.version();
    } catch (_) {
      return;
    }
    if (nativeVersion.isEmpty) {
      return;
    }
    if (nativeVersion == libwalletPackageVersion) {
      return;
    }
    final message =
        'libwallet version mismatch — loaded native binary is $nativeVersion '
        'but the Dart package is $libwalletPackageVersion. The wire shape may '
        'have changed between releases (events arriving as UnknownPendingRequest, '
        'requests.approve rejecting "keys are required", etc.). Fix: on iOS '
        'run `cd ios && pod install --repo-update`; on Android/macOS/Linux '
        'run `dart pub get` (the cached binary is now version-stamped per '
        'release as of 0.3.26).';
    developer.log(
      message,
      name: 'libwallet',
      // SEVERE in dart:developer mapping for debug, SHOUT for release.
      level: _isReleaseBuild ? 1200 : 900,
    );
    if (_isReleaseBuild) {
      throw StateError(message);
    }
  }

  /// True when the Dart VM was started with `-Ddart.vm.product=true`,
  /// which is set by AOT release builds (`flutter build` / `dart compile
  /// exe --release`). False under `dart test`, `dart run`, debug
  /// `flutter run`, etc. — the loose "is this code running in a
  /// shipped binary?" signal.
  static const bool _isReleaseBuild =
      bool.fromEnvironment('dart.vm.product', defaultValue: false);

  /// Stream of all server-pushed events.
  Stream<LibwalletEvent> get events => _transport.events;

  /// Stream of log lines emitted by the Go side of libwallet.
  ///
  /// On Flutter+iOS the Go runtime's stderr is NOT captured by the
  /// host app's logger, so every log line has to ride the event
  /// channel. Wire this stream up early in your app startup:
  ///
  /// ```dart
  /// import 'dart:developer' as developer;
  /// client.logs.listen((e) {
  ///   developer.log(e.message, name: 'libwallet.${e.level}');
  /// });
  /// ```
  ///
  /// Volume is controlled by `Info:setWalletInfo`'s `logLevel` field
  /// (empty → auto; `"off"` to silence; `"debug"` for everything).
  Stream<LogEvent> get logs =>
      events.where((e) => e is LogEvent).cast<LogEvent>();

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

  /// Close the transport and clean up resources.
  void dispose() {
    _transport.dispose();
  }
}
