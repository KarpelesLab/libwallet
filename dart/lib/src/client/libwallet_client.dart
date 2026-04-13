import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import '../api/account_api.dart';
import '../api/asset_api.dart';
import '../api/contact_api.dart';
import '../api/crash_api.dart';
import '../api/info_api.dart';
import '../api/lifecycle_api.dart';
import '../api/network_api.dart';
import '../api/nft_api.dart';
import '../api/remote_key_api.dart';
import '../api/request_api.dart';
import '../api/store_key_api.dart';
import '../api/token_api.dart';
import '../api/transaction_api.dart';
import '../api/wallet_api.dart';
import '../api/wallet_key_api.dart';
import '../api/web3_api.dart';
import '../api/web3_connection_api.dart';
import '../events/events.dart';
import 'ffi_transport.dart';
import 'json_rpc_connection.dart';
import 'response.dart';
import 'transport.dart';

/// Main client for interacting with the libwallet Go library.
///
/// Provides typed API namespaces, event streams, and manages the underlying
/// transport (FFI or Unix socket).
///
/// ## Usage
///
/// Initialize via FFI (preferred — no sockets, works in background):
/// ```dart
/// final client = LibwalletClient.initialize('/path/to/data');
/// final wallets = await client.wallets.list();
/// ```
///
/// Connect via Unix socket (legacy fallback):
/// ```dart
/// final client = await LibwalletClient.connect('/path/to/ipc.sock');
/// ```
class LibwalletClient {
  final Transport _transport;

  // API namespaces
  late final InfoApi info = InfoApi(_transport);
  late final LifecycleApi lifecycle = LifecycleApi(_transport);
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
  late final CrashApi crashes = CrashApi(_transport);

  LibwalletClient._(this._transport);

  /// Initialize the Go library via FFI (preferred).
  ///
  /// Loads the Go shared library and communicates via direct function calls.
  /// No sockets, no background disconnection issues.
  ///
  /// If [library] is provided, uses that DynamicLibrary. Otherwise loads
  /// the default platform library.
  static LibwalletClient initialize(
    String dataDir, {
    DynamicLibrary? library,
  }) {
    final transport = FfiTransport.initialize(dataDir, library: library);
    return LibwalletClient._(transport);
  }

  /// Connect to an existing Unix domain socket (legacy fallback).
  static Future<LibwalletClient> connect(String socketPath) async {
    final connection = await JsonRpcConnection.connect(socketPath);
    return LibwalletClient._(connection);
  }

  /// Wrap an already-connected [socket] (legacy fallback).
  static LibwalletClient fromSocket(Socket socket) {
    final connection = JsonRpcConnection.fromSocket(socket);
    return LibwalletClient._(connection);
  }

  /// Stream of all server-pushed events.
  Stream<LibwalletEvent> get events => _transport.events;

  /// Stream of Web3 request events.
  Stream<RequestEvent> get requestEvents =>
      events.where((e) => e is RequestEvent).cast<RequestEvent>();

  /// Stream of online/offline status events.
  Stream<OnlineStatusEvent> get onlineStatusEvents =>
      events.where((e) => e is OnlineStatusEvent).cast<OnlineStatusEvent>();

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
