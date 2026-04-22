/// Pure Dart client for the libwallet cryptocurrency wallet library.
///
/// Communicates with the Go library via direct FFI calls
/// (`NativeCallable.listener`) — no sockets, no background-disconnection
/// issues, no IPC.
///
/// ## Quick Start
///
/// ```dart
/// import 'package:libwallet/libwallet.dart';
///
/// final client = LibwalletClient.initialize('/path/to/data');
///
/// // Check connectivity
/// await client.info.ping();
///
/// // List wallets
/// final wallets = await client.wallets.list();
///
/// // Create a wallet with progress tracking
/// await for (final event in client.wallets.create(
///   name: 'My Wallet',
///   keys: [
///     KeyDescription.storeKey(storeKey),
///     KeyDescription.remoteKey(remoteKey),
///     KeyDescription.password('my-password'),
///   ],
/// )) {
///   switch (event) {
///     case Progress(:final fraction):
///       print('Progress: ${(fraction * 100).toStringAsFixed(1)}%');
///     case Complete(:final value):
///       print('Created wallet: ${value.id}');
///   }
/// }
///
/// // Listen for requests (connect / sign prompts from dApps)
/// client.pendingRequests.listen((req) {
///   // route to your approval UI
/// });
///
/// client.dispose();
/// ```
library;

// Client
export 'src/client/libwallet_client.dart' show LibwalletClient;
export 'src/client/response.dart'
    show LibwalletException, ProgressOr, Progress, Complete;

// Models
export 'src/models/amount.dart' show Amount;
export 'src/models/wallet.dart' show Wallet, WalletKey;
export 'src/models/account.dart' show Account;
export 'src/models/network.dart' show Network, NetworkType;
export 'src/models/asset.dart' show Asset, FiatQuote;
export 'src/models/transaction.dart' show Transaction;
export 'src/models/contact.dart' show Contact;
export 'src/models/token.dart' show Token, DiscoveredToken;
export 'src/models/nft.dart' show Nft, NftAttribute;
export 'src/models/crash.dart' show Crash;
export 'src/models/key_description.dart' show KeyDescription, SigningKey;
export 'src/models/onboarding.dart' show OnboardingState;
export 'src/models/request_event.dart'
    show
        PendingRequest,
        ConnectRequest,
        TransactionSignRequest,
        MessageSignRequest,
        AddNetworkRequest,
        ChainSwitchRequest,
        WatchAssetRequest,
        TxSignEffect,
        TxSignBalanceChange,
        TxSignWarning,
        TxSignBitcoinIO,
        UnknownPendingRequest;
export 'src/models/web3_connection.dart' show Web3Connection;
export 'src/models/name_resolution.dart' show NameResolution;
export 'src/models/signed_message.dart' show SignedMessage;
export 'src/models/remote_key_session.dart'
    show RemoteKeySession, RemoteKeyValidation;
export 'src/models/wallet_backup.dart' show WalletBackupEntry;
export 'src/models/nft_listing.dart' show NftListing;
export 'src/models/rpc_test.dart' show RpcTestResult;
export 'src/models/transaction_simulation.dart'
    show
        TransactionSimulation,
        Effect,
        BalanceChange,
        BitcoinIO,
        Warning,
        WarningSeverity;
export 'src/models/max_sendable_result.dart'
    show MaxSendableResult, ReservedAmount;
export 'src/models/swap_quote.dart'
    show
        SwapQuote,
        SwapTokenRef,
        SwapRouteHop,
        SwapResult,
        ApprovalPreview,
        SwapAvailability;
export 'src/models/unsigned_transaction.dart' show UnsignedTransaction;
export 'src/models/wc_session.dart'
    show WcSession, WcSessionProposal, WcSessionRequest;

// Events
export 'src/events/events.dart'
    show
        LibwalletEvent,
        RequestEvent,
        BalancesChangedEvent,
        TxHistoryUpdatedEvent,
        OnlineStatusEvent,
        LogEvent,
        JsEvent,
        UnknownEvent;

// Transport (for advanced use)
export 'src/client/transport.dart' show Transport;
export 'src/client/ffi_transport.dart' show FfiTransport;

// API classes (for type access, usually accessed via client.xxx)
export 'src/api/info_api.dart' show InfoApi, WalletInfo;
export 'src/api/lifecycle_api.dart' show LifecycleApi;
export 'src/api/name_api.dart' show NameApi;
export 'src/api/store_key_api.dart' show StoreKeyApi, StoreKeyPair;
export 'src/api/remote_key_api.dart' show RemoteKeyApi;
export 'src/api/wallet_api.dart' show WalletApi;
export 'src/api/wallet_key_api.dart' show WalletKeyApi;
export 'src/api/network_api.dart' show NetworkApi;
export 'src/api/account_api.dart'
    show AccountApi, NextAddress, HdAddress, AddressListing;
export 'src/api/asset_api.dart' show AssetApi;
export 'src/api/nft_api.dart' show NftApi;
export 'src/api/transaction_api.dart' show TransactionApi;
export 'src/api/token_api.dart' show TokenApi;
export 'src/api/contact_api.dart' show ContactApi;
export 'src/api/web3_api.dart' show Web3Api;
export 'src/api/web3_connection_api.dart' show Web3ConnectionApi;
export 'src/api/request_api.dart' show RequestApi;
export 'src/api/wallet_connect_api.dart' show WalletConnectApi;
export 'src/api/crash_api.dart' show CrashApi;
