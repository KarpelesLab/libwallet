# libwallet

[![pub package](https://img.shields.io/pub/v/libwallet.svg)](https://pub.dev/packages/libwallet)

Dart client for [libwallet](https://github.com/KarpelesLab/libwallet) — a multi-chain cryptocurrency wallet library with TSS (Threshold Signature Scheme) key management.

## Features

- **Multi-chain support**: EVM chains (Ethereum, Polygon, BNB, etc.), Bitcoin-family chains, and Solana
- **TSS key management**: Threshold signatures with distributed key storage — no single point of failure
- **Direct FFI**: Communicates with the Go library via direct function calls, no sockets or HTTP
- **Async callbacks**: Go goroutines call back into Dart via `NativeCallable.listener`
- **Typed API**: 17 API classes covering wallets, accounts, networks, transactions, tokens, NFTs, contacts, and Web3
- **Event streams**: Real-time events for Web3 requests, network status, and chain changes

## Supported Networks

| Network | Type | Curve | Features |
|---------|------|-------|----------|
| Ethereum & EVM chains | evm | secp256k1 | Balance, transfers, NFTs, Web3, EIP-712 |
| Bitcoin, Litecoin, Dogecoin, etc. | bitcoin | secp256k1 | Balance, address derivation |
| Solana | solana | ed25519 | Balance, SOL/SPL transfers, NFTs |

## Quick Start

```dart
import 'package:libwallet/libwallet.dart';

// Initialize via FFI (loads the Go shared library)
final client = LibwalletClient.initialize('/path/to/data');

// Check connectivity
await client.info.ping();

// List wallets
final wallets = await client.wallets.list();

// Create a wallet with TSS key shares
await for (final event in client.wallets.create(
  name: 'My Wallet',
  keys: [
    KeyDescription.storeKey(storeKeyPublic),
    KeyDescription.remoteKey(remoteKeyPublic),
    KeyDescription.password('user-password'),
  ],
)) {
  switch (event) {
    case Progress(:final count, :final running):
      print('Key generation: ${running}/${count + 1}');
    case Complete(:final value):
      print('Wallet created: ${value.id}');
  }
}

// Create an account (derives address from wallet)
final account = await client.accounts.create(
  name: 'Main',
  wallet: wallets.first.id,
  type: 'ethereum',
  index: 0,
);
print('Address: ${account.address}');

// Listen for Web3 events
client.requestEvents.listen((event) {
  print('Web3 request: ${event.requestId}');
});

// Clean up
client.dispose();
```

## API Overview

| Namespace | Description |
|-----------|-------------|
| `client.info` | Ping, version, onboarding state |
| `client.wallets` | Wallet CRUD, backup, restore, reshare, multi-create |
| `client.walletKeys` | Key share management, password change |
| `client.accounts` | Account CRUD, current account |
| `client.networks` | Network CRUD, current network, RPC testing |
| `client.assets` | Balance queries with fiat conversion |
| `client.transactions` | Transaction history, validation, signing |
| `client.swap` | Token swaps (Jupiter Ultra / dFlow on Solana, 1inch on EVM) |
| `client.tokens` | Custom token CRUD, on-chain discovery |
| `client.nfts` | NFT listing and metadata |
| `client.contacts` | Address book CRUD |
| `client.storeKeys` | Device-secured key generation |
| `client.remoteKeys` | Phone-based 2FA key setup |
| `client.web3` | Web3 JSON-RPC proxy |
| `client.web3Connections` | DApp connection management |
| `client.requests` | Web3 request approval/rejection |
| `client.crashes` | Crash report management |
| `client.lifecycle` | App lifecycle events |
| `client.walletConnect` | WalletConnect v2 (pairing, sessions, requests) |

## Running dApps in a WebView

`client.web3.injectionScript(...)` generates a JS blob that exposes
libwallet as `window.ethereum` (EIP-1193 + EIP-6963 discovery),
`window.solana` (Wallet Standard), and `window.mpurse` (Monacoin /
github.com/tadajam/mpurse). Wire it into a Flutter WebView to let
arbitrary dApps connect to your wallet.

See **[`doc/webview_integration.md`](doc/webview_integration.md)** for
the complete guide — outbound RPC bridge, inbound event relay,
approval-sheet dispatch, re-injection on navigation, and a full
minimal working example.

## Connecting to out-of-app dApps (WalletConnect v2)

For dApps running outside your app (mobile browsers, desktop sites that
can't embed a WebView), libwallet ships a full WalletConnect v2
implementation: relay WebSocket client, session persistence, pair /
propose / request / event / delete flows. Register a projectId at
cloud.walletconnect.com, then:

```dart
await client.walletConnect.start(projectId: myProjectId);
final topic = await client.walletConnect.pair(scannedUri);

client.walletConnectProposals.listen((proposal) async {
  // show approval sheet, then approveSession / rejectSession
});
client.walletConnectRequests.listen((req) async {
  // route through client.web3.request, reply via walletConnect.respond
});
```

Full walkthrough: **[`doc/walletconnect_integration.md`](doc/walletconnect_integration.md)**.

## Token swaps

`client.swap` exposes a quote-then-execute flow powered by Jupiter
Ultra + dFlow on Solana and 1inch on EVM. Quotes carry everything a
UI needs — expected output, min-received, price impact, route
breakdown, absolute fees — and the approval step (EVM ERC-20 input
only) returns a rich `ApprovalPreview` pre-decoded for an approval
sheet. The default approval amount is *exactly* the swap's input so
a compromised router can only drain what the user agreed to; apps
can opt into unlimited with `approvalAmount: 'max'`.

```dart
final quote = await client.swap.quote(
  tokenIn: SwapTokenRef(address: 'NATIVE', decimals: 9),
  tokenOut: SwapTokenRef(
    address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    symbol: 'USDC',
    decimals: 6,
  ),
  amountIn: '10000000',
);
if (quote.requiresApproval) {
  final preview = await client.swap.buildApproval(quoteId: quote.quoteId);
  await client.transactions.signAndSendSimple(preview.tx, keys: keys);
}
final result = await client.swap.execute(quoteId: quote.quoteId, keys: keys);
```

Full walkthrough with UI patterns, copy guidelines, and error
handling: **[`doc/swap_integration.md`](doc/swap_integration.md)**.

## Native Library

**No Go toolchain required.** This package ships with a Dart build hook
(`hook/build.dart`) that automatically downloads the matching pre-built
native binary from the [libwallet GitHub Release](https://github.com/KarpelesLab/libwallet/releases)
for your target platform at build time.

Supported targets:

| Platform | Binary |
|----------|--------|
| macOS arm64 / x64 | `.dylib` |
| Linux x64 | `.so` |
| Android arm64 / arm / x64 | `.so` |
| iOS device arm64 | static `.a` (linked into the app) |
| iOS simulator arm64 / x64 | static `.a` (linked into the app) |

The downloaded binary is cached per-version in the Dart build cache, so
subsequent builds are instant. The Dart package version and native library
version are locked together — `libwallet 0.3.1` always downloads the
`v0.3.1` GitHub Release binaries.

### Building from source (advanced / local development)

If you need to build the native library yourself (for example, to develop
libwallet locally or to use an unreleased version), clone the repo and run:

```bash
# macOS (host platform)
CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-headerpad_max_install_names" \
  go build -buildmode=c-shared -o dart/testserver/liblibwallet.dylib ./cshared/

# Linux
CGO_ENABLED=1 go build -buildmode=c-shared \
  -o dart/testserver/liblibwallet.so ./cshared/

# Android (with NDK)
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC=$NDK/.../aarch64-linux-android21-clang \
  go build -buildmode=c-shared -o liblibwallet.so ./cshared/

# iOS (static archive)
CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
  go build -buildmode=c-archive -o liblibwallet.a ./cshared/
```

When a local `dart/testserver/liblibwallet.<ext>` exists, the build hook
uses it instead of downloading — useful during development.

## License

Copyright 2025 Karpeles Lab Inc. See [LICENSE](LICENSE) for details.

Free for personal projects, educational use, and projects with fewer than 10,000 monthly active users. Contact contact@klb.jp for commercial licensing.
