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

## Native Library

This package requires the libwallet Go shared library. Build it from the [libwallet repository](https://github.com/KarpelesLab/libwallet):

```bash
# macOS
CGO_ENABLED=1 go build -buildmode=c-shared -o liblibwallet.dylib ./cshared/

# Linux
CGO_ENABLED=1 go build -buildmode=c-shared -o liblibwallet.so ./cshared/

# Android (with NDK)
CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC=$NDK/.../aarch64-linux-android21-clang \
  go build -buildmode=c-shared -o liblibwallet.so ./cshared/

# iOS (static archive)
CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
  go build -buildmode=c-archive -o liblibwallet.a ./cshared/
```

## License

Copyright 2025 Karpeles Lab Inc. See [LICENSE](LICENSE) for details.

Free for personal projects, educational use, and projects with fewer than 10,000 monthly active users. Contact contact@klb.jp for commercial licensing.
