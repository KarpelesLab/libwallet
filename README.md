# libwallet

[![pub package](https://img.shields.io/pub/v/libwallet.svg)](https://pub.dev/packages/libwallet)

A comprehensive cryptocurrency wallet library written in Rust, providing a modular framework for building secure cryptocurrency wallets with multi-chain support.

The core concept is to use TSS (Threshold Signature Scheme) for crypto signatures in order to store keys in multiple locations and enable recovery without compromise on security.

## Overview

libwallet offers a complete set of tools for managing cryptocurrency wallets, supporting multiple networks, assets, and account types. The library implements secure key management, transaction signing, asset tracking, and blockchain interaction through a well-defined API structure.

The backend is a single Rust crate (in [rust/](rust/)) compiled to a C-ABI native library (`cdylib`/`staticlib`). Clients drive it through one JSON request/response FFI entry point plus an event callback. The first-class client is the Dart/Flutter package under [dart/](dart/).

A number of features are still under development and this library is expected to evolve further.

## Supported Networks

| Network | Type | Curve | Features |
|---------|------|-------|----------|
| Ethereum & EVM chains | evm | secp256k1 (ECDSA) | Balance, transfers, NFTs, Web3 |
| Bitcoin, Litecoin, Dogecoin, etc. | bitcoin | secp256k1 (ECDSA) | Balance, address derivation |
| Solana | solana | ed25519 (EdDSA) | Balance, SOL transfers, SPL tokens, NFTs |

EVM chains include Ethereum, Polygon, BNB Chain, and any EVM-compatible network. Bitcoin-type chains include Bitcoin, Bitcoin Cash, Litecoin, Dogecoin, Monacoin, Namecoin, and Electra Protocol.

## Features

- **Multi-chain Support**: EVM chains, Bitcoin-family chains, and Solana
- **Secure Key Management**: TSS (Threshold Signature Scheme) with support for both ECDSA (secp256k1) and EdDSA (ed25519) curves
- **Transaction Handling**: Create, sign and broadcast transactions across supported networks
- **Asset Management**: Track native balances, ERC-20/SPL tokens, and NFTs
- **Account Management**: HD address derivation for ECDSA chains, direct pubkey addressing for Ed25519 chains
- **Web3 Integration**: Ethereum JSON-RPC provider for decentralized applications
- **Price Quotes**: Currency conversion for displaying asset values in fiat
- **Backup & Recovery**: Secure wallet backup and restore functionality

## Requirements

- Rust (stable) toolchain
- Access to blockchain RPC endpoints
- Platform cross-compile tooling for iOS/Android builds (optional): `rustup` targets, plus `cargo-ndk` + the Android NDK for Android

## Building

```bash
make            # cargo build --release (the FFI native library)
make test       # cargo test
make dart-native # build + stage the lib for the local Dart client
```

Or directly with cargo:

```bash
cd rust && cargo build --release && cargo test
```

The build produces `liblibwallet.{so,dylib,a}` under `rust/target/`. It exports the C entry points `LibwalletInit`, `LibwalletRequest`, `LibwalletSetEventCallback`, `LibwalletDestroy`, and `LibwalletFree`.

## Mobile Platform Support

Native libraries for iOS and Android are cross-compiled with cargo (see `.github/workflows/build.yml`):

- **Android**: `cargo-ndk` builds `liblibwallet.so` for arm64-v8a / x86_64 / armeabi-v7a (16 KB page aligned for Android 15+).
- **iOS**: `cargo build --target aarch64-apple-ios` (device) plus the simulator targets, wrapped into an `.xcframework` by `dart/ios/libwallet.podspec` at pod install time.

## Crate Layout

The Rust crate under [rust/](rust/) is organized as:

| Area | Description |
|------|-------------|
| `src/lib.rs` | The C FFI boundary (init / request / event callback / free) |
| `src/handlers/` | Request handlers per object/action (wallet, account, transaction, network, token, swap, web3, …) |
| `src/models/` | Persisted object types (wallet, account, transaction, network, token, …) |
| `src/db.rs`, `src/env.rs` | SQLite storage + environment/config/cache |
| `src/tss.rs`, `src/sign.rs`, `src/reshare.rs` | Threshold signing (ECDSA & EdDSA), key reshare |
| `src/evm.rs`, `src/bitcoin.rs`, `src/solana.rs`, `src/solana_spl.rs` | Chain-specific transaction building |
| `src/rpc.rs`, `src/rest.rs`, `src/walletconnect.rs` | Node RPC, REST, and WalletConnect transports |

## Database

All data is stored in a single **SQLite** database (`sql.db`), including configuration, cached data with automatic expiration, and all wallet/account/transaction state.

## Dart / Flutter

A Dart client is published on pub.dev as [`libwallet`](https://pub.dev/packages/libwallet). It communicates with the native library via direct FFI (no sockets), using `NativeCallable.listener` for native→Dart callbacks. Source lives in [dart/](dart/).

```yaml
dependencies:
  libwallet: ^0.5.0
```

```dart
import 'package:libwallet/libwallet.dart';

final client = LibwalletClient.initialize('/path/to/data');
final wallets = await client.wallets.list();
```

The Dart package's build hook downloads the matching native binary from the GitHub Release for the target platform at install time — no Rust toolchain needed for consumers.

## Managed Release

Releases are fully automated. A single `v{X}.{Y}.{Z}` tag triggers both the native library release (with per-platform binaries) and the Dart package publish.

**To cut a new release:**

1. Update the Dart package version in `dart/pubspec.yaml` (must match the tag)
2. Update `dart/CHANGELOG.md`
3. Commit and push: `git commit -am "bump to 0.5.1" && git push`
4. Tag and push: `git tag v0.5.1 && git push --tags`

**What happens automatically:**

- **Build workflow** (`.github/workflows/build.yml`) compiles the per-platform C-FFI libraries from the Rust crate (Android arm64/arm/x64, iOS device + simulator, macOS arm64/x64, Linux x64) and creates a GitHub Release with all binaries as assets.
- **Publish Dart workflow** (`.github/workflows/publish-dart.yml`) then:
  - Verifies the tag version matches `dart/pubspec.yaml`
  - Waits for the GitHub Release binaries to be uploaded
  - Publishes the Dart package to pub.dev via OIDC (no credentials stored)

The Dart package version and native library version are always locked together — consumers always get matching binaries.

## License

Copyright 2025 Karpeles Lab Inc - See [LICENCE.md](LICENCE.md) for details.

This library is provided under the Karpeles Lab Non-Commercial License, which allows free use for:
- Personal projects
- Educational institutions
- Small projects with fewer than 10,000 monthly active users

For commercial use or projects exceeding the user limit, contact mark@klb.jp for licensing options.
