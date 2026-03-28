# libwallet

[![Go Report Card](https://goreportcard.com/badge/github.com/KarpelesLab/libwallet)](https://goreportcard.com/report/github.com/KarpelesLab/libwallet)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/libwallet/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/libwallet?branch=master)

A comprehensive cryptocurrency wallet library written in Go, providing a modular framework for building secure cryptocurrency wallets with multi-chain support.

The core concept is to use TSS (Threshold Signature Scheme) for crypto signatures in order to store keys in multiple locations and enable recovery without compromise on security.

## Overview

libwallet offers a complete set of tools for managing cryptocurrency wallets, supporting multiple networks, assets, and account types. The library implements secure key management, transaction signing, asset tracking, and blockchain interaction through a well-defined API structure.

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

- Go 1.23 or later
- Access to blockchain RPC endpoints
- Mobile platform build tools for iOS/Android compilation (optional)

## Installation

```bash
go get github.com/KarpelesLab/libwallet
```

## Mobile Platform Support

libwallet supports both iOS and Android platforms via gomobile:

```bash
# Build for iOS (macOS only)
make ios

# Build for Android
make android
```

## Testing

```bash
go test ./...
```

## Package Structure

| Package | Description |
|---------|-------------|
| **wltbase** | Core infrastructure, database handling, and environment management |
| **wltwallet** | Wallet creation, TSS key generation (ECDSA & EdDSA), signing |
| **wltnet** | Network connections, RPC calls, chain-specific balance/asset queries |
| **wltacct** | Account management and address derivation |
| **wltasset** | Asset and balance tracking |
| **wlttx** | Transaction creation, signing, and broadcasting |
| **wltnft** | Non-fungible token operations |
| **wltobj** | Core value types (Amount, TimeId) |
| **wltcontact** | Contact management for frequently used addresses |
| **wltquote** | Price quote services for currency conversion |
| **wltsign** | Signature handling and key descriptions |
| **wltcrash** | Crash reporting and error tracking |

## Database

All data is stored in a single **SQLite** database (`sql.db`) using GORM, including configuration, cached data with automatic expiration, and all wallet/account/transaction state.

## API

libwallet provides a comprehensive API for integration. See [api.md](api.md) for detailed endpoint documentation.

## License

Copyright 2025 Karpeles Lab Inc - See [LICENCE.md](LICENCE.md) for details.

This library is provided under the Karpeles Lab Non-Commercial License, which allows free use for:
- Personal projects
- Educational institutions
- Small projects with fewer than 10,000 monthly active users

For commercial use or projects exceeding the user limit, contact contact@klb.jp for licensing options.
