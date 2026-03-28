# libwallet

A comprehensive cryptocurrency wallet library written in Go, providing a modular framework for building secure cryptocurrency wallets with multi-chain support.

The core concept is to use TSS (Threshold Signature Scheme) for crypto signatures in order to store keys in multiple locations and enable recovery without compromise on security.

## Overview

libwallet offers a complete set of tools for managing cryptocurrency wallets, supporting multiple networks, assets, and account types. The library implements secure key management, transaction signing, asset tracking, and blockchain interaction through a well-defined API structure.

A number of features are still under development and this library is expected to evolve further.

## Features

- **Multi-chain Support**: Compatible with both EVM chains (Ethereum, Polygon, etc.) and Bitcoin-based chains
- **Secure Key Management**: Implements threshold signature schemes (TSS) for wallet security
- **Transaction Handling**: Create, sign and broadcast transactions across supported networks
- **Asset Management**: Track cryptocurrency balances and NFTs
- **Account Management**: Create and manage accounts with hierarchical deterministic addresses
- **Web3 Integration**: Support for decentralized applications through a Web3 API
- **Price Quotes**: Currency conversion for displaying asset values in fiat
- **Backup & Recovery**: Secure wallet backup and restore functionality

## Requirements

- Go 1.23.1 or later
- Access to blockchain RPC endpoints
- Mobile platform build tools for iOS/Android compilation

## Installation

```bash
# Clone the repository
git clone <repository-url>

# Install dependencies
make deps

# Build the library
make
```

## Mobile Platform Support

libwallet supports both iOS and Android platforms:

```bash
# Build for iOS (macOS only)
make ios

# Build for Android
make android
```

## Testing

```bash
# Run all tests
make test
```

## Package Structure

libwallet is organized into modular packages:

- **wltbase**: Core infrastructure, database handling, and environment management
- **wltwallet**: Wallet creation, management, and key operations
- **wltnet**: Network connections and blockchain interactions
- **wltacct**: Account management and address generation
- **wltasset**: Asset and balance tracking
- **wlttx**: Transaction creation, signing, and broadcasting
- **wltnft**: Non-fungible token operations
- **wltcontact**: Contact management for frequently used addresses
- **wltquote**: Price quote services for currency conversion
- **wltsign**: Signature handling and key management
- **wltcrash**: Crash reporting and error tracking
- **chains**: Chain configuration and information

## Database System

- BoltDB in `data.db` (mostly for cache data, scheduled to be phased out)
- SQLite with GORM in `sql.db`

## API

libwallet provides a comprehensive API for integration. See [api.md](api.md) for detailed endpoint documentation.

Key API endpoints include:
- Wallet creation and management
- Account operations
- Transaction handling
- Network configuration
- Asset tracking
- Web3 integration

## License

Copyright 2025 Karpeles Lab Inc - See [LICENCE.md](LICENCE.md) for details.

This library is provided under the Karpeles Lab Non-Commercial License, which allows free use for:
- Personal projects
- Educational institutions
- Small projects with fewer than 10,000 monthly active users

For commercial use or projects exceeding the user limit, contact contact@klb.jp for licensing options.
