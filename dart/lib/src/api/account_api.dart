import 'dart:convert';
import 'dart:typed_data';

import '../client/transport.dart';
import '../models/account.dart';
import '../models/signed_message.dart';

/// Account CRUD and management.
class AccountApi {
  final Transport _conn;

  AccountApi(this._conn);

  /// List all accounts. Optionally filter by wallet ID.
  Future<List<Account>> list({String? wallet}) async {
    final params = <String, dynamic>{};
    if (wallet != null) params['Wallet'] = wallet;
    final data = await _conn.request('Account', 'GET', params.isNotEmpty ? params : null);
    if (data == null) return [];
    return (data as List)
        .map((e) => Account.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get an account by ID. Use `"@"` for the current account.
  Future<Account> get(String id) async {
    final data = await _conn.request('Account/$id', 'GET');
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Get the current account.
  Future<Account> getCurrent() => get('@');

  /// Create a new account.
  Future<Account> create({
    required String name,
    required String wallet,
    required String type,
    required int index,
  }) async {
    final data = await _conn.request('Account', 'POST', {
      'Name': name,
      'Wallet': wallet,
      'Type': type,
      'Index': index,
    });
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Create a read-only ("view") account from an on-chain address or a
  /// BIP-32 extended public key (xpub, bitcoin-family only).
  ///
  /// View accounts have no wallet backing them and cannot sign. They are
  /// useful for watching a counterparty's address, auditing a paper wallet,
  /// or mirroring a hardware wallet's public tree.
  ///
  /// - Exactly one of [address] or [xpub] must be provided.
  /// - [xpub] is only valid for `type: 'bitcoin'`; it enables HD gap-limit
  ///   scans (balance, next receive address, etc.).
  /// - Plain-[address] view accounts query balance for that single address
  ///   only — no HD tree.
  Future<Account> createView({
    required String type,
    String name = '',
    String? address,
    String? xpub,
  }) async {
    if ((address == null || address.isEmpty) == (xpub == null || xpub.isEmpty)) {
      throw ArgumentError(
          'createView requires exactly one of address or xpub');
    }
    final data = await _conn.request('Account:createView', 'POST', {
      'Name': name,
      'Type': type,
      if (address != null) 'Address': address,
      if (xpub != null) 'Xpub': xpub,
    });
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Update an account's name.
  Future<Account> update(String id, {required String name}) async {
    final data = await _conn.request('Account/$id', 'PATCH', {'Name': name});
    return Account.fromJson(data as Map<String, dynamic>);
  }

  /// Delete an account.
  Future<void> delete(String id) async {
    await _conn.request('Account/$id', 'DELETE');
  }

  /// Set an account as the current account.
  Future<void> setCurrent(String id) async {
    await _conn.request('Account/$id:setCurrent', 'POST');
  }

  /// Get the BIP-32 extended public key (xpub) for a Bitcoin-family account.
  Future<String> xpub(String id) async {
    final data = await _conn.request('Account/$id:xpub', 'POST');
    return (data as Map<String, dynamic>)['xpub'] as String;
  }

  /// Get the next clean (unused) address for a Bitcoin-family account.
  ///
  /// Queries the chain to determine the highest child index with activity,
  /// and returns the derived address at `lastI + 1`.
  ///
  /// [change] controls the derivation chain: false for receive (m/0/i),
  /// true for change (m/1/i). Defaults to receive.
  /// [network] is the network XUID; defaults to the current network.
  Future<NextAddress> nextAddress(
    String id, {
    bool change = false,
    String? network,
  }) async {
    final params = <String, dynamic>{'Change': change};
    if (network != null) params['Network'] = network;
    final data = await _conn.request('Account/$id:nextAddress', 'POST', params);
    return NextAddress.fromJson(data as Map<String, dynamic>);
  }

  /// Sign an arbitrary message with the account's TSS key.
  ///
  /// [message] is the raw bytes to sign.
  /// [keys] is the list of TSS key descriptors (from wallet state).
  /// [mode] selects the signing scheme:
  ///   - `solana` → raw EdDSA; returns base58 signature.
  ///   - `evm` / `personal_sign` → EIP-191 personal_sign; returns 0x-hex.
  ///   - `raw` → signs bytes as-is (caller already hashed); returns base64.
  ///   - `null` → auto-picks `solana` for ed25519, `evm` for secp256k1.
  Future<SignedMessage> signMessage(
    String id, {
    required Uint8List message,
    required List<Map<String, dynamic>> keys,
    String? mode,
  }) async {
    final params = <String, dynamic>{
      'Message': base64.encode(message),
      'Keys': keys,
    };
    if (mode != null) params['Mode'] = mode;
    final data =
        await _conn.request('Account/$id:signMessage', 'POST', params);
    return SignedMessage.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Sign an unsigned Solana transaction. Returns the signed transaction
  /// as base64. For EVM/Bitcoin sends use `TransactionApi.signAndSend`.
  Future<Uint8List> signTransaction(
    String id, {
    required Uint8List transaction,
    required List<Map<String, dynamic>> keys,
  }) async {
    final data = await _conn.request('Account/$id:signTransaction', 'POST', {
      'Transaction': base64.encode(transaction),
      'Keys': keys,
    });
    final signed = (data as Map)['transaction'] as String;
    return base64.decode(signed);
  }

  /// Sign a Solana transaction and broadcast it on the current network.
  /// Returns the broadcast signature (base58).
  Future<String> signAndSendTransaction(
    String id, {
    required Uint8List transaction,
    required List<Map<String, dynamic>> keys,
  }) async {
    final data =
        await _conn.request('Account/$id:signAndSendTransaction', 'POST', {
      'Transaction': base64.encode(transaction),
      'Keys': keys,
    });
    return (data as Map)['signature'] as String;
  }

  /// List all HD addresses (receive + change) that have seen any activity,
  /// plus the next clean address on each chain. Bitcoin-family accounts only.
  Future<AddressListing> allAddresses(String id, {String? network}) async {
    final params = <String, dynamic>{};
    if (network != null) params['Network'] = network;
    final data = await _conn.request(
        'Account/$id:allAddresses', 'POST', params.isNotEmpty ? params : null);
    return AddressListing.fromJson(data as Map<String, dynamic>);
  }
}

/// The next available HD address.
class NextAddress {
  /// Derived address.
  final String address;

  /// Derivation path under the account xpub (e.g. `m/0/5`).
  final String path;

  /// Child index within the chain.
  final int index;

  /// Chain: `receive` or `change`.
  final String chain;

  const NextAddress({
    required this.address,
    required this.path,
    required this.index,
    required this.chain,
  });

  factory NextAddress.fromJson(Map<String, dynamic> json) => NextAddress(
        address: json['address'] as String,
        path: json['path'] as String,
        index: json['index'] as int,
        chain: json['chain'] as String,
      );
}

/// One address entry in an HD address listing.
class HdAddress {
  /// Child index.
  final int index;

  /// Derived address.
  final String address;

  /// Derivation path (e.g. `m/0/3`).
  final String path;

  /// Whether this address has seen no activity yet.
  final bool clean;

  const HdAddress({
    required this.index,
    required this.address,
    required this.path,
    required this.clean,
  });

  factory HdAddress.fromJson(Map<String, dynamic> json) => HdAddress(
        index: json['index'] as int,
        address: json['address'] as String,
        path: json['path'] as String,
        clean: json['clean'] as bool,
      );
}

/// Full HD address listing for a Bitcoin-family account.
class AddressListing {
  /// Receive-chain addresses (m/0/*).
  final List<HdAddress> receive;

  /// Change-chain addresses (m/1/*).
  final List<HdAddress> change;

  const AddressListing({required this.receive, required this.change});

  factory AddressListing.fromJson(Map<String, dynamic> json) => AddressListing(
        receive: (json['receive'] as List)
            .map((e) => HdAddress.fromJson(e as Map<String, dynamic>))
            .toList(),
        change: (json['change'] as List)
            .map((e) => HdAddress.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}
