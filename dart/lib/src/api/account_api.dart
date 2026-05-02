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

  /// Returns every receive-address format available for this account on
  /// the given Bitcoin-family network — Native SegWit / SegWit
  /// (legacy-compatible) / Legacy / etc., ordered by display
  /// preference (modern first). The first entry's [AddressFormat.address]
  /// matches what `Account.address` shows when this network is current.
  ///
  /// Use cases:
  /// - "Show my address as Native SegWit / Legacy" picker.
  /// - Display every shape a counterparty could send funds to so the
  ///   user knows their wallet sees them all (the backend's
  ///   modchain_* indexing watches every key type, so funds received
  ///   at any of these forms land in the same balance).
  ///
  /// Errors when the resolved network isn't a Bitcoin-family chain.
  /// [network] is the network XUID; defaults to the current network.
  Future<AddressFormatsResult> addressFormats(
    String id, {
    String? network,
  }) async {
    final params = <String, dynamic>{};
    if (network != null) params['Network'] = network;
    final data = await _conn.request(
        'Account/$id:addressFormats', 'POST', params.isNotEmpty ? params : null);
    return AddressFormatsResult.fromJson(data as Map<String, dynamic>);
  }

  /// Lists every spendable UTXO the Bitcoin-family account currently
  /// holds — across the receive (`m/0`) and change (`m/1`) chains —
  /// ordered largest amount first. Powers an "advanced coin
  /// selection" picker: show the user every output (with its source
  /// address, amount, script type, and HD path) and let them choose
  /// which to spend by passing the selected `txo` strings back via
  /// `TransactionApi.signAndSend` in a transaction's `utxos` field.
  ///
  /// Errors when the resolved network isn't a Bitcoin-family chain.
  /// [network] is the network XUID; defaults to the current network.
  Future<BitcoinUTXOList> listUTXOs(
    String id, {
    String? network,
  }) async {
    final params = <String, dynamic>{};
    if (network != null) params['Network'] = network;
    final data = await _conn.request(
        'Account/$id:listUTXOs', 'POST', params.isNotEmpty ? params : null);
    return BitcoinUTXOList.fromJson(data as Map<String, dynamic>);
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

/// One receive-address format available for a Bitcoin-family account
/// on a specific chain. Returned by [AccountApi.addressFormats].
class AddressFormat {
  /// Stable script-type identifier: `"p2wpkh"` (Native SegWit),
  /// `"p2sh:p2wpkh"` (SegWit-wrapped, base58 address), `"p2pkh"`
  /// (Legacy). Use this when the UI needs to act on the format
  /// programmatically.
  final String kind;

  /// Human-facing label (`"Native SegWit"`, `"Legacy"`, `"CashAddr"`,
  /// …). Suitable for direct display in a picker.
  final String name;

  /// The formatted on-chain address string. Already chain-tagged
  /// (e.g. `"ltc1..."`, `"L..."`, `"bitcoincash:..."`).
  final String address;

  /// HD derivation suffix the address came from, relative to the
  /// account root. Currently always `"m/0/0"` (receive chain, index
  /// 0) — same path that drives `Account.address`.
  final String path;

  /// True for the format `Account.address` currently uses. Frontend
  /// can highlight this entry as the wallet's "primary" address.
  final bool isDefault;

  const AddressFormat({
    required this.kind,
    required this.name,
    required this.address,
    required this.path,
    required this.isDefault,
  });

  factory AddressFormat.fromJson(Map<String, dynamic> json) => AddressFormat(
        kind: json['kind'] as String,
        name: json['name'] as String,
        address: json['address'] as String,
        path: json['path'] as String,
        isDefault: (json['default'] as bool?) ?? false,
      );
}

/// Result of [AccountApi.addressFormats]: every receive-address shape
/// the account can render on a specific Bitcoin-family chain.
class AddressFormatsResult {
  /// The chain id the formats were rendered for (echoes the resolved
  /// network so callers don't have to re-look-up).
  final String chainId;

  /// Available formats, ordered by display preference (modern first).
  /// The first entry's [AddressFormat.isDefault] is always true.
  final List<AddressFormat> formats;

  const AddressFormatsResult({required this.chainId, required this.formats});

  factory AddressFormatsResult.fromJson(Map<String, dynamic> json) =>
      AddressFormatsResult(
        chainId: json['chainId'] as String,
        formats: (json['formats'] as List)
            .map((e) => AddressFormat.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

/// One unspent output entry returned by [AccountApi.listUTXOs].
class BitcoinUTXO {
  /// On-chain reference, `"<txid>:<vout>"`. Pass this back in a
  /// transaction's `utxos` field to spend this specific output.
  final String txo;

  /// BIP32 derivation path under the account xpub
  /// (e.g. `"m/0/3"` receive #3, `"m/1/0"` change #0).
  final String path;

  /// Output value in the chain's smallest unit (satoshis), as a
  /// decimal string for big-int safety.
  final String amount;

  /// Locking-script type: `"p2wpkh"` (Native SegWit), `"p2pkh"`
  /// (Legacy), `"p2sh:p2wpkh"` (SegWit-wrapped).
  final String script;

  /// Address the output locks to (e.g. `"ltc1..."`, `"L..."`,
  /// `"bitcoincash:..."`). Empty when the path/script combination
  /// could not be rendered.
  final String address;

  /// Block height the output landed in. Zero when still unconfirmed.
  final int height;

  const BitcoinUTXO({
    required this.txo,
    required this.path,
    required this.amount,
    required this.script,
    required this.address,
    required this.height,
  });

  factory BitcoinUTXO.fromJson(Map<String, dynamic> json) => BitcoinUTXO(
        txo: (json['txo'] as String?) ?? '',
        path: (json['path'] as String?) ?? '',
        amount: (json['amount'] as String?) ?? '0',
        script: (json['script'] as String?) ?? '',
        address: (json['address'] as String?) ?? '',
        height: (json['height'] as num?)?.toInt() ?? 0,
      );
}

/// The Account:listUTXOs response shape.
class BitcoinUTXOList {
  /// Echoes the resolved network's chain id (e.g. `"litecoin"`,
  /// `"bitcoin"`).
  final String chainId;

  /// Available UTXOs sorted largest-amount-first.
  final List<BitcoinUTXO> utxos;

  const BitcoinUTXOList({required this.chainId, required this.utxos});

  factory BitcoinUTXOList.fromJson(Map<String, dynamic> json) =>
      BitcoinUTXOList(
        chainId: (json['chainId'] as String?) ?? '',
        utxos: (json['utxos'] as List?)
                ?.map((e) => BitcoinUTXO.fromJson(e as Map<String, dynamic>))
                .toList() ??
            const [],
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
