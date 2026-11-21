import '../client/transport.dart';

/// Wallet recovery: open the secret another wallet left the user with, find
/// what its addresses hold, and move it into the user's own wallet.
///
/// ```dart
/// final session = await client.recovery.open(
///     RecoverySource.mnemonic('abandon abandon … about'));
/// try {
///   final found = (await session.scan()).where((a) => a.hasFunds);
///   for (final address in found) {
///     // Tokens first: the native coin pays their fees.
///     for (final asset in address.sweepOrder) {
///       final sweep = await session.prepareSweep(address,
///           toAccount: myAccount.id, asset: asset.asset);
///       if (await confirmWithUser(sweep)) await session.broadcast(sweep);
///     }
///   }
/// } finally {
///   await session.close();
/// }
/// ```
///
/// **Sources** ([RecoverySource]): a Bitfi salt and phrase, a BIP-39
/// mnemonic (with its passphrase, if any), a single private key (hex, WIF, or
/// a Solana keypair), or an Ethereum keystore file and its password.
///
/// **The secret never touches storage.** libwallet derives what it needs and
/// keeps it in memory under the session until [RecoverySession.close], or
/// until the app's process ends; nothing is written to the database. Close
/// the session as soon as the user is done.
///
/// **Chains:** Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Monacoin, Ethereum
/// (with ERC-20 tokens), Solana (with SPL tokens) and Tron (TRX and USDT).
/// Monero (Bitfi only) gives keys, not balances or sends.
///
/// See `docs/wallet-recovery.md` for the whole flow.
class RecoveryApi {
  final Transport _conn;

  RecoveryApi(this._conn);

  /// Open [source]. Throws when it can't be read: a phrase with a misspelled
  /// word, a wrong keystore password, a key in an unknown format. Bitfi and
  /// keystore sources take a second or so: their key derivation is slow by
  /// design.
  Future<RecoverySession> open(RecoverySource source) async {
    final data = Map<String, dynamic>.from(
        await _conn.request('Recovery:open', 'POST', source.toJson()) as Map);
    return RecoverySession._(
      _conn,
      data['Session'] as String,
      data['Type'] as String,
      (data['Chains'] as List)
          .map((c) => RecoveryChain.fromJson(Map<String, dynamic>.from(c as Map)))
          .toList(),
    );
  }
}

/// The secret another wallet left the user with.
class RecoverySource {
  final Map<String, dynamic> _params;

  const RecoverySource._(this._params);

  /// A Bitfi wallet: its salt (usually the email or phone number it was
  /// registered with) and secret phrase, exactly as typed into the Bitfi:
  /// case, spaces and punctuation count.
  factory RecoverySource.bitfi({required String salt, required String secret}) =>
      RecoverySource._({'Type': 'bitfi', 'Salt': salt, 'Secret': secret});

  /// A BIP-39 recovery phrase (12–24 words) and its optional passphrase
  /// (the "25th word"; a different passphrase is a different wallet).
  /// Spacing and case of the words don't matter.
  factory RecoverySource.mnemonic(String phrase, {String passphrase = ''}) =>
      RecoverySource._({
        'Type': 'mnemonic',
        'Mnemonic': phrase,
        if (passphrase.isNotEmpty) 'Passphrase': passphrase,
      });

  /// One private key: 64 hex characters (tried on every chain, including as
  /// a Solana seed), a Bitcoin-family WIF, or a Solana keypair (Phantom's
  /// base58 export, or solana-keygen's JSON byte array).
  factory RecoverySource.privateKey(String key) =>
      RecoverySource._({'Type': 'privateKey', 'Key': key});

  /// An Ethereum keystore file (the JSON text MetaMask, Geth or
  /// MyEtherWallet export) and its password.
  factory RecoverySource.keystore(String json, {required String password}) =>
      RecoverySource._(
          {'Type': 'keystore', 'Keystore': json, 'Password': password});

  Map<String, dynamic> toJson() => Map.of(_params);
}

/// A chain a source can hold funds on.
class RecoveryChain {
  /// `bitcoin`, `litecoin`, `dogecoin`, `bitcoin-cash`, `monacoin`,
  /// `ethereum`, `solana`, `tron` or `monero`.
  final String chain;
  final String symbol;
  final int decimals;

  const RecoveryChain({required this.chain, required this.symbol, required this.decimals});

  factory RecoveryChain.fromJson(Map<String, dynamic> json) => RecoveryChain(
        chain: json['Chain'] as String,
        symbol: json['Symbol'] as String,
        decimals: (json['Decimals'] as num).toInt(),
      );
}

/// An open recovery source. Close it when done ([close]): that wipes its
/// secret from memory.
class RecoverySession {
  final Transport _conn;
  final String _id;

  /// `bitfi`, `mnemonic`, `privateKey` or `keystore`.
  final String type;

  /// The chains this source can hold funds on.
  final List<RecoveryChain> chains;

  bool _closed = false;

  RecoverySession._(this._conn, this._id, this.type, this.chains);

  /// Whether [close] was called.
  bool get isClosed => _closed;

  Map<String, dynamic> _range(List<String>? chains, int start, int count) => {
        'Session': _id,
        if (chains != null) 'Chains': chains,
        'Start': start,
        'Count': count,
      };

  List<RecoveredAddress> _rows(dynamic data) =>
      ((data as Map)['Addresses'] as List)
          .map((a) => RecoveredAddress.fromJson(Map<String, dynamic>.from(a as Map)))
          .toList();

  /// Every address the source may have used, without touching the network:
  /// each chain's script types and the derivation layouts of the wallets
  /// that used it, for indexes `start` to `start + count - 1` (at most 100
  /// at once). A mnemonic covers BIP-44/49/84 receive and change addresses,
  /// MetaMask and Ledger Live Ethereum accounts, Phantom, Trust Wallet and
  /// Sollet Solana accounts, and Tron. Limit it with [chains].
  Future<List<RecoveredAddress>> addresses(
          {List<String>? chains, int start = 0, int count = 5}) async =>
      _rows(await _conn.request(
          'Recovery:addresses', 'POST', _range(chains, start, count)));

  /// [addresses] with what each one holds ([RecoveredAddress.assets]). An
  /// address that couldn't be checked has [RecoveredAddress.error] instead,
  /// never an empty list: show it, and offer to scan again.
  ///
  /// Wallets use addresses in order, so if anything turns up near the end of
  /// the range, scan the next one (`start: count`).
  Future<List<RecoveredAddress>> scan(
          {List<String>? chains, int start = 0, int count = 5}) async =>
      _rows(await _conn.request(
          'Recovery:scan', 'POST', _range(chains, start, count)));

  /// Build and sign, **without broadcasting**, a transfer of [asset] from a
  /// recovered [address] (a [RecoveredAddress], or its [RecoveredAddress.id]),
  /// so the user can review it first. Send to either [toAccount] (an account
  /// of the user's libwallet wallet on the same chain: its address on that
  /// chain is used) or [to] (any address on that chain).
  ///
  /// [asset] is `NATIVE` (default) or a token's contract / mint, as in
  /// [RecoveredAsset.asset]. [amount] is in base units; null moves
  /// everything (for the native coin: everything less the fee). [feeRate]
  /// overrides a Bitcoin-family chain's fee estimate, in satoshi per vbyte.
  ///
  /// Move tokens **before** the native coin: ETH, SOL and TRX pay the fees of
  /// moving their tokens, and a token can't move once they're gone.
  Future<RecoverySweep> prepareSweep(Object address,
      {String? toAccount,
      String? to,
      String asset = 'NATIVE',
      BigInt? amount,
      int? feeRate}) async {
    if ((to == null) == (toAccount == null)) {
      throw ArgumentError('pass exactly one of to and toAccount');
    }
    final id = address is RecoveredAddress ? address.id : address as String;
    final data = await _conn.request('Recovery:prepareSweep', 'POST', {
      'Session': _id,
      'Address': id,
      if (to != null) 'To': to,
      if (toAccount != null) 'ToAccount': toAccount,
      'Asset': asset,
      'Amount': amount?.toString() ?? 'max',
      if (feeRate != null) 'FeeRate': feeRate,
    });
    return RecoverySweep.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Send a transfer from [prepareSweep]. Returns the transaction id.
  Future<String> broadcast(RecoverySweep sweep) async {
    final data = await _conn.request('Recovery:broadcast', 'POST',
        {'Chain': sweep.chain, 'Raw': sweep.raw});
    return (data as Map)['Txid'] as String;
  }

  /// The private key of one recovered address, in the forms other wallets
  /// import. For Monero (which recovery can't sweep), this is the way out.
  /// Treat the result like the recovery phrase itself: show it only on the
  /// user's explicit request, and never store or log it.
  Future<RecoveredKeys> export(Object address) async {
    final id = address is RecoveredAddress ? address.id : address as String;
    final data = await _conn
        .request('Recovery:export', 'POST', {'Session': _id, 'Address': id});
    return RecoveredKeys.fromJson(Map<String, dynamic>.from(data as Map));
  }

  /// Forget the source and wipe its secret. Safe to call twice.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _conn.request('Recovery:close', 'POST', {'Session': _id});
  }
}

/// One address a recovered source may have used.
class RecoveredAddress {
  /// Names the address in [RecoverySession.prepareSweep] and
  /// [RecoverySession.export]; stable for the same source, e.g.
  /// `bitcoin:p2wpkh:m/84'/0'/0'/0/3`.
  final String id;
  final String chain;
  final String symbol;

  /// The address type: `p2wpkh`, `p2sh:p2wpkh`, `p2pkh`, `p2pukh` (legacy,
  /// uncompressed key), `evm`, `solana`, `tron` or `monero`.
  final String kind;
  final String address;

  /// Which wallets use this address, for display ("Native SegWit (BIP84),
  /// receive 3", "Phantom / Solflare, account 0", "Bitfi position 2").
  final String label;

  /// Its address index, account number or Bitfi position.
  final int index;

  /// The derivation path, for a mnemonic.
  final String? path;

  /// What the address holds, after [RecoverySession.scan]; null when it
  /// wasn't scanned or couldn't be checked.
  final List<RecoveredAsset>? assets;

  /// Why the address couldn't be checked.
  final String? error;

  const RecoveredAddress({
    required this.id,
    required this.chain,
    required this.symbol,
    required this.kind,
    required this.address,
    required this.label,
    required this.index,
    this.path,
    this.assets,
    this.error,
  });

  /// Whether the scan found anything here.
  bool get hasFunds => assets?.isNotEmpty ?? false;

  /// [assets] in the order to sweep them: tokens first, then the native coin
  /// that pays their fees.
  List<RecoveredAsset> get sweepOrder => [
        ...?assets?.where((a) => !a.isNative),
        ...?assets?.where((a) => a.isNative),
      ];

  factory RecoveredAddress.fromJson(Map<String, dynamic> json) => RecoveredAddress(
        id: json['Id'] as String,
        chain: json['Chain'] as String,
        symbol: json['Symbol'] as String? ?? '',
        kind: json['Kind'] as String,
        address: json['Address'] as String,
        label: json['Label'] as String? ?? '',
        index: (json['Index'] as num?)?.toInt() ?? 0,
        path: json['Path'] as String?,
        assets: (json['Assets'] as List?)
            ?.map((a) => RecoveredAsset.fromJson(Map<String, dynamic>.from(a as Map)))
            .toList(),
        error: json['Error'] as String?,
      );
}

/// Something a recovered address holds.
class RecoveredAsset {
  /// `NATIVE`, or the token's contract (ERC-20, TRC-20) or mint (SPL).
  final String asset;

  /// The token's symbol; empty for a token libwallet doesn't know.
  final String symbol;
  final int decimals;

  /// In base units.
  final BigInt balance;

  const RecoveredAsset({required this.asset, required this.symbol, required this.decimals, required this.balance});

  bool get isNative => asset == 'NATIVE';

  factory RecoveredAsset.fromJson(Map<String, dynamic> json) => RecoveredAsset(
        asset: json['Asset'] as String,
        symbol: json['Symbol'] as String? ?? '',
        decimals: (json['Decimals'] as num?)?.toInt() ?? 0,
        balance: BigInt.parse(json['Balance'] as String),
      );
}

/// A signed transfer from [RecoverySession.prepareSweep], not yet broadcast.
/// Show the user [amount], [fee] and [to] before [RecoverySession.broadcast].
class RecoverySweep {
  /// The recovered address's [RecoveredAddress.id].
  final String addressId;
  final String chain;
  final String from;
  final String to;
  final String asset;
  final String symbol;
  final int decimals;

  /// What arrives at [to], in base units.
  final BigInt amount;

  /// The network fee in the chain's native coin's base units. For a Tron
  /// token, the most it can burn (its fee limit); only the energy used is
  /// paid.
  final BigInt fee;

  /// Bitcoin family: what goes back to the recovered address when not
  /// everything was sent.
  final BigInt? change;

  /// Bitcoin family: the fee rate used, in satoshi per vbyte.
  final int? feeRate;

  /// The signed transaction, encoded as the chain's nodes take it.
  final String raw;

  /// The transaction id, when it's known before broadcasting (Solana, Tron).
  final String? txid;

  const RecoverySweep({
    required this.addressId,
    required this.chain,
    required this.from,
    required this.to,
    required this.asset,
    required this.symbol,
    required this.decimals,
    required this.amount,
    required this.fee,
    required this.raw,
    this.change,
    this.feeRate,
    this.txid,
  });

  factory RecoverySweep.fromJson(Map<String, dynamic> json) => RecoverySweep(
        addressId: json['Address'] as String,
        chain: json['Chain'] as String,
        from: json['From'] as String,
        to: json['To'] as String,
        asset: json['Asset'] as String? ?? 'NATIVE',
        symbol: json['Symbol'] as String? ?? '',
        decimals: (json['Decimals'] as num?)?.toInt() ?? 0,
        amount: BigInt.parse(json['Amount'] as String),
        fee: BigInt.parse(json['Fee'] as String),
        raw: json['Raw'] as String,
        change: json['Change'] == null ? null : BigInt.parse(json['Change'] as String),
        feeRate: (json['FeeRate'] as num?)?.toInt(),
        txid: json['Txid'] as String?,
      );
}

/// A recovered address's private key, from [RecoverySession.export].
class RecoveredKeys {
  final String address;

  /// Hex (Bitcoin family, Ethereum, Tron) or a base58 keypair (Solana, the
  /// format Phantom imports).
  final String? privateKey;

  /// Bitcoin family: the key as WIF, flagged for the address's key form.
  final String? wif;

  /// Monero: the private spend and view keys (hex).
  final String? spendKey;
  final String? viewKey;

  const RecoveredKeys({required this.address, this.privateKey, this.wif, this.spendKey, this.viewKey});

  factory RecoveredKeys.fromJson(Map<String, dynamic> json) => RecoveredKeys(
        address: json['Address'] as String,
        privateKey: json['PrivateKey'] as String?,
        wif: json['Wif'] as String?,
        spendKey: json['SpendKey'] as String?,
        viewKey: json['ViewKey'] as String?,
      );
}
