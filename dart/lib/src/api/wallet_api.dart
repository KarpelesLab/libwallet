import '../client/transport.dart';
import '../client/response.dart';
import '../models/key_description.dart';
import '../models/probe_activity.dart';
import '../models/wallet.dart';
import '../models/wallet_backup.dart';

export '../models/probe_activity.dart';

/// Wallet CRUD, backup, restore, reshare, and multi-create operations.
class WalletApi {
  final Transport _conn;

  WalletApi(this._conn);

  /// List all wallets.
  Future<List<Wallet>> list() async {
    final data = await _conn.request('Wallet', 'GET');
    if (data == null) return [];
    return (data as List)
        .map((e) => Wallet.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Get a wallet by ID.
  Future<Wallet> get(String id) async {
    final data = await _conn.request('Wallet/$id', 'GET');
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Create a new wallet. Yields progress updates, then the created wallet.
  Stream<ProgressOr<Wallet>> create({
    required String name,
    required List<KeyDescription> keys,
    String? curve,
  }) async* {
    final stream = _conn.send('Wallet', 'POST', {
      'Name': name,
      'Keys': keys.map((k) => k.toJson()).toList(),
      if (curve != null) 'Curve': curve,
    });
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress((d['progress'] as num?)?.toDouble() ?? 0.0);
      } else {
        yield Complete(Wallet.fromJson(resp.data as Map<String, dynamic>));
      }
    }
  }

  /// Create both secp256k1 and ed25519 wallets in one call.
  Stream<ProgressOr<Map<String, Wallet>>> multiCreate({
    required String name,
    required List<KeyDescription> keys,
  }) async* {
    final stream = _conn.send('Wallet:multiCreate', 'POST', {
      'Name': name,
      'Keys': keys.map((k) => k.toJson()).toList(),
    });
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress((d['progress'] as num?)?.toDouble() ?? 0.0);
      } else {
        final d = resp.data as Map<String, dynamic>;
        yield Complete({
          'secp256k1': Wallet.fromJson(d['secp256k1'] as Map<String, dynamic>),
          'ed25519': Wallet.fromJson(d['ed25519'] as Map<String, dynamic>),
        });
      }
    }
  }

  /// Update a wallet's name.
  Future<Wallet> update(String id, {required String name}) async {
    final data = await _conn.request('Wallet/$id', 'PATCH', {'Name': name});
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Delete a wallet and all associated data.
  Future<void> delete(String id) async {
    await _conn.request('Wallet/$id', 'DELETE');
  }

  /// Get a wallet backup. Returns one entry per wallet; each entry contains
  /// a suggested filename and base64url-encoded encrypted payload. Pass the
  /// entries (as a list of `{filename, data}` maps) back to [restore] to
  /// restore a wallet.
  Future<List<WalletBackupEntry>> backup(String walletId) async {
    final data = await _conn.request('Wallet/$walletId:backup', 'GET');
    if (data == null) return [];
    return (data as List)
        .map((e) => WalletBackupEntry.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  /// Restore wallets from backup files.
  Future<Map<String, dynamic>> restore(
      List<Map<String, String>> files) async {
    final data = await _conn.request('Wallet:restore', 'POST', {
      'files': files,
    });
    return data as Map<String, dynamic>;
  }

  /// Import an existing private key (hex or WIF) as a 1-of-1 wallet.
  ///
  /// The wallet is signable immediately. Promote it to a normal multi-share
  /// TSS wallet later via [promote] when the user wants MPC security —
  /// the address survives the upgrade.
  ///
  /// - [privateKey]: 0x-prefixed hex, bare hex, or Bitcoin-family WIF.
  ///   WIF is auto-sniffed and only supported for `secp256k1`.
  /// - [curve]: `'secp256k1'` (EVM / Bitcoin family) or `'ed25519'` (Solana).
  /// - [name]: human-readable wallet name (untrusted display string).
  /// - [keys]: a single [KeyDescription] specifying how to encrypt the
  ///   imported share at rest. Typically a Password descriptor; supports
  ///   the same `Password` / `StoreKey` / `RemoteKey` / `Plain` types
  ///   the existing wallet creation flow accepts.
  Future<Wallet> importPrivateKey({
    required String privateKey,
    required String curve,
    required String name,
    required List<KeyDescription> keys,
  }) async {
    final data = await _conn.request('Wallet:importPrivateKey', 'POST', {
      'PrivateKey': privateKey,
      'Curve': curve,
      'Name': name,
      'Keys': keys.map((k) => k.toJson()).toList(),
    });
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Import a BIP39 mnemonic phrase as a 1-of-1 wallet.
  ///
  /// The mnemonic's wordlist language is auto-detected (English, Japanese,
  /// Korean, Spanish, Chinese Simplified / Traditional, French, Italian,
  /// or Czech). Stored as decoded entropy + the detected language tag, so
  /// the same backup can be re-rendered in any other BIP39 language later
  /// for display — the seed derivation is always done in the original
  /// language to keep the wallet's address stable (BIP39 PBKDF2 is
  /// sensitive to the literal mnemonic string).
  ///
  /// The wallet is signable immediately and promotable via [promote].
  ///
  /// - [mnemonic]: 12, 15, 18, 21, or 24 BIP39 words separated by spaces.
  /// - [passphrase]: optional BIP39 passphrase ('' = none).
  /// - [curve], [name], [keys]: same semantics as [importPrivateKey].
  Future<Wallet> importMnemonic({
    required String mnemonic,
    String passphrase = '',
    required String curve,
    required String name,
    required List<KeyDescription> keys,
  }) async {
    final data = await _conn.request('Wallet:importMnemonic', 'POST', {
      'Mnemonic': mnemonic,
      'Passphrase': passphrase,
      'Curve': curve,
      'Name': name,
      'Keys': keys.map((k) => k.toJson()).toList(),
    });
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Probe on-chain activity for every BIP44 standard derivation path
  /// under a mnemonic-backed wallet. Returns one row per
  /// (chain, BIP variant) candidate with the derived address and a
  /// `hasActivity` flag; the host UI uses the result to decide which
  /// chains to migrate to MPC (see [promoteMnemonic]) or to surface to
  /// the user for manual selection when nothing has activity yet.
  ///
  /// - [walletId]: the mnemonic-backed wallet's ID.
  /// - [keys]: length 1 — decrypts the mnemonic share. Typically the
  ///   Password used at import time.
  /// - [networks]: optional filter; pass e.g. `['ethereum','solana']`
  ///   to limit probing to those chains. Empty/null probes all
  ///   supported chains (Bitcoin, Litecoin, Monacoin, Bitcoin Cash,
  ///   Dogecoin, Ethereum, Solana).
  /// - [timeoutSeconds]: per-probe timeout budget; default 10 s.
  ///   RPC failures land on `row.error` rather than failing the
  ///   whole request.
  Future<List<ProbeActivityRow>> probeActivity(
    String walletId, {
    required List<KeyDescription> keys,
    List<String>? networks,
    int timeoutSeconds = 10,
  }) async {
    final data = await _conn.request('Wallet/$walletId:probeActivity', 'POST', {
      'Keys': keys.map((k) => k.toJson()).toList(),
      if (networks != null) 'Networks': networks,
      'Timeout': timeoutSeconds,
    });
    if (data == null) return [];
    return (data as List)
        .map((e) => ProbeActivityRow.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  /// Migrate a mnemonic-backed wallet into N fresh MPC wallets, one
  /// per chain in [chains]. Each migration derives the mnemonic at the
  /// chain's BIP32 path and reshares the resulting privkey into a new
  /// TSS committee; the source mnemonic wallet is NOT modified, so the
  /// caller keeps it until every migrated wallet is validated.
  ///
  /// secp256k1 source wallets only in this release; ed25519 mnemonic
  /// migration is a follow-up.
  ///
  /// - [walletId]: the source mnemonic wallet's ID.
  /// - [oldKeys]: length 1, decrypts the source mnemonic.
  /// - [chains]: 1+ entries, typically built from [probeActivity]
  ///   rows the user selected.
  /// - [newKeys]: the TSS committee shape applied to EACH new
  ///   wallet (same committee, independent shares).
  /// - [threshold]: TSS threshold for the new committee.
  Future<List<Wallet>> promoteMnemonic(
    String walletId, {
    required List<KeyDescription> oldKeys,
    required List<ChainMigration> chains,
    required List<KeyDescription> newKeys,
    required int threshold,
  }) async {
    final data = await _conn.request('Wallet/$walletId:promoteMnemonic', 'POST', {
      'Old': oldKeys.map((k) => k.toJson()).toList(),
      'Chains': chains.map((c) => c.toJson()).toList(),
      'New': newKeys.map((k) => k.toJson()).toList(),
      'Threshold': threshold,
    });
    if (data == null) return [];
    return (data as List)
        .map((e) => Wallet.fromJson(Map<String, dynamic>.from(e as Map)))
        .toList();
  }

  /// Promote an imported 1-of-1 wallet (RawKey / Mnemonic) to a normal
  /// N-of-T TSS wallet via tss-lib's resharing protocol. The master pubkey
  /// and chaincode are preserved (the wallet's address does NOT change),
  /// only the storage of the signing key changes — the imported share
  /// is replaced by [newKeys] split into TSS shares with a [threshold]-of-N
  /// reconstruction policy.
  ///
  /// Currently supports secp256k1 wallets only; ed25519 promotion is a
  /// follow-up.
  ///
  /// - [walletId]: the imported wallet's ID.
  /// - [oldKeys]: a single [KeyDescription] that decrypts the imported
  ///   share (e.g., the Password used at import time).
  /// - [newKeys]: ≥ 2 [KeyDescription]s for the new TSS committee.
  /// - [threshold]: minimum signers required (1 ≤ threshold < newKeys.length).
  Future<Wallet> promote(
    String walletId, {
    required List<KeyDescription> oldKeys,
    required List<KeyDescription> newKeys,
    required int threshold,
  }) async {
    final data = await _conn.request('Wallet/$walletId:promote', 'POST', {
      'Old': oldKeys.map((k) => k.toJson()).toList(),
      'New': newKeys.map((k) => k.toJson()).toList(),
      'Threshold': threshold,
    });
    return Wallet.fromJson(data as Map<String, dynamic>);
  }

  /// Reshare wallet keys. Yields progress updates, then the regenerated
  /// wallet with its new key shares.
  Stream<ProgressOr<Wallet>> reshare(
    String walletId, {
    required List<KeyDescription> oldKeys,
    required List<KeyDescription> newKeys,
  }) async* {
    final stream = _conn.send('Wallet/$walletId:reshare', 'POST', {
      'Old': oldKeys.map((k) => k.toJson()).toList(),
      'New': newKeys.map((k) => k.toJson()).toList(),
    });
    await for (final resp in stream) {
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      if (resp.isProgress) {
        final d = resp.data as Map<String, dynamic>;
        yield Progress((d['progress'] as num?)?.toDouble() ?? 0.0);
      } else {
        yield Complete(Wallet.fromJson(resp.data as Map<String, dynamic>));
      }
    }
  }

  /// Run the mobile-led ClawdWallet keygen ceremony (Stage 1).
  ///
  /// Mobile is the keygen leader: this call sends a
  /// `walletsign/<sid>/init` message to each non-self peer (agent +
  /// wdrone) over Spot, then drives the local eddsatss keygen party to
  /// completion. The session row identified by [remoteKey] must already
  /// be Status=valid on the phplatform policy module side
  /// (Crypto/ClawdWallet:create handles that).
  ///
  /// - [remoteKey]: `<crws-id>:<crwsv-id>` issued by the policy module.
  /// - [peers]: full committee from the `:create` response, each entry
  ///   shaped `{spot_id, moniker, key}` where `key` is base64url of the
  ///   peer's raw Ed25519 pubkey bytes. Pass through verbatim.
  /// - [wdroneSpotId]: explicit wdrone spot id (also present in [peers]).
  /// - [name]: human-readable wallet name.
  /// - [curve]: `'ed25519'` only in Stage 1.
  /// - [meMoniker]: optional override for selecting this party in the
  ///   committee; defaults to matching the local Spot TargetId against
  ///   [peers].
  ///
  /// Returns `{wlt_id, solana_address, pubkey}` on success.
  Future<Map<String, dynamic>> initiateKeygen({
    required String remoteKey,
    required List<Map<String, dynamic>> peers,
    required String wdroneSpotId,
    required String name,
    String curve = 'ed25519',
    String? meMoniker,
  }) async {
    final data = await _conn.request('Wallet:initiateKeygen', 'POST', {
      'remote_key': remoteKey,
      'peers': peers,
      'wdrone_spot_id': wdroneSpotId,
      'name': name,
      'curve': curve,
      if (meMoniker != null) 'me_moniker': meMoniker,
    });
    return Map<String, dynamic>.from(data as Map);
  }

  /// Join a ClawdWallet sign ceremony (Stage 1).
  ///
  /// Mobile is *not* a signer in the 2-of-3 ClawdWallet sign topology
  /// (agent + wdrone do the signing), so this is wired for completeness
  /// and for any future flow that wants mobile to co-sign. Joiner-only:
  /// expects an inbound `walletsign/<sid>/init` message from the
  /// initiator (the agent for tx-sign).
  ///
  /// - [walletId]: the local wallet's `wlt-*` id (returned by
  ///   [initiateKeygen]).
  /// - [remoteKey]: `<crws-id>:<crwsv-id>` for the sign session.
  /// - [peers]: signer committee from the policy module, same shape as
  ///   [initiateKeygen] peers.
  /// - [digest]: base64 of the 32-byte digest to sign.
  /// - [curve]: `'ed25519'` only in Stage 1.
  /// - [meMoniker]: optional override for selecting this party.
  ///
  /// Returns `{signature}` where `signature` is base64 of the 64-byte
  /// Ed25519 signature.
  Future<Map<String, dynamic>> joinSign({
    required String walletId,
    required String remoteKey,
    required List<Map<String, dynamic>> peers,
    required String digest,
    String curve = 'ed25519',
    String? meMoniker,
  }) async {
    final data = await _conn.request('Wallet:joinSign', 'POST', {
      'wlt_id': walletId,
      'remote_key': remoteKey,
      'peers': peers,
      'digest': digest,
      'curve': curve,
      if (meMoniker != null) 'me_moniker': meMoniker,
    });
    return Map<String, dynamic>.from(data as Map);
  }
}
