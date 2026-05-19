/// One row of Wallet:probeActivity output — a (chain, BIP variant)
/// candidate with its derived address and on-chain activity flag.
///
/// The host UI typically:
///   1. Calls `client.wallets.probeActivity(...)` after a mnemonic
///      import.
///   2. Filters rows by `hasActivity == true` to auto-select which
///      chains the user already uses.
///   3. Shows rows with `hasActivity == false` as unselected options
///      so the user can pick additional chains.
///   4. Passes the chosen rows as `ChainMigration` entries to
///      `client.wallets.promoteMnemonic(...)`.
class ProbeActivityRow {
  /// Chain tag — `"bitcoin"`, `"litecoin"`, `"monacoin"`,
  /// `"bitcoin-cash"`, `"dogecoin"`, `"ethereum"`, `"solana"`.
  final String network;

  /// Short UI label disambiguating multiple BIP variants on the same
  /// chain (e.g. `"P2WPKH (BIP84)"` vs `"P2PKH (BIP44)"` for BTC,
  /// `"sollet (seed[:32])"` vs `"phantom (m/44'/501'/0'/0')"` for
  /// Solana).
  final String variant;

  /// `"secp256k1"` or `"ed25519"`.
  final String curve;

  /// BIP32 path that produced [address]. Empty string is valid for
  /// Solana's Sollet/Backpack no-derivation convention.
  final String derivationPath;

  /// Derived address in the chain's native encoding
  /// (`bc1...` / `1...` / `0x...` / base58).
  final String address;

  /// Public key, base64url-encoded — 33-byte compressed SEC1 for
  /// secp256k1, raw 32-byte for ed25519.
  final String pubkey;

  /// True when the backend detected non-zero balance or any tx
  /// history at [address]. False both for genuinely empty accounts
  /// and for candidates where the probe RPC failed; check [error]
  /// to distinguish.
  final bool hasActivity;

  /// Raw balance in the chain's smallest units (wei / satoshi /
  /// lamports), as a decimal string. Empty on probe error.
  final String balance;

  /// Per-candidate probe error. Empty on success. A non-empty value
  /// means RPC couldn't answer for this candidate — the other rows
  /// are still valid.
  final String error;

  const ProbeActivityRow({
    required this.network,
    required this.variant,
    required this.curve,
    required this.derivationPath,
    required this.address,
    required this.pubkey,
    required this.hasActivity,
    this.balance = '',
    this.error = '',
  });

  factory ProbeActivityRow.fromJson(Map<String, dynamic> json) =>
      ProbeActivityRow(
        network: (json['network'] as String?) ?? '',
        variant: (json['variant'] as String?) ?? '',
        curve: (json['curve'] as String?) ?? '',
        derivationPath: (json['derivationPath'] as String?) ?? '',
        address: (json['address'] as String?) ?? '',
        pubkey: (json['pubkey'] as String?) ?? '',
        hasActivity: (json['hasActivity'] as bool?) ?? false,
        balance: (json['balance'] as String?) ?? '',
        error: (json['error'] as String?) ?? '',
      );

  @override
  String toString() => 'ProbeActivityRow($network/$variant $address '
      'hasActivity=$hasActivity${error.isEmpty ? "" : " err=$error"})';
}

/// One entry in a multi-chain promote/migrate request — which BIP32
/// derivation path on the source mnemonic wallet to migrate into a
/// fresh MPC wallet. Built from [ProbeActivityRow] rows the user
/// ticked.
class ChainMigration {
  /// Chain tag (same vocabulary as [ProbeActivityRow.network]).
  /// Used for the new wallet's default name and carried through to
  /// the response; the backend does not infer the derivation from
  /// this field, it uses [derivationPath] verbatim.
  final String network;

  /// BIP32 path at which to derive the source mnemonic's privkey.
  /// Empty string selects the Solana Sollet/Backpack no-derivation
  /// convention (ed25519 seed == PBKDF2(mnemonic)[:32]).
  final String derivationPath;

  /// Signing curve for the migrated chain wallet.
  /// `"secp256k1"` → produces a DKLs23 wallet (Bitcoin, Ethereum, …).
  /// `"ed25519"`   → produces a FROST wallet (Solana, Sui, …).
  /// Empty defaults to `"secp256k1"` for backwards-compat with
  /// callers from before the ed25519 fan-out was added; new code
  /// should always pass an explicit value.
  final String curve;

  /// Optional name for the newly-created MPC wallet. Defaults to
  /// `"<source wallet name> / <network>"` when empty.
  final String name;

  const ChainMigration({
    required this.network,
    required this.derivationPath,
    this.curve = '',
    this.name = '',
  });

  Map<String, dynamic> toJson() => {
        'network': network,
        'derivationPath': derivationPath,
        if (curve.isNotEmpty) 'curve': curve,
        if (name.isNotEmpty) 'name': name,
      };

  /// Convenience: build a ChainMigration from a probe row the user
  /// picked. Carries the row's [ProbeActivityRow.curve] through so
  /// each migrated chain lands on the right protocol (DKLs23 vs
  /// FROST) without the caller having to special-case Solana.
  ///
  /// Strips any `/0/0` address-level suffix that ended up in the
  /// probe path — callers usually want to migrate at the BIP44
  /// account level (m/44'/.../0'), NOT at the specific first
  /// address. Pass [stripAddressSuffix: false] to promote exactly
  /// the probed address instead.
  factory ChainMigration.fromProbeRow(
    ProbeActivityRow row, {
    String? name,
    bool stripAddressSuffix = false,
  }) {
    var path = row.derivationPath;
    if (stripAddressSuffix) {
      // Trim trailing "/0/0" so the migration lands at the account
      // level (m/44'/60'/0' rather than m/44'/60'/0'/0/0). Leaves
      // the path alone when it doesn't match that shape (e.g.
      // Solana's empty-path Sollet case).
      final parts = path.split('/');
      if (parts.length >= 3 &&
          parts[parts.length - 1] == '0' &&
          parts[parts.length - 2] == '0') {
        path = parts.sublist(0, parts.length - 2).join('/');
      }
    }
    return ChainMigration(
      network: row.network,
      derivationPath: path,
      curve: row.curve,
      name: name ?? '',
    );
  }
}
