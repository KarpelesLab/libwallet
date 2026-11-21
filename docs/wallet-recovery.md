# Wallet recovery

Recovery mode lets a user bring funds over from another wallet using whatever
secret that wallet left them with: a recovery phrase, a private key, a keystore
file, or a Bitfi salt and phrase. libwallet decodes the secret, finds which
addresses hold funds, and builds transfers into the user's own libwallet
wallet. The user reviews each transfer before it is sent.

This is for funds the user wants to **move**, not to import. The other wallet's
secret never becomes part of the user's wallet. It is held in memory for the
recovery session only, and closing the session wipes it.

Hosts reach it through `client.recovery` in Dart, or the `Recovery:*` requests
on any host (see the [reference](#request-reference)).

---

## The flow

```dart
// 1. Open the source. Throws on a misspelled phrase, a wrong keystore
//    password or a key it can't read.
final session = await client.recovery.open(
    RecoverySource.mnemonic(phrase, passphrase: passphrase));

try {
  // 2. Find the funds: every address the source may have used, with what
  //    each one holds.
  final scanned = await session.scan();
  final failed = scanned.where((a) => a.error != null);   // show these, offer a retry
  final funded = scanned.where((a) => a.hasFunds);

  // 3. Move them, tokens before the native coin that pays their fees.
  for (final address in funded) {
    for (final asset in address.sweepOrder) {
      final sweep = await session.prepareSweep(address,
          toAccount: myAccountOnThatChain.id, asset: asset.asset);
      // 4. Show sweep.amount, sweep.fee and sweep.to, and send only on the
      //    user's say-so.
      if (await confirm(sweep)) {
        final txid = await session.broadcast(sweep);
      }
    }
  }
} finally {
  // 5. Wipe the secret.
  await session.close();
}
```

`prepareSweep` signs but never broadcasts, so building a transfer to show the
user is always safe.

## Sources

| Source | Dart | What it accepts |
|---|---|---|
| Recovery phrase | `RecoverySource.mnemonic(phrase, passphrase: …)` | 12–24 BIP-39 words, plus the optional passphrase (a different passphrase is a different wallet). Spacing and case don't matter. A phrase with a bad checksum is refused, since a mistyped word would otherwise open an empty wallet. |
| Private key | `RecoverySource.privateKey(key)` | 64 hex characters, a Bitcoin-family WIF, or a Solana keypair (Phantom's base58 export, or solana-keygen's `[…]` byte array). |
| Keystore file | `RecoverySource.keystore(json, password: …)` | An Ethereum v3 keystore (MetaMask, Geth, MyEtherWallet), scrypt or PBKDF2. The password is checked against the file's MAC first, so a wrong password says so. |
| Bitfi | `RecoverySource.bitfi(salt: …, secret: …)` | The salt (usually the email or phone number the Bitfi was set up with) and the secret phrase, exactly as typed into the device. Case, spaces and punctuation count. |

Opening a Bitfi or a keystore takes about a second: their key derivation is
slow on purpose.

## What it looks at

A source can have used many addresses: one per chain, script type, derivation
layout and index. `session.addresses()` lists them without any network access,
and `session.scan()` also says what each one holds. Both cover indexes
`start` to `start + count - 1` (default 0 to 4, at most 100 per call), and
`chains:` limits them to some chains. Each address says which `layout` it
belongs to (`bitfi` or `key` for those sources) and has a `label` for display.

| Chain | Private key / keystore | Bitfi |
|---|---|---|
| Bitcoin, Litecoin | Native SegWit, P2SH SegWit, legacy (compressed and uncompressed key) | Legacy (uncompressed key), SegWit |
| Monacoin | Native SegWit, legacy | Legacy, SegWit |
| Dogecoin, Bitcoin Cash | Legacy | Legacy |
| Ethereum + ERC-20 | The key | The key at each position |
| Solana + SPL | Hex keys (as a seed) and Solana keypairs | — |
| Tron (TRX, USDT) | The key | — |
| Monero | — | Keys only (see below) |

### Recovery phrases: derivation layouts

A recovery phrase doesn't say which paths its wallet derived, and wallets
disagree. libwallet covers them as **layouts**. The standard ones are scanned
by default; the others are what older or non-standard wallets did, and are
scanned on request, because each one multiplies the addresses to check.

| Layout | Paths (`a` account, `c` change, `i` index) | Chains | Default |
|---|---|---|---|
| `bip84` | `m/84'/coin'/a'/c/i`, native SegWit | BTC, LTC, MONA | ✅ |
| `bip49` | `m/49'/coin'/a'/c/i`, P2SH SegWit | BTC, LTC | ✅ |
| `bip44` | `m/44'/coin'/a'/c/i`, legacy; Ethereum `m/44'/60'/0'/0/i` (MetaMask, Trezor, most wallets); Tron `m/44'/195'/0'/0/i` | all but Solana | ✅ |
| `ledger-live` | `m/44'/60'/i'/0/0`, `m/44'/195'/i'/0/0` | ETH, TRX | ✅ |
| `ledger-legacy` | `m/44'/60'/0'/i`: Ledger's old Chrome app, MyEtherWallet's "Ledger (ETH)" | ETH | ✅ |
| `phantom` | `m/44'/501'/i'/0'` (Phantom, Solflare) | SOL | ✅ |
| `trust` | `m/44'/501'/i'` (Trust Wallet, older Solflare) | SOL | ✅ |
| `sollet` | the seed itself, no derivation | SOL | ✅ |
| `mixed-scripts` | the BIP-44/49/84 paths with the *other* script types: e.g. the standard BIP-44 path used for native or P2SH SegWit, or a BIP-84 path used for legacy addresses | BTC, LTC, MONA (and legacy on each) | |
| `blockchain-info` | `m/44'/coin'/a'/i`: Blockchain.info's legacy HD wallets, which had no change level | Bitcoin family | |
| `bitcoin-core` | `m/0'/0'/i'` (receive) and `m/0'/1'/i'` (change), every script type | BTC, LTC | |
| `multibit` | `m/0'/0/i` and `m/0'/1/i`, legacy (MultiBit HD) | BTC | |
| `samourai` | `m/84'/0'/2147483646'`, `…45'`, `…44'` (Whirlpool postmix, premix, bad bank) | BTC | |

Pass `layouts:` to `addresses()` / `scan()`: null for the standard set,
`['all']` for every layout, or ids (`['blockchain-info', 'bitcoin-core']`).
`session.layouts` lists them with a label and whether each is standard, for a
"search more thoroughly" option. `accounts:` (default 1, at most 20) covers
Bitcoin-family accounts `0` to `accounts - 1` on the account-level layouts
(`bip84`, `bip49`, `bip44`, `mixed-scripts`, `blockchain-info`); Ethereum,
Tron and Solana accounts are the index itself.

**When the standard scan finds nothing** but the user is sure the phrase held
funds, scan again with `layouts: ['all']` and a few `accounts`. Then try a
larger `count`, and check the passphrase: a different passphrase is a
different wallet, and an empty one is a passphrase too.

A WIF key says whether its addresses use the compressed or uncompressed public
key, so only the matching script types are listed. A 64-character hex key could
be either, so both are listed.

**Scan beyond the first page when funds turn up near its end.** Wallets use
addresses in order, so funds at index 4 mean index 5 and later may hold some
too: `session.scan(start: 5)`.

Every address has a stable `id` such as `bitcoin:p2wpkh:m/84'/0'/0'/0/3`,
`ethereum:evm:key` or `litecoin:p2pukh:bitfi:2`. It names the address in
`prepareSweep` and `export`. An id for a path no layout lists is accepted too
(`chain:scheme:path`, with any BIP-32 path), so a user who knows their old
wallet used an unusual path can still get at it.

## Balances

`scan()` gives each address its `assets` (native coin and tokens, balances in
base units) or an `error`. **An address that couldn't be checked is never shown
as empty**: a node failing must not look like an empty wallet, or the user
might give up on funds that are still there. Show the error and offer to scan
again.

- Bitcoin family: unspent outputs.
- Ethereum: ETH and every ERC-20 token the indexer knows the address holds.
- Solana: SOL and every SPL / Token-2022 token account. Symbols come from
  libwallet's curated list; unknown tokens have an empty `symbol`, so show
  their mint.
- Tron: TRX and USDT. Tron nodes can't list an address's tokens, so others
  aren't found.

## Moving funds

`session.prepareSweep(address, toAccount: …)` builds and signs a transfer of
one asset (`asset: 'NATIVE'` by default, or a token's contract or mint from the
scan). It moves everything unless `amount:` is given in base units, and returns
a `RecoverySweep`: `amount` and `to` (what arrives where), `fee`, and the
signed `raw` transaction. `session.broadcast(sweep)` sends it.

Where it goes:

- **`toAccount:`**: an account of the user's libwallet wallet. libwallet uses
  that account's address on the swept chain. A Bitcoin-family account receives
  on Litecoin, Dogecoin and the others at its own address for that chain (its
  default receive address there). An account of another chain is refused:
  an Ethereum account can't receive bitcoin.
- **`to:`**: any address. It must be an address of the swept chain; another
  network's address is refused, because the funds would be lost.

Sending to the recovered address itself is refused.

**Fees, and why tokens go first.** Each chain's native coin pays for moving its
tokens: ETH for ERC-20, SOL for SPL (plus the rent of the recipient's token
account when it has none yet, about 0.002 SOL), and TRX for TRC-20 energy.
Sweeping the native coin first would strand the tokens with nothing to pay for
them. `RecoveredAddress.sweepOrder` lists tokens first. When an address
doesn't hold enough of the native coin to move a token, `prepareSweep` says so
up front rather than producing a transfer that fails on-chain. The fix is to
send that address a little of the native coin first.

| Chain | `fee` | Notes |
|---|---|---|
| Bitcoin family | Size estimate × fee rate | The node's estimate unless `feeRate:` (sat/vbyte) is given. An exact `amount` sends any change back to the recovered address (`change`). |
| Ethereum | Worst case (gas limit × max fee) | Moving everything reserves this; less is usually paid. |
| Solana | Signature fee, plus the recipient's token-account rent when it pays one | — |
| Tron | Bandwidth, plus account creation for a new recipient; a token's fee limit (100 TRX) | The token's fee is a cap: only the energy used is burnt. |

## Exporting a key

`session.export(address)` returns the private key of one recovered address, in
the forms other wallets import: hex and WIF for Bitcoin chains, hex for
Ethereum and Tron, a base58 keypair for Solana, and spend and view keys for
Monero. It's for what recovery can't move itself, Monero above all.

Treat the result like the recovery phrase itself: show it only when the user
explicitly asks, behind a warning, and never store or log it.

## Monero

Bitfi wallets hold Monero, but recovery can't check Monero balances or send
it. Scanning a Monero address gives an error that says so. Export the address's
spend and view keys into a Monero wallet instead.

## Safety rules for implementors

- **Close the session** (`session.close()`) as soon as the user is done, and
  when the recovery screen goes away. The secret stays in memory until then,
  and until the app's process ends at the latest. It is never written to
  disk, so an app restart loses the session: open it again.
- **Confirm before broadcasting.** Show `amount`, `symbol`, `fee` and `to`
  from the `RecoverySweep` and broadcast only after the user agrees.
- **Prefer `toAccount`** over a typed address: it can't be mistyped, and it
  can't name another chain.
- Don't keep the phrase, key, keystore password or Bitfi secret anywhere: in
  state, logs, analytics or crash reports. Clear the input fields after
  opening.
- **Gate `export` behind an explicit request.**

## Not covered (yet)

- Ethereum mainnet only. The same key may hold funds on other EVM chains
  (BSC, Polygon, Arbitrum…); export the key to reach them.
- Bitcoin Taproot (BIP-86) addresses and Electrum-format seeds.
- Tron tokens other than USDT.
- Token-2022 mints with an active transfer fee.
- Monero balances and sends.

## Request reference

For hosts that use the request API directly (browser, other bindings). Every
amount is a string of base units.

| Request | Params | Returns |
|---|---|---|
| `Recovery:open` | `{Type: "mnemonic", Mnemonic, Passphrase?}` · `{Type: "privateKey", Key}` · `{Type: "keystore", Keystore, Password}` · `{Type: "bitfi", Salt, Secret}` | `{Session, Type, Chains: [{Chain, Symbol, Decimals}], Layouts?: [{Id, Label, Standard}]}` (`Layouts` for a mnemonic) |
| `Recovery:addresses` | `{Session, Chains?, Start?, Count?, Accounts?, Layouts? ("standard", "all" or ids)}` | `{Addresses: [{Id, Chain, Symbol, Kind, Address, Layout, Label, Index, Path?}]}` |
| `Recovery:scan` | as `addresses` | the same, with `Assets: [{Asset, Symbol, Decimals, Balance}]` or `Error` on each |
| `Recovery:prepareSweep` | `{Session, Address (an Id), To \| ToAccount, Asset?, Amount? ("max"), FeeRate?}` | `{Address, Chain, From, To, Asset, Symbol, Decimals, Amount, Fee, Raw, Change?, FeeRate?, FeeLimit?, Txid?}` |
| `Recovery:broadcast` | `{Chain, Raw}` | `{Txid}` |
| `Recovery:export` | `{Session, Address}` | `{Address, PrivateKey, Wif?}` or, for Monero, `{Address, SpendKey, ViewKey}` |
| `Recovery:close` | `{Session}` | `{Closed}` |

The older `Bitfi:*` requests remain for the web wallet's no-login Bitfi page
(`web/recover/bitfi.html`) and share their code with recovery. New hosts should
use `Recovery:*` with `Type: "bitfi"`.
