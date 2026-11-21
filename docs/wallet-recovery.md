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
`chains:` limits them to some chains.

| Chain | Recovery phrase | Private key / keystore | Bitfi |
|---|---|---|---|
| Bitcoin, Litecoin | BIP-84 native SegWit, BIP-49 SegWit, BIP-44 legacy, receive and change | Native SegWit, P2SH SegWit, legacy (compressed and uncompressed key) | Legacy (uncompressed key), SegWit |
| Monacoin | BIP-84, BIP-44 | Native SegWit, legacy | Legacy, SegWit |
| Dogecoin, Bitcoin Cash | BIP-44 | Legacy | Legacy |
| Ethereum + ERC-20 | MetaMask / standard (`m/44'/60'/0'/0/i`), Ledger Live (`m/44'/60'/i'/0/0`) | The key | The key at each position |
| Solana + SPL | Phantom / Solflare (`m/44'/501'/i'/0'`), Trust Wallet / older Solflare (`m/44'/501'/i'`), Sollet (the seed itself) | Hex keys (as a seed) and Solana keypairs | — |
| Tron (TRX, USDT) | `m/44'/195'/0'/0/i` | The key | — |
| Monero | — | — | Keys only (see below) |

A WIF key says whether its addresses use the compressed or uncompressed public
key, so only the matching script types are listed. A 64-character hex key could
be either, so both are listed.

**Scan beyond the first page when funds turn up near its end.** Wallets use
addresses in order, so funds at index 4 mean index 5 and later may hold some
too: `session.scan(start: 5)`.

Every address has a stable `id` such as `bitcoin:p2wpkh:m/84'/0'/0'/0/3`,
`ethereum:evm:key` or `litecoin:p2pukh:bitfi:2`. It names the address in
`prepareSweep` and `export`. An id for a path that isn't in the list is
accepted too, so a user who knows their old wallet used an unusual account can
still get at it.

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
| `Recovery:open` | `{Type: "mnemonic", Mnemonic, Passphrase?}` · `{Type: "privateKey", Key}` · `{Type: "keystore", Keystore, Password}` · `{Type: "bitfi", Salt, Secret}` | `{Session, Type, Chains: [{Chain, Symbol, Decimals}]}` |
| `Recovery:addresses` | `{Session, Chains?, Start?, Count?}` | `{Addresses: [{Id, Chain, Symbol, Kind, Address, Label, Index, Path?}]}` |
| `Recovery:scan` | as `addresses` | the same, with `Assets: [{Asset, Symbol, Decimals, Balance}]` or `Error` on each |
| `Recovery:prepareSweep` | `{Session, Address (an Id), To \| ToAccount, Asset?, Amount? ("max"), FeeRate?}` | `{Address, Chain, From, To, Asset, Symbol, Decimals, Amount, Fee, Raw, Change?, FeeRate?, FeeLimit?, Txid?}` |
| `Recovery:broadcast` | `{Chain, Raw}` | `{Txid}` |
| `Recovery:export` | `{Session, Address}` | `{Address, PrivateKey, Wif?}` or, for Monero, `{Address, SpendKey, ViewKey}` |
| `Recovery:close` | `{Session}` | `{Closed}` |

The older `Bitfi:*` requests remain for the web wallet's no-login Bitfi page
(`web/recover/bitfi.html`) and share their code with recovery. New hosts should
use `Recovery:*` with `Type: "bitfi"`.
