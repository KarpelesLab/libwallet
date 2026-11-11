# CatCard hardware wallets

libwallet can use a [CatCard](https://github.com/TibaneLabs/catcard) — our
open firmware for Coldcard hardware (mk3, mk4, mk5, Q1) — as the signer for
Bitcoin, Ethereum and Solana accounts, over the device's own USB protocol.

> **The CatCard firmware's README says it is not ready for funds**: "Do not
> put funds on a device running this." Its signing paths are covered by host
> tests but, at the time of writing, had not been exercised end to end on a
> device. This integration has likewise only been run against a simulated
> device (see [What has been verified](#what-has-been-verified)). Treat it as
> a development integration.

A CatCard wallet has `Protocol: "catcard"`. Like a Ledger or an air-gapped
signer wallet it holds watch-only accounts: the public keys were read from the
device, and each account remembers the derivation path the device needs to
sign for it. The private keys never leave the device.

The device must be in its **CatCard** USB mode (Settings → Hardware On/Off →
USB mode; the default) and unlocked. In its `ckcc` mode it speaks stock
Coldcard's protocol under stock's USB identity, which this does not use.

## Reaching the device

Every `CatCard:*` call that talks to the device takes the link to use.

| `Transport` | Where | Who opens the device |
|---|---|---|
| `hid` | desktop (macOS, Linux, Windows) | libwallet, over USB (default there) |
| `webhid` | the browser build (Chromium) | libwallet, through WebHID (default there) |
| `bridge` | everywhere, and the only one on iOS / Android | the host app |

With `hid`, `Device` selects a device by the path `CatCard:list` returned
(default: the first one). With `webhid`, `Request: true` shows the browser's
device picker — it needs a user gesture — and later calls reuse the device the
page was granted.

The device is USB `39f2:0401`; libwallet opens its vendor HID interface (usage
page `0xFF00`), not the keyboard or security-key interfaces it may also
present. On Linux the device node is root-only by default:

```
# /etc/udev/rules.d/70-catcard.rules
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="39f2", ATTRS{idProduct}=="0401", TAG+="uaccess"
```

### The bridge

A phone cannot open a vendor HID interface, but the device is also a
class-compliant smart-card reader, which iOS (CryptoTokenKit) and Android can
drive. With `bridge` the host carries the messages. For each one libwallet
emits an event and waits up to thirty seconds for the answer:

```
event  catcard:packet          {"id": "pkt-…", "packet": "<hex>"}
call   CatCard:packetResponse  {"Id": "pkt-…", "Data": "<hex>"}
                            or {"Id": "pkt-…", "Error": "why it failed"}
```

`packet` is a whole message, `[u16 opcode LE][u32 length LE][payload]`, and
`Data` the whole reply, `[u16 status LE][u32 length LE][payload]`. That is
exactly the data of the one APDU the reader answers, so a relay is:

```
→  80 CC 00 00  00 hh ll  <packet>  00 00        (extended Lc and Le)
←  <Data>  90 00
```

(The firmware's `docs/PHONE-APP.md` has the details.) Over any other channel
that reaches the HID interface, split the packet into the firmware's 64-byte
reports instead. In Dart, `client.catcard.bridge((message) => …)` does the
event and the answer.

Everything that matters is sealed before it reaches the bridge: the relay sees
`Identify`, the pairing handshake's public keys, and ciphertext.

## Pairing

The device shares addresses and signs only inside an encrypted channel that is
paired afresh on every connection — nothing is stored on either side. The
handshake is an X25519 exchange in which the host commits to its key before
the device reveals its own; both sides derive two ChaCha20-Poly1305 keys and a
**six-digit code**, which a person compares on the host and on the device.
That comparison is the whole defence against a relay in the middle, so
libwallet never accepts the code itself:

```
event  catcard:pair          {"id": "pair-…", "code": "398 660", "board": "q1", "version": "7.0.0", "bench": false}
call   CatCard:pairResponse  {"Id": "pair-…", "Accept": true}     the user compared the codes
                          or {"Id": "pair-…", "Accept": false}    they differ, or the user cancelled
```

The first route that needs the channel (`getKeys`, `signTransaction`) starts
the handshake and emits `catcard:pair`; show the code, large, next to "does
your CatCard show the same code?", and answer only on the user's tap. The
device shows the same code and asks its owner. The call waits up to two
minutes for each of them. `bench: true` means the device runs a development
image whose host can press keys or read memory: warn the user.

The paired session is kept in memory — never persisted, never returned — and
reused by later calls over the same link, so the code is compared once per
connection. It ends when the device ends it (unplug, logout, a bus reset), on
any record that fails to authenticate, or with `CatCard:disconnect`; the next
call then pairs again. `CatCard:info` reports `paired`.

The device throttles pairing: a few seconds between attempts, and after three
handshakes abandoned before their reveal it blocks pairing until its owner
dismisses a warning. libwallet starts one handshake per call and never
retries on its own.

## Reading accounts

```
CatCard:info     → {board, firmware, protocol, unlocked, blank, pairing, hostWallet, bench, paired}
CatCard:getKeys  {Account?, Scripts?}       → {format: "catcard", master_fingerprint, version, keys: […]}
CatCard:import   {Keys, Name?, Wallet?}     → {wallet, accounts, skipped}
```

`CatCard:info` is the device's `Identify`: it needs no pairing and asks nobody
anything.

`CatCard:getKeys` asks the device to share its addresses. **The account is
chosen on the device, not by the host**: its owner is asked "Computer asks for
this wallet's addresses. Share?", types the account number, and (on a
multichain build) ticks the chains. For that account the device shares:

- **Bitcoin** — the account key of every script type: `m/84'/0'/n'` (`p2wpkh`),
  `m/49'/0'/n'` (`p2sh:p2wpkh`), `m/44'/0'/n'` (`p2pkh`), `m/86'/0'/n'`
  (`p2tr`), with the master fingerprint. `Scripts` selects which are reported
  (default `["p2wpkh"]`).
- **Ethereum** — the key at `m/44'/60'/n'/0/0`.
- **Solana** — the key at `m/44'/501'/n'/0'`.

`Account`, when given, is only a check: if the owner picked another account
the call fails (409). `Count` other than 1 and `Paths` are refused — the
protocol shares one account, at its standard paths. Chains the device shares
but does not sign for (Litecoin, Dogecoin, Bitcoin Cash, Monacoin, Namecoin,
Electra Protocol, Tron) come back with `chain: "unsupported"` and a `reason`,
and are skipped on import; so are Bitcoin test-network keys.

While the device's owner is being waited for, `catcard:waiting` events report
`{for: "addresses" | "signature", stage: "queued" | "deciding"}` (`queued`:
they are in another menu, and the device asks when they are back on one). The
call waits up to fifteen minutes.

`CatCard:import` creates the wallet, or with `Wallet` adds to an existing
CatCard wallet — to import a second account, run `getKeys` again and pick it
on the device; keys the wallet already holds are skipped. It does not need the
device.

## Signing

```
CatCard:signTransaction {Account, Transaction, Network?|RPC?, Offline?, Broadcast?}
```

`Transaction` is the object `Account:signAndSendTransaction` takes:

- **Ethereum** `{to, value, data?}` — nonce, gas and fees are filled from the
  node. The chain id comes from the Network model, never from the node; with an
  explicit `RPC` the caller supplies `chainId`.
- **Solana** `{to, amount, asset?}`, or a ready `{message}` (base58 / base64)
  that names the account as a signer.
- **Bitcoin** `{To, Amount, FeeRate?}` (satoshi) — built as a PSBT. The
  account's UTXOs and, when the node serves them, the previous transactions of
  the inputs are fetched first, so the device can verify the amounts it shows.

With `Offline: true` no node is contacted: the transaction must be complete
and cannot be broadcast. `Broadcast: true` sends it after signing.

The device shows its ordinary review for the chain — what *it* parsed: amounts,
destinations, the fee, the signing address — and its owner approves or cancels
there.

**The device only signs with keys of an account it shared in the same
session.** After a reconnect the first `signTransaction` therefore asks the
device to share its addresses again, and its owner must pick the account the
transaction's account belongs to (and its chain); otherwise the call fails
with 409 and says which account to pick.

Nothing the device returns is trusted on its own:

- A shared key is only reported once the address the device gave for it
  derives from it here (and, for Bitcoin, the first receive address from the
  account key).
- Before a device is asked to sign, the key it shared for the account must be
  the account's key: a device holding another seed or passphrase is refused.
- **Ethereum**: only the device's `r` and `s` are used. The transaction that
  is returned is the one built here, and it must recover to the account.
- **Solana**: the signature must verify under the account key over the message
  that was built; the transaction is assembled here.
- **Bitcoin**: every input must carry a signature that verifies, over that
  input's sighash, under the key derived from the account's own extended key;
  the PSBT must then be the pending transaction, fully signed — the same
  acceptance an air-gapped signer's answer goes through.

A signature from other keys is refused with code 409.

## What the protocol does not have

The firmware's host protocol has two questions — share addresses, sign a
transaction — and nothing else. These routes exist for symmetry with
`Ledger:*` and answer 501:

- `CatCard:showAddress` — there is no command to display one address. The
  device's own Address Explorer shows them; `CatCard:getKeys` checks that the
  device still derives the addresses libwallet holds.
- `CatCard:signMessage` — a sign request carries a Bitcoin PSBT, an EVM
  transaction or a Solana transaction, never a message. (EIP-712 typed data
  likewise.)

Also not available over this protocol: choosing the account from the host,
arbitrary derivation paths, multisig, and signing for the address-only chains.
Firmware upgrades and the bench/debug commands are deliberately not
implemented here.

Error codes: 404 no device, 423 device locked, 409 wrong device / wrong
account shared / device busy, 4001 refused on the device or the pairing code
not confirmed, 403 the device refused the request (with its reason), 408
nobody answered, 410 the session ended, 501 not something this protocol or
this firmware can do.

## What has been verified

No physical device was available when this was written.

- The session's cryptography matches the firmware's own known-answer vector
  (commitment, device key, both directional keys, the code `398 660`, and two
  sealed records) byte for byte, and the host-wallet layouts match the vectors
  in the firmware's reference tools.
- Everything else — pairing, sharing, signing for the three chains, the
  refusals, the bridge — runs in tests against a simulated device that
  implements the device's side of the protocol from its documentation and
  signs for real from a test mnemonic.
- Not exercised: a real device over USB HID (including which hidapi backend
  reports the vendor usage page on each OS), WebHID in a browser, the
  smart-card reader relay on a phone, and the firmware's actual review and
  signing behaviour.
