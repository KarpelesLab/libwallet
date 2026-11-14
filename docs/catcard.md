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
| `ccid` | everywhere; the default on iOS / Android | the host app, through the device's smart-card reader |
| `bridge` | everywhere | the host app, carrying whole messages |

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

### The smart-card reader (`ccid`): iOS and Android

A phone cannot open a vendor HID interface — iOS gives an app no HID API at
all — but in its CatCard USB mode the device is also a class-compliant CCID
**smart-card reader** with one card that is always inserted, and a phone can
drive that. The card answers one proprietary APDU that carries a CatCard
message, so everything above (pairing, keys, signing) works unchanged.

libwallet cannot open a smart-card slot itself; the host app does, and relays
APDUs. For each one libwallet emits an event and waits up to thirty seconds
for the answer:

```
event  catcard:apdu          {"id": "apdu-…", "apdu": "<hex of the command APDU>"}
call   CatCard:apduResponse  {"Id": "apdu-…", "Data": "<hex of the response APDU, status word included>"}
                          or {"Id": "apdu-…", "Error": "why it failed"}
```

Send the bytes exactly as given and return exactly what comes back —
including a `61 xx` status. libwallet builds the APDUs (`CLA 80`, or `90` for
a chunk with more to follow; `INS CC`; extended `Lc`/`Le`), chains a message
longer than one APDU, pages a long reply with `GET RESPONSE`, and turns the
card's status words into errors (`6D00`/`6E00`: not a CatCard's reader).
`ShortApdu: true` keeps to short APDUs (255 data bytes, `Le` 256) for a
smart-card API without extended ones; it costs more round trips.

**On iOS**, use CryptoTokenKit, as the firmware's `docs/PHONE-APP.md` §1
describes:

1. `TKSmartCardSlotManager.default` lists the slots; the CatCard's is named
   after its USB product string, "CatCard". It is there from power-on, before
   the PIN is typed.
2. `slot.makeSmartCard()` and `card.beginSession` power the card on. There is
   no application to select — do not send `SELECT`.
3. Relay each `catcard:apdu` with `card.transmit(_:)`, which returns the
   response including the two status bytes — that is `Data`. Do not use the
   `send(ins:p1:p2:data:le:)` convenience: the class byte is part of the
   protocol.

In Dart (the app supplies the platform channel to CryptoTokenKit):

```dart
final sub = client.catcard.ccidBridge((apdu) => catCardSlot.transmit(apdu));
final keys = await client.catcard.getKeys();   // ccid is the default on iOS / Android
```

On Android the same APDUs go to the reader through the platform's USB CCID
support (or a CCID library over `UsbManager`); the relay is identical.

One APDU is in flight at a time, and only one session exists: a reconnect is
a new pairing.

### The message bridge (`bridge`)

With `bridge` the host carries whole messages instead of APDUs, over whatever
it has that reaches the device (an emulator socket, its own HID code). For
each one libwallet emits an event and waits up to thirty seconds:

```
event  catcard:packet          {"id": "pkt-…", "packet": "<hex>"}
call   CatCard:packetResponse  {"Id": "pkt-…", "Data": "<hex>"}
                            or {"Id": "pkt-…", "Error": "why it failed"}
```

`packet` is `[u16 opcode LE][u32 length LE][payload]` and `Data` the whole
reply, `[u16 status LE][u32 length LE][payload]` — the firmware's HID `START`
frame without its kind and sequence bytes; over HID, split it into the
firmware's 64-byte reports. In Dart, `client.catcard.bridge((message) => …)`.

Over either relay, everything that matters is sealed before it leaves
libwallet: the host sees `Identify`, the pairing handshake's public keys, and
ciphertext.

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

The first route that needs the channel (`getKeys`, `signTransaction`,
`showAddress`, `signMessage`) starts the handshake and emits `catcard:pair`; show the code, large, next to "does
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

## Firmware versions

Every CatCard firmware with the host-wallet protocol shares an account's
addresses and signs transactions. Newer firmware adds three requests: the
address at one path (which can also be shown on the device), a signature over
a message, and `HostInfo`, which says what the firmware answers. libwallet
sends `HostInfo` once per paired session; a firmware that does not know it has
the original requests only, and on such a device:

- `CatCard:showAddress`, `CatCard:signMessage` and `CatCard:getKeys {Paths}`
  answer **501**, saying the device's firmware is too old;
- everything else works as before.

`CatCard:info` reports what the device said as `hostInfo`:

```
"hostInfo": {
  "legacy": false,            true: older firmware, the original requests only
  "addressAt": true,          showAddress and getKeys {Paths} work
  "signMessage": true,        signMessage works
  "pathsAllowed": false,      the owner ticked "Allow during session" (below)
  "shared": true,             something was shared this session
  "messageMax": 960,          longest message, in bytes
  "chains": [{"chain": 1, "name": "Bitcoin", "addresses": true, "sign": true,
              "messages": true, "formats": ["p2wpkh", "p2sh:p2wpkh", "p2pkh", "p2tr"]}, …]
}
```

`HostInfo` only travels inside the paired channel, and `CatCard:info` never
starts a pairing: `hostInfo` is `null` until some other call has paired, and
is asked afresh on each `info` after that.

## Reading accounts

```
CatCard:info     → {board, firmware, protocol, unlocked, blank, pairing, hostWallet, bench, paired, hostInfo}
CatCard:getKeys  {Account?, Scripts?}       → {format: "catcard", master_fingerprint, version, keys: […]}
CatCard:getKeys  {Paths, Chain?, Format?}   → the same shape, one key per path
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
the call fails (409). `Count` other than 1 is refused — the device shares one
account per request. Chains the device shares
but does not sign for (Litecoin, Dogecoin, Bitcoin Cash, Monacoin, Namecoin,
Electra Protocol, Tron) come back with `chain: "unsupported"` and a `reason`,
and are skipped on import; so are Bitcoin test-network keys.

### Keys by their path

With `Paths` (newer firmware) the host names the keys instead, and no account
is shared:

```
CatCard:getKeys {Paths: ["m/44'/60'/0'/0/1", "m/44'/501'/1'/0'"], Chain?, Format?}
```

Each path is asked for on its own, in order, on one session. The chain is read
from the path's coin type (`0'` Bitcoin, `60'` Ethereum, `501'` Solana);
`Chain` (`bitcoin`, `ethereum`, `solana`) names it for a path that does not
say, and applies to every path of the request. `Format` is the Bitcoin script
kind (`p2wpkh`, `p2sh:p2wpkh`, `p2pkh`, `p2tr`) when the path's purpose
(`84'`, `49'`, `44'`, `86'`) does not give it. A Solana path is hardened
throughout. At most 32 paths per request; `Account` cannot be combined with
`Paths`.

- **Ethereum, Solana** — the key comes back as a leaf key, and `CatCard:import`
  takes it like any other.
- **Bitcoin** — a path names one address key, not an account: there is no
  extended key to derive the account's other addresses from. It comes back
  with `chain: "unsupported"`, its `address`, `pubkey` and `script`, and a
  `reason`; `CatCard:import` skips it. Use it to read or check a single
  address. To import a Bitcoin account, share it without `Paths`.

#### "Allow during session"

For each address asked by its path the device's owner sees "Computer asks for
the <chain> address at" with the path in full, then:

```
[ ] Allow during session
    Share it
```

"Share it" shares that one address. Ticking **Allow during session** first
also lets this session have any later address by its path *without a
question* — until the session ends (unplug, logout, a new pairing, a change of
passphrase). It is worth telling the user what that means: the computer can
then learn the public key and address at any path it names, which is enough
to learn which addresses are this wallet's. It covers nothing else — sharing
an account and every signature are still asked for — and it is never stored.
`hostInfo.pathsAllowed` reports it.

While the device's owner is being waited for, `catcard:waiting` events report
`{for: "addresses" | "address" | "signature" | "message", stage: "queued" | "deciding"}` (`queued`:
they are in another menu, and the device asks when they are back on one). The
call waits up to fifteen minutes.

`CatCard:import` creates the wallet, or with `Wallet` adds to an existing
CatCard wallet — to import a second account, run `getKeys` again and pick it
on the device; keys the wallet already holds are skipped. It does not need the
device. It refuses `Keys` whose
address is not the one the key derives, and then creates nothing.

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

**The device only signs with keys it shared in the same session** — keys
below an account it shared, or a key it shared by its own path. After a
reconnect the first request that signs therefore asks first:

- **Ethereum, Solana** (one key per account) — for that one key by its path:
  the owner answers one question about one key, or none if they ticked
  "Allow during session". On older firmware the device is asked to share its
  addresses again instead, and its owner must pick the account the
  transaction's account belongs to (and its chain); otherwise the call fails
  with 409 and says which account to pick.
- **Bitcoin** — always to share its addresses again: a spend's inputs sit on
  many keys below the account, so the account itself must be shared. Its
  owner must pick that account.

The device remembers the sixteen latest keys it shared by path. If it reports
that a key libwallet believed shared no longer is (its owner changed the
passphrase, which drops everything shared), the call fails with 409 and the
next one asks again.

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

## Showing an address

```
CatCard:showAddress {Account}   → {address, account, path}
```

Newer firmware only (501 otherwise). The device puts the account's address on
its screen — "Same as the computer shows?" — and the call returns once its
owner has said it matches (4001 if they say it does not, or decline to share
it). Show the same address in your UI while they compare.

The address is the account's own for Ethereum and Solana, and the **first
receive address** (`…/0/0` below the account key, in the account's script
type) for Bitcoin; `path` says which key was shown. The comparison screen
appears even when "Allow during session" was ticked.

libwallet checks the device's answer as well: the public key and the address
it reports must be the ones held for the account, or the call fails with 409
("the device shows …, but this account is …") — another device, or another
passphrase.

## Signing a message

```
CatCard:signMessage {Account, Message, Scheme?}
                                → {signature, account, address, scheme, verified, path?}
```

Newer firmware only (501 otherwise). `Message` is base64. The device's owner
reads the message on the device, with the address that signs, and approves.

| Account | `Scheme` | `signature` | Verified by libwallet |
|---|---|---|---|
| Ethereum | `eip191` (default; the only one) | `0x` + 65 bytes `r‖s‖v` hex, `v` 27/28 | yes: recovers to the account |
| Bitcoin `p2wpkh`, `p2sh:p2wpkh`, `p2pkh` | `bip137` (default) | base64 of the 65 bytes | yes: recovers to the key at `path` |
| Bitcoin `p2wpkh`, `p2tr` | `bip322` (default for `p2tr`) | base64 of the witness stack | **no** |
| Bitcoin `p2wpkh`, `p2sh:p2wpkh`, `p2tr` | `bip322-full` | base64 of the `to_sign` transaction | **no** |

A Bitcoin message is signed with the account's first receive address (`…/0/0`);
`path` reports the key and `address` the address. A scheme that does not sign
for the account's address type (BIP-137 for taproot, BIP-322 simple for
`p2sh:p2wpkh` or `p2pkh`, any BIP-322 for `p2pkh`) is refused with 400 before
the device is involved.

**libwallet does not verify BIP-322 signatures** — it has no BIP-322 verifier.
For those it checks only that the device answered for the request that was
made and that the address it signed for is the account's; the signature
itself is the device's word, and the result says `verified: false`. Verify it
with your own tooling if it matters. (The firmware runs its own BIP-322
verifier before handing the signature back.)

**What can be signed.** The device signs only text its screen shows
faithfully, and refuses the rest:

- Bitcoin: one line of printable ASCII, at most 240 characters.
- Ethereum: printable ASCII in at most 24 lines and 960 bytes; no line
  beginning or ending with a space; no blank first or last line.

libwallet applies these rules before asking the device and answers **400**
with the device's wording ("message too long", "plain ASCII only", "a line
starts or ends blank", …). A message that passes them but is too long for
that board's screen is refused by the device itself, also reported as 400
with its reason ("too long to show here").

**Not signed:** EIP-712 typed data, raw digests, Solana messages, and messages
for the address-only chains. A Solana account gets 400; `hostInfo.chains[].messages`
says which chains a firmware signs messages for.

The key must have been shared in the session. If it has not, libwallet first
asks the device for it by its path (the owner sees the share question, unless
they allowed addresses for the session), then for the signature.

## What is not available

Not available over this protocol: choosing the account from the host for an
account share, importing a Bitcoin account from a path, multisig, EIP-712,
and signing for the address-only chains. Firmware upgrades and the
bench/debug commands are deliberately not implemented here.

Error codes: 404 no device, 502 the link failed or the card refused the APDU, 423 device locked, 409 wrong device / wrong
account shared / device busy, 4001 refused on the device or the pairing code
not confirmed, 403 the device refused the request (with its reason), 400 a
request the device would not take (a message it does not sign, with its
reason), 408 nobody answered, 410 the session ended, 501 not something this
protocol or this device's firmware can do.

## What has been verified

No physical device was available when this was written.

- The session's cryptography matches the firmware's own known-answer vector
  (commitment, device key, both directional keys, the code `398 660`, and two
  sealed records) byte for byte, and the host-wallet layouts match the vectors
  in the firmware's reference tools.
- The APDUs match the firmware's reference client (`tools/ccidclient.py
  --selftest`) and the worked `Identify` exchange in `docs/PHONE-APP.md`.
- Everything else — pairing, sharing, signing for the three chains, the
  refusals, both relays — runs in tests against a simulated device that
  implements the device's side of the protocol from its documentation and
  signs for real from a test mnemonic. Every operation is also run through a
  simulated card (command chaining, and with short APDUs replies paged by
  `GET RESPONSE`).
- The address-by-path, message and `HostInfo` layouts match the firmware's
  pinned vectors (`catcard-usb`'s `hostwallet` tests, `tools/hostwallet.py
  --selftest`). Showing an address, signing messages, keys by path, the
  session allowance and the old-firmware fallback run against the same
  simulated device, which produces real EIP-191 and BIP-137 signatures. Its
  BIP-322 answers are placeholders: libwallet does not verify those, and
  nothing here tests that a real one is well formed. These requests were
  written against firmware changes that were not yet committed, and may still
  move.
- Not exercised: a real device over USB HID (including which hidapi backend
  reports the vendor usage page on each OS), WebHID in a browser, the
  smart-card reader on a phone (CryptoTokenKit, or Android's CCID path) or
  through a desktop PC/SC stack, and the firmware's actual review and signing
  behaviour — including its screens for sharing an address, comparing one
  and reading a message, and what each board's panel refuses as too long. The firmware's own documentation says its reader has not yet been
  exercised against an iPhone or on hardware.

## Generic routes

> The generic routes work too. `Account:signTransaction`,
> `Account:signAndSendTransaction`, `Account:signMessage`,
> `Account:signTypedData`, `Transaction:signAndSend`, `Swap:execute` and the
> dApp request approvals see that the account is on a hardware wallet and
> have the device sign — no `Keys`; the link params (`Transport`, …) pass
> through. An air-gapped account makes the call emit `airgap:sign` and wait
> for `Airgap:submitSignature` (or `Airgap:cancelSign`) — for a message or
> typed data as for a transaction. Hardware wallets are not included in
> `Wallet:backup`.
>
> | | Ledger | Air-gapped (Keystone UR) | CatCard |
> |---|---|---|---|
> | Bitcoin, EVM, Solana transactions | yes | yes | yes |
> | Tron transactions (TRX, TRC-20) | yes (Tron app) | yes (`tron-sign-request`) | 501 — no firmware request |
> | `personal_sign`, Bitcoin messages | yes | yes | yes |
> | EIP-712 typed data | yes, as two hashes | yes (the JSON is shown) | 501 — no firmware request |
> | Solana messages | yes, as an off-chain message | yes | 501 — no firmware request |
> | Tron messages | yes | yes | 501 — no firmware request |
>
> A serialized Solana transaction that other parties sign too gets this
> account's signature in its own slot; it is only sent once none is missing
> (`missingSignatures` in the result). A Bitcoin `Transaction` may be the
> explicit `{UTXOs: [{txid, vout, amount, path}], Outputs: [{address, amount,
> path?}]}` — every input is spent, what is left over is the fee, and an
> output with a `path` (`m/1/5`) is marked as the account's own.
