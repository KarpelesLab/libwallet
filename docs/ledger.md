# Ledger hardware wallets

libwallet can use a Ledger device (Nano S / S Plus / X, Stax, Flex) as the
signer for Ethereum, Bitcoin and Solana accounts, through the
[`lsdk`](https://crates.io/crates/lsdk) crate (0.1.1).

A Ledger wallet has `Protocol: "ledger"`. Like an air-gapped signer wallet it
holds watch-only accounts: the public keys were read from the device, and each
account remembers the derivation path the device needs to sign for it. The
private keys never leave the device.

## Reaching the device

Every `Ledger:*` call that talks to the device takes the link to use.

| `Transport` | Where | Who opens the device |
|---|---|---|
| `hid` | desktop (macOS, Linux, Windows) | libwallet, over USB (default there) |
| `webhid` | the browser build (Chromium) | libwallet, through WebHID (default there) |
| `bridge` | everywhere, and the only one on iOS / Android | the host app |

With `hid`, `Device` selects a device by the path `Ledger:list` returned
(default: the first one). With `webhid`, `Request: true` shows the browser's
device picker — it needs a user gesture — and later calls reuse the device the
page was granted.

On Linux the USB device node is root-only by default: install udev rules for
USB vendor `2c97`. The native library links `libudev` there.

### The bridge

With `bridge` the host carries the APDUs, over whatever it has (Bluetooth,
USB-OTG, an emulator). For each exchange libwallet emits an event and waits up
to five minutes for the answer:

```
event  ledger:apdu            {"id": "apdu-…", "apdu": "<hex>"}
call   Ledger:apduResponse    {"Id": "apdu-…", "Data": "<hex, status word included>"}
                           or {"Id": "apdu-…", "Error": "why it failed"}
```

In Dart, `client.ledger.bridge((apdu) => device.exchange(apdu))` does this.

## Reading accounts

The device runs one app at a time and each app knows one chain, so keys are
read app by app, into the same wallet:

```
Ledger:getKeys   {Account?: 0, Count?: 1, Scripts?, Paths?}  → {keys: […], master_fingerprint?}
Ledger:import    {Keys, Name?, Wallet?}                      → {wallet, accounts}
```

- **Ethereum** — one account per index at `m/44'/60'/i'/0/0` (Ledger Live's
  layout), or at each of `Paths`.
- **Bitcoin** — the account key at `m/84'/0'/i'`; `Scripts` adds `p2sh:p2wpkh`
  (BIP-49) and `p2pkh` (BIP-44).
- **Solana** — one account per index at `m/44'/501'/i'/0'`, or at each of `Paths`.
- **Tron** — one account per index at `m/44'/195'/i'/0/0`, or at each of `Paths`.

`Ledger:import` creates the wallet, or with `Wallet` adds to an existing Ledger
wallet; keys it already holds are skipped. It does not need the device. It refuses `Keys` whose
address is not the one the key derives, and then creates nothing.

`Ledger:info` reports the running app (`BOLOS` on the dashboard),
`Ledger:openApp {Name}` and `Ledger:quitApp` switch apps (over USB the device
reconnects when it does), and `Ledger:showAddress {Account}` displays the
address on the device and fails if it is not the one libwallet holds.

## Signing

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

```
Ledger:signTransaction {Account, Transaction, Network?|RPC?, Offline?, Broadcast?}
Ledger:signMessage     {Account, Message: <base64>}
Ledger:signTypedData   {Account, TypedData: <EIP-712 JSON>}
```

`Transaction` is the object `Account:signAndSendTransaction` takes:

- **Ethereum** `{to, value, data?}` — nonce, gas and fees are filled from the
  node. The chain id comes from the Network model, never from the node; with an
  explicit `RPC` the caller supplies `chainId`.
- **Solana** `{to, amount, asset?}`, or a ready `{message}` (base58 / base64)
  that names the account as a signer.
- **Bitcoin** `{To, Amount, FeeRate?}` (satoshi) — built as a PSBT and signed
  under the account's default wallet policy. The account's UTXOs and, when the
  node serves them, the previous transactions of the inputs are fetched first,
  so the device can verify the amounts it shows.

- **Tron** `{to, value, token?, feeLimit?}` (base units; `token` is a TRC-20
  contract) anchored on the node's current block — or on `refBlock`, a
  `getnowblock` reply, when offline — or ready `rawDataHex`, which must be a
  contract libwallet can read whose owner is the account. The Tron app shows
  a TRX transfer in full. It shows a TRC-20 transfer as a token transfer only
  for tokens it knows; libwallet does not send it token descriptors, so other
  tokens need "Allow custom contracts" enabled in the app's settings.

With `Offline: true` no node is contacted: the transaction must be complete
and cannot be broadcast. `Broadcast: true` sends it after signing.

`Ledger:signMessage` does Ethereum `personal_sign`, Bitcoin message
signatures, Tron `signMessageV2` and Solana messages. The Solana app does not
sign bare bytes: the text (UTF-8, at most 1212 bytes) is wrapped as an
off-chain message — signing domain, version 0, no application domain, the
account as the one signer, the length — and the result carries
`signedMessage` (base64), the bytes the signature is over. A verifier that
expects a signature over the bare message will not accept it.

`Ledger:signTypedData` signs EIP-712 typed data. The Ethereum app is given the
domain separator and the message's struct hash, and shows those two hashes: it
does not display the typed data, and its blind-signing setting must allow it.

There is no `lsdk` client for the Tron app; libwallet sends its three APDUs
itself, as Ledger's `hw-app-trx` does.

Nothing the device returns is trusted on its own. A result is only handed back
when it verifies against the account: the signed EVM transaction must recover
to the account address, a Solana signature must verify over the message that
was built, a Tron signature must recover to the account, and a Bitcoin PSBT
must be the pending transaction, fully signed. A
device holding other keys (or another passphrase) is refused with code 409.

Error codes: 404 no device / app not installed, 409 wrong app or wrong device,
423 device locked, 4001 refused on the device, 408 bridge timeout.

## Device management

The device can also be managed, through the vendor's manager API and HSM
channel (lsdk reaches both with rsurl, natively and in the browser). These routes
need the dashboard:

```
Ledger:status        → {model, firmware, bootloader, updater, update?: {version, flashMcu, handle}}
Ledger:genuineCheck  → {genuine}
Ledger:apps          → installed apps (the device asks to allow the listing)
Ledger:catalog       → apps available for this device and firmware
Ledger:installApp    {Name}      Ledger:uninstallApp {Name}
Ledger:firmwareUpdate {Update: <handle>}     → installs the updater; the device restarts
Ledger:firmwareFlash  {Update?}              → bootloader mode: flash the MCU / bootloader
```

Progress arrives as `ledger:progress` events `{op, app?, type, progress?}`.
The web wallet opens the app an operation needs by itself, and offers to
install it when the device does not have it.
