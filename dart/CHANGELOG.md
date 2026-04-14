## 0.3.6

- **WalletConnect v2**: full wallet-side implementation. `client.walletConnect`
  covers pair / sessions / approveSession / rejectSession / respond /
  respondError / emitEvent / disconnect. Two sugar streams
  (`walletConnectProposals`, `walletConnectRequests`) deliver typed
  `WcSessionProposal` / `WcSessionRequest` objects. Sessions persist
  across restarts (SQL-backed); relay reconnects with backoff.
  Protocol pieces implemented: X25519 + HKDF + ChaCha20-Poly1305
  envelopes, Ed25519 relay JWT auth, CAIP-10/-2 namespace handling,
  `wc_sessionPropose` / `Settle` / `Request` / `Event` / `Delete`. See
  `doc/walletconnect_integration.md`.
- **Transaction simulation + decoding**: new `client.transactions.simulate`.
  On EVM (erigon v3 backend), uses `debug_traceCall` with the `callTracer`
  to walk the full call frame tree and return every ERC-20 Transfer +
  Approval and every value-carrying CALL at any depth as
  `TransactionSimulation.effects`. Second pass with `prestateTracer`
  (diff mode) returns per-address native-balance deltas as
  `balanceChanges`. Top-level calldata decoded into `decodedMethod` +
  `decodedArgs` (`native_transfer` / `erc20_transfer` / `erc20_approve` /
  `unknown`). Revert reasons decoded from standard `Error(string)` ABI.
  Solana wraps `simulateTransaction` (logs + unitsConsumed + err).
  Bitcoin parses via `outscript.BtcTx` (inputs + outputs + fee).
- **WebView injection**: new `client.web3.injectionScript(...)` generates
  a JS blob exposing libwallet as `window.ethereum` (EIP-1193 + EIP-6963),
  `window.solana` (Wallet Standard), and `window.mpurse` (Monacoin —
  github.com/tadajam/mpurse). Full wiring walkthrough in
  `doc/webview_integration.md`.
- **Bitcoin-family message signing (via mpurse)**: `mpurse_signMessage`
  signs with the TSS key over the standard "\x18Bitcoin Signed Message:\n"
  / "\x19Monacoin Signed Message:\n" / etc. prefix, returning the
  65-byte compact signature (base64, Bitcoin Core `signmessage` format).
  `mpurse_signRawTransaction` parses the hex, matches inputs to the
  user's xpub via `modchain_lookupTxoBIP32`, signs each input, and
  returns the signed hex. `mpurse_sendRawTransaction` is a direct
  passthrough to `sendrawtransaction`. `mpurse_sendAsset` still errors
  (Counterparty server interaction is out of scope).
- **Monacoin network support**: `bitcoinAddress` recognizes `monacoin`
  chain id and emits the bech32 `mona1...` address via
  `outscript.Out.Address("monacoin")`.
- **Typed pending-request flow**: `PendingRequest` is now sealed with
  one subtype per Web3 request kind (ConnectRequest, PersonalSignRequest,
  SignTypedDataRequest, SolanaSign* / Mpurse* / …, UnknownPendingRequest).
  The `request` event now carries the full request object so consumers
  can render the prompt on first paint without a follow-up
  `Request/<id>` fetch. New `client.pendingRequests` stream yields
  fully-parsed requests ready for pattern matching.
- **Example package layout**: new `example/libwallet_example.dart` CLI
  sample covering init / wallet create with live progress / account /
  balance / pendingRequests subscription. Satisfies pub.dev's example
  requirement.
- **pubspec**: description trimmed to 129 chars (was 212) to satisfy
  pub.dev's metadata scan.

## 0.3.5

- **Direct account signing**: new `Account.signMessage`, `signTransaction`,
  `signAndSendTransaction` endpoints let wallet-host apps sign directly
  without routing through the Web3 pending-request/approve flow. Removes
  ~80 lines of async listener code from the typical Dart integration.
- **View accounts** (read-only): `accounts.createView(type:, address:, xpub:)`
  creates accounts with no backing wallet — suitable for watching a
  counterparty address or an HD tree (xpub, bitcoin-family). Balance and
  NFT queries work; signing is rejected. New `Account.isViewOnly` getter.
- **Progress redesign**: progress events are now a single 0..1 `fraction`
  instead of `{count, running}`. ECDSA wallet creation now emits fine-
  grained ticks during Paillier / NTilde safe-prime generation (one per
  prime found out of 4, per key) — previously the UI was blind for 20+
  seconds per key share. Requires tss-lib v2.2.4+.
- **Typed-API cleanup**: removed `dynamic` returns and raw `Map<String,
  dynamic>` param inputs across the API surface. New typed models:
  `SignedMessage`, `RemoteKeySession`, `RemoteKeyValidation`, `NftListing`,
  `WalletBackupEntry`, `RpcTestResult`, `UnsignedTransaction`. Methods
  like `transactions.signAndSend(UnsignedTransaction)`, `wallets.backup()`,
  `remoteKeys.validate()` now return proper model instances. Raw param
  maps on `contacts.update`, `networks.update`, `tokens.update` replaced
  with named parameters.
- **Validation**: reject wallet `Curve` values outside `{secp256k1,
  ed25519}`; reject account type/curve mismatches (e.g. `solana` on
  secp256k1, `ethereum` on ed25519). Bitcoin accounts now derive on
  BIP-44 coin_type 0 (`m/44/0/0/i`) instead of Ethereum's coin_type 60.

## 0.3.4

- **Email 2FA**: `RemoteKey:new` (and `remoteKeys.create`) now accept
  an email address in addition to phone numbers. Pass either `number` or
  `email` — the EllipX backend routes SMS vs email verification based on
  whether the value contains `@`.

## 0.3.3

- **Bitcoin balance fix**: `modchain_assets` returns `balance` as a
  decimal-formatted number (`"0.00000000"`), not int64. Decode via
  `outscript.BtcAmount` which handles both forms. Previously failed with:
  `json: cannot unmarshal number 0.00000000 into Go struct field`.
- **Solana NFT fix**: `getAssetsByOwner` (Helius DAS API) requires named
  JSON-RPC params, not positional. New `Network.DoRPCNamed()` helper.
  Previously failed with: `invalid type: map, expected a string`.
- **Bitcoin UTXO decode**: `modchain_lookupTxoBIP32` response uses the
  same `BtcAmount` serialization for `amt` and `balance` fields. Type
  switched from int64 to outscript.BtcAmount across wlttx/bitcoin.go.
- **EVM NFT lookup hardening**: type assertions on the `modchain_assets`
  response in wltnet/nft.go could panic if any field was missing or the
  wrong type. Replaced with comma-ok form.
- iOS Dart Tests CI timeout bumped 45 → 60 minutes (Xcode build slow).

## 0.3.2

- **iOS simulator support**: build hook now detects `iphoneos` vs
  `iphonesimulator` SDK and downloads the correct binary. Previously
  the simulator would try to link the device-only binary and fail.
- Release now includes `liblibwallet-iossimulator-arm64.a` (Apple Silicon)
  and `liblibwallet-iossimulator-x64.a` (Intel Mac simulators) alongside
  the existing `liblibwallet-ios-arm64.a` device binary.

## 0.3.1

- **Bitcoin HD address support**: `bitcoin`-type accounts now derive
  multi-address HD trees under their account xpub. Balance queries call
  `modchain_assets(xpub)` which scans `0..lastI+20` child keys (BIP-44
  style gap limit) server-side.
- New `AccountApi.xpub(id)`: returns the BIP-32 extended public key.
- New `AccountApi.nextAddress(id)`: returns the next clean receive (or
  change) address based on on-chain scan.
- New `AccountApi.allAddresses(id)`: lists all HD addresses across
  receive and change chains with activity markers.
- `Account.Address` now points to `m/0/0` (first receive address) instead
  of `m/0` for Bitcoin-family accounts. BTC/LTC/DOGE/BCH supported.

## 0.3.0

- **EIP-1559 transactions**: Auto-selected when the chain supports it. New
  `maxFeePerGas` and `maxPriorityFeePerGas` fields on `Transaction`.
- **ERC-20 transfers**: New `erc20_transfer` transaction type. Pass a token
  XUID in `Asset`, recipient in `To`, and amount — libwallet encodes the
  `transfer(address,uint256)` call automatically.
- **ENS / SNS name resolution**: New `client.names.resolve('vitalik.eth')` API.
  Auto-detects `.eth` (Ethereum) and `.sol` (Solana) suffixes.
- **Solana devnet**: Routes to the correct Helius devnet RPC endpoint
  when using a Solana network with `chainId: "devnet"`.
- Local dev: `hook/build.dart` now prefers a local `testserver/liblibwallet.<ext>`
  over downloading from GitHub Releases.
- Fix: macOS dylibs built with `-headerpad_max_install_names` so Dart can
  bundle them without relinking.

## 0.2.0

- Auto-download native binaries from GitHub Releases at build time
- CI testing on macOS, Android emulator, and iOS simulator
- 43 integration tests covering all API endpoints
- Full dartdoc on all model fields (~130 fields)
- Comprehensive README with usage examples

## 0.1.0

- Initial release
- FFI transport with `NativeCallable.listener` for Go→Dart callbacks
- 17 typed API classes covering all libwallet endpoints
- 15 model classes with full dartdoc
- Socket transport as legacy fallback
- Native asset hook for pub.dev binary distribution
