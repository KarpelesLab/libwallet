## 0.3.11

- **Solana ed25519 self-heal across every sign path**: 0.3.10 only
  repaired the legacy pubkey encoding inside `Transaction:signAndSend`.
  A tester reported sends still failing on 0.3.10, which turned out to
  be a different entry point: `Account:signAndSendTransaction` and the
  Web3 `solana_sign_{message,transaction,send_transaction}` approvers
  bypassed the repair. Extracted the fix into
  `wltacct.EnsureEd25519PubkeyOnAccount` and wired it into every
  Solana-capable sign path, including `Account:signMessage`. The
  helper also saves the repaired Account row synchronously (not just
  via the async `wallet:pubkey_repaired` handler) so the next
  `FindAccount` / `window.solana.publicKey` read returns the
  corrected address in the same request lifecycle.
- **Visibility log**: self-heal now emits
  `ed25519-repair: account <id> (wallet <id>) pubkey/address
  repaired: ...` to `log.Printf` when it fires. If affected users
  report that sends still fail after upgrading, grep logs for
  `ed25519-repair:` — presence confirms the native binary upgrade
  landed and the repair ran; absence means the app is still running
  a pre-0.3.9 `liblibwallet.<ext>` from the package cache.
- **Regression test**: `TestEdDSAWalletCreate` now asserts the stored
  `Wallet.Pubkey` byte-matches the canonical compressed-Y Ed25519
  form, and that stdlib `ed25519.Verify(storedPubkey, msg, sig)`
  accepts the TSS signature. Either assert would have caught the
  original 0.3.9 encoding bug locally — same rejection Solana does
  on-chain.

## 0.3.10

- **Solana ed25519 self-heal now actually runs** (follow-up to 0.3.9):
  the self-heal path in 0.3.9 had a wrong type assertion against the
  signing context — it silently never triggered, so affected wallets
  kept failing every send attempt. Fixed to use `wltintf.GetEnv(ctx)`.
  Additionally, added a pre-flight repair step in the Solana send
  path that decrypts one key share BEFORE building the transaction
  and patches `acct.Pubkey` in-memory, so the **first** send on an
  upgraded install succeeds instead of needing a failed-then-retry
  cycle. New exported helper `wltwallet.EnsureEd25519Pubkey` is a
  no-op when the wallet is already correct.

## 0.3.9

- **Solana ed25519 pubkey fix** (breaking for existing Solana wallets):
  ed25519 wallets created pre-0.3.9 stored the X coordinate of the
  Edwards point (big-endian) as the "public key" instead of the
  standard compressed encoding (Y little-endian with X's sign bit in
  the MSB of byte 31). Consequences: the displayed Solana address was
  wrong, balance queries hit a different address from the one the
  TSS signs with, and every `sendTransaction` failed with
  "Transaction did not pass signature verification". Fixed at wallet
  creation via `ToEd25519PubKey().Serialize()`. Existing broken
  wallets self-heal on the first sign attempt (which fails once,
  then the repair propagates to the wallet + linked accounts and
  the retry succeeds).
- **On-chain tx history backfill** (EVM): `client.transactions.list()`
  now includes on-chain activity, not just txs this install built.
  Triggered in the background on `Account:setCurrent` /
  `Network:setCurrent` / env init. First tries
  `modchain_historyByAddress`, falls back to Otterscan's
  `ots_searchTransactionsAfter` (erigon v3). New
  `client.txHistoryUpdates` stream fires when new rows land.
- **Immediate balance refresh after sends**: every `Transaction:
  signAndSend` / `Account:signAndSendTransaction` /
  `mpurse_sendRawTransaction` / `solana_sign_send_transaction` now
  nudges the background balance poller. Users see the new balance
  within ~1 s instead of up to 60 s.

## 0.3.8

- **Background balance polling**: new `client.balanceChanges` stream
  yields a `BalancesChangedEvent` (full `{network, account, assets}`
  snapshot) every 60 s when the current account / network balances
  change. Lifecycle-aware — pauses under `Lifecycle:update('background')`
  / `paused`, resumes with an immediate poll on `foreground` /
  `resumed` / `active`.
- **RPC timeouts (reliability fix)**: all `Network.DoRPC` /
  `DoRPCNamed` calls are now bounded by a 30 s default deadline.
  A misbehaving upstream (dead Ethereum public RPC, stale Solana
  endpoint, etc.) can no longer wedge a goroutine forever. The
  balance poller uses a tighter 15 s cap. Callers that need a
  specific deadline can use the existing `DoRPCCtx` /
  `DoRPCNamedCtx`. Fixes an iOS CI hang.
- **Network:testRPC extended**: now accepts `type` = `evm` /
  `solana` / `bitcoin` and probes the right health method per
  family. EVM is still the default; `RpcTestResult` gained
  `solanaVersion` / `solanaCluster` / `bitcoinChain` /
  `bitcoinBlocks` fields + `isEvm` / `isSolana` / `isBitcoin`
  getters.
- **Android 16 KB page alignment**: CI now builds every Android
  `.so` (both the AAR and the Dart FFI set) with
  `-Wl,-z,max-page-size=16384` and verifies it with `readelf`.
  Required for Android 15+ devices with 16 KB page size (Pixel 8+).

## 0.3.7

- **Wallet-identity plumbing**: new `client.info.setWalletInfo(clientId:,
  name?, version?)` registers the host wallet with libwallet. The
  `clientId` is sent as the `Sec-ClientId` HTTP header on every
  `Crypto/WalletSign:*` call, which the WalletSign backend uses to
  pick branded SMS / email copy, apply per-app rate limits, and tag
  audit logs. `name` / `version` are stored for future use (untrusted
  display strings, diagnostics). Called once at startup; backward-
  compatible (header not sent if not configured).
- **EIP-6963 UUID fix**: webview injection docs corrected — generate a
  fresh UUIDv4 per page load (spec requirement), do NOT persist
  across launches. `rdns` is the stable identifier dApps key off, not
  `uuid`.
- **Drop Unix-socket transport fallback**: FFI is the only supported
  transport now. Removed `LibwalletClient.connect(socketPath)` /
  `.fromSocket(socket)`, `JsonRpcConnection`, request framing helper,
  and the socket-based testserver binary. `Transport` interface stays
  (test mocks still work) but has one implementation.

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
