## 0.3.30

- **`Info:version` now exposes the release tag.** New `version` field
  alongside `dateTag` / `gitTag`, populated from the `v*` tag the
  binary was built from (empty on dev / non-tagged builds). The Dart
  wrapper got a typed `client.info.versionInfo()` returning a
  `VersionInfo` (version + gitTag + dateTag) for diagnostics; the
  long-broken `client.info.version()` now correctly returns the
  release-tag string instead of the toString'd map.

- **Runtime version-mismatch detection.** `LibwalletClient.initialize`
  asynchronously calls `Info:version` and compares it against the
  hardcoded `libwalletPackageVersion` constant. If the loaded native
  binary is from a different release (the post-upgrade footgun:
  pubspec moved but the linked `.a` / `.so` / `.dylib` didn't), an
  actionable warning is logged via `dart:developer` telling the host
  to run `pod install --repo-update` (iOS) or `dart pub get` (all
  other platforms — caches are version-stamped since 0.3.26). Works
  on every platform, not just iOS.

- **Fixed: build-time `-X` ldflags targeted the wrong package.** The
  `Makefile` and `build.yml` had been passing `-X main.dateTag=...` /
  `-X main.gitTag=...` for the entire history of the project, but
  those variables live in `wltbase`. The `-X` was a silent no-op —
  every release binary shipped with empty `dateTag` / `gitTag`.
  Corrected to use the fully qualified package path; release binaries
  built on or after this commit return populated values from
  `Info:version`. Also propagated the ldflags to the c-shared /
  c-archive Dart-FFI builds, which had no version metadata at all.

## 0.3.29

- **CI publish workflow: install BOTH Flutter and Dart.** v0.3.28
  switched from `dart-lang/setup-dart` to `subosito/flutter-action`
  so the publish job had Flutter on PATH (needed once the package
  pinned a Flutter SDK lower bound). But Flutter's bundled Dart does
  not configure pub.dev OIDC credentials, so `dart pub publish --force`
  hung indefinitely waiting for an interactive auth flow. Install the
  Dart SDK action *after* Flutter so its credential plumbing is the
  one in effect.

## 0.3.28

- **CI publish workflow: install Flutter alongside Dart.** Once the
  package declares a Flutter SDK lower bound (added in 0.3.27), plain
  `dart-lang/setup-dart` rejects `dart pub get` with "libwallet
  requires the Flutter SDK, version solving failed". Switch the publish
  step to `subosito/flutter-action` so the Flutter+Dart SDK pair is
  available on PATH. Cuts a no-op release after v0.3.27 because the
  workflow file used at publish time is the one snapshot-bound to the
  triggering tag, so the fix only takes effect on a fresh tag push.

## 0.3.27

- **pubspec: declare a Flutter SDK constraint.** Required by pub.dev
  whenever `flutter.plugin.platforms` is set; published as a no-op
  release after v0.3.26 was rejected at validation. v0.3.26's
  GitHub Release assets remain valid for any pinned consumer.

## 0.3.26

- **Build hook: invalidate the binary cache on a Dart upgrade.**
  The `hook/build.dart` cache filename was version-agnostic
  (`liblibwallet-android-arm64.so`), so a previously cached binary kept
  serving stale code after `dart pub upgrade` — the Dart layer would
  decode events using the new shape while the loaded `.so` / `.dylib`
  still emitted the old shape. Most visible failure: post-0.3.24
  signing events arriving with pre-unification type strings like
  `sign_typed_data` instead of `message_sign`, falling through to
  `UnknownPendingRequest`. Cached filenames now embed the package
  version (`liblibwallet-android-arm64-v0.3.26.so`); the next
  `dart pub get` after this upgrade re-downloads the matching binary.

- **iOS: ship as a Flutter FFI plugin (fixes external `dlsym` failure).**
  The build hook's `LinkMode = LookupInProcess()` for the iOS `.a`
  archive worked for the in-tree test app, but Flutter's iOS pipeline
  did not reliably pass the static archive through to Xcode's linker
  for *external* consumers — the FFI symbols (`LibwalletInit`, …) got
  dead-stripped and `dlsym` failed at runtime with "symbol not found".
  This release adds `flutter.plugin.platforms.ios.ffiPlugin: true` to
  `pubspec.yaml` and ships `ios/libwallet.podspec`, which downloads
  the matching per-SDK static archives from the GitHub Release at
  `pod install` time and force-loads them into the host app target via
  per-SDK `OTHER_LDFLAGS`. Both device + simulator slices are pulled,
  combined into a single fat simulator archive via `lipo`, and the
  per-SDK xcconfig picks the correct one per build configuration.
  No code changes for app authors — `flutter pub upgrade` then a
  fresh `pod install` is enough.

## 0.3.25

- **Rich payloads on the remaining approval events.** Same
  decode-at-emit philosophy as 0.3.24's sign events, now applied
  to `ConnectRequest`, `AddNetworkRequest`, and `WatchAssetRequest`:
  - **`ConnectRequest`** now carries `method` (which RPC asked),
    `family` (evm/solana/bitcoin), `availableAccounts`
    (curve-compatible accounts pre-fetched for the picker),
    `alreadyConnectedIds` (pre-check in picker; render "Reconnect"
    vs "Connect"), and `requestedPermissions` (EIP-2255).
  - **`AddNetworkRequest`** flags phishing vectors: `isKnown`
    (chainId in the static chain registry), `knownName` (the
    canonical name — compare to `network.name` to detect
    impersonation), `alreadyExists` (no-op approval), and the
    `nameMismatch` convenience getter.
  - **`WatchAssetRequest`** gains typed EIP-747 accessors:
    `assetType`, `address`, `symbol`, `decimals`, `image`,
    `tokenId`, plus `addressLooksInvalid` and `isAlreadyTracked`
    heuristics. The old `asset` raw-map getter still works for
    backward compat.

## 0.3.24

- **BREAKING: unified signing events.** Every on-chain transaction
  signing flow (`eth_sendTransaction`, `solana_signTransaction`,
  `solana_signAndSendTransaction`, `mpurse_signRawTransaction`)
  now comes through a single `TransactionSignRequest`. Every
  arbitrary-data signing flow (`personal_sign`,
  `eth_signTypedData*`, `solana_signMessage`, `mpurse_signMessage`)
  comes through a single `MessageSignRequest`. Branch on
  `req.method` (and `req.chain`) for chain-specific copy.

  **Removed Dart classes:** `SignRequest`, `PersonalSignRequest`,
  `SignTypedDataRequest`, `SolanaSignMessageRequest`,
  `SolanaSignTransactionRequest`,
  `SolanaSignAndSendTransactionRequest`,
  `MpurseSignMessageRequest`, `MpurseSignTransactionRequest`.

- **Rich decoded payload on every event** — host UIs no longer
  need a follow-up `Transaction:simulate` call to render an
  approval sheet. `TransactionSignRequest` carries:
  - `decodedMethod` / `decodedArgs` — recognised top-level
    operation (`native_transfer`, `erc20_transfer`,
    `erc20_approve`, …)
  - `effects` — every transfer / approve at any call depth
  - `balanceChanges` — signed native-balance deltas per address
  - `warnings` — stable-coded advisories
    (`recipient_is_contract`, `erc20_approve_unlimited`,
    `net_loss_exceeds_amount`, …)
  - `willRevert` / `revertReason`
  - `feeAmount` + `feeDecimals` + `feeSymbol`, `networkName`,
    `sizeBytes`, `raw`
  - chain-specific extras: `evmTransaction`,
    `solanaUnitsConsumed`, `solanaLogs`, `bitcoinInputs`,
    `bitcoinOutputs`, `bitcoinFeeSats`

  EVM gets the full simulate decoder run at request-emit time;
  Solana decodes the common System Program transfer locally;
  Bitcoin runs through the existing `simulateBitcoin` decoder.

- **`MessageSignRequest` decoded payload:**
  - `messageBytes` (raw) + `messageText` (UTF-8 try)
  - `structuredData` / `structuredPrimaryType` /
    `structuredDomain` for EIP-712
  - **Auto-detected SIWE / SIWS** (`isSiwe` / `isSiws`) with
    parsed `siweFields` (`domain`, `address`, `uri`, `version`,
    `chainid`, `nonce`, `issuedat`, `expirationtime`, …) — UIs
    can render a friendly "Login to example.com" prompt instead
    of a raw message body.
  - `warnings` (e.g. message contains a URL)

- **New helper types** for the rich payload: `TxSignEffect`,
  `TxSignBalanceChange`, `TxSignWarning`, `TxSignBitcoinIO` —
  exported from `package:libwallet/libwallet.dart`.

## 0.3.23

- **BREAKING: unified network-switch approval.** Every network
  switch — `wallet_switchEthereumChain` (with or without an
  unknown-but-recognized chain) AND cross-family action methods —
  now flows through a single `ChainSwitchRequest` event. Two
  shapes distinguished by which fields are populated:
  - **Pre-specified target** (`req.targetNetwork != null`): dApp
    named a specific chain. Render a confirm sheet. When
    `req.isNewNetwork` is true, the chain isn't in the wallet yet
    and approval implies Add + Switch. Approve with
    `accounts: [accountId]` only — `network` is taken from the
    request.
  - **Picker** (`req.targetNetwork == null`,
    `req.candidateNetworks` populated): dApp triggered a
    cross-family action. Render a network + account picker.
    Approve with both `network: pickedId` and
    `accounts: [pickedId]`.

  `ChangeNetworkRequest` and `AddAndSwitchNetworkRequest` are
  removed. Hosts pattern-matching on those need to switch to
  `ChainSwitchRequest` and branch on `req.targetNetwork != null`.
  See `dart/doc/webview_integration.md` for the new example.

  `AddNetworkRequest` is unchanged — pure add (no switch) is a
  distinct intent from `wallet_addEthereumChain`.

  On approval libwallet still does Save (when new) + SetCurrent +
  implicit connect server-side. Hosts do **not** need a separate
  `client.networks.setCurrent(...)` call.

## 0.3.22

- **EIP-2255 wire shape fix.** `wallet_requestPermissions` and
  `wallet_getPermissions` now return one permission entry per
  capability (the EIP-2255 shape) with all authorised addresses in
  a single `restrictReturnedAccounts` caveat — instead of one entry
  per account with a missing `parentCapability` field. dApps that
  read `perm.parentCapability` (etherscan.io, MetaMask test-dapp,
  most wallet UI kits) now get `"eth_accounts"` instead of
  `undefined`.
- **`eth_accounts` is filtered to EVM-compatible addresses.** Solana
  / Monacoin accounts that happen to be connected to the same dApp
  no longer leak through, and `"N/A"` placeholders (from ed25519
  accounts re-derived for an EVM network) are dropped. Empty result
  is `[]`, not `null`.
- **Cross-chain auto-switch (`ChainSwitchRequest`).** When a dApp
  calls an action method (sign / send / connect) on a chain family
  different from the wallet's current network, libwallet now emits
  a `chain_switch` approval that lets the user pick BOTH the target
  network AND an account in one prompt. On approve, the wallet
  switches network and saves a `ConnectedSite` for `(host, account)`
  so the original method runs with the dApp already connected. Skip
  the prompt automatically when the wallet has no compatible
  network or account for the requested family — original handler
  errors more informatively in that case.
- **`Web3:request` recognises `wallet_revokePermissions`** (EIP-2255
  revoke). Was unhandled in pre-0.3.21 builds and fell through to
  the chain RPC relay producing `failed to decode response …
  invalid character 'm'`. Already fixed in 0.3.21; the docs now call
  this out explicitly.
- **`wallet_switchEthereumChain` accepts both spec + bare-string
  param shapes.** Etherscan and other EIP-3326-compliant dApps no
  longer 500 with `failed to convert map[string]interface {} to
  string`. When the target chain isn't registered yet but is in
  libwallet's static metadata, emits a combined
  `add_and_switch_network` approval instead of bouncing 4902.
- **Network change happens server-side.** When the user approves
  any network-changing request (`change_network`,
  `add_and_switch_network`, `chain_switch`), libwallet calls
  `SetCurrent` itself before returning to the dApp. Hosts no longer
  need to call `client.networks.setCurrent(...)` after
  `requests.approve(...)` — the workaround is redundant on 0.3.22+.
- **NFTs on non-mainnet EVM chains return `[]` instead of 500.**
  `Nft:list` on Sepolia (and any other non-mainnet EVM chain not
  covered by the modchain provider) now returns an empty list so
  the wallet UI just renders "no NFTs" instead of failing the whole
  asset view.
- **Doc: webview integration guide gained a "Network + permission
  semantics" section** answering who switches the network on
  approval, who switches the account, what the EIP-2255 wire shape
  is, and where the typical workarounds were masking real bugs.
  Step 4's example switch covers `AddNetworkRequest`,
  `ChangeNetworkRequest`, `AddAndSwitchNetworkRequest`,
  `ChainSwitchRequest`, and `WatchAssetRequest` with concrete
  approve calls.

## 0.3.21

- **Fix: `wallet_revokePermissions` (EIP-2255).** Was unhandled in
  0.3.20 and fell through to the chain-RPC relay, surfacing as
  `invalid character 'm' looking for beginning of value` on
  etherscan.io and any other dApp that calls it. Now revoking
  `eth_accounts` drops every `ConnectedSite` row for the requesting
  host (same effect as `solana_disconnect` on the Solana side) and
  returns null. Unknown permissions are silently ignored for
  forward-compat (matches MetaMask).

## 0.3.20

- **Fix: `swap.availability()` 404 on 0.3.19.** The handler
  signature included a spurious `*struct{}` second arg that
  apirouter's dispatcher didn't match, so the endpoint never
  resolved at call time. Realigned to the idiomatic zero-param
  shape used by other parameterless handlers.
- **Fix: `wallet_switchEthereumChain` params.** 0.3.19 decoded the
  first param as a string, which failed with `failed to convert
  map[string]interface {} to string` on EIP-3326-compliant dApps
  like etherscan.io. Now accepts both the spec shape
  `[{chainId: "0x…"}]` and the bare-string form some non-compliant
  dApps still send.
- **New: combined add + switch approval flow.** When a dApp calls
  `wallet_switchEthereumChain` for a chain the wallet hasn't seen
  yet but which libwallet recognizes from its static chain
  metadata, emits a single `add_and_switch_network` approval
  request (new `AddAndSwitchNetworkRequest` subtype). The UI can
  render "etherscan.io wants to add Polygon and switch to it" in
  one prompt instead of bouncing the dApp with a 4902 error and
  forcing it to retry through `wallet_addEthereumChain`.
  Unknown-to-libwallet chains still return 4902.
- **Breaking: `rawRequest` / `rawRequestWithProgress` removed**
  from `LibwalletClient`. The typed API namespaces cover the
  feature surface; the raw door encouraged callers to hardcode
  paths and couple themselves to internal wire shapes, which
  meant every server-side rename silently broke them. Migrate to
  the equivalent typed call (`client.info.ping()`,
  `client.transactions.list()`, etc).

## 0.3.19

- **New `swap.availability()` endpoint** — UI feature-flag for the
  "Swap" button. No RPC calls; returns `{available, network,
  providers, reason}` in a couple of ms. Gate per specific
  `<type>.<chainId>` (e.g. `"evm.1"` / `"solana.mainnet-beta"`) so
  devnet / testnet / unsupported EVM chains don't render the Swap
  affordance:
  - Solana mainnet → available (Jupiter + dFlow).
  - Solana devnet / testnet → `unsupported_chain`.
  - EVM chains covered by 1inch (`1`, `10`, `56`, `100`, `137`,
    `250`, `324`, `8453`, `42161`, `43114`, `59144`) → available
    once `OneInchAPIKey` is compiled in; `missing_api_key` until
    then.
  - Other EVM chains → `unsupported_chain` (1inch doesn't cover
    them — would 404 upstream).
  - Bitcoin-family (bitcoin, bitcoin-cash, litecoin, dogecoin,
    monacoin, …) → `unsupported_chain`.
  - `SwapAvailability.chainFamily` / `chainId` getters split
    `network` for apps that need the family vs. the specific id.

## 0.3.18

- **`accounts.delete()` now cascade-removes Web3 connections** that
  reference the deleted account. Before 0.3.18 those rows were left
  behind pointing at a non-existent account id — every list of
  connected sites for that account would keep returning stale data
  until the user manually deleted each one. Done synchronously, so
  no orphan window exists. Scoped: unrelated connections for other
  accounts are untouched. Transactions are intentionally NOT
  cascaded (tx history outlives the originating account by design).

## 0.3.17

- **`Transaction:list` now supports cursor pagination + filters that
  the docs always promised.** Up to 0.3.16 the handler was hardcoded
  to 50 rows and the `From` / `Network` query params were silently
  ignored on this path (only `DELETE Transaction` honoured them).
  New `before` (RFC3339Nano cursor on `Created`) and `limit`
  (default 50, capped 200) params drive an infinite-scroll pattern
  — the response stays a flat list, clients derive the next cursor
  from `last.created`. Dart `transactions.list()` gains the new
  parameters with an example in the docstring.

## 0.3.16

- **Fix: `Transaction:signAndSend` now backfills `Fee` server-side**
  before saving. The new typed `UnsignedTransaction` deliberately
  omits `fee` (server is the source of truth) but signAndSend
  wasn't recomputing it on its own — apps that went straight to
  signAndSend (or used the typed shape) ended up with `null` Fee
  in tx history. Same formulas Validate already uses (gas ×
  gasPrice on EVM, `5000 + ceil(cuLimit*cuPrice/1e6)` on Solana).
  No client change needed.
- **`Transaction:maxSendable` no longer takes `network`** — it's
  derived from the asset key's `<type>.<chainId>.` prefix (the
  same shape `Asset:list` returns). Empty / bare `NATIVE` falls
  back to the current network. Pre-release cleanup; 0.3.15 was
  not consumed externally with the old shape.

## 0.3.15

- **Swap API** (`SwapApi` / `client.swap`): token swaps on Solana
  (Jupiter Ultra primary, dFlow fallback) and EVM (1inch). Two-step
  flow: `quote()` returns a `SwapQuote` with expected output, min
  output after slippage, route breakdown, and a 90 s quoteId;
  `execute(quoteId, keys)` signs and broadcasts, returning a
  `SwapResult` with the on-chain tx hash + explorer URL. All
  providers are wired with a 50 bps referral fee to libwallet's fee
  accounts (Solana: `BF436…`, EVM: `0x17Ab…`).
- **Approval detection + tight default on EVM swaps**: for ERC-20
  input tokens on 1inch, `quote()` now reads the router's current
  allowance via `eth_call` and populates
  `SwapQuote.requiresApproval`, `approvalSpender`,
  `currentAllowance`, and `neededAllowance`. When
  `requiresApproval` is true, call the new `swap.buildApproval()`
  — it returns a rich `ApprovalPreview` (token, spender label,
  amount, `isUnlimited` flag, current allowance, network fee, plus
  the validated `Transaction` to sign) ready to drop into an
  approval sheet. Default approval amount is **exactly** the swap's
  input amount, so a compromised router can only drain what the
  user already agreed to. Pass `approvalAmount: 'max'` to opt into
  the classic unlimited approve, or a decimal string for a custom
  cap — surface the trade-off via `preview.isUnlimited` in the UI.
- **Richer Quote payload for UI approval sheets**: `SwapQuote` now
  carries `providerLabel` (human-friendly name), `referralFee`
  (the 50 bps platform fee as an absolute amount in the input
  token's units), and `networkFee` (estimated chain gas in native
  currency). Apps no longer have to compute these from bps or
  gas*gasPrice themselves.
- **Known limitations in v1**:
  - The 1inch API key ships empty in this build; populate
    `wltswap.OneInchAPIKey` to enable EVM swaps.
  - No token resolver yet: callers pass `SwapTokenRef` with
    `address` + `decimals` fully resolved (the data is already
    available from `Asset:list`).

## 0.3.14

- **`Transaction:maxSendable`** (`TransactionApi.maxSendable`): new
  cross-chain endpoint that returns the largest amount safely
  sendable from an account, with a breakdown of the fee and (on
  Solana) rent-exempt reservations. Fixes the "tap Max → get
  `insufficient funds for rent`" bug: apps can now pre-compute the
  right amount instead of letting the broadcast fail. EVM and
  Bitcoin supported; token (ERC-20 / SPL) assets return an explicit
  error — full token balance is always sendable, fees paid in
  native.
- **Solana native-send preflight**: `Transaction:validate` now runs
  a balance / fee / rent check for Solana native transfers before
  signing. Typed codes: `insufficient_balance`, `below_sender_rent`,
  `recipient_rent_not_funded` — apps see a structured error with the
  exact shortfall instead of Solana's opaque simulator rejection.
- **`TransactionSimulation.warnings`**: simulate now returns a list
  of advisory `Warning`s with stable codes. Non-blocking — the tx
  can still be signed; apps decide whether to confirm with the
  user. Initial codes: `recipient_is_contract` (EVM native send to
  a contract address), `recipient_new_account` (Solana recipient
  doesn't exist yet), `erc20_approve_unlimited` (approve with top
  bit set — drainer vector), `priority_fee_recommended` (Solana
  median priority fee > 0 but tx has no ComputeBudget).
- **Solana priority fees** (opt-in): new `computeUnitLimit` /
  `computeUnitPrice` / `priorityLevel` fields on
  `UnsignedTransaction`. Set `priorityLevel: "low" | "medium" |
  "high"` to have `validate` pick a percentile of recent on-chain
  prioritization fees; or pin `computeUnitPrice` (microlamports/CU)
  directly. `"none"` opts out explicitly. Empty (default) preserves
  the legacy 5000-lamport flat fee — the serialized message is
  byte-identical to pre-0.3.14 for unchanged callers.
- **Solana displayed balance excludes rent reserve**: a user who
  receives 0.01 SOL now sees `0.01` in their wallet instead of
  `0.01089` (the extra ~0.00089 is the rent-exempt minimum the
  account needs to stay alive on-chain and is never spendable
  without closing the account). `maxSendable` still reports the raw
  balance and breakdown for apps that want to show "0.01 spendable
  + 0.00089 reserved + 0.000005 fee".

## 0.3.13

- **Logs routed over the event channel** (fixes 0.3.12's silent
  logging on iOS). 0.3.12 wired every internal diagnostic through
  `wltlog`, but the underlying `log.Printf` writes to the Go
  runtime's `os.Stderr` — which Flutter+iOS swallows entirely, and
  Flutter+Android filters out of `flutter logs` by default. End
  result: testers saw no output even with `logLevel: "debug"`. Fixed
  by routing every wltlog emission through the apirouter broadcast
  channel (same pipe Web3 requests / balance changes already use).
- **New `LogEvent` + `client.logs` stream**: subscribe once at
  startup and forward to `developer.log` / `print` so the logs show
  up in Flutter's log output on every platform:

      import 'dart:developer' as developer;
      client.logs.listen((e) {
        developer.log(e.message, name: 'libwallet.${e.level}');
      });
      await client.info.setWalletInfo(
        clientId: '...',
        logLevel: kDebugMode ? 'debug' : 'off',
      );

  `LogEvent` is also emitted on the general `client.events` stream
  for hosts that want a single subscription.
- **Sink safety**: a panic inside the sink falls back to stderr
  with no rethrow, so a broken logging pipeline can never take down
  a send.

## 0.3.12

- **Leveled logging (`wltlog`) controlled by `setWalletInfo`**: new
  `LogLevel` field on `WalletInfo`. Valid: `"debug" | "info" | "warn"
  | "error" | "off"`; empty resolves to libwallet's auto-default —
  `"debug"` on dev binaries (gitTag empty), `"info"` on release
  binaries. Typical pattern: `logLevel: kDebugMode ? "debug" : "off"`.
  Every log call site routes through `wltlog.{Debugf,Infof,Warnf,
  Errorf}`; lines are prefixed `[debug] / [info] / [warn] / [error]`
  so testers can grep by level regardless of the host's logger.
  `getWalletInfo` also returns `effectiveLogLevel` so the host can
  see what libwallet actually resolved `""` to.
- **Ed25519 self-heal diagnostics**: the self-heal now logs a
  specific skip reason at every gate (nil account, no wallet,
  `GetEnv(ctx)` nil, `WalletById` failed, wrong curve, no keys,
  decrypt failed, empty want, already-correct), visible at `debug`.
  The actual repair (Pubkey/Address flip) logs at `info`. Combined
  with the always-on `want` vs `acct.Pubkey` vs `wallet.Pubkey`
  dump, a tester flipping `logLevel: "debug"` gets everything
  needed to pin down why a Solana send fails.
- **`FindAccount` now runs `check()` on the address-lookup path**:
  previously only the ID-lookup branch refreshed Curve / Address —
  tx.From is almost always an address, so account records with an
  empty Curve (rare but possible) would silently short-circuit the
  Ed25519 self-heal's curve gate. Fixed by calling `acct.check(e)`
  after the by-Address fetch.
- **Pre-broadcast Ed25519 verify**: `Transaction:signAndSend` on
  Solana now runs `ed25519.Verify(fee_payer, message, sig)` locally
  before sending to the RPC. Catches pubkey/key-share mismatches
  with a specific error message ("TSS key shares may be inconsistent
  with stored pubkey") instead of the generic Solana-side rejection.
- **Extended pre-flight repair to every Solana sign path**: 0.3.11
  put the pre-flight only in `Transaction:signAndSend`. The shared
  helper `wltacct.EnsureEd25519PubkeyOnAccount` is now called from
  `Account:signMessage` (solana mode), `Account:signTransaction`,
  `Account:signAndSendTransaction`, and Web3 `solana_sign_message`
  / `solana_sign_transaction` / `solana_sign_send_transaction`. The
  helper also saves the repaired Account row synchronously so the
  dApp's next `window.solana.publicKey` read returns the corrected
  address.
- **Per-RPC timing logs** (at `debug`): every `Network.DoRPC` /
  `DoRPCNamed` emits `rpc: chain=X method=Y OK in Nms (B bytes)` or
  `FAIL in Nms: err`. Quiet at `info`; noisy but invaluable when
  reproducing a bug.
- **Per-key-decrypt timing** (`wallet-sign` logs, at `debug`): entry
  line with wallet id/threshold/keys/msg_len; per-key "decrypted in
  N ms (type=Password|StoreKey|…)". Pubkey mismatch detected during
  sign logs at `warn`.

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
