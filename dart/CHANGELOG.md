## 0.4.36

- **Added: device-to-device wallet transfer.** New endpoints
  `Wallet:exportToDevice` (old device, paints a QR),
  `Wallet:exportToDevice:confirm` / `:cancel` (decision callback
  after the user confirms on the source device), and
  `Wallet:importFromDevice` (new device, takes the scanned code).
  Single Spot round trip per transfer, 5-minute single-use
  pairing token, AES-256-GCM payload sealed with a key derived
  from the QR-borne token, includes the wallet JSON + device
  share private keys in one shot so the destination can sign
  immediately without a reshare. Dart surface ships
  `DeviceTransferSession`, `DeviceShareEntry`, and
  `DeviceTransferImportResult` models. Full implementor guide in
  `doc/device_share.md` under the "Device-to-device transfer"
  section.

## 0.4.35

- **Modernized: TSS protocols.** All new wallets are now created
  with modern threshold protocols — DKLs23 for secp256k1
  (Bitcoin / Ethereum / …) and FROST per RFC 9591 for ed25519
  (Solana / Sui / …). The legacy GG18 / eddsatss keygen paths are
  no longer reachable; existing wallets created under those
  protocols keep working (sign + reshare + promote all detect the
  protocol and use the matching primitive). `Wallet.protocol`
  surfaces `"dkls23"` or `"frost"` for new wallets; existing rows
  with empty `protocol` are interpreted per their curve. Modern
  resharing, modern promote, and the ClawdWallet keygen handshake
  all run through the new protocols transparently — no Dart-side
  API change beyond the optional `ChainMigration.curve` below.

- **Added: `ChainMigration.curve`** for the modern `Wallet:promoteMnemonic`
  fan-out. The Go side now dispatches each chain on its curve —
  `"secp256k1"` lands on a DKLs23 wallet (Bitcoin, Ethereum, …) and
  `"ed25519"` lands on a FROST wallet (Solana, Sui, …) — so one
  BIP39 mnemonic can produce wallets on both curves in the same
  call. The Dart model picks the field up automatically when you
  build via `ChainMigration.fromProbeRow(row)`; manual constructions
  should pass `curve: 'secp256k1'` or `curve: 'ed25519'` explicitly.
  Empty defaults to `"secp256k1"` for backwards compatibility with
  pre-modern callers.

- **Added: `SwapQuote.status` + `SwapQuote.statusMessage` + `SwapQuote.isExecutable`.**
  `SwapApi.maxSpendable` previously errored out on two soft-failure
  paths — the wallet's spendable balance can't cover network fee +
  rent, or the provider returned no route at the resolved amount
  (Jupiter's "Failed to get quotes" on dust-sized SOL trades).
  Hosts that built source-list UIs by hiding any asset that
  errored ended up hiding assets the user actually held: e.g.,
  swap most of your SOL → USDC, end up with 0.0061 SOL, and SOL
  disappears from the "from" picker even though the wallet still
  owns it. `maxSpendable` now returns a `SwapQuote` with
  `status == "balance_too_small"` or `status == "no_route"` and a
  human-readable `statusMessage` instead. `isExecutable` returns
  false for these — show the row with the message and skip
  `SwapApi.execute` until the conditions change. `SwapApi.quote` /
  `SwapApi.quotes` still error on no-route (the user is asking
  for a specific trade and a silent no-route would be misleading).

## 0.4.33

- **Changed: transient phplatform errors retry transparently** in
  every libwallet → `Crypto/WalletSign:*` call (`remoteNew`,
  `remoteVerify`, `remoteSign`, `remoteReshare`, `walletkey`'s
  key-list + setGeneratedKey, etc.). HTTP 5xx — including the
  "There was a database error" blip the integration tests have
  been tripping on — retries up to 3 attempts with 500ms / 1s
  backoff. 4xx errors (auth, validation, not-found) pass through
  immediately. Context cancellation aborts the loop. Affects
  runtime callers too, not just tests — a brief backend hiccup no
  longer surfaces as a user-visible error.

## 0.4.32

- **Fixed: Jupiter "Failed to get quotes" on tiny Solana swaps.**
  At small input amounts (typically under ~0.01 SOL), Jupiter's
  RFQ market makers (JupiterZ) will gladly fill the trade — they
  even subsidize the gas — but stacking our 50 bps platform fee on
  top makes the route stop penciling and Jupiter falls back to
  aggregator routes that can't handle the size. The Jupiter
  adapter now retries once without the `referralFee` /
  `referralAccount` params on the specific "Failed to get quotes"
  no-route response. The retry's success path returns a Quote
  with `feeBps: 0` and `referralFee: 0` so the host's approval
  sheet correctly shows "no platform fee on this swap". One extra
  RTT only when the first attempt couldn't route.



- **Added: `Asset.isNative` + `Asset.tokenAddress`** on the Dart
  model (plus matching `IsNative()` / `TokenAddress()` on Go's
  `wltasset.Asset`). Use `asset.isNative` to branch native-vs-token
  instead of inventing a matcher on `Asset.type` / `Asset.symbol`
  / `Asset.name`. libwallet emits `Type: "fungible"` for both
  native and tokens — `Asset.key`'s `.NATIVE` suffix is the only
  invariant native-vs-token signal, and these getters wrap it as
  the canonical predicate.
- **Doc clarification on `Asset.type`** — the field's old example
  list (`"native"`, `"erc20"`, `"spl-token"`) was aspirational;
  the runtime value is always `"fungible"` for balance entries.
  Updated to reflect reality and point readers at `isNative`.

## 0.4.31

- **Added: `client.swap.quotes(...)`** — quote the same swap across
  every available provider for the chain in parallel and get one
  `QuoteAttempt` per provider back. Successful attempts carry a
  `SwapQuote` (with its own `quoteId` ready for `swap.execute(...)`);
  failed attempts carry a typed `SwapError` so the picker UI can
  render `"Jupiter Ultra: Failed to get quotes"` next to
  `"dFlow: 0.00748 SOL → 1.49 USDC"`. The user picks; libwallet
  never silently switches between providers.
- **Changed: `swap.quote(...)` no longer silently falls back from
  Jupiter to dFlow on Solana.** If the primary provider errors,
  the host receives that error directly. Hosts that want
  comparison should call `swap.quotes(...)` instead; hosts that
  want the old "best-effort single quote" behaviour can call
  `swap.quote(provider: 'jupiter_ultra')` then `swap.quote(provider:
  'dflow')` themselves on failure.
- **Changed: Jupiter `HTTP 400 "Failed to get quotes"`** is now
  classified as `no_liquidity` instead of `provider_bad_request`.
  This is semantically correct (it's a routing failure, not a
  malformed request) and matches Jupiter's `HTTP 200` "empty
  transaction" path which already maps to `no_liquidity`. Hosts
  that branch on the error code now see one code for both
  no-route surfaces.

## 0.4.30

- **Fixed: `Swap:quote` / `Swap:maxSpendable` rejected `Asset.Key`-shaped
  token addresses.** Hosts that piped `Asset.Key` (the
  `"solana.mainnet.<mint>"` / `"evm.1.<contract>"` shape returned by
  `Asset:list`) into `tokenIn.address` / `tokenOut.address` got an
  HTTP 400 from Jupiter ("Invalid outputMint") or 1inch — libwallet
  was passing the prefixed string straight through to the aggregator,
  which only accepts bare mints / contracts. The swap entry points
  now strip the `<type>.<chainId>.` prefix; bare addresses pass
  through unchanged. The `"NATIVE"` sentinel works in both forms.

- **Added: `MessageSignRequest.verifyingContractLabel`** — typed-data
  approval sheets can now show `"Uniswap V3: SwapRouter02"` (or
  `"OpenSea: Seaport 1.6"`, `"Aave V3: Pool"`, …) above the raw
  `0x…` for EIP-712 messages whose domain `verifyingContract`
  matches a known address in libwallet's contract registry. Empty
  for unknown contracts — host falls back to the raw address.
  Domain `chainId` is normalised (JSON number, decimal string, hex
  string, `0x`-prefixed) so dApp idiosyncrasies don't matter.
- **Added: `LibwalletClient.contracts.lookup(chainKey:, address:)`**
  — generic registry lookup for hosts that want to label addresses
  at other render sites (effect rows, watch_asset, explorer-link
  rows). Returns a `ContractLabel` (`address`, `label`, `kind`,
  `project`) or `null` for unknown addresses. Same registry that
  backs the typed-data field.
- **Initial registry coverage:** Uniswap V2/V3 routers, Universal
  Router, Permit2; OpenSea Seaport 1.5 + 1.6; Aave V3 Pool;
  Compound V3 Comet (cUSDCv3, cWETHv3); Balancer V2 Vault;
  Curve 3pool. Chains: Ethereum, Base, Arbitrum, Optimism, Polygon,
  Avalanche. Permit2 + Seaport are deterministic-address contracts —
  they resolve correctly across every chain that's in the registry
  without per-chain copies of the entry.

## 0.4.29

- **Added: `Network.addressUrl(address)` + `Network.transactionUrl(hash)`
  helpers on the Dart model.** Pure-sync, return a fully-composed
  block-explorer URL with the right per-chain shape applied —
  `?cluster=<id>` suffix for non-mainnet Solana, `/address/` vs
  `/tx/` paths, `""` when no explorer is resolvable. Hosts no longer
  need to fork the per-chain composition logic to render "tap address
  → open in explorer" affordances on signing-critical rows.
- **Added: `Network.resolvedBlockExplorer`** — populated by libwallet
  with the bare base URL after resolving the `"auto"` sentinel
  against the chain registry. Backs the URL helpers; also useful to
  hosts that compose other URL shapes (`/token/`, `/block/`). Empty
  when no canonical explorer is known (custom chains with nothing
  configured) — hosts should hide the affordance in that case.

- **Added: `Amount.max(decimals)` sentinel — resolved at build time.**
  Pass `Amount.max(...)` as `Transaction.amount` and libwallet's build
  path (`Transaction.Validate`, called by `signAndSend`) substitutes
  `balance - actual-fee` at the latest possible moment using the
  resolved gas estimate of the actual tx contents (recipient,
  calldata). Eliminates the `transactions.maxSendable` →
  `transactions.signAndSend` race where the gas price or balance can
  drift between the two calls — the same `Validate` pass that picks
  the gas number also picks the amount. Native EVM only in this
  release; Bitcoin uses the existing UTXO-pinning path
  (`bitcoinUtxos` + `bitcoinFeeRate` from `MaxSendable`); Solana MAX
  resolution is a follow-up. Wire form: `{"v": "MAX", "e": <decimals>}`
  (or bare `"MAX"` string).
- **Added: `Transaction:maxSendable` accepts `data` (EVM).** When
  set, the EVM path runs `eth_estimateGas` with the calldata to get
  the contract's actual gas cost instead of the 21000 EOA-transfer
  default — the right number for previews of native swaps where the
  default reserved ~10x too little. The placeholder value passed to
  estimateGas (some swap routers revert with `value: 0`) is
  `balance/2`, computed internally; the caller never has to specify
  it. Plain transfers (no `data`) keep the 21000 fast-path with no
  extra RTT. **Prefer `Amount.max` in the actual tx** over computing
  max upfront — same answer with no drift-window between maxSendable
  and signAndSend.

## 0.4.28

- **Added: Solana mainnet token-list auto-discovery on first asset
  list.** The first time `Asset:list` runs for a (mainnet Solana,
  owner) pair, libwallet calls Helius DAS `getAssetsByOwner` with
  `showFungible: true` and seeds the user's `Token` table with the
  fungibles the address actually holds — name + symbol + decimals
  in one round trip, no manual `Token:create` per token. A
  conservative spam filter rejects entries with empty symbol,
  symbol > 12 chars, name > 64 chars (typical link-stuffing
  pattern), or non-positive decimals. Subsequent `Asset:list`
  calls skip the discovery (config flag gated per
  network/owner) and use the cached Token rows for name/symbol
  enrichment. Devnet/testnet are excluded — DAS coverage there
  is patchy.
- **Changed: Solana SPL balances enrich names from the Token table.**
  `SolanaTokenBalances` previously returned `EPjFW.../EPjFW`-style
  truncated mint fallback whenever the embedded curated registry
  didn't recognise a mint. Now the result is overlaid with the
  user's Token-table metadata (populated by the auto-discovery,
  by `Token:create`, or by post-swap registration). So newly-
  acquired tokens — via swap, airdrop, or transfer — surface with
  their proper name without a manual lookup.

## 0.4.27

- **Fixed: balances stayed stale after a successful swap.**
  `Swap:execute` paths through Jupiter / dFlow / 1inch broadcast via
  the aggregator's own HTTP/RPC route and never called
  `wltintf.NotifyTxBroadcast`, so the balance poller didn't get the
  nudge it does after every other broadcast. Both the spent
  (`TokenIn`) and earned (`TokenOut`) balances now refresh within
  ~a second of the swap landing instead of waiting up to 60 s for
  the next polling tick.
- **Added: previously-unknown swap outputs auto-register in the
  user's token list.** When `Swap:execute` lands on a `TokenOut` the
  user has never held before, libwallet inserts a `Token` row with
  the metadata from the swap quote (symbol, decimals) so the new
  asset surfaces in `Token:list` with its name instead of
  "Unknown". Native outputs (SOL / ETH) are skipped. Failure to add
  the token is non-fatal — logged but doesn't fail the swap.
- **Added: `wlttoken.EnsureToken(env, network, address, symbol,
  name, decimals, type)`** — Go-side helper that idempotently
  ensures a Token row exists for `(network, address)`. Currently
  called by the swap path; available for any future caller that
  wants to surface a previously-unknown asset without an explicit
  `Token:create` round trip.

## 0.4.26

- **Fixed: Solana devnet / testnet transaction-explorer links resolved
  to "Transaction not found".** `Network.TransactionUrl` was appending
  `/tx/<hash>` to the explorer base without `?cluster=`, so links to
  explorer.solana.com / solscan.io / solana.fm always queried the
  default cluster (mainnet). Non-mainnet `ChainId`s now get
  `?cluster=<id>` suffixed; mainnet stays bare.

## 0.4.25

- **Added: `LibwalletClient.wallets.createAgentWallet`** — one
  high-level call that opens the server-side `Crypto/WalletSign:newAgent`
  session (filling in `mobile_spot_id` from libwallet's own Spot
  client) and drives the 3-party EdDSA keygen ceremony to completion.
  Returns a `CreateAgentWalletResult` with the new wallet id + Solana
  address. The host passes its existing `AtOnline` session in as
  `api:` so libwallet doesn't have to manage bearer tokens. Replaces
  the previous "do four things in a row from the screen" flow.
- **Removed: `info.spotId()` / `Info:spotId` endpoint.** Hosts no
  longer need to read the local Spot TargetId — `createAgentWallet`
  fills it in internally. The shape of the previous flow (host reads
  spot id, app posts newAgent, app calls initiateKeygen) collapsed
  to a single call.
- **Added: dependency on `atonline_api` ^0.5.0** (passed in by the
  host; libwallet does not store or refresh tokens).

## 0.4.24

- **Added: `LibwalletClient.clawdWallet.pair(url)`** — verifies a
  ClawdWallet pairing URL (`tibane://pair?agent=...&token=...`) by
  handshaking with the agent over Spot and returns the verified
  `AgentIdentity` (`agentSpotId`, `suggestedName`, `agentVersion`,
  `capabilities`). Used as the deep-link replacement for the manual
  "paste agent_spot_id" field on the Create-agent-wallet flow. The
  app hands a URL string in; libwallet drives the entire Spot
  handshake. Failures throw typed `PairingException` subclasses —
  `PairingURLMalformedException`, `PairingAgentUnreachableException`
  (15s timeout), `PairingTokenInvalidException`,
  `PairingTokenExpiredException`, `PairingTokenConsumedException`,
  `PairingBadRequestException`, and
  `PairingIdentityMismatchException` (security: response's
  `agent_spot_id` ≠ URL `agent` param). Wire contract:
  `tibaneapp/docs/clawdwallet-pairing.md`.

## 0.4.23

- **Fixed: `libwalletPackageVersion` was stuck at `0.4.20` in the
  0.4.21 and 0.4.22 publishes.** The bump for those releases only
  touched `pubspec.yaml`; the constant in `lib/src/version.dart`
  was never updated, so `LibwalletClient.initialize` would trip
  its stale-binary mismatch check at runtime against the bundled
  native library. Republished with both files in sync. Use
  `dart run tools/bump_version.dart <version>` (not a hand edit)
  to keep them locked.

## 0.4.22

- **Added: `info.spotId()`** returns the local Spot TargetId
  (`k.<base64url>`). Hosts pass it into `Crypto/WalletSign:newAgent`
  as `mobile_spot_id` so the policy module includes the mobile in
  the canonical peers list for the keygen ceremony.
- **Changed: `peers[].id` wire tag** (was `spot_id`) on
  `Wallet:initiateKeygen` and `Wallet:joinSign`. Aligns with
  tss-lib's `MessageWrapper_PartyID` protobuf JSON tag so wdrone
  can unmarshal peers directly into `tss.SortedPartyIDs`.

## 0.4.21

- **Added: `Wallet:initiateKeygen` + `Wallet:joinSign`** for the
  ClawdWallet skill-gated agent-wallet protocol. `initiateKeygen` is
  the keygen leader — it sends `walletsign/<sid>/init` to each peer in
  the committee with the canonical InitPayload, then runs the local
  EdDSA keygen as a share holder. `joinSign` is the joiner side of the
  threshold-sign ceremony (mobile is not in the sign committee for
  ClawdWallet; the agent leads). PartyID.Key is taken from the
  peer-supplied `key` field, matching wdrone's existing convention.

## 0.4.20

- **Fixed: `Account:signAndSendTransaction` (Solana) failed
  with "failed to decode account address" whenever the wallet
  UI was on a non-Solana network.** `acct.Address` is the
  network-specific display string and becomes `"N/A"` off
  Solana, so basing the slot lookup on it broke any host that
  hadn't called `networks.setCurrent` for a Solana cluster
  first. Read the raw 32-byte pubkey from the stable
  `acct.Pubkey` field instead.

## 0.4.19

- **Fixed: Solana `Account:signAndSendTransaction` posted to
  whatever the wallet UI was currently showing** — typically an
  EVM RPC, which then returned
  `The method sendTransaction does not exist`. The send path
  now picks an actual Solana network: if `CurrentNetwork` is
  already a Solana cluster (so a user testing on devnet keeps
  that selection) it's preserved, otherwise the default Solana
  mainnet entry seeded by `MakeDefaultNetworks` is used.

## 0.4.18

- **Fixed: Solana sponsored transactions silently lost the
  owner's signature.** `Account:signTransaction` /
  `signAndSendTransaction` wrote the signature unconditionally
  into signature slot 0. For sponsored txs the relay (fee
  payer) holds slot 0 and the wallet owner is at slot 1+ — so
  the owner's signature clobbered the relay's slot, the relay
  re-signed slot 0 with its own key (overwriting the owner's),
  and the tx hit Solana with slot 1 still zeroed and got
  rejected with "missing signature for account 1". libwallet
  now walks the message's account-keys array to find which
  slot matches the signer's pubkey and writes there. Handles
  both legacy and v0 versioned messages. Pubkeys that aren't
  required signers for the transaction are rejected.

## 0.4.17

- **Fixed: the FFI transport only worked on macOS.** The
  default library loader unconditionally opened
  `liblibwallet.dylib`, so iOS, Android, Linux, and Windows
  builds either failed to find a library or loaded a stale
  one. Now picks the right thing per platform:
    - iOS uses `DynamicLibrary.process()` (bridge symbols are
      statically linked into the host binary via
      `LibwalletBridge.m`; there is no `.dylib` to dlopen);
    - Android constructs the versioned per-ABI filename
      `liblibwallet-android-<abi>-v<version>.so` that
      `hook/build.dart` actually ships;
    - macOS / Linux / Windows use the conventional
      `liblibwallet.{dylib,so}` / `libwallet.dll`.
  Unknown platforms or ABIs raise `UnsupportedError` instead
  of silently failing.

## 0.4.16

- **Fixed: bitcoin "send max" intermittently failed with
  insufficient-funds at signAndSend** even when the
  `maxSendable` value was correct. Two races contributed:
  1. Math mismatch — `maxSendable` budgeted vsize for 1 output
     (max-send → no change), but `signAndSend`'s coin-selection
     guard assumes 2 outputs (recipient + change). For an
     exact-max send, build's fee was strictly larger and
     `change` went negative.
  2. Fee-rate drift — both calls independently asked
     `estimatesmartfee`, and a different reading between them
     would push the math out of agreement.

  Fix bundles two complementary parts:
    - `MaxSendableResult` now exposes `bitcoinUtxos` +
      `bitcoinFeeRate` carrying the exact selection + sat/vB
      it computed against.
    - `UnsignedTransaction` accepts `bitcoinFeeRate` (`utxos`
      already existed). When set, the build path skips the
      `estimatesmartfee` RPC and uses the pinned values.
    - New convenience `UnsignedTransaction.maxSend(m, to: ...)`
      threads both fields automatically — recommended path
      for any "Send Max" button.
    - `maxSendable` now budgets at 2-output vsize so the
      coin-selection check passes; build emits a 1-output tx
      and the small ~31 vbyte × rate overestimate goes to
      the miner. No special-casing needed elsewhere.
- **New: `priority` field on `Transaction:maxSendable` + the
  existing `priorityLevel` on `Transaction` now drives bitcoin
  fee selection.** Map: `"low"` → `estimatesmartfee` target 144
  blocks (cheap), `""` / `"medium"` → 6 (default), `"high"` →
  2 (fast). Call `maxSendable` twice with different priorities
  to power a "cheap vs fast" comparison UI; pass the chosen
  result through `UnsignedTransaction.maxSend` and the actual
  send uses the same fee budget. EVM and Solana semantics
  unchanged (Solana already used `priorityLevel` for
  ComputeBudget pricing).

## 0.4.15

- **Fixed: `transactions.maxSendable` returned 0 right after a
  send.** The bitcoin path was still scanning only `m/0` while
  `signAndSend` had moved to both chains in 0.4.10 — change
  UTXOs landed on `m/1` and were invisible to maxSendable.
  Switched to the same combined fetch `signAndSend` uses.
- **Performance: collapsed two bitcoin UTXO fetchers into one.**
  Coin selection, max-sendable, listUTXOs, sign-raw, and the
  simulate dry-run all now read from a single
  `modchain_assets` call. Previously some paths additionally
  hit `modchain_lookupTxoBIP32` per chain just to discover the
  next change index — which becomes meaningful overhead on
  wallets with hundreds of historical outputs. Next-change-
  index is now derived from the same unspent set's `m/1`
  entries (see `nextChangeIndex` for the fully-spent-history
  caveat).

## 0.4.14

- **Fixed: every bitcoin-family `signAndSend` failed with `-25
  bad-txns-inputs-missingorspent` since BTC support shipped on
  Apr 14.** `parseTxoRef` reversed the txid bytes before storing
  them in `BtcTxInput.TXID`, but outscript also reverses TXID
  at marshal time (its convention is "TXID stored in displayable
  / big-endian form, wire reversal happens at serialize"). The
  double-reverse meant every broadcast tx referenced a bogus
  txid that was the modchain-reported id with its bytes flipped
  — and the litecoin / bitcoin / dogecoin / monacoin / bitcoin-
  cash node correctly rejected it because no such UTXO exists.
  All previous `bad-txns-inputs-missingorspent` reports
  attributed to "modchain reindex lag" or "stale UTXO state"
  were really this bug. The 0.4.12 in-memory tracker and 0.4.12
  spent-filter remain useful but were never the actual fix.
- **Same byte-order bug fixed in `SignRawBitcoinTx`** (mpurse /
  Counterparty path): wire-decoded TXIDs were reversed before
  the modchain ownership lookup, making every input report as
  "not owned by this account". Removed the reverse.
- **Regression test pins the byte-order convention** so a future
  refactor that flips `parseTxoRef` back to the old behaviour
  fires loudly at test time, not in production.

## 0.4.13

- **Diagnostics: bitcoin broadcast errors now carry the inputs +
  raw tx hex.** When `sendrawtransaction` rejects a tx (e.g.
  `bad-txns-inputs-missingorspent`) the error message now
  includes the full `(txid:vout)` list libwallet selected and
  the hex-encoded transaction. Without these, reproducing the
  failure required guessing which UTXO modchain reported but
  the bitcoin node disagreed about. Format:
  `sendrawtransaction: <upstream> (inputs=a:0,b:1 rawhex=...)`.

## 0.4.12

- **Fixed: bitcoin-family `signAndSend` errored with `-25
  bad-txns-inputs-missingorspent`** in two distinct cases:
  1. modchain returning a `txo[]` entry with a non-null `spent`
     field. Fetch path now drops anything with a populated
     `spent` value before coin selection sees it.
  2. Back-to-back sends. Send #1 spends UTXO A and creates
     change UTXO B; send #2 issued seconds later picked A
     again because modchain hadn't reindexed past send #1's
     mempool tx, and the broadcast failed because the bitcoin
     node knew A was already spent.
- **New: in-memory UTXO tracker** that bridges the
  modchain-reindex gap. After every successful broadcast it
  records the inputs that were just spent + the change UTXO
  that was just created (with the broadcast tx hash filled in).
  The next coin-selection call layers this on top of modchain's
  response — drops the spent ones, injects the pending change.
  TTL: 1 hour. When modchain catches up the matching pending
  entry auto-prunes (the modchain ground truth replaces our
  local copy). Process-local state — survives within one
  libwallet session, lost on restart (by which time modchain is
  current anyway). Lets a user fire several bitcoin sends in a
  row without waiting for confirmations between them.

## 0.4.11

- **Fixed: bitcoin-family `signAndSend` errored with "pubkey of
  type *ecdsa.PublicKey does not support pubkey:comp export"**
  on the first spend that touched a non-`p2wpkh` UTXO (legacy
  `p2pkh` or wrapped-segwit `p2sh:p2wpkh`). The TSS input
  signer's `Public()` returned `*ecdsa.PublicKey`, but
  outscript's witness builder requires a type that implements
  `SerializeCompressed()`. Returns `*secp256k1.PublicKey`
  directly now (which has the method natively). Latent since
  forever; surfaced by 0.4.10's m/0+m/1 coin selection because
  before then we only ever spent receive-chain p2wpkh outputs.

## 0.4.10

- **Fixed: bitcoin-family `signAndSend` could only spend receive-
  chain UTXOs.** Coin selection used to fetch only `m/0` —
  anything that landed on a change address (`m/1/i`) showed up in
  the balance but couldn't be spent until it happened to land on
  a future receive address. `buildBitcoinTx` now scans both
  chains via a single `modchain_assets` call and signs each
  input with the right key derived from its own path
  (`m/0/*` vs `m/1/*`).
- **Fixed: bitcoin-family fee under-payment with mixed-shape
  inputs.** Per-input vsize is now read from the actual script
  type (`p2wpkh` ≈ 68 vb, `p2sh:p2wpkh` ≈ 91, `p2pkh` ≈ 148)
  instead of assuming every input is `p2wpkh`. A wallet that
  received funds at a legacy address mixed with segwit no
  longer broadcasts an under-paid tx that stalls in the mempool.
- **`account.findAccount` fallback by network-derived address.**
  Frontends often hand back the displayed `Account.address`
  (which is the current network's derived form, e.g. `ltc1...`)
  as `from`, but the DB column still holds the creation-time
  address. `FindAccount` now derives each candidate's address
  for the current network and matches — fixes
  `LibwalletException(404): file does not exist` on
  `Transaction:maxSendable` (and any other `from`-resolving
  endpoint) when called from a non-EVM chain.
- **Fixed: bitcoin-family `Asset:list` (cont.)** — reverted the
  0.4.9 lookupTxoBIP32 sum back to `modchain_assets` now that
  the backend merges receive + change correctly. Single RPC,
  same source of truth as the rest of the bitcoin path.
- **`txo.path` accepted alongside legacy `i`/`branch`.** Newer
  modchain emits `path: "m/0/0"` only; the wallet now reads the
  trailing segment for the BIP32 child index and falls back to
  the legacy `i` field when present.
- **New: `accounts.listUTXOs(id, network: ...)`** — returns
  every spendable UTXO the bitcoin-family account holds across
  receive + change, ordered largest amount first. Each entry
  carries `txo`, `path`, `amount`, `script`, `address`, and
  `height`. Pair with the new `utxos` field on
  `UnsignedTransaction` to power a manual coin-selection
  picker.
- **New: `UnsignedTransaction.utxos: List<String>?`** — when set
  on a `bitcoin_transfer`, libwallet skips greedy auto-selection
  and uses exactly the supplied `"<txid>:<vout>"` entries
  (each verified to be owned). Empty / null preserves the
  auto-selection behaviour.
- **`transactions.simulate(...)` for bitcoin: dry-run preview.**
  When the tx hasn't been built yet (no `raw`), the simulator
  runs the same coin-selection + fee math `signAndSend` would,
  stops short of signing, and returns the planned shape:
  inputs with resolved `amount` + `address` + `path`,
  recipient + change outputs with addresses, fee in sats, and
  the new `bitcoinChange` and `bitcoinVSize` fields. Honours
  the manual `utxos` selection so a manually-picked spend
  previews exactly what it'll send. Decode-from-`raw` path
  unchanged.

## 0.4.9

- **Fixed: Bitcoin-family `Asset:list` reported zero balance even
  when the xpub held funds.** `bitcoinBalance` was calling
  `modchain_assets` with the account xpub. That endpoint can
  return `balance:0 / txo:null` for some xpubs even when
  spendable UTXOs exist at the standard `m/0` / `m/1` paths
  (observed on Litecoin: a wallet with 0.1 LTC at `m/0/0`
  surfaced as 0 in `Asset:list` while every other libwallet
  bitcoin path — sign, max-sendable, next-address — saw the
  funds correctly because they all use `modchain_lookupTxoBIP32`).

  Switched xpub balance queries to sum
  `modchain_lookupTxoBIP32(m/0)` + `(m/1)`, which is now the
  single source of truth for bitcoin-family balance / signing /
  max across the whole library. Plain-address fallback (used by
  view-only accounts with no xpub) keeps `modchain_assets` since
  that path works for single addresses. Amounts stay in satoshis
  via `outscript.BtcAmount`, so no float drift.

## 0.4.8

- **New: `accounts.addressFormats(id, network: ...)`** — returns
  every receive-address shape available for a Bitcoin-family
  account on the given chain, ordered by display preference
  (modern first). Use it to power a "show my address as Native
  SegWit / SegWit-wrapped / Legacy / …" picker, or to display
  every form a counterparty might use to send funds (the backend
  already watches every key type, so funds received at any of
  these forms land in the same balance).

  Per-chain coverage:
  - bitcoin → Native SegWit (`bc1...`), SegWit-wrapped (`3...`),
    Legacy (`1...`)
  - litecoin → Native SegWit (`ltc1...`), SegWit-wrapped (`M...`),
    Legacy (`L...`)
  - monacoin → Native SegWit (`mona1...`), Legacy (`M...`)
  - bitcoin-cash → CashAddr (`bitcoincash:...`)
  - dogecoin → Standard (`D...`)

  The first entry's `isDefault` is true and matches the address
  shown in `Account.address` for that chain — so a frontend
  switching from `Account.address` to the picker sees the same
  primary address. Pinned by a Go test that asserts byte-equality
  between `AddressFormats[0].address` and the canonical
  `bitcoinAddress()` output, so the default entry can never
  silently drift from the rest of libwallet.
- **New Dart models `AddressFormat` and `AddressFormatsResult`**,
  exported from the top-level barrel.

## 0.4.7

- **Fixed: every EVM `signAndSend` without a prior `validate` call
  errored with "invalid maxFeePerGas".** The fee-population block
  (MaxFeePerGas / MaxPriorityFeePerGas / Nonce / Gas) lived only
  inside `Transaction:validate`, so a Dart caller that built an
  `UnsignedTransaction` and shipped it straight to `signAndSend`
  reached signing with empty fee fields. `signAndSend` now runs
  `validate` as its first step (idempotent — only fills empty
  fields). Side benefit: closes a latent bug where an
  `erc20_transfer` built without `validate` would have signed with
  the recipient address as `to` instead of the token contract.
- **Fixed: `swap.maxSpendable` for SOL → SPL handed back amounts
  Jupiter would reject** when the user didn't already hold the
  output mint. Jupiter / dFlow auto-inject
  `createAssociatedTokenAccount` for the destination, costing
  ~2,039,280 lamports of rent paid by the taker. The previous max
  reserved only the system-account rent, leaving the wallet too
  tight to cover the new ATA — Jupiter then returned HTTP 400
  "Failed to get quotes". Now: when the input is native SOL and
  the user has no ATA for the output mint, the output ATA's
  rent-exempt minimum is subtracted from the resolved max
  (probed live via `getTokenAccountsByOwner` +
  `getMinimumBalanceForRentExemption`, with a canonical fallback).
  Doesn't apply to non-Solana chains, native→wSOL, or when the
  user already holds the output mint.

## 0.4.6

- **New: `swap.maxSpendable(...)`** — returns the same `SwapQuote`
  shape as `swap.quote()`, automatically resolved to the largest
  `tokenIn` amount the account can spend. `quote.amountIn` carries
  the resolved value so the UI can render "MAX → 1.234 SOL"
  alongside the standard quote display. Native input reserves the
  network fee + (Solana) rent-exempt minimums; token input returns
  the full balance because gas is paid in the chain's native
  currency. Returns `invalid_request` if the resolved max is zero.
- **New: `"MAX"` sentinel on `swap.quote(amountIn: ...)`.** Same
  end result as `swap.maxSpendable` — the libwallet side resolves
  the max amount before issuing the upstream quote, so a Max
  button in a swap form can wire straight to `quote()` without
  branching on a separate code path.
- **`transactions.maxSendable()` now supports tokens.** Previously
  errored with "v1 supports native assets only" for any token
  asset. SPL (Solana) and ERC-20 (EVM) now return `max == balance`
  (fees are paid in native currency, so the full token balance is
  spendable). The `fee` field reports the *native-currency* fee a
  token transfer would cost so the UI can warn when the user
  doesn't have enough native to cover gas.

## 0.4.5

- **Fixed: every Solana swap quote crashed with `404 Not Found` from
  Jupiter Ultra.** Jupiter's `/ultra/v1/order` endpoint accepts only
  `GET` with query parameters; we'd been POSTing JSON since the
  swap feature shipped. Switched to GET with `url.Values`;
  `/execute` stays POST (the signed transaction blob doesn't fit a
  query string). The httptest-backed adapter test is now pinned to
  GET so a future regression fires loudly instead of silently
  404'ing in production.
- **Improved: surface Jupiter routing errors verbatim.** When
  Jupiter returns HTTP 200 with `transaction:""` (insufficient
  funds, no route, slippage too tight) the adapter now passes
  through the upstream `errorMessage` instead of the generic
  "Jupiter returned an empty order".

## 0.4.4

- **New: `Token:listCurated` endpoint + `tokens.listCurated(network)`
  Dart method.** Returns a vetted list of well-known tokens per
  chain (USDT / USDC / DAI / WBTC / WETH / LINK / UNI on EVM
  mainnet, USDC / USDT / SOL / mSOL / JUP and ~650 other Jupiter-
  verified mints above $1M mcap on Solana mainnet, plus
  hand-curated entries upstream feeds don't carry — notably
  `DRtvTCzfiKGhCVREmBbZdN9sB8PHeq9KdRZ3VmFhpump` ("Tibane Thecat",
  $ChiefPussy)). Frontend use cases:
  - "Swap to X" dropdown without asking the user to paste a
    contract address.
  - Map an unrecognized mint / contract in the user's balances to
    its `symbol` + `logoURI` + `tags`.
  - Pass `"<type>.<chainId>"` form (same shape `Asset.network`
    returns — e.g. `"evm.1"`, `"solana.mainnet"`).
- **New Dart model `CuratedToken`** with `chainKey`, `address`,
  `symbol`, `name`, `decimals`, `type`, `logoUri`, `coingeckoId`,
  `cmcId`, `tags` + `isStablecoin` / `isWrapped` convenience
  getters. Exported from the top-level barrel.
- **Data source**: embedded JSON per chain (go:embed), refreshed at
  release time via `go generate ./wlttoken/curated/...` which pulls
  Uniswap's default list for EVM and Jupiter's verified feed for
  Solana. No runtime external fetch, no API keys. Hand-curated
  overlays merge on top of the generated base.
- **SPL balance enrichment**: on Solana, `Asset:list` now reads
  `name` / `symbol` from the curated registry when the mint is
  well-known. USDC on Solana used to surface as
  `Symbol="EPjFWd"` / `Name="EPjFWdd5..."`; now surfaces as
  `Symbol="USDC"` / `Name="USD Coin"`. Unlisted mints keep the
  previous truncated display.
- **Chains seeded on day 1**: EVM 1 / 10 / 56 / 137 / 324 / 8453
  / 42161 / 43114 + Solana mainnet. Gnosis (100), Fantom (250),
  Linea (59144) are registered with empty lists — Uniswap doesn't
  cover them; to be filled by an alternative feed or overlay in a
  follow-up.

## 0.4.3

- **Fixed: `Asset:list` crashed with `-32602 Invalid param: WrongSize`
  on Solana** for any wallet whose account is secp256k1
  (EVM-flavoured). `Account.UpdateAddressForNetwork` was blindly
  base58-encoding the 33-byte compressed secp256k1 pubkey as if it
  were a 32-byte ed25519 point; Solana's `getBalance` then rejected
  the oversized pubkey. Non-ed25519 accounts on a Solana network
  now resolve to `Address="N/A"` (same convention EVM / Bitcoin
  use for ed25519 accounts) and the balance call is skipped.
- **Fixed: `Swap:availability` reported every Solana wallet as
  `unsupported_chain`.** The live Solana network row uses
  `ChainId="mainnet"` (set by `wltnet/api.go`), but the
  availability gate only accepted Solana's internal cluster name
  `"mainnet-beta"`. The Swap button was hidden on Solana as a
  result. Gate now matches the real stored ChainId.

## 0.4.2

- **Fixed: `eth_sendTransaction` approval crashed with "failed to get
  env"** before signing. The transaction-sign approval handler was
  passing `*env` (whose embedded context is the bare psql sqlCtx) to
  `Transaction.SignAndSend`, which expects an apirouter context so it
  can extract the env. Now passes the original apirouter context.
  This also clears the cascading "unexpected end of JSON input" the
  dApp side reported — that was the dApp's parser choking on the
  stringified upstream error.
- **Fixed: `personal_ecRecover` returned RPC error -32601** ("method
  does not exist"). The previous default-relay path forwarded it to
  the chain's JSON-RPC node, but `personal_ecRecover` is a wallet-
  side operation and most public nodes don't implement it. Now
  handled locally: applies the EIP-191 prefix, runs ECDSA recovery,
  returns the EIP-55 address. Accepts both `{27, 28}` and `{0, 1}`
  v bytes, matching MetaMask / ethers / viem tolerance.
- **Fixed: `wallet_switchEthereumChain` crashed loading the approval
  back out of psql** with `math/big: cannot unmarshal "1.74…e+76"
  into a *big.Int`. `Account.IL` (the BIP32 intermediate value) was
  emitted as a raw JSON number, lost precision through float64 in
  the `any` roundtrip the request loader does, then failed to
  unmarshal. `Account` now has custom `MarshalJSON` /
  `UnmarshalJSON` that emit IL as a JSON string and parse the
  string-or-number / scientific-notation forms on the way back in.

## 0.4.1

- **`Wallet:probeActivity`** — new endpoint for mnemonic-backed
  wallets. Walks the BIP44 standard derivation paths for every
  supported chain (BTC BIP44 + BIP84, LTC BIP84, MONA BIP44 + BIP84,
  BCH BIP44, DOGE BIP44, EVM mainnet, Solana Sollet + Phantom
  conventions) and probes each candidate's RPC in parallel for
  on-chain activity. Returns one row per candidate with the derived
  address, pubkey, raw balance, and a `hasActivity` flag. Host UI
  uses this to auto-select which chains to migrate; per-candidate
  RPC errors land on `row.error` so one upstream failure doesn't
  fail the whole scan.
- **`Wallet:promoteMnemonic`** — new endpoint. Migrates a mnemonic
  wallet into N fresh MPC wallets, one per chain the caller picked
  from the probe output. Each migration derives the mnemonic at the
  chain's BIP32 path (full hardened BIP32 for secp256k1 via
  `ecckd.Derive`; Sollet seed[:32] / SLIP-0010 for ed25519) and
  runs TSS resharing on the resulting privkey. The source mnemonic
  wallet is NOT modified — the caller validates each migrated
  wallet, then deletes the source separately. secp256k1 source
  only in this release; ed25519 mnemonic migration is a follow-up.
- **Dart models added**: `ProbeActivityRow`, `ChainMigration`.
  `ChainMigration.fromProbeRow(row, stripAddressSuffix: true)`
  drops the trailing `/0/0` address-suffix so migration lands at the
  BIP44 account level (`m/44'/60'/0'`) instead of a specific
  leaf address — preserves the ability to derive child receive /
  change addresses from the new MPC wallet.
- **Test vectors locked in** (`wltwallet/bip44_vectors_test.go`,
  `derivation_test.go`): the user-supplied BTC / EVM / BTC-segwit /
  Solana addresses for two reference mnemonics pin the derivation
  math so a future change can't silently land imports on the wrong
  address and lose user funds.
- **Existing mnemonic import sign path unchanged** in this release —
  the mnemonic wallet still signs at the BIP32 master, so direct
  signing from a mnemonic wallet won't match MetaMask / Phantom
  addresses. Users hitting that: run `Wallet:probeActivity` then
  `Wallet:promoteMnemonic` to get proper per-chain MPC wallets, and
  sign from those. The direct-sign path will be rewritten to use
  Account-level derivation paths in a follow-up.

## 0.4.0

- **Import existing wallets: raw private keys + BIP39 mnemonics, with
  promote-to-MPC.** Three new endpoints on `client.wallets`:

  - `importPrivateKey({privateKey, curve, name, keys})` — accepts
    `0x`-prefixed hex, bare hex, or Bitcoin-family WIF (auto-sniffed;
    WIF only for `secp256k1`). The imported wallet is stored as a
    1-of-1 share with a new `RawKey` content type and is signable
    immediately — no TSS rounds, just direct `crypto/ecdsa` /
    `crypto/ed25519`.

  - `importMnemonic({mnemonic, passphrase, curve, name, keys})` —
    auto-detects the BIP39 wordlist (English, Japanese, Korean,
    Spanish, Chinese Simplified / Traditional, French, Italian, Czech)
    and stores the decoded entropy + the detected language tag, NOT
    the raw mnemonic string. That lets the same backup be re-rendered
    in any other language for display, while keeping the seed
    derivation stable (BIP39's PBKDF2 is sensitive to the literal
    mnemonic, so the original language must drive sign-time
    derivation). Optional BIP39 passphrase supported.

  - `promote(walletId, {oldKeys, newKeys, threshold})` — converts an
    imported 1-of-1 wallet into a normal N-of-T TSS wallet via
    tss-lib's resharing protocol. The master pubkey and chaincode
    are preserved (the wallet's address does NOT change) — only the
    storage of the signing key changes from "single share, full
    privkey" to "M shares with T-threshold reconstruction". After
    promote the imported share row is deleted; the wallet looks
    identical to a freshly-created TSS wallet. **secp256k1 only**
    in this release; ed25519 promote is a follow-up.

  All three reuse the existing `KeyDescription` encryption layer
  (`Password`, `StoreKey`, `RemoteKey`, `Plain`) — `RawKey` /
  `Mnemonic` are *content* types, the encryption-at-rest mechanism
  is orthogonal. So importing with `Keys: [Password(...)]` works
  out of the box.

  Both curves on day 1 for the import path: `secp256k1` (EVM /
  Bitcoin family) + `ed25519` (Solana).

## 0.3.32

- **iOS: ship as `.xcframework` (Apple's recommended format).** The
  podspec's `prepare_command` now wraps the per-SDK static archives
  into `libwallet.xcframework` via `xcodebuild -create-xcframework`,
  and the spec switches from `vendored_libraries` to
  `vendored_frameworks`. CocoaPods picks the right slice for the
  active SDK at build time, eliminating the wrong-SDK
  "ignoring file ... built for iOS [Simulator]" warning the previous
  layout emitted on every link. `-force_load` is still required
  because the FFI entry points are dlsym'd, but it now reaches into
  the xcframework's source slice (which exists from `pod install`
  onward) — Xcode's link-phase input validation runs before the
  CocoaPods Copy XCFrameworks build phase, so referencing the
  build-time copy path errored with "Build input file cannot be
  found" even though the file would exist by link time.

## 0.3.31

- **Fixed: `personal_sign` / `eth_signTypedData_v3` / `_v4` returned
  DER, not Ethereum wire format.** ecrecover, viem.verifyTypedData,
  ethers.verifyMessage, OpenSea, Snapshot, Permit2, MetaMask test-dapp's
  Recover button — every off-chain Ethereum signature verifier — would
  reject the output with "Invalid signature v value" or a silent
  address mismatch. Now produces the canonical 65-byte form
  R(32) || S(32) || V(1) where V ∈ {27, 28} via the new
  `wltacct.SignEthereumDigest` helper, which post-processes the TSS
  signer's DER output (parse → bruteforce recovery code → repack).
  Same fix applied to the host-direct `Account:signMessage` flow with
  `Mode: "evm"` / `"personal_sign"`. EIP-155 chain-id adjustment is
  intentionally NOT applied — that lives in the on-chain transaction
  signing path; off-chain flows always use legacy v.

## 0.3.30

- **`Info:version` now exposes the release tag.** New `version` field
  alongside `dateTag` / `gitTag`, populated from the `v*` tag the
  binary was built from (empty on dev / non-tagged builds). The Dart
  wrapper got a typed `client.info.versionInfo()` returning a
  `VersionInfo` (version + gitTag + dateTag) for diagnostics; the
  long-broken `client.info.version()` now correctly returns the
  release-tag string instead of the toString'd map.

- **Runtime version-mismatch detection (with release-mode rejection).**
  `LibwalletClient.initialize` asynchronously calls `Info:version` and
  compares it against the hardcoded `libwalletPackageVersion` constant.
  Result is exposed as `client.ready` (a `Future<void>`):
  - **Debug/test Dart VM** (`dart.vm.product=false`): mismatch logs an
    actionable warning via `dart:developer` and `ready` completes
    normally — debug runs of the in-tree test app can iterate against a
    locally-built binary without ceremony.
  - **Release Dart VM** (AOT, `dart.vm.product=true`): `ready` rejects
    with a `StateError` carrying the same message. Apps should
    `await client.ready` after `initialize` and surface a fatal-error
    UI on failure — operating with mismatched wire shapes is what
    causes events to arrive as `UnknownPendingRequest`, sign approvals
    to error with "keys are required", etc.

  Catches the same class of bug across iOS (skipped `pod install`),
  Android (stale build-hook cache), and macOS/Linux/Windows.

- **Fixed: build-time `-X` ldflags targeted the wrong package.** The
  `Makefile` and `build.yml` had been passing `-X main.dateTag=...` /
  `-X main.gitTag=...` for the entire history of the project, but
  those variables live in `wltbase`. The `-X` was a silent no-op —
  every release binary shipped with empty `dateTag` / `gitTag`.
  Corrected to use the fully qualified package path; release binaries
  built on or after this commit return populated values from
  `Info:version`. Also propagated the ldflags to the c-shared /
  c-archive Dart-FFI builds, which had no version metadata at all.

- **Release tooling: `dart/tools/bump_version.dart`.** One command
  (`dart run tools/bump_version.dart --patch` / `--minor` / `--major`
  / explicit `X.Y.Z`) rewrites both `pubspec.yaml` and
  `lib/src/version.dart` — the two files that have to move in
  lockstep for the runtime mismatch check to work. CI runs the
  script's `--check` mode on every push so a release commit that only
  touches `pubspec.yaml` fails fast.

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
