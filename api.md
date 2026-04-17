# libwallet API

## Info

### `Info:ping`

Ping the lib to check if everything is doing fine.

### `Info:version`

Returns the lib's version

### `Info:paths`

Returns system paths information (UserCacheDir, UserConfigDir, UserHomeDir, TempDir, DataDir, Environ)

### `Info:first_run`

Return the date/time of the first run based on the storage endpoint

### `Info:onboarding`

returns an object with the state of the user's onboarding, useful to check if we need to prompt the user to create or restore a wallet

## Crash

* `GET Crash` Lists all crash events sorted by creation time
* `GET Crash/<id>` Fetch details of a specific crash event
* `DELETE Crash/<id>` Delete a specific crash event

## Lifecycle

* `Lifecycle:update`

## StoreKey

* `StoreKey:new` *REMOVED* use `StoreKey:create`
* `StoreKey:create` Returns a store key and its public key in PKIX format (private/public)
* `StoreKey:derivePassword` returns the public key for a given password based on the password and WalletKeyId
  * Password
  * WalletKeyId

## RemoteKey

* `RemoteKey:new` takes: `number` (phone in international format OR email address) or `email` alias, returns `session`. The backend routes SMS vs email verification based on whether the value contains `@`.
* `RemoteKey:reshare` takes: `key`, `curve` (`secp256k1` or `ed25519`), return `session` to initialize a key reshare
* `RemoteKey:validate` takes: `session` (returned by new or reshare), `code`, returns `RemoteKey`

## Wallet

* `GET`
* `POST Wallet` to create a new Wallet
  * `Name`
  * `Curve` (optional): `secp256k1` (default, for EVM/Bitcoin) or `ed25519` (for Solana)
  * `Keys`: [ {"Type": "StoreKey", "Key": storeKey}, {"Type": "RemoteKey", "Key": remoteKey}, {"Type": "Password", "Key": password} ]
* `PATCH Wallet/<id>`
  * `Name`
* `DELETE Wallet/<id>` delete a wallet, its accounts, and everything
* ~~`GET Wallet:backup` Generate backup of all local wallet data for icloud/etc~~ **Use Wallet:restore instead**
* `GET Wallet/<id>:backup` Generate backup of a given wallet for icloud/etc
* `POST Wallet:restore` Restore/refresh/sync data from icloud backup
  * `files` : [ {"filename": "xxx", "data": "yyy"}, {...}, ...]
  * The api will respond with the following:
    * `update` if true, the backup is too old and needs to be generated again (call Wallet:backup and upload the data)
    * `delete` is an optional array of string. If specified, the files listed here should be deleted from the backup (old or deprecated)
    * `errors` if specified, means the restore failed on any of the files. Errors will contain the filename and the details.
    * `backup` if specified, contains a array in the form `[{"filename":"...","data":"..."},...]` (the same as backup) which are files that should be written to the backup
    * `update_count` number of items updated from this restore operation
    * `existing_count` number of items that already existed and do not need to be updated
    * `missing_count` number of items missing from the backup
* `POST Wallet:multiCreate` Create both secp256k1 and ed25519 wallets in one call
  * `Name`
  * `Keys`: same format as POST Wallet
  * Returns: `{ "secp256k1": Wallet, "ed25519": Wallet }`
* `POST Wallet/<id>:reshare` Reshare wallet keys among a new set of key holders
  * `Old` Array of key descriptions to be replaced `[]*wltsign.KeyDescription`
  * `New` Array of new key descriptions `[]*wltsign.KeyDescription`

## Wallet/Key

* `GET Wallet/Key/<id>`
* `POST Wallet/Key/<id>:recrypt` allows changing the password of a wallet key
  * `"Old": {"Type": "Password", "Key": password}`
  * `"New": {"Type": "Password", "Key": newpassword}`

## Network

* `GET Network`
  * TestNet=false (optional): if set to false, exclude testnets
* `GET Network/<id>`
* `POST Network`
  * Type: `evm`, `bitcoin`, or `solana`
  * ChainId
  * Name
  * RPC (=auto)
  * CurrencySymbol
  * BlockExplorer (=auto)
  * TestNet (bool)
  * Priority (int, larger values returned first)
* `Network/<id>:setCurrent`
* `PATCH Network/id`
* `DELETE Network/id`
* `POST Network:testRPC` Probe an RPC endpoint and return a health snapshot
  * `URL` URL of RPC server to test
  * `Type` (optional, default `evm`) — one of `evm` / `solana` / `bitcoin`
  * EVM: `net_version` → `{ChainId, Name?, CurrencySymbol?, EVM_Info?}`
  * Solana: `getVersion` + `getGenesisHash` → `{SolanaVersion, SolanaCluster}` (cluster ∈ mainnet-beta / devnet / testnet / unknown)
  * Bitcoin-family: `getblockchaininfo` → `{Chain, Blocks}`

## Account

* `GET Account`
  * `Wallet` to list only accounts linked to a specific wallet
* `GET Account/<id>`
* `POST Account`
  * `Name`
  * `Wallet` Id of attached wallet
  * `Type` ethereum, bitcoin, or solana
  * `Index` Index of the account (starts at zero, two accounts of the same wallet / type / index will have the same address)
* `PATCH Account/<id>`
  * `Name`
* `DELETE Account/<id>` Delete an account and everything related
* `Account/<id>:setCurrent`
* `Account:createView` Create a read-only (view) account with no backing wallet — cannot sign, but can query balance/NFTs.
  * `Type` ethereum, bitcoin, or solana
  * `Address` on-chain address to watch (mutually exclusive with `Xpub`)
  * `Xpub` BIP-32 extended public key (bitcoin-family only; enables HD gap-limit scans)
  * `Name` optional display name
* `Account/<id>:signMessage` Sign a raw message with the account's TSS key (wallet-host direct-signing, bypasses Web3 approval flow)
  * `Message` base64 bytes to sign
  * `Keys` TSS key descriptors
  * `Mode` optional: `solana` (base58 sig), `evm`/`personal_sign` (0x-hex sig, EIP-191), `raw` (base64 sig). Defaults to `solana` for ed25519 accounts, `evm` for secp256k1.
* `Account/<id>:signTransaction` Sign an unsigned Solana transaction (base64 in, base64 out). EVM/Bitcoin transactions should use `Transaction:signAndSend`.
* `Account/<id>:signAndSendTransaction` Sign + broadcast a Solana transaction via the current network's RPC. Returns the broadcast signature (base58).

## Web3

* `Web3:request` Proxy a JSON-RPC call from a dApp webview to the wallet. Used internally by the injected provider.
  * `url` dApp origin (used for per-host connection state)
  * `query.method` / `query.params` — the JSON-RPC method being invoked
* `Web3:injectionScript` Generate JavaScript to inject into a WebView. Exposes `window.ethereum` (EIP-1193 + EIP-6963), `window.solana` (Wallet Standard), and `window.mpurse` (Monacoin). See `Web3Api.injectionScript` in the Dart client for a walkthrough.
  * `Name` wallet display name (required)
  * `Rdns` reverse DNS identifier, e.g. `com.example.wallet` (required)
  * `Uuid` stable per-install UUID — cache on the host (required)
  * `Icon` data: URL or https:// URL for the wallet icon (required for EIP-6963)
  * `Bridge` name of the host JS message channel the script will post to (required)
  * `Host` optional dApp origin — pre-populates connected accounts in the returned script

## WalletConnect v2

* `WalletConnect:start` Open the relay WebSocket.
  * `ProjectID` (required) WalletConnect Cloud project id
  * `RelayURL` defaults to `wss://relay.walletconnect.com`
* `WalletConnect:stop` Close the relay connection.
* `WalletConnect:pair` Start pairing from a `wc:...` URI. Returns the pairing topic.
* `WalletConnect:sessions` List all non-disconnected sessions.
* `WalletConnect:approveSession` Approve a `wc_sessionPropose`.
  * `PairingTopic` the topic the propose arrived on
  * `Accounts` CAIP-10 list (e.g. `eip155:1:0xabc…`)
  * `Methods` / `Events` optional filters (default: echo proposer's request)
* `WalletConnect:rejectSession` Reject a `wc_sessionPropose` with a JSON-RPC error (default code 5000 "User rejected").
* `WalletConnect:respond` Respond to a `wc_sessionRequest` with a successful result.
  * `Topic`, `ID`, `Result`
* `WalletConnect:respondError` Respond to a `wc_sessionRequest` with a JSON-RPC error.
* `WalletConnect:emitEvent` Push a `wc_sessionEvent` to a session (used for `chainChanged` / `accountsChanged`).
  * `Topic`, `Name`, `Data`, `ChainID` (CAIP-2)
* `WalletConnect:disconnect` Send `wc_sessionDelete` and tear down the session locally.

## Asset

* `GET` (list only)
  * _convert=USD (add FiatAmount and FiatCurrency to each asset with converted amount, can accept USD/EUR/GBP/JPY)

## Nft

* `GET Nft` List NFTs for the current (or specified) account and network
  * Network (optional): limit to a specific network, defaults to current network
  * Account (optional): limit to a specific account, defaults to current account
  * Returns: `{ network, account, nfts }` where nfts is an array of NFT metadata
* `GET Nft/<id>` Fetch a specific NFT by id

## Transaction

* `GET Transaction`
  * From: limit transaction list to a given account
  * Network: find transactions on a given network
  * _convert=USD (add FiatAmount and FiatCurrency to each asset with converted amount, can accept USD/EUR/GBP/JPY)
* `GET Transaction/<id>`
* `Transaction:validate` Validates if a transaction is OK, returns errors if anything seems wrong
  * Supported transaction types: `transfer`, `evm`, `solana_transfer`, `solana_spl_transfer`, `erc20_transfer`, `bitcoin_transfer`
  * Solana-native transfers run a preflight check and fail fast with a typed `PreflightError` (codes: `insufficient_balance`, `below_sender_rent`, `recipient_rent_not_funded`) instead of deferring the rejection to the RPC simulator.
  * Solana priority-fee fields (all opt-in; zero preserves legacy 5000-lamport flat fee):
    * `computeUnitLimit` (uint32): SetComputeUnitLimit argument
    * `computeUnitPrice` (uint64, microlamports per CU): explicit price pin; wins over `priorityLevel`
    * `priorityLevel`: `"none"` | `"low"` (25th pctile) | `"medium"` (50th) | `"high"` (75th) of recent `getRecentPrioritizationFees`
* `Transaction:signAndSend`
  * Same params as `Transaction:validate` plus:
  * Keys: [ {"Id": "wkey-xxx", "Key": privateKey, {"Id": "wkey-yyy", "Key": password} ]
  * For Solana transactions, signing uses EdDSA TSS and broadcasts via `sendTransaction`
* `Transaction:simulate` Pre-flight an unsigned transaction and return a structured preview for the approval UI. Same params as `Transaction:validate`. Response fields: `chain`, `willRevert`, `revertReason`, `decodedMethod` (native_transfer / erc20_transfer / erc20_approve / unknown), `decodedArgs`, `gasEstimate` (EVM), `logs` / `unitsConsumed` (Solana), `bitcoinInputs` / `bitcoinOutputs` / `bitcoinFee` (Bitcoin-family), `effects` (every transfer at any call depth — anti-drainer signal), `balanceChanges` (signed native-balance deltas per address), `warnings` (advisory findings — see below).
  * `warnings` codes (stable): `recipient_is_contract` (EVM native send to a contract — funds may be stuck), `recipient_new_account` (Solana recipient doesn't exist yet), `erc20_approve_unlimited` (approve at/above 2^255 — drainer vector), `net_loss_exceeds_amount` (sender loses more than declared amount + fee), `priority_fee_recommended` (Solana network median priority fee > 0 but tx has no ComputeBudget).
* `Transaction:maxSendable` Compute the largest amount safely sendable from an account, accounting for network fees and (on Solana) rent-exempt minimums. Native-only in v1 — for tokens use Asset:list since the full balance is sendable and fees are paid in native.
  * `from` Sender account address or ID (defaults to current)
  * `to` (optional): recipient — on Solana, used to check if the account exists; new accounts need rent-exempt funding counted against Max
  * `asset` (optional): asset key, defaults to network native
  * `network` (optional): override current network
  * Response: `{ chain, max, balance, fee, reserved: [{kind, amount}], reason }` where `kind` is `"fee"` / `"sender_rent"` / `"recipient_rent"`. `reason` is populated when `max` is zero.
* `DELETE Transaction`
  * From: limit transaction deletion to a given account
  * Network: delete transactions on a given network
  * If no parameter is passed, ALL of the transaction history will be cleared
* `DELETE Transaction/id`

## Swap

Token swaps powered by Jupiter Ultra + dFlow (Solana) and 1inch (EVM). Two-step flow: `Swap:quote` returns a quote cached server-side for 90 s, `Swap:execute` signs and broadcasts. On EVM, ERC-20 input tokens require a prior `approve` — use `Swap:buildApproval` in between. 50 bps referral fee is routed to the configured fee accounts; Solana auto-falls-back from Jupiter to dFlow on provider failure. Full UI integration guide in `dart/doc/swap_integration.md`.

* `Swap:quote` Get a swap quote.
  * `tokenIn`, `tokenOut`: `{ address, symbol, decimals }`. Address `"NATIVE"` means the chain's native currency (SOL / ETH); on EVM also accepts the 1inch sentinel `0xeeee…eeee`.
  * `amountIn`: input amount in base units (decimal string)
  * `slippageBps` (optional): default 50 (0.5%)
  * `from` (optional): sender account (defaults to current)
  * `network` (optional): override current network
  * `provider` (optional): pin a specific aggregator — `"jupiter_ultra"` / `"dflow"` / `"1inch"`. Empty = auto with fallback.
  * Response: `{ quoteId, provider, providerLabel, chain, tokenIn, tokenOut, amountIn, amountOut, minAmountOut, priceImpact, feeBps, slippageBps, referralFee, networkFee, route: [{venue, share}], expiresAt, requiresApproval, approvalSpender, currentAllowance, neededAllowance }`. The approval fields are populated for non-native EVM inputs; zero-valued otherwise.
* `Swap:buildApproval` Build the ERC-20 `approve` transaction an EVM swap needs as a prerequisite. Only call when `quote.requiresApproval == true`.
  * `quoteId`: from a prior `Swap:quote`
  * `approvalAmount` (optional): defaults to exactly the quote's `amountIn` (tight — compromised router can only drain what the user agreed to swap). Pass `"max"` / `"unlimited"` for the classic uint256 max, or a decimal string for a custom cap.
  * `from` (optional): override the account the quote was issued for
  * Response `ApprovalPreview`: `{ token, spender, spenderLabel, amount, isUnlimited, currentAllowance, networkFee, tx }`. Pass `tx` to `Transaction:signAndSend`.
* `Swap:execute` Sign and broadcast a previously-issued quote.
  * `quoteId`
  * `Keys`: same key-descriptor array as `Transaction:signAndSend`
  * `from` (optional)
  * Response `SwapResult`: `{ quoteId, provider, chain, hash, url, quote }`. Quote expires after 90 s — if execution fails with `quote_expired`, re-quote.
  * Stable error codes: `quote_expired`, `quote_not_found`, `no_liquidity`, `slippage_exceeded`, `provider_unavailable`, `provider_bad_request`, `unsupported_chain`, `unsupported_token_pair`, `missing_api_key`, `invalid_request`.

## Token

* `GET Token` List all registered tokens (searchable by Name, Symbol, Address, Type)
* `GET Token/<id>` Fetch a specific token
* `POST Token` Register a custom token
  * `Name` Display name
  * `Symbol` Token symbol (e.g. "USDC")
  * `Address` Contract address (EVM) or mint address (Solana)
  * `Decimals` Token decimal places
  * `Type` (optional): `erc20`, `nft`, `spl-token`, `spl-token-2022` (auto-detected from network if omitted)
  * `Network` Network XUID the token belongs to
  * `Logo` (optional): Logo URL
  * `Memo` (optional): User notes
* `PATCH Token/<id>` Update Name, Symbol, Decimals, Type, Logo, Memo
* `DELETE Token/<id>`
* `Token:discoverToken` Auto-detect token metadata from on-chain data
  * `Network` Network XUID
  * `Address` Contract/mint address
  * Returns: `{ name, symbol, decimals, total_supply, address, type }`
  * EVM: queries name(), symbol(), decimals(), totalSupply() via eth_call
  * Solana: queries mint account info via getAccountInfo

## Contact

* `GET Contact`
* `GET Contact/id`
* `POST Contact`
  * Name
  * Address
  * Type: `ethereum`, `bitcoin`, or `solana`
  * Memo
* `PATCH Contact/id`
* `DELETE Contact/id`

## Web3

* `POST Web3:request`
  * `url` URL making the web3 request
  * `query` Content of the query, an object with `method` and optionally `params`
  * Supported methods:
    * `eth_chainId` — returns current chain ID as 0x-prefixed hex
    * `net_version` — returns current chain ID as decimal string
    * `web3_clientVersion` — returns library version
    * `web3_sha3` — keccak256 hash
    * `eth_requestAccounts` — prompts user to connect accounts
    * `eth_accounts` — returns connected accounts
    * `personal_sign` — EIP-191 personal message signing
    * `eth_signTypedData_v4` / `eth_signTypedData_v3` / `eth_signTypedData` — EIP-712 typed data signing
    * `eth_sendTransaction` — sign and broadcast a transaction
    * `wallet_addEthereumChain` — EIP-3085 add a new chain
    * `wallet_switchEthereumChain` — EIP-3326 switch chains
    * `wallet_requestPermissions` / `wallet_getPermissions` — EIP-2255 permissions
    * `wallet_watchAsset` — EIP-747 request to watch a token
    * `solana_connect` / `solana_requestAccounts` — connect and return public keys
    * `solana_accounts` — return connected Solana accounts
    * `solana_disconnect` — disconnect all accounts for the requesting site
    * `solana_signMessage` — sign an arbitrary message (params: `{ message, pubkey }`)
    * `solana_signTransaction` — sign a transaction (params: `{ transaction }`, base64-encoded)
    * `solana_signAndSendTransaction` — sign and broadcast (params: `{ transaction }`, base64-encoded)
    * All other methods are relayed to the current network's RPC

## Web3/Connection

Web3/Connection manages which sites have access to which accounts

* `GET Web3/Connection`
* `GET Web3/Connection/<id>`
  * Host: list only connections for a given host
* `POST Web3/Connection`
  * Host: hostname of the connected site
  * Account: id of the connected account
* `DELETE Web3/Connection/<id>`

## Request

* EVENT: `{"result":"event","event":"request","data":{"request_id":"..."}}` A new request is PENDING
* `GET Request:test` to run a test on the event
* `GET Request/<id>` to fetch a given request including its details (request, etc)
  * Type can be one of: connect, sign, personal_sign, sign_typed_data, add_network, change_network, watch_asset, solana_sign_message, solana_sign_transaction, solana_sign_send_transaction, test
  * Status can be one of: pending, accepted, rejected, timedout
  * Transaction can be optionally included if request is for sign
  * Value can be optionally included, is context of the request (will replace Transaction)
* `POST Request/<id>:approve`
  * Must pass Accounts as an array of account IDs if the request Type is connect
* `POST Request/<id>:reject`
