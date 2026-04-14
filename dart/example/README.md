# libwallet example

A minimal command-line sample that initializes libwallet, creates (or
reuses) a wallet with live progress output, derives an Ethereum
account, queries balances on the current network, and listens for
incoming dApp requests.

## Run

```sh
dart run example/libwallet_example.dart /path/to/data-dir
```

`data-dir` is where libwallet stores its encrypted state (keys,
accounts, connections). Use a throwaway directory the first time you
run it.

## What it covers

- Initializing `LibwalletClient` over FFI.
- Creating a 3-share password-only wallet with `ProgressOr` events
  (`Progress(fraction)` / `Complete(wallet)`).
- Deriving an `ethereum`-type account on the default network.
- Listing `client.assets` for the current network.
- Subscribing to `client.pendingRequests` so any dApp connect/sign
  request is visible (the sample auto-rejects — real apps show an
  approval sheet).
- Clean shutdown with `client.dispose()`.

## Connecting a WebView

The CLI sample doesn't exercise the dApp / WebView side. For that,
see **[`doc/webview_integration.md`](../doc/webview_integration.md)** —
it walks through the outbound RPC bridge, inbound event relay, and
approval-sheet dispatch for `window.ethereum` (EIP-6963),
`window.solana` (Wallet Standard), and `window.mpurse` (Monacoin).
