# WebView integration guide

This guide walks through wiring a Flutter/Dart WebView to libwallet so
arbitrary dApps can speak Web3 (Ethereum / Solana / Monacoin) through
the user's wallet — discovery, connection, signing, sending, and
real-time state updates.

The libwallet side is already done. What the host app has to do:

1. Ask libwallet for the injected JS blob (`client.web3.injectionScript(...)`).
2. Run it in the WebView on every page load.
3. Forward JS-initiated RPC calls to libwallet (`client.web3.request(...)`)
   and route responses back into the WebView.
4. Forward libwallet events (`client.jsEvents`) into the WebView.
5. Render the approval UI when `client.pendingRequests` fires.

Each of these is a small amount of code; skipping any of them breaks a
piece of the protocol (dApp hangs, wallet discovery fails, chain-switch
is invisible, etc.), so treat them as non-optional.

## Architecture in one diagram

```
┌─────────────────────────┐            ┌────────────────────────┐
│   dApp (inside WebView) │            │   libwallet (Go core)  │
│                         │            │                        │
│  window.ethereum        │            │  Web3:request          │
│  window.solana          │            │  Web3:injectionScript  │
│  window.mpurse          │            │  Request:approve/reject│
│                         │            │                        │
└──────┬──────────────┬───┘            └──┬──────────────────┬──┘
       │ postMessage  │ __libwalletEvent  │ request()        │ events
       │ (outbound)   │ (inbound)         │                  │
       ▼              ▲                   ▼                  ▲
┌─────────────────────┴─────────────────────────────────────────┐
│                       Host app (Dart)                         │
│  JavaScriptChannel  ────►  client.web3.request(url, query)    │
│  runJavaScript      ◄────  client.jsEvents                    │
│  approval sheet     ◄────  client.pendingRequests             │
└───────────────────────────────────────────────────────────────┘
```

Everything in the middle box is what you implement.

## Prerequisites

- A WebView that supports JS channels and `runJavaScript`. Tested with
  `webview_flutter 4.x`. Same shape works on `flutter_inappwebview`,
  `InAppWebView`, and equivalent Android/iOS native WebViews.
- A **UUIDv4 per page load**. Per EIP-6963, the `uuid` in the announce
  event identifies the announcement for the lifetime of the page only.
  Generate a fresh one every time you inject — do NOT cache across
  launches, and do NOT share it across tabs/pages.

## Step 1 — ask libwallet for the script

```dart
final js = await client.web3.injectionScript(
  name: 'MyWallet',
  rdns: 'com.example.mywallet',          // reverse-DNS, required by EIP-6963
  uuid: Uuid().v4(),                     // fresh per page load (spec requirement)
  icon: 'data:image/svg+xml;base64,...', // or https://... URL
  bridge: 'libwalletBridge',             // name of the JS channel you install
  host: currentPageUrl,                  // optional — pre-fills connected accounts
);
```

Regenerate the script (and its UUID) on every navigation. The provider
JS itself has no external dependencies; the heavy work is the
embedded config JSON which is small.

## Step 2 — outbound: JS → host → libwallet → host → JS

When the dApp calls `ethereum.request({method, params})` the injected
provider serializes `{id, method, params}` and calls
`window.libwalletBridge.postMessage(json)` (where `libwalletBridge` is
the name you passed as `bridge:`).

Wire a JS channel on the WebView that routes these to libwallet:

```dart
webview.addJavaScriptChannel(
  'libwalletBridge',
  onMessageReceived: (JavaScriptMessage msg) async {
    final req = jsonDecode(msg.message) as Map<String, dynamic>;
    final id = req['id'];
    try {
      final result = await client.web3.request(
        url: currentPageUrl,
        query: {
          'method': req['method'],
          'params': req['params'],
        },
      );
      final payload = jsonEncode({'result': result});
      await webview.runJavaScript(
        '__libwalletResolve($id, ${jsonEncode(payload)})',
      );
    } on LibwalletException catch (e) {
      final payload = jsonEncode({
        'error': {'code': int.tryParse(e.code) ?? -32000, 'message': e.message},
      });
      await webview.runJavaScript(
        '__libwalletResolve($id, ${jsonEncode(payload)})',
      );
    }
  },
);
```

Important:

- **`jsonEncode(payload)` twice.** The provider calls `JSON.parse(payload)`
  on the argument, so it needs to be a quoted JSON string on the JS
  side — the outer `jsonEncode` produces that. Skipping one level makes
  `__libwalletResolve` throw silently inside the provider.
- **Always resolve.** Even on error, call `__libwalletResolve` — the
  Promise on the dApp side is still waiting. Dropping it means a stuck
  dApp.
- **`id` is an integer** from the JS side. Don't quote it.

## Step 3 — inbound: libwallet events → WebView

libwallet emits `js:accountsChanged` and `js:chainChanged` events
whenever the connected account set or current chain changes. The
provider's `__libwalletEvent(name, data)` entry point re-dispatches
them per standard (EIP-1193 emit, mpurse `updateEmitter`, etc.).

```dart
client.jsEvents.listen((event) {
  // event.jsEventName is 'accountsChanged' or 'chainChanged'
  final name = jsonEncode(event.jsEventName);
  final data = jsonEncode(event.data);
  webview.runJavaScript('__libwalletEvent($name, $data)');
});
```

Use a single, long-lived subscription — don't re-subscribe per page
load (the host's event stream is the same across navigations).

## Step 4 — approval UI

Whenever a dApp asks for something that needs a human decision
(connect, sign, add network, etc.) libwallet puts a `PendingRequest`
on `client.pendingRequests`. The full request payload is attached to
the event, so you can render the prompt on first paint:

```dart
client.pendingRequests.listen((req) async {
  switch (req) {
    case ConnectRequest():
      final accts = await showConnectSheet(req.host); // your UI
      if (accts.isNotEmpty) {
        await client.requests.approve(req.id, accounts: accts);
      } else {
        await client.requests.reject(req.id);
      }

    case TransactionSignRequest():
      // Unified on-chain tx signing. Covers eth_sendTransaction,
      // solana_signTransaction, solana_signAndSendTransaction,
      // mpurse_signRawTransaction. Branch on req.chain / req.method
      // for chain-specific copy; the decoded payload (effects,
      // balanceChanges, warnings, fee, etc.) drives the sheet.
      final ok = await showTransactionSheet(
        host: req.host,
        chain: req.chain,
        method: req.method,
        decodedMethod: req.decodedMethod,
        decodedArgs: req.decodedArgs,
        effects: req.effects,
        balanceChanges: req.balanceChanges,
        warnings: req.warnings,
        feeAmount: req.feeAmount,
        feeDecimals: req.feeDecimals,
        feeSymbol: req.feeSymbol,
        networkName: req.networkName,
        sizeBytes: req.sizeBytes,
        willRevert: req.willRevert,
        revertReason: req.revertReason,
      );
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
          : await client.requests.reject(req.id);

    case MessageSignRequest():
      // Unified message signing — personal_sign,
      // eth_signTypedData*, solana_signMessage, mpurse_signMessage.
      // Branch on req.method or use the decoded helpers:
      //
      //   - req.isSiwe / req.isSiws  → render "Login to <domain>"
      //   - req.structuredData       → typed-data tree view
      //   - req.messageText          → plain text fallback
      //
      final ok = await showMessageSheet(
        host: req.host,
        chain: req.chain,
        method: req.method,
        text: req.messageText,
        bytes: req.messageBytes,
        structured: req.structuredData,
        primaryType: req.structuredPrimaryType,
        domain: req.structuredDomain,
        isSiwe: req.isSiwe,
        isSiws: req.isSiws,
        siweFields: req.siweFields,
        warnings: req.warnings,
      );
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
          : await client.requests.reject(req.id);

    case AddNetworkRequest():
      // dApp called wallet_addEthereumChain — pure add, no
      // switch. Show the proposed network. On approve, libwallet
      // saves the Network record without activating it (distinct
      // from ChainSwitchRequest below which DOES switch). No
      // host-side `networks.setCurrent` call needed.
      final ok = await showAddNetworkSheet(req.host, req.network);
      ok
          ? await client.requests.approve(req.id)
          : await client.requests.reject(req.id);

    case ChainSwitchRequest():
      // Every network switch comes through this single request
      // type. Two shapes:
      //
      //   • Pre-specified target (req.targetNetwork != null):
      //     dApp explicitly asked for a specific chain via
      //     wallet_switchEthereumChain. UI shows a confirm
      //     sheet, user picks only an account. When
      //     req.isNewNetwork is true, approval implies
      //     Add + Switch — surface the added risk in the copy.
      //
      //   • Picker (req.targetNetwork == null): dApp triggered
      //     a cross-family action (e.g. solana_signTransaction
      //     while the wallet is on EVM). UI shows both a
      //     network and an account picker.
      //
      // On approve libwallet atomically: Saves the network
      // if new, calls SetCurrent, and connects the dApp to
      // the chosen account. The host does NOT need a separate
      // `networks.setCurrent(...)` call afterwards.
      if (req.targetNetwork != null) {
        final account = await showTargetSwitchSheet(
          host: req.host,
          target: req.targetNetwork!,
          isNew: req.isNewNetwork,
          accounts: req.candidateAccounts,
        );
        if (account == null) {
          await client.requests.reject(req.id);
        } else {
          await client.requests.approve(req.id, accounts: [account.id]);
        }
      } else {
        final pick = await showChainAccountPicker(
          family: req.requestedFamily, // "evm" / "solana" / "bitcoin"
          method: req.requestedMethod, // for UI copy
          currentNetwork: req.currentNetwork,
          networks: req.candidateNetworks,
          accounts: req.candidateAccounts,
        );
        if (pick == null) {
          await client.requests.reject(req.id);
        } else {
          await client.requests.approve(
            req.id,
            network: pick.network.id,
            accounts: [pick.account.id],
          );
        }
      }

    case WatchAssetRequest():
      final ok = await showWatchAssetSheet(req.host, req.token);
      ok
          ? await client.requests.approve(req.id)
          : await client.requests.reject(req.id);

    default:
      // Forward-compat: reject anything the host doesn't understand.
      await client.requests.reject(req.id);
  }
});
```

`askKeys()` is where your UI collects the password / biometric /
remote-key ceremony. Each `SigningKey` pairs a `wallet.keys[i].id` with
its key material — the user's password-encrypted key share is
decrypted server-side using the password the user just typed.

## Network + permission semantics

This section answers the three questions every host integrator hits
once and never asks again. Before you build a workaround, check here.

### Who actually switches the network on approval?

**libwallet does — server-side, atomically with `approve()`.** Every
network switch (whether from `wallet_switchEthereumChain` or an
implicit cross-family action method) flows through a single
`ChainSwitchRequest`. On approve libwallet calls `SetCurrent`
(and `Save` first if the chain is freshly proposed) before the
original RPC handler returns to the dApp. A `chainChanged` event is
then broadcast on `client.jsEvents` and the EIP-1193 provider
re-emits it.

The host should **not** call `client.networks.setCurrent(...)` after
`requests.approve(...)`. Doing so is harmless (it's a no-op since
SetCurrent already ran) but it's a red flag that something else is
wrong: usually the "Current network" badge in the dApp staying on
"not connected" because `eth_accounts` returned bad data, not because
the switch didn't happen.

### Who switches the connected account?

For `ChainSwitchRequest`, libwallet **both** switches the current
network AND saves a `ConnectedSite` for `(host, account)` on
approval — the user's pick is treated as implicit consent for the
dApp to use that account. The original action method then proceeds
against the new state, with the dApp already considered connected.

Apps may still see a follow-up `ConnectRequest` if the original
method was `eth_requestAccounts` / `solana_connect` /
`mpurse_getAddress` — the connect handlers don't (yet) skip the
prompt when a ConnectedSite already exists. For now: render the
second prompt; the user will see "Connect <dApp>?" and can confirm
once more. Tracked as a follow-up.

### EIP-2255 permissions wire shape

`wallet_requestPermissions` and `wallet_getPermissions` return EIP-2255
exactly:

```json
[
  {
    "id": "perm:https://app.example.com",
    "parentCapability": "eth_accounts",
    "invoker": "https://app.example.com",
    "caveats": [
      {
        "type": "restrictReturnedAccounts",
        "value": ["0xaddr1", "0xaddr2"]
      }
    ]
  }
]
```

Notes:

- **One entry per permission**, not one per account. All authorised
  EVM addresses go into the single `restrictReturnedAccounts` caveat
  value array. (Pre-0.3.22 builds emitted one entry per account with
  no `parentCapability` field — dApps reading `perm.parentCapability`
  printed `undefined`.)
- **`eth_accounts` returns only EVM addresses.** Solana / Monacoin
  accounts that happen to be connected to the same host don't leak
  through, and no `"N/A"` placeholders appear (those came from
  ed25519 accounts re-derived for EVM during a chain switch).
- **Empty result is `[]` not `null`.** A dApp that hasn't been granted
  permissions sees an empty array, not a missing key.

### `wallet_revokePermissions`

Handled fully server-side — no `PendingRequest` fires. Per EIP-2255,
revoking shouldn't require user confirmation (the dApp is asking the
wallet to forget about it), so we just drop every `ConnectedSite`
row for the host and return `null`. The next call to `eth_accounts`
returns `[]`; a `chainChanged` / `accountsChanged` is NOT emitted
since there's no signed-in account left to change.

If you see `failed to decode response to wallet_revokePermissions:
invalid character 'm' looking for beginning of value`, you're on a
build older than 0.3.21 — that's the chain RPC relay returning a
plain "method not found" string. Update libwallet.

## Step 5 — inject on every page load

```dart
webview.setNavigationDelegate(NavigationDelegate(
  onPageFinished: (url) async {
    final js = await client.web3.injectionScript(
      name: 'MyWallet',
      rdns: 'com.example.mywallet',
      uuid: Uuid().v4(), // fresh UUIDv4 per load — spec requirement
      icon: iconDataUrl,
      bridge: 'libwalletBridge',
      host: url,
    );
    await webview.runJavaScript(js);
  },
));
```

Inject on `onPageFinished` rather than `onPageStarted` — some dApp
bundles race-check `window.ethereum` at DOM-ready, and late injection
after bundle load still works because EIP-6963 is event-driven.

## Gotchas

- **JS channel name must match the `bridge:` argument.** Mismatch =
  silent hang. The provider logs `console.warn` if it can't find the
  channel — check the WebView console first.
- **Fresh UUID per page load.** EIP-6963 scopes `uuid` to "the
  lifetime of the page" — generate a new UUIDv4 on every injection.
  Don't cache it, don't persist it across launches. dApps identify a
  wallet across page loads via `rdns` (which IS stable), not `uuid`.
- **iOS WKWebView text-channel escaping.** The Dart `runJavaScript`
  wrapper handles quoting, but if you build the JS string manually,
  backtick-escape user-provided strings. Use `jsonEncode` for
  everything going into a `runJavaScript` call.
- **Multiple frames / iframes.** The injection only covers the main
  frame by default. Inject into sub-frames only if you trust them;
  most dApps don't need it.
- **The Solana provider exposes only legacy window.solana.** A full
  Wallet Standard implementation is announced via
  `wallet-standard:register-wallet`, but the feature set is minimal
  (connect, disconnect, signMessage, signTransaction,
  signAndSendTransaction). dApps that depend on advanced features
  (e.g. `solana:signIn`) will need additions — open an issue.
- **mpurse_signRawTransaction is strict.** Every input must belong to
  the connected account. Counterparty / monacoin asset txs work out of
  the box; arbitrary multi-party co-sign flows don't.

## End-to-end minimal example

```dart
class WebWalletWebView extends StatefulWidget {
  final String url;
  final LibwalletClient client;

  const WebWalletWebView({
    required this.url,
    required this.client,
  });

  @override
  State<WebWalletWebView> createState() => _WebWalletWebViewState();
}

class _WebWalletWebViewState extends State<WebWalletWebView> {
  late final WebViewController _webview;
  late final StreamSubscription _eventsSub;
  late final StreamSubscription _requestsSub;

  @override
  void initState() {
    super.initState();

    _webview = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..addJavaScriptChannel('libwalletBridge', onMessageReceived: _onRpc)
      ..setNavigationDelegate(NavigationDelegate(
        onPageFinished: (url) async {
          final js = await widget.client.web3.injectionScript(
            name: 'MyWallet',
            rdns: 'com.example.mywallet',
            uuid: const Uuid().v4(), // fresh per injection
            icon: _kWalletIconDataUrl,
            bridge: 'libwalletBridge',
            host: url,
          );
          await _webview.runJavaScript(js);
        },
      ))
      ..loadRequest(Uri.parse(widget.url));

    _eventsSub = widget.client.jsEvents.listen((e) {
      final name = jsonEncode(e.jsEventName);
      final data = jsonEncode(e.data);
      _webview.runJavaScript('__libwalletEvent($name, $data)');
    });

    _requestsSub = widget.client.pendingRequests.listen(_onPending);
  }

  Future<void> _onRpc(JavaScriptMessage msg) async {
    final req = jsonDecode(msg.message) as Map<String, dynamic>;
    final id = req['id'];
    String payload;
    try {
      final result = await widget.client.web3.request(
        url: await _webview.currentUrl() ?? widget.url,
        query: {'method': req['method'], 'params': req['params']},
      );
      payload = jsonEncode({'result': result});
    } on LibwalletException catch (e) {
      payload = jsonEncode({
        'error': {'code': int.tryParse(e.code) ?? -32000, 'message': e.message},
      });
    }
    await _webview.runJavaScript('__libwalletResolve($id, ${jsonEncode(payload)})');
  }

  Future<void> _onPending(PendingRequest req) async {
    // Dispatch to your approval UI — see "Step 4" above.
    // In a minimal demo, auto-reject:
    await widget.client.requests.reject(req.id);
  }

  @override
  void dispose() {
    _eventsSub.cancel();
    _requestsSub.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => WebViewWidget(controller: _webview);
}
```

## Testing against real dApps

- **EIP-6963 discovery**: open https://revoke.cash/ or any dApp that
  lists available wallets. Your name + icon should appear.
- **Personal sign**: https://sign.ethereum.org or any SIWE-powered
  dApp.
- **Typed data**: https://opensea.io listing flow.
- **Solana**: https://jup.ag (uses Wallet Standard).
- **Monacoin mpurse**: https://monapalette.info and other mpurse-aware
  dApps.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| dApp doesn't show wallet in picker | EIP-6963 announce is blocked — check console, verify icon is a valid data: URL or HTTPS |
| Every RPC call hangs | `bridge:` name doesn't match the JS channel name |
| `__libwalletResolve is not a function` | Script wasn't re-injected after navigation |
| Accounts don't update when user switches | `jsEvents` listener not wired or WebView was disposed before the stream |
| `could not find account` on approve | User switched network between the request and approve — refetch the account by ID, not by address |
| `this input is not owned by this account` on mpurse_signRawTransaction | dApp sent a multi-party tx; v1 only signs fully-owned txs |
| dApp shows "Current network: not connected" right after a network switch | dApp is reading `perm.parentCapability` / a malformed `eth_accounts`; pre-0.3.22 emitted the wrong shape. Update libwallet. |
| dApp's "Request Permissions" prints `undefined, undefined` | Same root cause: missing `parentCapability` on each EIP-2255 perm entry. Fixed in 0.3.22+. |
| `eth_accounts` returns `["N/A"]` or a base58 Solana address on an EVM dApp | A non-EVM account is connected to the host. Pre-0.3.22 didn't filter; 0.3.22+ returns only `0x…` addresses. |
| `failed to decode response to wallet_revokePermissions: invalid character 'm'` | Pre-0.3.21 build — `wallet_revokePermissions` was unhandled and fell through to the chain RPC relay. Update libwallet. |
| Host calls `client.networks.setCurrent(...)` after `requests.approve(...)` to "force" the switch | Not needed — libwallet does SetCurrent server-side as part of approve. The workaround was probably masking Bug 1 above; remove it once you're on 0.3.22+. |
