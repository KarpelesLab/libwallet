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
- A persistent **install UUID**. Generate once, store in platform
  storage, never change. EIP-6963 uses this to let dApps remember
  which wallet the user chose.

## Step 1 — ask libwallet for the script

```dart
final js = await client.web3.injectionScript(
  name: 'MyWallet',
  rdns: 'com.example.mywallet',          // reverse-DNS, required by EIP-6963
  uuid: installUuid,                     // stable per install
  icon: 'data:image/svg+xml;base64,...', // or https://... URL
  bridge: 'libwalletBridge',             // name of the JS channel you install
  host: currentPageUrl,                  // optional — pre-fills connected accounts
);
```

Regenerate the script per page navigation if `host` should reflect the
new origin. The script has no external dependencies; it's safe to
cache and reuse for many dApps during a session.

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

    case PersonalSignRequest():
      final text = req.messageAsText ?? 'binary: ${req.messageBytes.length} bytes';
      final ok = await showSignSheet(req.host, text);
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
          : await client.requests.reject(req.id);

    case SignTypedDataRequest():
      final ok = await showTypedDataSheet(req.host, req.typedData);
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
          : await client.requests.reject(req.id);

    case SolanaSignTransactionRequest():
      final ok = await showSolanaTxSheet(req.host, req.transactionBytes);
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
          : await client.requests.reject(req.id);

    case MpurseSignMessageRequest():
      final ok = await showSignSheet(req.host, req.message);
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
          : await client.requests.reject(req.id);

    case MpurseSignTransactionRequest():
      final ok = await showBtcTxSheet(req.host, req.unsignedTxHex);
      ok
          ? await client.requests.approve(req.id, keys: await askKeys())
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

## Step 5 — inject on every page load

```dart
webview.setNavigationDelegate(NavigationDelegate(
  onPageFinished: (url) async {
    final js = await client.web3.injectionScript(
      name: 'MyWallet',
      rdns: 'com.example.mywallet',
      uuid: installUuid,
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
- **Install UUID must persist.** Rotating the UUID every launch breaks
  wallet-remembering in dApps. Generate once, store in secure storage.
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
  final String installUuid;

  const WebWalletWebView({
    required this.url,
    required this.client,
    required this.installUuid,
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
            uuid: widget.installUuid,
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
