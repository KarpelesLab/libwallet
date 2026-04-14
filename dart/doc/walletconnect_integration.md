# WalletConnect v2 integration guide

libwallet ships a full WalletConnect v2 wallet-side implementation — the
relay WebSocket client, envelope crypto (ChaCha20-Poly1305 +
X25519/HKDF), session persistence (SQL-backed, restart-safe), and the
pair/propose/settle/request/event/delete message flow. What the host app
has to wire is the UI.

Pair with the WebView guide: the WebView guide covers in-app dApps
(injected providers); this covers out-of-app dApps (the user scans a
QR or pastes a `wc:…` URI).

## Prerequisites

- A WalletConnect Cloud `projectId` — register once at
  `cloud.walletconnect.com`. Needed for relay access.
- Keep the projectId in platform config; don't hardcode in source.

## Step 1 — start the relay

```dart
await client.walletConnect.start(projectId: myProjectId);
```

This opens the WebSocket, replays subscriptions for every existing
active session, and reconnects with exponential backoff if the link
drops. Call it once at app startup.

`relayUrl:` is optional — defaults to
`wss://relay.walletconnect.com`. Override if you run your own relay
or point at a different environment.

## Step 2 — pair

When the user scans a QR code or pastes a `wc:TOPIC@2?...` URI:

```dart
final pairingTopic = await client.walletConnect.pair(uri);
```

The relay subscription is now live on the pairing topic; the dApp's
`wc_sessionPropose` message will arrive shortly.

## Step 3 — handle the proposal

```dart
client.walletConnectProposals.listen((proposal) async {
  final ok = await showConnectSheet(
    name: proposal.name,
    url: proposal.url,
    icons: proposal.icons,
    request: proposal.proposal, // shows requested chains/methods/events
  );
  if (!ok) {
    await client.walletConnect.rejectSession(proposal.pairingTopic);
    return;
  }
  await client.walletConnect.approveSession(
    proposal.pairingTopic,
    accounts: [
      // CAIP-10: <namespace>:<chainId>:<address>
      'eip155:1:0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
      // 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:SomeBase58Pubkey',
    ],
    // Leave methods/events unset to echo what the dApp requested.
  );
});
```

After `approveSession`, libwallet generates the session X25519 keypair,
derives the session symKey via ECDH + HKDF, subscribes to the session
topic, emits `wc_sessionSettle` on it, and replies to the pairing-topic
proposal. The session is now `active` and persists across restarts.

## Step 4 — handle session requests

```dart
client.walletConnectRequests.listen((req) async {
  // req.method is an EIP-1193-style JSON-RPC method name; everything
  // libwallet's Web3:request handler understands works here.
  try {
    final result = await client.web3.request(
      url: req.peerMetadata['url'] as String? ?? 'wc://${req.topic}',
      query: {'method': req.method, 'params': req.params},
    );
    await client.walletConnect.respond(req.topic, req.id, result);
  } on LibwalletException catch (e) {
    await client.walletConnect.respondError(
      req.topic,
      req.id,
      code: int.tryParse(e.code) ?? 5000,
      message: e.message,
    );
  }
});
```

Approval UI for signing methods (`personal_sign`, `eth_sendTransaction`,
`eth_signTypedData`, Solana sign*, mpurse sign*) is handled inside
`client.web3.request(...)` via the existing `client.pendingRequests`
stream — wire that the same way you do for the WebView flow.

## Step 5 — push chain / account updates

When the user changes networks or connected accounts, tell every active
session so the dApp re-renders:

```dart
Future<void> pushChain(String caip2ChainId, String hexChainId) async {
  final sessions = await client.walletConnect.sessions();
  for (final s in sessions.where((s) => s.isActive)) {
    await client.walletConnect.emitEvent(
      topic: s.topic,
      name: 'chainChanged',
      data: hexChainId,        // EIP-1193 shape
      chainId: caip2ChainId,   // required CAIP-2 routing hint
    );
  }
}
```

Similarly `name: 'accountsChanged'` with a `['0xabc…']` list.

## Step 6 — disconnect

```dart
await client.walletConnect.disconnect(session.topic);
```

Sends `wc_sessionDelete` to the dApp, marks the session disconnected
locally, and unsubscribes from the relay topic.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ProjectID is required` | No projectId passed; register at cloud.walletconnect.com |
| dApp QR shows "trying to connect" forever | Relay dial failed — check your projectId is valid for the chosen relayUrl |
| Proposals arrive but session never settles | dApp rejected your accounts — inspect the `requiredNamespaces` field and make sure your CAIP-10 accounts match every `eip155:*` / `solana:*` chain the dApp asked for |
| `unknown topic` on `respond` | Session expired (7-day default) or was disconnected — fetch with `sessions()` to confirm |

## Security notes

- libwallet's stored Ed25519 relay identity key lets the same wallet
  re-authenticate with the relay after restart. It's never shared with
  dApps and never leaves the device.
- Session symmetric keys are stored in the SQL database alongside the
  rest of libwallet's state. Protect that directory at the OS level.
- `sessions()` includes expired rows; filter with `.isActive &&
  s.expiry?.isAfter(DateTime.now())` before showing to users.
