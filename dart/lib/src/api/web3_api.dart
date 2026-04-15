import '../client/transport.dart';

/// Web3 JSON-RPC proxy + webview injection helper.
class Web3Api {
  final Transport _conn;

  Web3Api(this._conn);

  /// Send a Web3 JSON-RPC request. Most consumers won't call this directly
  /// — the typical use is to wire a webview's JS channel to route
  /// messages from [injectionScript] into this method.
  Future<dynamic> request({
    required String url,
    required Map<String, dynamic> query,
  }) async {
    return await _conn.request('Web3:request', 'POST', {
      'url': url,
      'query': query,
    });
  }

  /// Generate JavaScript to inject into a WebView. Exposes libwallet as:
  ///
  /// - **`window.ethereum`** — EIP-1193 provider, announced via EIP-6963.
  ///   Ethereum + any configured EVM chain (Polygon, BSC, Sepolia, …).
  /// - **`window.solana`** — legacy provider + minimal Wallet Standard
  ///   announce. Solana mainnet + devnet.
  /// - **`window.mpurse`** — Monacoin (https://github.com/tadajam/mpurse).
  ///   `getAddress`, `signMessage`, `signRawTransaction`,
  ///   `sendRawTransaction` all work; `sendAsset` requires external
  ///   Counterparty construction and returns an error.
  ///
  /// For the full wiring walkthrough (outbound RPC bridge, inbound event
  /// relay, approval UI, on-navigation re-injection, testing against real
  /// dApps, common pitfalls) see
  /// `doc/webview_integration.md` in the package source, or
  /// https://github.com/KarpelesLab/libwallet/blob/master/dart/doc/webview_integration.md
  ///
  /// Short form: the script expects two host-side hooks, both wired once:
  ///
  /// 1. **Outbound**: a JS message channel named by [bridge] (e.g.
  ///    `libwalletBridge`). The host reads each `postMessage(json)`, calls
  ///    [request] with the decoded payload, and on completion runs
  ///    `webview.runJavaScript('__libwalletResolve($id,
  ///    ${jsonEncode(jsonEncode(response))})')`.
  /// 2. **Inbound**: whenever `client.jsEvents` fires (accountsChanged /
  ///    chainChanged / …), the host runs
  ///    `webview.runJavaScript('__libwalletEvent(${jsonEncode(name)},
  ///    ${jsonEncode(data)})')` and the provider re-emits it in the right
  ///    shape per standard (EIP-1193 / mpurse updateEmitter / Solana).
  ///
  /// [name] / [icon] / [rdns] / [uuid] are the EIP-6963 info fields.
  /// Per EIP-6963, [uuid] must be a UUIDv4 that uniquely identifies this
  /// provider announcement for the lifetime of the page — generate a
  /// fresh one on every injection (or on every `start` of a new WebView
  /// session). Do NOT persist it across launches. Icon is a `data:` URL
  /// (recommended — works offline and avoids leaking the user's wallet
  /// to your CDN) or HTTPS URL.
  ///
  /// [host] is optional. When provided (e.g. the current page URL), the
  /// returned script pre-populates connected accounts so the provider can
  /// answer `eth_accounts` synchronously on first paint.
  Future<String> injectionScript({
    required String name,
    required String rdns,
    required String uuid,
    required String icon,
    required String bridge,
    String? host,
  }) async {
    final data = await _conn.request('Web3:injectionScript', 'POST', {
      'Name': name,
      'Rdns': rdns,
      'Uuid': uuid,
      'Icon': icon,
      'Bridge': bridge,
      if (host != null) 'Host': host,
    });
    return (data as Map)['script'] as String;
  }
}
