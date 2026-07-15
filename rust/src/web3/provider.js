// libwallet webview provider shim.
//
// Produced by the Go Web3:injectionScript endpoint. The Go side replaces
// __LIBWALLET_CONFIG__ with a JSON literal, so this file is valid JS
// before substitution too (eases local editing). The host is expected to
// have installed:
//
//   - a message channel named in config.bridge, with .postMessage(string)
//     that the host reads and routes to Web3:request — call it "outbound"
//   - two globals: __libwalletResolve(id, json) and __libwalletEvent(name,
//     data) that the host invokes via webview.runJavaScript(...) when
//     libwallet produces a response or emits a js:* event
//
// Round-trip is symmetric: dApp → provider.request(...) → outbound bridge
// → Web3:request → __libwalletResolve → Promise resolves in dApp.
// Host events → __libwalletEvent → provider.emit(...) → dApp listener.
(function () {
  'use strict';

  // Origin gating (EIP-1193/6963 privacy). Integrators are told to inject
  // main-frame-only, but a webview configured to inject into all frames must
  // not expose the wallet to a cross-origin sub-frame (e.g. an embedded ad or
  // tracker) — that frame could otherwise enumerate the connected account and
  // silently link the user's on-chain identity across sites. Install only in
  // the top document or a sub-frame that is same-origin with it; bail out of a
  // cross-origin sub-frame (reading top.location.origin throws for one).
  try {
    if (window.top !== window.self &&
        window.top.location.origin !== window.location.origin) {
      return;
    }
  } catch (_) {
    return; // cross-origin parent — access denied, so do not inject
  }

  var CONFIG = __LIBWALLET_CONFIG__;

  var bridgeChannel = window[CONFIG.bridge];
  if (!bridgeChannel || typeof bridgeChannel.postMessage !== 'function') {
    console.warn('[libwallet] host bridge "' + CONFIG.bridge +
      '" not installed; provider calls will hang');
    bridgeChannel = { postMessage: function () {} };
  }

  // ── RPC plumbing ────────────────────────────────────────────────────
  var nextId = 1;
  var pending = Object.create(null);

  function rpc(method, params) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      pending[id] = { resolve: resolve, reject: reject };
      bridgeChannel.postMessage(JSON.stringify({
        id: id,
        method: method,
        params: params || [],
      }));
    });
  }

  // Host invokes this when a Web3:request completes.
  window.__libwalletResolve = function (id, payload) {
    var entry = pending[id];
    if (!entry) return;
    delete pending[id];
    var msg;
    try { msg = typeof payload === 'string' ? JSON.parse(payload) : payload; }
    catch (e) { entry.reject(e); return; }
    if (msg && msg.error) {
      var err = new Error(msg.error.message || msg.error || 'libwallet error');
      if (msg.error.code) err.code = msg.error.code;
      entry.reject(err);
    } else {
      entry.resolve(msg && 'result' in msg ? msg.result : msg);
    }
  };

  // ── Tiny EventEmitter (avoids Node polyfill bloat) ──────────────────
  function Emitter() { this._h = Object.create(null); }
  Emitter.prototype.on = function (ev, fn) {
    (this._h[ev] = this._h[ev] || []).push(fn);
    return this;
  };
  Emitter.prototype.addListener = Emitter.prototype.on;
  Emitter.prototype.removeListener = function (ev, fn) {
    var arr = this._h[ev]; if (!arr) return this;
    this._h[ev] = arr.filter(function (f) { return f !== fn; });
    return this;
  };
  Emitter.prototype.off = Emitter.prototype.removeListener;
  Emitter.prototype.removeAllListeners = function (ev) {
    if (ev) delete this._h[ev]; else this._h = Object.create(null);
    return this;
  };
  Emitter.prototype.emit = function (ev /*, ...args */) {
    var arr = (this._h[ev] || []).slice();
    var args = Array.prototype.slice.call(arguments, 1);
    for (var i = 0; i < arr.length; i++) {
      try { arr[i].apply(null, args); } catch (e) { console.error(e); }
    }
  };

  // ── EIP-1193 provider (+ EIP-6963 announce) ─────────────────────────
  function EthereumProvider() {
    Emitter.call(this);
    this.isLibwallet = true;
    this.isMetaMask = false;
    this.chainId = CONFIG.initialChainId || null;
    this.networkVersion = CONFIG.initialNetworkVersion || null;
    this.selectedAddress = (CONFIG.initialAccounts &&
      CONFIG.initialAccounts[0]) || null;
  }
  EthereumProvider.prototype = Object.create(Emitter.prototype);
  EthereumProvider.prototype.request = function (args) {
    if (!args || typeof args.method !== 'string') {
      return Promise.reject(new Error('request requires {method, params}'));
    }
    return rpc(args.method, args.params);
  };
  // Legacy shims some dApps still use.
  EthereumProvider.prototype.enable = function () {
    return this.request({ method: 'eth_requestAccounts' });
  };
  EthereumProvider.prototype.send = function (method, params) {
    if (typeof method === 'string') return this.request({ method: method, params: params });
    // ethers v5 legacy signature: send({method, params}, cb)
    return this.request(method);
  };
  EthereumProvider.prototype.sendAsync = function (payload, cb) {
    var self = this;
    this.request(payload).then(
      function (r) { cb(null, { id: payload.id, jsonrpc: '2.0', result: r }); },
      function (e) { cb(e); }
    );
  };

  var ethereum = new EthereumProvider();
  try {
    Object.defineProperty(window, 'ethereum', {
      value: ethereum, writable: true, configurable: true, enumerable: true,
    });
  } catch (_) {
    window.ethereum = ethereum;
  }

  // EIP-6963 announce. Fires on load and on every requestProvider pull.
  var providerInfo = Object.freeze({
    uuid: CONFIG.uuid,
    name: CONFIG.name,
    icon: CONFIG.icon,
    rdns: CONFIG.rdns,
  });
  function announceEth() {
    window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
      detail: Object.freeze({ info: providerInfo, provider: ethereum }),
    }));
  }
  window.addEventListener('eip6963:requestProvider', announceEth);
  announceEth();

  // ── Solana provider + Wallet Standard announce ──────────────────────
  function SolanaProvider() {
    Emitter.call(this);
    this.isLibwallet = true;
    this.isPhantom = false;
    this.publicKey = null;
    this.isConnected = false;
  }
  SolanaProvider.prototype = Object.create(Emitter.prototype);
  SolanaProvider.prototype.connect = function (options) {
    var self = this;
    return rpc('solana_connect', [options || {}]).then(function (res) {
      var pubStr = res && (res.publicKey || res);
      self.publicKey = pubStr ? { toString: function () { return pubStr; }, toBase58: function () { return pubStr; } } : null;
      self.isConnected = !!self.publicKey;
      self.emit('connect', self.publicKey);
      return { publicKey: self.publicKey };
    });
  };
  SolanaProvider.prototype.disconnect = function () {
    var self = this;
    return rpc('solana_disconnect', []).then(function () {
      self.isConnected = false;
      self.publicKey = null;
      self.emit('disconnect');
    });
  };
  SolanaProvider.prototype.signMessage = function (message) {
    var b64 = toBase64(message);
    return rpc('solana_signMessage', [{ message: b64 }]).then(function (res) {
      return {
        signature: fromBase58((res && res.signature) || ''),
        publicKey: res && res.publicKey,
      };
    });
  };
  SolanaProvider.prototype.signTransaction = function (tx) {
    var serialized = tx && typeof tx.serialize === 'function'
      ? tx.serialize({ requireAllSignatures: false, verifySignatures: false })
      : tx;
    return rpc('solana_signTransaction', [{
      transaction: toBase64(serialized),
    }]).then(function (res) {
      return res; // caller is expected to feed res.transaction into Transaction.from(...)
    });
  };
  SolanaProvider.prototype.signAndSendTransaction = function (tx, options) {
    var serialized = tx && typeof tx.serialize === 'function'
      ? tx.serialize({ requireAllSignatures: false, verifySignatures: false })
      : tx;
    return rpc('solana_signAndSendTransaction', [{
      transaction: toBase64(serialized),
      options: options || {},
    }]);
  };

  var solana = new SolanaProvider();
  try {
    Object.defineProperty(window, 'solana', {
      value: solana, writable: true, configurable: true, enumerable: true,
    });
  } catch (_) {
    window.solana = solana;
  }

  // Solana Wallet Standard — minimal register event. Full feature set is
  // out of scope for v1; dApps that rely on window.solana keep working.
  try {
    window.dispatchEvent(new CustomEvent('wallet-standard:register-wallet', {
      detail: function (api) {
        if (!api || typeof api.register !== 'function') return;
        api.register({
          version: '1.0.0',
          name: CONFIG.name,
          icon: CONFIG.icon,
          chains: ['solana:mainnet', 'solana:devnet', 'solana:testnet'],
          features: {
            'standard:connect': { connect: function () { return solana.connect(); } },
            'standard:disconnect': { disconnect: function () { return solana.disconnect(); } },
            'solana:signMessage': { signMessage: function (input) { return solana.signMessage(input.message); } },
            'solana:signTransaction': { signTransaction: function (input) { return solana.signTransaction(input.transaction); } },
            'solana:signAndSendTransaction': { signAndSendTransaction: function (input) { return solana.signAndSendTransaction(input.transaction, input.options); } },
          },
          accounts: [],
        });
      },
    }));
  } catch (_) { /* host may not support CustomEvent; non-fatal */ }

  // ── mpurse (Monacoin) — https://github.com/tadajam/mpurse ───────────
  function MpurseProvider() {
    this.updateEmitter = new Emitter();
  }
  MpurseProvider.prototype.getAddress = function () {
    return rpc('mpurse_getAddress', []);
  };
  MpurseProvider.prototype.signMessage = function (message) {
    return rpc('mpurse_signMessage', [message]);
  };
  MpurseProvider.prototype.signRawTransaction = function (tx) {
    return rpc('mpurse_signRawTransaction', [tx]);
  };
  MpurseProvider.prototype.sendRawTransaction = function (tx) {
    return rpc('mpurse_sendRawTransaction', [tx]);
  };
  MpurseProvider.prototype.sendAsset = function (to, asset, amount, memoType, memoValue) {
    return rpc('mpurse_sendAsset', [{
      to: to, asset: asset, amount: amount,
      memoType: memoType, memoValue: memoValue,
    }]);
  };
  // Proxy services (mpchain / counterBlock / counterParty) are upstream
  // services — not implemented here. dApps needing them should call the
  // HTTP endpoints directly.
  MpurseProvider.prototype.mpchain = function () {
    return Promise.reject(new Error('mpurse.mpchain is not provided by libwallet; call the service directly'));
  };
  MpurseProvider.prototype.counterBlock = function () {
    return Promise.reject(new Error('mpurse.counterBlock is not provided by libwallet; call the service directly'));
  };
  MpurseProvider.prototype.counterParty = function () {
    return Promise.reject(new Error('mpurse.counterParty is not provided by libwallet; call the service directly'));
  };

  var mpurse = new MpurseProvider();
  try {
    Object.defineProperty(window, 'mpurse', {
      value: mpurse, writable: true, configurable: true, enumerable: true,
    });
  } catch (_) {
    window.mpurse = mpurse;
  }

  // ── Host → JS event pump ────────────────────────────────────────────
  // Host calls __libwalletEvent('accountsChanged', [...]) etc. — we fan
  // out to each provider with the appropriate shape per standard.
  window.__libwalletEvent = function (name, data) {
    try {
      if (name === 'accountsChanged') {
        var accounts = Array.isArray(data) ? data : (data && data.accounts) || [];
        ethereum.selectedAddress = accounts[0] || null;
        ethereum.emit('accountsChanged', accounts);
        mpurse.updateEmitter.emit('addressChanged', accounts[0] || '');
        // Solana connect/disconnect driven by explicit connect() call —
        // we don't guess here.
      } else if (name === 'chainChanged') {
        var chainId = (data && data.chainId) || data;
        ethereum.chainId = chainId;
        if (typeof chainId === 'string' && chainId.indexOf('0x') === 0) {
          ethereum.networkVersion = String(parseInt(chainId, 16));
        }
        ethereum.emit('chainChanged', chainId);
      } else if (name === 'stateChanged') {
        mpurse.updateEmitter.emit('stateChanged', data);
      } else if (name === 'disconnect') {
        ethereum.emit('disconnect', data);
        solana.isConnected = false;
        solana.publicKey = null;
        solana.emit('disconnect');
      } else {
        // Forward unknown events to all providers — forward-compat escape.
        ethereum.emit(name, data);
      }
    } catch (e) {
      console.error('[libwallet] event dispatch failed:', e);
    }
  };

  // ── encoding helpers ────────────────────────────────────────────────
  function toBase64(src) {
    if (src instanceof Uint8Array) {
      var s = '';
      for (var i = 0; i < src.length; i++) s += String.fromCharCode(src[i]);
      return btoa(s);
    }
    if (typeof src === 'string') return btoa(src);
    if (src && src.buffer instanceof ArrayBuffer) return toBase64(new Uint8Array(src.buffer));
    return src;
  }
  var B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function fromBase58(str) {
    if (!str) return new Uint8Array(0);
    var bytes = [0];
    for (var i = 0; i < str.length; i++) {
      var c = B58_ALPHABET.indexOf(str[i]);
      if (c < 0) throw new Error('invalid base58 char: ' + str[i]);
      for (var j = 0; j < bytes.length; j++) {
        var v = bytes[j] * 58 + c; bytes[j] = v & 0xff; c = v >> 8;
      }
      while (c) { bytes.push(c & 0xff); c >>= 8; }
    }
    for (var k = 0; k < str.length && str[k] === '1'; k++) bytes.push(0);
    return new Uint8Array(bytes.reverse());
  }

  // Make debugging easier.
  window.__libwallet = { config: CONFIG, ethereum: ethereum, solana: solana, mpurse: mpurse };
})();
