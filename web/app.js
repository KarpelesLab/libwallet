// ============================================================================
// libwallet — client-side wallet logic
//
// State machine of screens:
//   loading → (wasm-error) | onboarding | unlock → dashboard
//
// The signing/derivation core is a Rust→WASM module produced separately by CI
// (`wasm-pack build --target web`) and served from ./pkg/libwallet.js. We load
// it via dynamic import so a 404 during local preview yields a friendly screen
// instead of a hard module-load failure. No part of the crypto is stubbed here.
//
// Security invariants:
//   - The plaintext mnemonic lives ONLY in the `session.mnemonic` variable and
//     never touches localStorage.
//   - The password is never stored; it is used transiently for encrypt/decrypt.
//   - localStorage holds only the encrypted vault blob and non-secret settings.
// ============================================================================

// ---- Configuration (easy to change) ---------------------------------------

const STORAGE = {
  vault:    'libwallet.vault.v1',   // encrypted mnemonic (base64 from encrypt_blob)
  settings: 'libwallet.settings.v1' // non-secret: custom EVM chain config
};

// Default EVM network. Overridable from the Settings tab.
const DEFAULT_EVM = {
  name:     'Ethereum',
  chainId:  1,
  rpc:      'https://ethereum-rpc.publicnode.com',
  explorer: 'https://etherscan.io/tx/'
};

const SOLANA_RPC       = 'https://api.mainnet-beta.solana.com';
const SOLANA_EXPLORER  = 'https://explorer.solana.com/tx/';
const BTC_API          = 'https://mempool.space/api';
const BTC_EXPLORER     = 'https://mempool.space/tx/';

const RPC_TIMEOUT_MS = 15000;

const DECIMALS = { evm: 18, bitcoin: 8, solana: 9 };
const SYMBOL   = { evm: 'ETH', bitcoin: 'BTC', solana: 'SOL' };

const CHAIN_META = {
  evm:     { name: 'Ethereum',    tag: 'EVM · secp256k1', badge: 'Ξ' },
  bitcoin: { name: 'Bitcoin',     tag: 'BTC · secp256k1', badge: '₿' },
  solana:  { name: 'Solana',      tag: 'SOL · ed25519',   badge: '◎' }
};

// ---- In-memory session (cleared on lock / reload) -------------------------

const session = {
  mnemonic:  null,   // string, only while unlocked (walletcore path)
  mpc:       false,  // true when the dashboard is backed by the MPC committee
  addresses: null,   // { evm, bitcoin, solana }
  balances:  {}      // chain → formatted string
};

let wasm = null;         // the loaded module namespace
let evmChain = { ...DEFAULT_EVM };
let onboardDraft = { mnemonic: null, words: 12 }; // holds phrase before password set

// ---- Tiny DOM helpers ------------------------------------------------------

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const el = (tag, cls, html) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
};
const short = (s, head = 10, tail = 8) =>
  s && s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;

// ============================================================================
// Boot
// ============================================================================

boot();

async function boot() {
  wireStaticEvents();
  loadSettings();
  try {
    // Dynamic import → catchable if pkg/ is missing during local preview.
    const mod = await import('./pkg/libwallet.js');
    if (typeof mod.default === 'function') await mod.default(); // init()
    wasm = mod;
  } catch (err) {
    console.error(err);
    $('#wasmErrDetail').textContent = String(err && err.message || err);
    return showScreen('wasm-error');
  }
  route();
}

// Decide the first real screen once wasm is ready.
function route() {
  // An on-device MPC wallet is the primary wallet — it takes priority over the
  // walletcore vault. Present its unlock screen (passkey / password) instead of
  // a fresh keygen or the walletcore password prompt.
  if (localStorage.getItem(BK_MPC_LS)) {
    prepareMpcUnlock();
    return showScreen('mpc-unlock');
  }
  if (localStorage.getItem(STORAGE.vault)) {
    showScreen('unlock');
    setTimeout(() => $('#pwUnlock')?.focus(), 60);
  } else {
    showScreen('onboarding');
    goStep('choose');
  }
}

// ============================================================================
// Screen + step management
// ============================================================================

const VAULT_SCREENS = new Set(['onboarding', 'unlock', 'wasm-error', 'loading']);

function showScreen(name) {
  $$('.screen').forEach(s => s.classList.remove('active'));
  $(`#screen-${name}`)?.classList.add('active');
  // Guilloché backdrop only behind the vault-style screens.
  $('#vaultBg').hidden = !VAULT_SCREENS.has(name);
  // Lock indicator only on the dashboard.
  $('#lockState').classList.toggle('show', name === 'dashboard');
}

// "Console mode": reach the Backend (on-device MPC) tab WITHOUT a walletcore
// wallet. The dashboard's account/send/settings tabs need a derived session, so
// hide them (and the lock control) and show a way back to onboarding. The
// Backend tab runs its own independent libwallet session (backendOpen).
function setConsoleMode(on) {
  ['accounts', 'send', 'settings'].forEach(t => {
    const b = $(`.tabs button[data-tab="${t}"]`);
    if (b) b.style.display = on ? 'none' : '';
  });
  const ls = $('#lockState');
  if (ls) ls.style.display = on ? 'none' : '';
  $('#bkBackToSetup')?.classList.toggle('hidden', !on);
}

function openBackendConsole() {
  setConsoleMode(true);
  showScreen('dashboard');
  $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === 'backend'));
  $$('.tabpane').forEach(p => p.classList.toggle('on', p.dataset.pane === 'backend'));
  backendOpen();
}

// Onboarding is a multi-step card flow inside one screen.
function goStep(step) {
  $$('#screen-onboarding [data-step]').forEach(c => c.classList.toggle('hidden', c.dataset.step !== step));
  if (step === 'create') renderSeed();
}

// ============================================================================
// Onboarding — create
// ============================================================================

function generatePhrase() {
  onboardDraft.mnemonic = wasm.generate_mnemonic(onboardDraft.words);
  return onboardDraft.mnemonic;
}

function renderSeed() {
  if (!onboardDraft.mnemonic) generatePhrase();
  const words = onboardDraft.mnemonic.trim().split(/\s+/);
  const grid = $('#seedGrid');
  grid.innerHTML = '';
  words.forEach((w, i) => {
    const cell = el('div', 'seed-word');
    cell.innerHTML = `<span class="n">${i + 1}</span><span class="w">${w}</span>`;
    grid.appendChild(cell);
  });
  // Re-seal the cover and reset the confirmation on every (re)render.
  $('#sealCover').classList.remove('lifted');
  $('#savedConfirm').checked = false;
  $('#createContinue').disabled = true;
}

// ============================================================================
// Onboarding — finish (encrypt + store)
// ============================================================================

function finishSetup() {
  const pw = $('#pwNew').value;
  const confirm = $('#pwConfirm').value;
  const errEl = $('#pwErr');
  errEl.textContent = '';

  if (pw.length < 8) { errEl.textContent = 'Use at least 8 characters.'; return; }
  if (pw !== confirm) { errEl.textContent = 'Passwords do not match.'; return; }
  if (!onboardDraft.mnemonic) { errEl.textContent = 'No phrase to save — start over.'; return; }

  try {
    const blob = wasm.encrypt_blob(onboardDraft.mnemonic, pw);
    localStorage.setItem(STORAGE.vault, blob);
  } catch (err) {
    errEl.textContent = 'Could not encrypt the phrase: ' + (err.message || err);
    return;
  }

  // Move straight into an unlocked session; wipe the draft.
  const mnemonic = onboardDraft.mnemonic;
  onboardDraft = { mnemonic: null, words: 12 };
  $('#pwNew').value = $('#pwConfirm').value = '';
  unlockWith(mnemonic);
  toast('ok', 'Wallet created', 'Your phrase is encrypted and stored on this device.');
}

// ============================================================================
// Unlock / lock
// ============================================================================

function tryUnlock(pw) {
  const errEl = $('#unlockErr');
  errEl.textContent = '';
  const blob = localStorage.getItem(STORAGE.vault);
  if (!blob) return route();
  let mnemonic;
  try {
    mnemonic = wasm.decrypt_blob(blob, pw);
  } catch {
    errEl.textContent = 'Wrong password. Try again.';
    return;
  }
  $('#pwUnlock').value = '';
  unlockWith(mnemonic);
}

// Derive addresses and enter the dashboard for a known-good mnemonic.
async function unlockWith(mnemonic) {
  session.mnemonic = mnemonic;
  session.mpc = false;   // walletcore path: not MPC-backed
  try {
    session.addresses = wasm.derive_addresses(mnemonic);
  } catch (err) {
    session.mnemonic = null;
    toast('error', 'Derivation failed', err.message || String(err));
    return;
  }
  // Register the seed as 1-of-1 model wallets (secp256k1 + ed25519) so the
  // walletcore wallet uses the SAME agnostic handlers as the committee wallet —
  // Account:balance / signAndSendTransaction / Transaction:simulate. The seed is
  // its single key; nothing here does client-side chain RPC.
  backendOpen();
  session.accounts = await importWalletcoreWallet(mnemonic);
  session.addresses = {
    evm: session.accounts.evm.address,
    bitcoin: session.accounts.bitcoin.address,
    solana: session.accounts.solana.address,
  };
  // A real wallet: restore all tabs (in case console mode hid them) and default
  // back to the Accounts tab. Clear any MPC guards (re-enable Send, show reveal).
  setConsoleMode(false);
  applyMpcGuards();
  $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === 'accounts'));
  $$('.tabpane').forEach(p => p.classList.toggle('on', p.dataset.pane === 'accounts'));
  renderAccounts();
  onSendChainChange();
  showScreen('dashboard');
  refreshAllBalances();
}

function lock() {
  // MPC-backed session: locking returns to the MPC unlock screen (passkey /
  // password), not the walletcore password prompt. Drop the in-session unlock
  // material and restored wallet handles so nothing can sign until re-unlocked.
  if (session.mpc) {
    session.mpc = false;
    session.mnemonic = null;
    session.addresses = null;
    session.accounts = null;
    session.balances = {};
    backend.wallet = null;
    backend.walletEd = null;
    if (localStorage.getItem(BK_MPC_LS)) {
      prepareMpcUnlock();
      return showScreen('mpc-unlock');
    }
    // No stored record (e.g. persistence failed): fall back to onboarding.
    showScreen('onboarding');
    return goStep('choose');
  }
  session.mnemonic = null;
  session.addresses = null;
  session.accounts = null;
  session.wcKey = null;
  session.balances = {};
  backend.wallet = null;
  backend.walletEd = null;
  showScreen('unlock');
  setTimeout(() => $('#pwUnlock')?.focus(), 60);
}

function removeWallet() {
  localStorage.removeItem(STORAGE.vault);
  session.mnemonic = null;
  session.addresses = null;
  closeModal();
  route();
  toast('ok', 'Wallet removed', 'The encrypted vault was cleared from this browser.');
}

// ============================================================================
// Dashboard — accounts
// ============================================================================

function renderAccounts() {
  const list = $('#assetList');
  list.innerHTML = '';
  for (const chain of ['evm', 'bitcoin', 'solana']) {
    const addr = session.addresses[chain];
    const m = CHAIN_META[chain];
    const card = el('div', 'asset');
    card.dataset.chain = chain;
    card.innerHTML = `
      <div class="asset-head">
        <div class="asset-name">
          <span class="chain-badge">${m.badge}</span>
          <span class="meta"><span class="n">${m.name}</span><br><span class="t">${m.tag}</span></span>
        </div>
        <div class="balance"><span class="loading" data-bal="${chain}">—</span></div>
      </div>
      <div class="addr-row">
        <span class="addr" title="${addr}">${addr}</span>
        <button class="copy" type="button" data-copy="${addr}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M5 15V5a2 2 0 012-2h10" stroke="currentColor" stroke-width="1.8"/></svg>
          Copy
        </button>
      </div>`;
    list.appendChild(card);
  }
}

function setBalance(chain, text, isLoading) {
  const node = $(`[data-bal="${chain}"]`);
  if (!node) return;
  if (isLoading) { node.className = 'loading'; node.textContent = 'Loading…'; return; }
  node.className = '';
  node.innerHTML = `<span class="amt">${text}</span><span class="sym"> ${SYMBOL[chain]}</span>`;
}

// Chain balances now come from libwallet (Account:balance → rpc::call_async in
// Rust, endpoint resolved from the Network model) — the browser makes no chain
// RPC of its own. Both wallet types resolve through model accounts: the MPC
// wallet's committee accounts, or address-only view accounts for the walletcore
// path (see ensureViewAccounts). session.accounts maps chain → {id, address}.
async function refreshAllBalances() {
  if (!session.accounts) return;
  ['evm', 'bitcoin', 'solana'].forEach(c => setBalance(c, null, true));
  await Promise.allSettled(['evm', 'bitcoin', 'solana'].map(fetchChainBalance));
}

async function fetchChainBalance(chain) {
  const acct = session.accounts[chain];
  if (!acct) { setBalance(chain, 'unavailable'); return; }
  try {
    const r = await backendRequest('Account:balance', 'POST', { Id: acct.id });
    const raw = BigInt(r.balance ?? r.Balance ?? '0');
    session.balances[chain] = raw;
    setBalance(chain, formatUnits(raw, DECIMALS[chain], 6));
  } catch { setBalance(chain, 'unavailable'); }
}

// Import a BIP-39 mnemonic as 1-of-1 model wallets — secp256k1 (EVM + Bitcoin)
// and ed25519 (Solana) — so the walletcore wallet is signed by the SAME agnostic
// handlers as the committee wallet (Account:signAndSendTransaction etc.), with
// the seed as its single key. Returns the chain → {id, address} account map.
// session.wcKey is the in-memory seal password that unlocks the seed at sign
// time (never persisted; the encrypted mnemonic vault stays the reload source).
async function importWalletcoreWallet(mnemonic) {
  if (!session.wcKey) {
    const b = crypto.getRandomValues(new Uint8Array(32));
    session.wcKey = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  }
  const pw = session.wcKey;
  const [wSecp, wEd] = [
    await backendRequest('Wallet:importMnemonic', 'POST',
      { Name: 'walletcore', Curve: 'secp256k1', Mnemonic: mnemonic, Keys: [{ Type: 'Password', Key: pw }] }),
    await backendRequest('Wallet:importMnemonic', 'POST',
      { Name: 'walletcore', Curve: 'ed25519', Mnemonic: mnemonic, Keys: [{ Type: 'Password', Key: pw }] }),
  ];
  backend.wallet = wSecp;
  backend.walletEd = wEd;
  const [evm, btc, sol] = await Promise.all([
    backendRequest('Account', 'POST', { Name: '', Wallet: wSecp.Id, Type: 'ethereum', Index: 0 }),
    backendRequest('Account', 'POST', { Name: '', Wallet: wSecp.Id, Type: 'bitcoin', Index: 0 }),
    backendRequest('Account', 'POST', { Name: '', Wallet: wEd.Id, Type: 'solana', Index: 0 }),
  ]);
  return {
    evm:     { id: evm.Id, address: evm.Address },
    bitcoin: { id: btc.Id, address: btc.Address },
    solana:  { id: sol.Id, address: sol.Address },
  };
}

// ============================================================================
// Dashboard — send
// ============================================================================

let currentSendChain = 'evm';

function onSendChainChange() {
  currentSendChain = $('#sendChain').value;
  const addr = session.addresses?.[currentSendChain] || '';
  $('#sendCard').dataset.chain = currentSendChain;
  $('#sendFromAddr').textContent = short(addr, 12, 10);
  $('#sendFromAddr').title = addr;
  $('#amountLabel').textContent = `Amount (${SYMBOL[currentSendChain]})`;
  $('#sendErr').textContent = '';
  $('#feeNote').textContent = currentSendChain === 'bitcoin'
    ? 'Fee is estimated from mempool.space and paid from your balance on top of the amount; change returns to your own address.'
    : 'Network fee is estimated live and added on top of the amount.';
  updateSendAvailability();
}

function fillMax() {
  const bal = session.balances[currentSendChain];
  if (bal == null) { toast('error', 'Balance unknown', 'Refresh balances first.'); return; }
  // Leave headroom for fees; a precise max is computed at send time.
  $('#sendAmount').value = formatUnits(bal, DECIMALS[currentSendChain], DECIMALS[currentSendChain]);
}

async function onSendSubmit() {
  const to = $('#sendTo').value.trim();
  const amount = $('#sendAmount').value.trim();
  const err = $('#sendErr');
  err.textContent = '';
  if (!to) { err.textContent = 'Enter a recipient address.'; return; }
  if (!amount || Number(amount) <= 0) { err.textContent = 'Enter an amount greater than zero.'; return; }

  const btn = $('#sendSubmit');
  btn.disabled = true; btn.textContent = 'Preparing…';
  try {
    let prepared;
    if (session.mpc)                         prepared = await prepareMpc(currentSendChain, to, amount);
    else if (currentSendChain === 'evm')     prepared = await prepareEvm(to, amount);
    else if (currentSendChain === 'solana')  prepared = await prepareSolana(to, amount);
    else                                     prepared = await prepareBitcoin(to, amount);
    confirmSend(prepared);
  } catch (e) {
    err.textContent = e.message || String(e);
  } finally {
    btn.disabled = false; btn.textContent = 'Review & send';
  }
}

// --- EVM prepare -----------------------------------------------------------

// The ONE signer for every chain. Callers build the per-chain Transaction and
// pass a local-sign thunk; the MPC-vs-local routing (which account, which
// curve's committee, the biometric) lives here alone — no prepare* branches on
// session.mpc. For an MPC session it signs the committee via the chain-agnostic
// Account:signTransaction; otherwise it runs the local mnemonic signer. Must be
// called from a click handler so the committee biometric has transient
// activation. Returns the raw signed tx (0x-hex for EVM/BTC, base58 for Solana).
async function signChainTx(chain, mpcTx, localSign) {
  if (!session.mpc) return localSign();
  const acct = session.mpcAccounts[chain];
  if (!acct) throw new Error(`No MPC account for ${chain}.`);
  const wallet = chain === 'solana' ? backend.walletEd : backend.wallet;
  const keys = await mpcCommitteeKeys(wallet);   // biometric, in the caller's click
  const r = await backendRequest('Account:signTransaction', 'POST', {
    Id: acct.id, Transaction: mpcTx, Keys: keys
  });
  return r.raw ?? r.Raw;
}

function validateSendAddress(chain, to) {
  if (chain === 'evm' && !/^0x[0-9a-fA-F]{40}$/.test(to)) throw new Error('That is not a valid EVM address.');
  if (chain === 'solana' && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(to)) throw new Error('That is not a valid Solana address.');
}

function explorerUrl(chain, id) {
  if (chain === 'evm') return evmChain.explorer + id;
  if (chain === 'solana') return SOLANA_EXPLORER + id;
  return BTC_EXPLORER + id;
}

// MPC send: libwallet builds, signs (committee), and broadcasts via
// Account:signAndSendTransaction — the browser only supplies recipient + amount
// and the committee Keys (biometric in the confirm click). No client-side chain
// RPC: nonce/gas/EIP-1559 fees (EVM), blockhash (Solana), and UTXO discovery
// (Bitcoin) all happen in Rust. Preview is a best-effort Transaction:simulate.
async function prepareMpc(chain, to, amount) {
  validateSendAddress(chain, to);
  const acct = session.accounts?.[chain];
  if (!acct) throw new Error(`No account for ${chain}.`);
  const base = toBaseUnits(amount, DECIMALS[chain]);
  const mpcTx = chain === 'bitcoin'
    ? { To: to, Amount: Number(base) }
    : { to, value: base.toString() };

  const rows = [
    ['Network', CHAIN_META[chain].name],
    ['Amount', `${amount} ${SYMBOL[chain]}`],
    ['To', short(to, 12, 10)],
    ['Network fee', 'computed at send'],
  ];
  // Best-effort preview (revert check + gas estimate). EVM simulates from the
  // call; Solana/Bitcoin need a built tx so their preview is skipped here.
  if (chain === 'evm') {
    try {
      const sim = await backendRequest('Transaction:simulate', 'POST', {
        Id: acct.id,
        Transaction: { type: 'evm', to, from: acct.address, value: base.toString() },
      });
      if (sim.willRevert) rows.push(['⚠ Warning', sim.revertReason || 'transaction may revert']);
      if (sim.gasEstimate) rows.push(['Gas estimate', String(sim.gasEstimate)]);
    } catch { /* preview is best-effort */ }
  }

  return {
    chain, to, amount, rows,
    broadcast: async () => {
      // Runs in the confirm-modal click so the committee biometric inside
      // mpcCommitteeKeys has transient activation.
      const wallet = chain === 'solana' ? backend.walletEd : backend.wallet;
      const keys = await mpcCommitteeKeys(wallet);
      const r = await backendRequest('Account:signAndSendTransaction', 'POST', {
        Id: acct.id, Transaction: mpcTx, Keys: keys,
      });
      const id = r.hash ?? r.txid ?? r.signature ?? r.Hash ?? r.Txid ?? r.Signature;
      return { id, url: explorerUrl(chain, id) };
    },
  };
}

async function prepareEvm(to, amount) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) throw new Error('That is not a valid EVM address.');
  const from = session.addresses.evm;
  const value = toBaseUnits(amount, DECIMALS.evm);

  const [nonceHex, chainIdHex] = await Promise.all([
    rpc(evmChain.rpc, 'eth_getTransactionCount', [from, 'pending']),
    rpc(evmChain.rpc, 'eth_chainId', [])
  ]);
  const chainId = Number(BigInt(chainIdHex));
  const nonce = Number(BigInt(nonceHex));

  // Gas estimate (fallback 21000 for plain value transfers).
  let gas = 21000n;
  try {
    const g = await rpc(evmChain.rpc, 'eth_estimateGas',
      [{ from, to, value: '0x' + value.toString(16) }]);
    gas = BigInt(g);
  } catch { /* keep default */ }

  // Prefer EIP-1559: baseFee (from latest block) + priority tip. Fall back to legacy gasPrice.
  let fee;
  try {
    const [block, tipHex] = await Promise.all([
      rpc(evmChain.rpc, 'eth_getBlockByNumber', ['latest', false]),
      rpc(evmChain.rpc, 'eth_maxPriorityFeePerGas', []).catch(() => '0x3b9aca00') // 1 gwei
    ]);
    const baseFee = BigInt(block.baseFeePerGas);
    const tip = BigInt(tipHex);
    const maxFee = baseFee * 2n + tip;
    fee = { type: '1559', maxFeePerGas: maxFee.toString(), maxPriorityFeePerGas: tip.toString(), perGas: maxFee };
  } catch {
    const gp = BigInt(await rpc(evmChain.rpc, 'eth_gasPrice', []));
    fee = { type: 'legacy', gasPrice: gp.toString(), perGas: gp };
  }

  const feeWei = fee.perGas * gas;
  const txJson = {
    chainId, nonce, gas: Number(gas), to,
    value: value.toString(), data: '0x'
  };
  if (fee.type === '1559') {
    txJson.maxFeePerGas = fee.maxFeePerGas;
    txJson.maxPriorityFeePerGas = fee.maxPriorityFeePerGas;
  } else {
    txJson.gasPrice = fee.gasPrice;
  }

  return {
    chain: 'evm', to, amount,
    rows: [
      ['Network', `${evmChain.name} (chain ${chainId})`],
      ['Amount', `${amount} ETH`],
      ['To', short(to, 12, 10)],
      ['Est. network fee', `${formatUnits(feeWei, 18, 8)} ETH`],
      ['Gas limit', String(gas)]
    ],
    broadcast: async () => {
      // Runs from the confirm modal's "Sign & broadcast" click, so the committee
      // biometric inside signChainTx has valid transient activation. EVM's MPC
      // and local signers take the same Transaction shape.
      const raw = await signChainTx('evm', txJson,
        () => wasm.sign_evm_tx(session.mnemonic, JSON.stringify(txJson)));
      const hash = await rpc(evmChain.rpc, 'eth_sendRawTransaction', [raw]);
      return { id: hash, url: evmChain.explorer + hash };
    }
  };
}

// --- Solana prepare --------------------------------------------------------

async function prepareSolana(to, amount) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(to)) throw new Error('That is not a valid Solana address.');
  const lamports = toBaseUnits(amount, DECIMALS.solana);
  const res = await rpc(SOLANA_RPC, 'getLatestBlockhash', [{ commitment: 'finalized' }]);
  const recentBlockhash = res.value?.blockhash || res.blockhash;
  if (!recentBlockhash) throw new Error('Could not fetch a recent blockhash.');

  const txJson = { to, lamports: Number(lamports), recentBlockhash };
  return {
    chain: 'solana', to, amount,
    rows: [
      ['Network', 'Solana mainnet-beta'],
      ['Amount', `${amount} SOL`],
      ['To', short(to, 10, 8)],
      ['Fee', '~0.000005 SOL (network)']
    ],
    broadcast: async () => {
      // MPC committee (ed25519) reads `value` as string lamports; the local
      // signer takes lamports as a number — build both, route via signChainTx.
      const mpcTx = { to, value: String(lamports), recentBlockhash };
      const signed = await signChainTx('solana', mpcTx,
        () => wasm.sign_solana_transfer(session.mnemonic, JSON.stringify(txJson)));
      const sig = await rpc(SOLANA_RPC, 'sendTransaction', [signed, { encoding: 'base58' }]);
      return { id: sig, url: SOLANA_EXPLORER + sig };
    }
  };
}

// --- Bitcoin prepare -------------------------------------------------------

async function prepareBitcoin(to, amount) {
  const from = session.addresses.bitcoin;
  const amountSats = Number(toBaseUnits(amount, DECIMALS.bitcoin));
  if (amountSats <= 0) throw new Error('Enter a valid amount.');

  const [utxos, fees] = await Promise.all([
    httpJson(`${BTC_API}/address/${from}/utxo`),
    httpJson(`${BTC_API}/v1/fees/recommended`)
  ]);
  if (!Array.isArray(utxos) || utxos.length === 0) throw new Error('No spendable UTXOs at this address.');

  const feeRate = Math.max(1, Number(fees.halfHourFee || fees.hourFee || 1)); // sat/vB
  // Greedy selection over confirmed-first, largest-first UTXOs.
  const sorted = [...utxos].sort((a, b) => b.value - a.value);
  const DUST = 546;
  // vsize estimate for P2WPKH: ~68 vB/input, ~31 vB/output, ~11 vB overhead.
  const estFee = (nIn, nOut) => Math.ceil(feeRate * (nIn * 68 + nOut * 31 + 11));

  let picked = [], sum = 0, feeSats = 0, change = 0;
  for (const u of sorted) {
    picked.push(u); sum += u.value;
    feeSats = estFee(picked.length, 2);           // assume a change output
    change = sum - amountSats - feeSats;
    if (change >= 0) break;
  }
  if (change < 0) throw new Error('Insufficient funds after fees.');
  // If change would be dust, fold it into the fee and drop the change output.
  if (change < DUST) {
    feeSats = estFee(picked.length, 1);
    change = sum - amountSats - feeSats;
    if (change < 0) throw new Error('Insufficient funds after fees.');
    change = 0;
  }

  const txJson = {
    utxos: picked.map(u => ({ txid: u.txid, vout: u.vout, value: u.value })),
    to, amountSats, feeSats, changeAddress: from
  };

  return {
    chain: 'bitcoin', to, amount,
    rows: [
      ['Network', 'Bitcoin mainnet'],
      ['Amount', `${formatUnits(BigInt(amountSats), 8, 8)} BTC`],
      ['To', short(to, 10, 8)],
      ['Network fee', `${formatUnits(BigInt(feeSats), 8, 8)} BTC (${feeRate} sat/vB)`],
      ['Inputs', `${picked.length} UTXO${picked.length > 1 ? 's' : ''}`],
      ['Change', change ? `${formatUnits(BigInt(change), 8, 8)} BTC` : 'none']
    ],
    broadcast: async () => {
      // MPC committee (secp256k1) takes explicit inputs/outputs; omitting each
      // UTXO's script tells Rust to derive the account's own P2WPKH scriptPubKey
      // (self-spend). The local signer takes the higher-level txJson and does its
      // own selection. Route both via signChainTx.
      const outputs = [{ address: to, amount: amountSats }];
      if (change > 0) outputs.push({ address: from, amount: change });
      const mpcTx = {
        UTXOs: picked.map(u => ({ txid: u.txid, vout: u.vout, amount: u.value })),
        Outputs: outputs
      };
      const raw = await signChainTx('bitcoin', mpcTx,
        () => wasm.sign_bitcoin_tx(session.mnemonic, JSON.stringify(txJson)));
      const hex = (raw || '').replace(/^0x/, '');
      const txid = await httpText(`${BTC_API}/tx`, { method: 'POST', body: hex });
      return { id: txid.trim(), url: BTC_EXPLORER + txid.trim() };
    }
  };
}

// --- Confirm modal + broadcast --------------------------------------------

function confirmSend(p) {
  const rows = p.rows.map(([k, v]) => `<div class="kv"><span class="k">${k}</span><span class="v">${v}</span></div>`).join('');
  openModal(`
    <div class="card-pad stack" style="--gap:18px">
      <div class="eyebrow">Confirm · signed on this device</div>
      <h2 class="title">Review transaction</h2>
      <div class="panel" style="padding:4px 16px">${rows}</div>
      <div class="err-inline" id="confirmErr"></div>
      <div class="btn-row">
        <button class="btn subtle" type="button" data-close>Cancel</button>
        <button class="btn primary grow" type="button" id="confirmBroadcast">Sign &amp; broadcast</button>
      </div>
    </div>`);

  $('#confirmBroadcast').onclick = async () => {
    const btn = $('#confirmBroadcast');
    const cerr = $('#confirmErr');
    cerr.textContent = '';
    btn.disabled = true; btn.textContent = 'Broadcasting…';
    try {
      const { id, url } = await p.broadcast();
      closeModal();
      $('#sendTo').value = ''; $('#sendAmount').value = '';
      toast('ok', 'Transaction sent',
        `<a href="${url}" target="_blank" rel="noopener">${short(id, 14, 12)} ↗</a>`);
      setTimeout(refreshAllBalances, 2500);
    } catch (e) {
      cerr.textContent = e.message || String(e);
      btn.disabled = false; btn.textContent = 'Sign & broadcast';
    }
  };
}

// ============================================================================
// Reveal recovery phrase (re-confirm with password)
// ============================================================================

function openReveal() {
  openModal(`
    <div class="card-pad stack" style="--gap:16px">
      <div class="eyebrow" style="color:var(--warn)">Sensitive</div>
      <h2 class="title">Reveal recovery phrase</h2>
      <p class="subtitle">Confirm your password. Make sure nobody can see your screen.</p>
      <input class="input" id="revealPw" type="password" placeholder="Password" autocomplete="current-password" />
      <div class="err-inline" id="revealErr"></div>
      <div class="btn-row">
        <button class="btn subtle" type="button" data-close>Cancel</button>
        <button class="btn primary grow" type="button" id="revealGo">Reveal</button>
      </div>
    </div>`);
  setTimeout(() => $('#revealPw')?.focus(), 60);

  $('#revealGo').onclick = () => {
    const pw = $('#revealPw').value;
    const blob = localStorage.getItem(STORAGE.vault);
    let phrase;
    try { phrase = wasm.decrypt_blob(blob, pw); }
    catch { $('#revealErr').textContent = 'Wrong password.'; return; }
    showRevealed(phrase);
  };
}

function showRevealed(phrase) {
  const words = phrase.trim().split(/\s+/);
  const grid = words.map((w, i) =>
    `<div class="seed-word"><span class="n">${i + 1}</span><span class="w">${w}</span></div>`).join('');
  openModal(`
    <div class="card-pad stack" style="--gap:16px">
      <div class="eyebrow">Recovery phrase</div>
      <div class="panel warn" style="font-size:12.5px">Anyone with these words controls your funds. Never share or type them into a website.</div>
      <div class="seed-grid">${grid}</div>
      <div class="btn-row">
        <button class="btn ghost grow" type="button" id="revealCopy">Copy phrase</button>
        <button class="btn primary grow" type="button" data-close>Done</button>
      </div>
    </div>`);
  $('#revealCopy').onclick = () => copyText(phrase, $('#revealCopy'), 'Copy phrase');
}

// ============================================================================
// Modal + toast primitives
// ============================================================================

function openModal(html) {
  $('#modalBox').innerHTML = html;
  $('#modalScrim').classList.add('open');
}
function closeModal() {
  $('#modalScrim').classList.remove('open');
  $('#modalBox').innerHTML = '';
}

function toast(kind, title, detailHtml) {
  const t = el('div', `toast ${kind}`);
  const icon = kind === 'ok'
    ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
    : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 8v5m0 3h.01M12 3l9 16H3l9-16z" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  t.innerHTML = `<span class="ic">${icon}</span><div class="body"><div class="t">${title}</div>${detailHtml ? `<div class="d">${detailHtml}</div>` : ''}</div>`;
  $('#toasts').appendChild(t);
  setTimeout(() => { t.style.transition = 'opacity .4s, transform .4s'; t.style.opacity = '0'; t.style.transform = 'translateY(8px)'; setTimeout(() => t.remove(), 400); }, kind === 'error' ? 8000 : 6000);
}

// ============================================================================
// Number formatting (BigInt-based — no float drift)
// ============================================================================

// Decimal string → integer base units (BigInt). Throws on malformed input.
function toBaseUnits(amountStr, decimals) {
  const s = String(amountStr).trim();
  if (!/^\d*\.?\d*$/.test(s) || s === '' || s === '.') throw new Error('Invalid amount.');
  let [whole, frac = ''] = s.split('.');
  if (frac.length > decimals) throw new Error(`Too many decimal places (max ${decimals}).`);
  frac = frac.padEnd(decimals, '0');
  return BigInt((whole || '0') + frac);
}

// Integer base units (BigInt) → human decimal string, trimmed, capped display.
function formatUnits(units, decimals, maxFrac = 8) {
  const neg = units < 0n;
  let v = neg ? -units : units;
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  let frac = (v % base).toString().padStart(decimals, '0').slice(0, maxFrac).replace(/0+$/, '');
  const out = frac ? `${whole}.${frac}` : `${whole}`;
  return neg ? '-' + out : out;
}

// ============================================================================
// Network helpers
// ============================================================================

function withTimeout(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(t) };
}

// JSON-RPC 2.0 POST. Returns `result` or throws with the RPC error message.
async function rpc(url, method, params) {
  const to = withTimeout(RPC_TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: to.signal
    });
    if (!r.ok) throw new Error(`RPC HTTP ${r.status}`);
    const j = await r.json();
    if (j.error) throw new Error(j.error.message || 'RPC error');
    return j.result;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Network timed out.');
    throw e;
  } finally { to.done(); }
}

// REST GET → JSON (mempool.space).
async function httpJson(url) {
  const to = withTimeout(RPC_TIMEOUT_MS);
  try {
    const r = await fetch(url, { signal: to.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Network timed out.');
    throw e;
  } finally { to.done(); }
}

// REST request → text (mempool.space broadcast / raw responses).
async function httpText(url, opts = {}) {
  const to = withTimeout(RPC_TIMEOUT_MS);
  try {
    const r = await fetch(url, { ...opts, signal: to.signal });
    const text = await r.text();
    if (!r.ok) throw new Error(text || `HTTP ${r.status}`);
    return text;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Network timed out.');
    throw e;
  } finally { to.done(); }
}

// ============================================================================
// Clipboard
// ============================================================================

async function copyText(text, btn, restore) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for insecure contexts.
    const ta = el('textarea'); ta.value = text; document.body.appendChild(ta);
    ta.select(); try { document.execCommand('copy'); } catch {} ta.remove();
  }
  if (btn) {
    const label = btn.querySelector('svg') ? null : restore;
    btn.classList.add('done');
    const original = btn.innerHTML;
    if (btn.classList.contains('copy')) btn.innerHTML = btn.innerHTML.replace('Copy', 'Copied');
    else btn.textContent = 'Copied';
    setTimeout(() => { btn.classList.remove('done'); btn.innerHTML = original; if (label) btn.textContent = label; }, 1400);
  }
}

// ============================================================================
// Settings (EVM chain config)
// ============================================================================

function loadSettings() {
  try {
    const raw = localStorage.getItem(STORAGE.settings);
    if (raw) evmChain = { ...DEFAULT_EVM, ...JSON.parse(raw) };
  } catch { evmChain = { ...DEFAULT_EVM }; }
  fillSettingsForm();
}

function fillSettingsForm() {
  $('#setChainName').value = evmChain.name;
  $('#setChainId').value   = evmChain.chainId;
  $('#setRpc').value       = evmChain.rpc;
  $('#setExplorer').value  = evmChain.explorer;
}

function saveChain() {
  const next = {
    name:     $('#setChainName').value.trim() || 'EVM',
    chainId:  Number($('#setChainId').value.trim()) || 1,
    rpc:      $('#setRpc').value.trim(),
    explorer: $('#setExplorer').value.trim() || DEFAULT_EVM.explorer
  };
  if (!/^https?:\/\//.test(next.rpc)) { toast('error', 'Invalid RPC', 'Enter a full https:// endpoint.'); return; }
  evmChain = next;
  localStorage.setItem(STORAGE.settings, JSON.stringify(next));
  toast('ok', 'Network saved', `${next.name} · chain ${next.chainId}`);
  if (session.addresses) { onSendChainChange(); refreshAllBalances(); }
}

// ============================================================================
// Password strength (advisory only)
// ============================================================================

function scorePassword(pw) {
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 4); // 0..4
}
function renderStrength(pw) {
  const wrap = $('#strengthWrap');
  if (!pw) { wrap.hidden = true; return; }
  wrap.hidden = false;
  const score = scorePassword(pw);
  const pct = [8, 30, 55, 78, 100][score];
  const colors = ['#F0616D', '#F0616D', '#E7B44C', '#8E96FF', '#35C88E'];
  const notes  = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
  $('#strengthFill').style.width = pct + '%';
  $('#strengthFill').style.background = colors[score];
  $('#strengthNote').textContent = `${notes[score]}${pw.length < 8 ? ' · needs 8+ characters' : ''}`;
}

// ============================================================================
// Static event wiring
// ============================================================================

function wireStaticEvents() {
  // Topbar lock
  $('#btnLock').onclick = lock;

  // --- Onboarding: choose ---
  $$('#screen-onboarding [data-go]').forEach(b => b.onclick = () => {
    const go = b.dataset.go;
    onboardDraft.mnemonic = null; // fresh phrase each time create is entered
    goStep(go);
    if (go === 'import') setTimeout(() => $('#importPhrase').focus(), 60);
  });
  $$('#screen-onboarding [data-back]').forEach(b => b.onclick = () => goStep(b.dataset.back));

  // Developer entry: open the on-device MPC backend console (passkeys / TSS)
  // without first creating a walletcore wallet; and the way back.
  $('#openBackendConsole').onclick = openBackendConsole;
  $('#bkBackToSetup').onclick = () => { setConsoleMode(false); showScreen('onboarding'); goStep('choose'); };

  // --- Create: word count toggle ---
  $$('#wordCount button').forEach(b => b.onclick = () => {
    $$('#wordCount button').forEach(x => x.classList.remove('on'));
    b.classList.add('on');
    onboardDraft.words = Number(b.dataset.words);
    onboardDraft.mnemonic = null;
    renderSeed();
  });

  // --- Create: reveal cover ---
  const lift = () => $('#sealCover').classList.add('lifted');
  $('#sealCover').onclick = lift;
  $('#sealCover').onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); lift(); } };

  $('#copySeed').onclick  = () => copyText(onboardDraft.mnemonic || '', $('#copySeed'), 'Copy phrase');
  $('#regenSeed').onclick = () => { onboardDraft.mnemonic = null; renderSeed(); };
  $('#savedConfirm').onchange = e => $('#createContinue').disabled = !e.target.checked;
  $('#createContinue').onclick = () => goStep('password');

  // --- Import ---
  $('#importContinue').onclick = () => {
    const phrase = $('#importPhrase').value.trim().replace(/\s+/g, ' ').toLowerCase();
    const err = $('#importErr');
    err.textContent = '';
    if (!phrase) { err.textContent = 'Enter your recovery phrase.'; return; }
    let ok = false;
    try { ok = wasm.validate_mnemonic(phrase); } catch (e) { err.textContent = e.message || String(e); return; }
    if (!ok) { err.textContent = 'That phrase is not a valid BIP-39 mnemonic.'; return; }
    onboardDraft.mnemonic = phrase;
    goStep('password');
  };

  // --- Password step ---
  $('#pwNew').oninput = e => renderStrength(e.target.value);
  $('#finishSetup').onclick = finishSetup;
  $('#pwConfirm').onkeydown = e => { if (e.key === 'Enter') finishSetup(); };

  // Show/hide password toggles
  $$('[data-toggle]').forEach(b => b.onclick = () => {
    const input = $('#' + b.dataset.toggle);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    b.textContent = show ? 'Hide' : 'Show';
  });

  // --- Unlock ---
  $('#unlockForm').onsubmit = e => { e.preventDefault(); tryUnlock($('#pwUnlock').value); };
  $('#forgetFromUnlock').onclick = () => confirmRemove();

  // --- MPC unlock (on-device committee wallet) ---
  // The button handler runs WebAuthn directly in this click task (no setTimeout)
  // so the passkey derivation keeps its transient user activation.
  $('#mpcUnlockBtn').onclick = mpcUnlock;
  $('#mpcForget').onclick = mpcForget;
  $('#mpcUnlockPw').onkeydown = e => { if (e.key === 'Enter') mpcUnlock(); };

  // --- Dashboard: tabs ---
  $$('.tabs button').forEach(b => b.onclick = () => {
    $$('.tabs button').forEach(x => x.classList.remove('on'));
    b.classList.add('on');
    $$('.tabpane').forEach(p => p.classList.toggle('on', p.dataset.pane === b.dataset.tab));
    if (b.dataset.tab === 'backend') backendOpen();
  });

  wireBackendEvents();

  // --- Dashboard: accounts ---
  $('#refreshBalances').onclick = refreshAllBalances;
  $('#revealPhrase').onclick = openReveal;
  // MPC-backed dashboards forget the on-device committee record (its own
  // confirm + onboarding fallback); walletcore wallets clear the vault.
  $('#removeWallet').onclick = () => session.mpc ? mpcForget() : confirmRemove();

  // Copy buttons (event delegation for dynamically-rendered addresses)
  $('#assetList').addEventListener('click', e => {
    const btn = e.target.closest('[data-copy]');
    if (btn) copyText(btn.dataset.copy, btn);
  });

  // --- Dashboard: send ---
  $('#sendChain').onchange = onSendChainChange;
  $('#sendMax').onclick = fillMax;
  $('#sendSubmit').onclick = onSendSubmit;

  // --- Settings ---
  $('#saveChain').onclick = saveChain;
  $('#resetChain').onclick = () => { evmChain = { ...DEFAULT_EVM }; localStorage.removeItem(STORAGE.settings); fillSettingsForm(); toast('ok', 'Reset', 'EVM network set back to Ethereum mainnet.'); };

  // --- Modal dismiss ---
  $('#modalScrim').addEventListener('click', e => {
    if (e.target.id === 'modalScrim' || e.target.closest('[data-close]')) closeModal();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

// ============================================================================
// Backend demo — the REAL libwallet request API, running in-browser via WASM.
//
// This is fully additive and independent of the walletcore wallet above: it
// opens its own in-memory libwallet session (SQLite DB + TSS engine + handlers,
// all compiled to WASM) and drives it with the same {path,verb,params} request
// contract the Dart client uses. Nothing here touches the persistent vault.
//
// Request shapes below are mirrored from dart/lib/src/api/*.dart:
//   Info:version            → info_api.dart      version()
//   Wallet (POST)           → wallet_api.dart    create()  (1-of-3 committee)
//   Wallet (GET)            → wallet_api.dart    list()
//   Network (GET)           → network_api.dart   list()
//   Account (POST)          → account_api.dart   create()
//   Account/<id>:signMessage→ account_api.dart   signMessage()
// ============================================================================

const backend = {
  handle:   null,   // libwallet session handle (u32)
  ready:    false,
  wallet:   null,   // last created Wallet object (has .Keys for signing) — secp256k1 primary (EVM + BTC)
  walletEd: null,   // paired ed25519 Wallet from the same committee (Solana); set by Wallet:multiCreate
  password: null,   // share password for the created wallet (session-only)
  passkey:  null,   // {credentialId,salt} when the wallet's shares are passkey-PRF-sealed
  mpc: null,        // {credentialId,saltFirst,mode,saltSecond,password} for a passkey-2FA committee:
                    //   mode 'password' → [Password(prf.first), Password(password), RemoteKey]
                    //   mode 'passkey'  → [Password(prf.first), Password(prf.second), RemoteKey] (no password)
  accounts: [],     // derived Account objects
  clientId: null,   // configured Sec-ClientId (Info:setWalletInfo), for RemoteKey 2FA
  rk: {             // RemoteKey 2FA creation flow state
    session:  null, // session id from RemoteKey:new, consumed by RemoteKey:validate
    resource: null, // "crwsv-…" RemoteKey resource from RemoteKey:validate
    passkeyCredId: null // rawId of the passkey enrolled against this RemoteKey (reused for dual-PRF create)
  }
};

// Fixed Client ID (AtOnline appId) — the app registered on the server for this
// wallet's origin (karpeleslab.github.io). It selects the WalletSign 2FA
// email/SMS branding AND the WebAuthn RP-ID/origin the server issues, so passkey
// (Role B) verification only succeeds when the wallet is served from that
// origin. Applied automatically; NOT user-overridable.
const BK_CLIENT_ID = 'oaap-fz65wz-jaoj-b5hf-wonj-do54q5au';

// localStorage key for the persisted on-device MPC wallet. We store the
// backend's OWN encrypted backup blob (from Wallet:backup) — the committee
// shares stay sealed inside it exactly as the backend wrote them — plus the
// non-secret WebAuthn material (credentialId + PRF salts + mode) needed to
// re-derive the passkey secrets at unlock. The password is NEVER stored.
const BK_MPC_LS = 'libwallet.mpc.wallet';

// Persist the current backend wallet so it survives a reload. Backs it up via
// the backend's Wallet:backup (returns an ARRAY [{filename,data}]) and records
// the passkey material from backend.mpc (if any). No-ops without a wallet.
async function saveMpcWallet() {
  if (!backend.wallet) return;
  try {
    // Back up BOTH curves of the committee (secp256k1 primary + paired ed25519).
    const ids = [backend.wallet.Id, backend.walletEd?.Id].filter(Boolean);
    const wallets = [];
    for (const id of ids) {
      const arr = await backendRequest('Wallet:backup', 'POST', { Id: id });
      const entry = Array.isArray(arr) ? arr[0] : arr;
      if (entry && entry.data) wallets.push({ walletId: id, filename: entry.filename, data: entry.data });
    }
    if (!wallets.length) return;
    const rec = {
      wallets,                                  // [{walletId,filename,data}, …] — secp first, ed second
      primaryId: backend.wallet.Id,
      // Cache the derived on-chain addresses so unlock skips re-deriving. Set at
      // create time (session.addresses = await deriveMpcAddresses()) before this
      // runs; null-safe for any legacy caller that hasn't populated them.
      addresses: session.addresses || null,
      mpc: backend.mpc ? {
        credentialId: bufToB64url(backend.mpc.credentialId),
        saltFirst: bufToB64url(backend.mpc.saltFirst),
        saltSecond: backend.mpc.saltSecond ? bufToB64url(backend.mpc.saltSecond) : null,
        mode: backend.mpc.mode,
      } : null,
    };
    try { localStorage.setItem(BK_MPC_LS, JSON.stringify(rec)); } catch {}
  } catch (e) {
    // Persistence is best-effort; a backup failure must not break wallet create.
    bkLog('err', 'saveMpcWallet: ' + (e.message || e));
  }
}

// Read the persisted MPC record (or null if absent/corrupt).
function readMpcRecord() {
  try { return JSON.parse(localStorage.getItem(BK_MPC_LS)); }
  catch { return null; }
}

// Derive the committee's on-chain addresses (index 0) via Account:create. The
// secp256k1 wallet yields the EVM + Bitcoin addresses; the paired ed25519 wallet
// (if any) yields Solana. Account POST returns the created Account object with an
// .Address field (see backendCreateAccount / backendAccountCardHtml, which read
// a.Address). Deterministic for a given wallet + type + index.
async function deriveMpcAddresses() {
  const wid = backend.wallet.Id;
  const [evm, btc] = await Promise.all([
    backendRequest('Account', 'POST', { Name: '', Wallet: wid, Type: 'ethereum', Index: 0 }),
    backendRequest('Account', 'POST', { Name: '', Wallet: wid, Type: 'bitcoin', Index: 0 }),
  ]);
  let sol = null;
  if (backend.walletEd) sol = await backendRequest('Account', 'POST', { Name: '', Wallet: backend.walletEd.Id, Type: 'solana', Index: 0 });
  // Capture the created Account Ids alongside the addresses: committee send
  // (Account:signTransaction) needs the account Id. Deterministic per
  // wallet+type+index, so this is re-derivable on every unlock (not persisted).
  session.mpcAccounts = {
    evm:     { id: evm.Id, address: evm.Address },
    bitcoin: { id: btc.Id, address: btc.Address },
    solana:  sol ? { id: sol.Id, address: sol.Address } : null,
  };
  // session.accounts is the unified chain → {id, address} map used by balance
  // and preview (same shape for both wallet types); for MPC it is the committee
  // accounts, so balance/preview and committee send share the same account Ids.
  session.accounts = session.mpcAccounts;
  return { evm: evm.Address, bitcoin: btc.Address, solana: sol ? sol.Address : null };
}

// Enter the REAL dashboard (Accounts/Send/Settings) backed by the MPC committee.
// Reuses renderAccounts / refreshAllBalances by populating session.addresses —
// from the stored record when present, else derived live.
async function enterMpcDashboard() {
  session.mnemonic = null;      // MPC has no single mnemonic
  session.mpc = true;           // dashboard is backed by the MPC committee
  session.balances = {};
  const rec = readMpcRecord();
  // Always derive: this populates session.mpcAccounts (the Account Ids committee
  // send needs), which the cached record does not carry. Prefer the cached
  // addresses for render when present (identical values, saves nothing now but
  // keeps the fast-path contract), else use the freshly derived ones.
  const derived = await deriveMpcAddresses();
  session.addresses = (rec && rec.addresses) ? rec.addresses : derived;
  setConsoleMode(false);        // all wallet tabs visible
  applyMpcGuards();
  // Default to the Accounts tab.
  $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === 'accounts'));
  $$('.tabpane').forEach(p => p.classList.toggle('on', p.dataset.pane === 'accounts'));
  renderAccounts();
  onSendChainChange();
  showScreen('dashboard');
  refreshAllBalances();
}

// Guard the walletcore-only affordances for an MPC-backed session, and re-enable
// them for the walletcore path. Committee Send is a later pass, so it is disabled
// with an inline notice; the mnemonic-reveal control is hidden (no mnemonic);
// Remove-wallet routes to mpcForget.
function applyMpcGuards() {
  const mpc = !!session.mpc;
  // --- Send: committee send is wired for every chain via Account:signTransaction ---
  updateSendAvailability();
  // --- Settings: reveal recovery phrase is walletcore-only ---
  const reveal = $('#revealPhrase');
  if (reveal) reveal.classList.toggle('hidden', mpc);
}

// Enable/disable Send per chain. Committee send now works on every chain
// (EVM/Solana/Bitcoin) through the chain-agnostic Account:signTransaction, so
// nothing is blocked in either the MPC or walletcore path. Retained as the one
// hook that would gate a chain if a future network lacked offline signing.
function updateSendAvailability() {
  const blocked = false;
  const sendBtn = $('#sendSubmit');
  if (sendBtn) sendBtn.disabled = blocked;
  const notice = $('#sendMpcNotice');
  if (notice) notice.classList.toggle('hidden', !blocked);
}

// Prepare the MPC unlock screen for the stored wallet: password-mode wallets
// (and legacy plain-password wallets with no passkey material) show a password
// field; passkey-mode wallets hide it. Adjust the button copy accordingly.
function prepareMpcUnlock() {
  const rec = readMpcRecord();
  const pwRow = $('#mpcUnlockPwRow');
  const pw = $('#mpcUnlockPw');
  const btn = $('#mpcUnlockBtn');
  const err = $('#mpcUnlockErr');
  if (err) err.textContent = '';
  if (pw) pw.value = '';
  // rec.mpc null → a plain-password wallet (no passkey); rec.mpc.mode
  // 'password' → passkey seals share 1, a password seals share 2.
  const needsPw = !rec || !rec.mpc || rec.mpc.mode === 'password';
  const hasPasskey = !!(rec && rec.mpc);
  if (pwRow) pwRow.classList.toggle('hidden', !needsPw);
  if (pw) pw.disabled = !needsPw;
  if (btn) btn.textContent = hasPasskey ? 'Unlock with passkey' : 'Unlock';
}

// Restore + unlock the persisted MPC wallet. Wired to #mpcUnlockBtn and runs in
// the click task so WebAuthn keeps its transient user activation.
async function mpcUnlock() {
  const err = $('#mpcUnlockErr');
  const btn = $('#mpcUnlockBtn');
  err.textContent = '';
  const rec = readMpcRecord();
  if (!rec) { err.textContent = 'No stored wallet to unlock.'; return; }

  // Password-mode (and plain-password) wallets require a non-empty password
  // BEFORE we touch WebAuthn / the backend.
  const needsPw = !rec.mpc || rec.mpc.mode === 'password';
  const pwValue = $('#mpcUnlockPw').value || '';
  if (needsPw && !pwValue) { err.textContent = 'Enter your password.'; return; }

  btn.disabled = true; btn.textContent = 'Unlocking…';
  try {
    // 1. Ensure the backend session is open.
    if (backend.handle == null) backendOpen();
    // 2. Restore the sealed wallet blob(s) into the in-memory DB. Newer records
    //    hold BOTH curves in rec.wallets; older single-wallet records carry a
    //    top-level walletId/filename/data (backward compat).
    const wallets = rec.wallets || (rec.walletId ? [{ walletId: rec.walletId, filename: rec.filename, data: rec.data }] : []);
    const primaryId = rec.primaryId || rec.walletId;
    for (const wj of wallets) {
      await backendRequest('Wallet:restore', 'POST', { files: [{ filename: wj.filename, data: wj.data }] });
    }
    // 3. Load both restored wallet objects (each carries .Keys for signing).
    backend.wallet = await backendRequest('Wallet', 'GET', { Id: primaryId });
    const otherId = wallets.map(w => w.walletId).find(id => id && id !== primaryId);
    backend.walletEd = otherId ? await backendRequest('Wallet', 'GET', { Id: otherId }) : null;
    // 4. Rebuild the in-session unlock material from the record.
    backend.passkey = null;
    if (rec.mpc) {
      backend.mpc = {
        credentialId: new Uint8Array(b64urlToBuf(rec.mpc.credentialId)),
        saltFirst: new Uint8Array(b64urlToBuf(rec.mpc.saltFirst)),
        saltSecond: rec.mpc.saltSecond ? new Uint8Array(b64urlToBuf(rec.mpc.saltSecond)) : null,
        mode: rec.mpc.mode,
        password: (rec.mpc.mode === 'password' ? (pwValue || null) : null),
      };
      backend.password = null;
      // 5. Validate the unlock now so a wrong passkey/password fails clearly:
      //    derive the passkey secret(s) once (one biometric gesture). This is
      //    the same derivation signMessage uses, so success proves the passkey.
      try {
        await passkeyDeriveTwo(
          backend.mpc.credentialId,
          backend.mpc.saltFirst,
          backend.mpc.saltSecond ?? backend.mpc.saltFirst
        );
      } catch {
        throw new Error('Passkey/wallet unlock failed');
      }
    } else {
      // Plain-password wallet: no passkey material. Accept the password (it can
      // only be validated by actually signing).
      backend.mpc = null;
      backend.password = pwValue;
    }
    // 6. Reset derived accounts and surface the restored wallet in the console.
    backend.accounts = [];
    $('#bkAccountList').innerHTML = '';
    $('#bkCreateAccount').disabled = false;
    refreshSignAccounts();
    // Land in the real MPC dashboard (Accounts/Send/Settings), not the console.
    // Addresses come from the stored record, or are derived on the spot.
    await enterMpcDashboard();
    toast('ok', 'Wallet unlocked', 'Your on-device MPC wallet was restored and is ready to sign.');
  } catch (e) {
    err.textContent = e.message || String(e);
  } finally {
    btn.disabled = false;
    prepareMpcUnlock(); // restores the correct button label
  }
}

// Forget the persisted MPC wallet and fall back to onboarding.
function mpcForget() {
  if (!confirm('Forget this wallet on this device? You can only restore it from its backup or recovery material.')) return;
  localStorage.removeItem(BK_MPC_LS);
  backend.wallet = null;
  backend.walletEd = null;
  backend.mpc = null;
  // Clear any live MPC dashboard session too (when forgotten from the dashboard).
  session.mpc = false;
  session.mnemonic = null;
  session.addresses = null;
  session.balances = {};
  showScreen('onboarding');
  goStep('choose');
}

// UTF-8 string → standard base64 (for Account:signMessage Message param).
function b64utf8(str) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(str)));
}

function bkEsc(s) {
  return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function bkStatus(kind, text) {
  const pill = $('#bkStatus');
  pill.className = 'bk-status' + (kind ? ' ' + kind : '');
  $('#bkStatusText').textContent = text;
}

// Append one line to the event tape. kind ∈ req|res|evt|err.
function bkLog(kind, msg) {
  const log = $('#bkLog');
  const row = el('div', 'row ' + kind);
  const tag = { req: 'request', res: 'result', evt: 'event', err: 'error' }[kind] || kind;
  row.innerHTML = `<span class="tag">${tag}</span><span class="msg">${bkEsc(msg)}</span>`;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
  // Cap the tape so a long session doesn't grow unbounded.
  while (log.childElementCount > 200) log.removeChild(log.firstChild);
}

// Core call: serialise {path,verb,params}, dispatch (async), parse the
// envelope. Logs both sides to the tape. Throws on an error envelope.
async function backendRequest(path, verb = 'GET', params) {
  if (backend.handle == null) throw new Error('Backend session not initialised.');
  const reqObj = { path, verb };
  if (params !== undefined) reqObj.params = params;
  bkLog('req', `${verb} ${path}`);
  const raw = await wasm.libwallet_request(backend.handle, JSON.stringify(reqObj));
  let env;
  try { env = JSON.parse(raw); }
  catch { bkLog('err', 'unparseable response'); throw new Error('Backend returned invalid JSON.'); }
  if (env.result === 'error') {
    bkLog('err', `${env.code || ''} ${env.error || 'error'}`.trim());
    const e = new Error(env.error || 'Backend error'); e.code = env.code; throw e;
  }
  bkLog('res', `${path} · ${typeof env.data === 'object' ? 'ok' : String(env.data)}`);
  return env.data;
}

// Lazily open the session the first time the tab is shown.
function backendOpen() {
  if (backend.ready || backend.handle != null) return;
  try {
    backend.handle = wasm.libwallet_init();
  } catch (err) {
    bkStatus('err', 'init failed');
    bkLog('err', 'libwallet_init: ' + (err.message || err));
    return;
  }
  // Stream backend-emitted events (e.g. wallet:created) onto the tape.
  try {
    wasm.libwallet_set_event_callback(backend.handle, json => {
      let name = 'event';
      try { const e = JSON.parse(json); name = e.event || 'event'; } catch {}
      bkLog('evt', name + ' · ' + json);
    });
  } catch { /* callback wiring is best-effort */ }

  backend.ready = true;
  bkStatus('live', 'session #' + backend.handle);
  bkLog('evt', 'session opened · in-memory DB');

  // Prove the real backend answers, then show the seeded state.
  loadBackendVersion();
  backendListNetworks();
  backendListWallets();

  // Apply the fixed Tibane Client ID (Info:setWalletInfo). Not overridable.
  applyClientId();
}

// Reflect whether a Client ID is configured (gates the RemoteKey 2FA flow).
function bkClientIdState(set) {
  const pill = $('#bkClientIdState');
  pill.className = 'bk-status' + (set ? ' live' : '');
  $('#bkClientIdStateText').textContent = set ? 'set' : 'not set';
  $('#bkRkSend').disabled = !set;
}

// Info:setWalletInfo {ClientId} — register the fixed Tibane Client ID (it
// selects the WalletSign 2FA branding). Not user-overridable.
async function applyClientId() {
  const err = $('#bkClientIdErr');
  err.textContent = '';
  try {
    await backendRequest('Info:setWalletInfo', 'POST', { ClientId: BK_CLIENT_ID });
    backend.clientId = BK_CLIENT_ID;
    bkClientIdState(true);
  } catch (e) {
    err.textContent = e.message || String(e);
    bkClientIdState(false);
  }
}

// Step 1 — RemoteKey:new {email|number}: start a 2FA session. Routes SMS vs
// email on whether the value contains '@'.
async function backendRkSend() {
  const err = $('#bkRkErr');
  err.textContent = '';
  if (!backend.clientId) { err.textContent = 'Set a Client ID above first.'; return; }
  const target = $('#bkRkTarget').value.trim();
  if (!target) { err.textContent = 'Enter an email or phone number.'; return; }
  const params = target.includes('@') ? { email: target } : { number: target };
  const btn = $('#bkRkSend');
  btn.disabled = true; btn.textContent = 'Sending…';
  bkStatus('busy', 'RemoteKey:new…');
  try {
    const data = await backendRequest('RemoteKey:new', 'POST', params);
    // The WalletSign backend owns the response shape; the session identifier is
    // passed verbatim to validate. Be forgiving about its exact key.
    backend.rk.session = (data && (data.session ?? data.Session)) ?? data;
    $('#bkRkStep2').classList.remove('hidden');
    bkStatus('live', 'code sent · #' + backend.handle);
    toast('ok', 'Code sent', 'Enter the verification code you received.');
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'RemoteKey:new failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Send code';
  }
}

// Step 2 — RemoteKey:validate {session, code}: verify the 2FA code. On success
// the response carries {RemoteKey: "crws-…:crwsv-…"}.
async function backendRkVerify() {
  const err = $('#bkRkErr');
  err.textContent = '';
  if (!backend.rk.session) { err.textContent = 'Request a code first.'; return; }
  const code = $('#bkRkCode').value.trim();
  if (!code) { err.textContent = 'Enter the verification code.'; return; }
  const btn = $('#bkRkVerify');
  btn.disabled = true; btn.textContent = 'Verifying…';
  bkStatus('busy', 'RemoteKey:validate…');
  try {
    const data = await backendRequest('RemoteKey:validate', 'POST', { session: backend.rk.session, code });
    const resource = (data && (data.RemoteKey ?? data.remoteKey)) ?? data;
    if (!resource) throw new Error('No RemoteKey in response.');
    backend.rk.resource = resource;
    $('#bkRkStep3').classList.remove('hidden');
    bkStatus('live', '2FA verified · #' + backend.handle);
    toast('ok', '2FA verified', 'RemoteKey issued — name your wallet and create it.');
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'RemoteKey:validate failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Verify';
  }
}

// Step 3 — Wallet POST with two local Password shares + one RemoteKey share.
async function backendRkCreate() {
  const err = $('#bkRkErr');
  err.textContent = '';
  if (!backend.rk.resource) { err.textContent = 'Verify the 2FA code first.'; return; }
  const name = $('#bkRkName').value.trim() || 'Browser 2FA wallet';
  const pw = $('#bkRkPw').value;
  if (pw.length < 6) { err.textContent = 'Password must be at least 6 characters.'; return; }
  const btn = $('#bkRkCreate');
  btn.disabled = true; btn.textContent = 'Running keygen…';
  bkStatus('busy', 'TSS keygen (2FA)…');
  // Defer so the button state paints before the local keygen work.
  setTimeout(async () => {
    try {
      const keys = [
        { Type: 'Password',  Key: pw },
        { Type: 'Password',  Key: pw },
        { Type: 'RemoteKey', Key: backend.rk.resource }
      ];
      // multiCreate builds a PAIR of committees (secp256k1 + ed25519) from the
      // SAME key shares — one committee, two curves (EVM/BTC + Solana).
      const pair = await backendRequest('Wallet:multiCreate', 'POST', { Name: name, Keys: keys });
      const w = pair.secp256k1 ?? pair.Secp256k1;
      const wEd = pair.ed25519 ?? pair.Ed25519;
      backend.wallet = w;
      backend.walletEd = wEd || null;
      backend.password = pw;
      backend.accounts = [];
      $('#bkAccountList').innerHTML = '';
      $('#bkCreateAccount').disabled = false;
      refreshSignAccounts();

      bkStatus('live', '2FA wallet created · #' + backend.handle);
      toast('ok', '2FA wallet created', 'Self-custody wallet with a server-held RemoteKey share.');
      backendListWallets();
      // Derive addresses BEFORE the backup so the record captures them, then land
      // in the real MPC dashboard (not the Backend console).
      session.addresses = await deriveMpcAddresses();
      await saveMpcWallet();
      await enterMpcDashboard();
    } catch (e) {
      err.textContent = e.message || String(e);
      bkStatus('err', '2FA keygen failed');
    } finally {
      btn.disabled = false; btn.textContent = 'Create wallet';
    }
  }, 30);
}

// Step 3 (passkey) — build a three-factor committee sealed by ONE passkey plus
// the verified RemoteKey. DEFAULT (three distinct factors):
//   [Password(prf.first), Password(<entered password>), RemoteKey(resource)]
// OPT-OUT ("No password", #bkRkNoPassword checked, weaker):
//   [Password(prf.first), Password(prf.second), RemoteKey(resource)]
// where prf.first/second come from one biometric (two distinct PRF salts). The
// RemoteKey (from the 2FA verify) authorizes the server-held share. All WebAuthn
// runs directly in this click task (no setTimeout).
async function backendRkCreatePasskey() {
  const err = $('#bkRkErr');
  err.textContent = '';
  if (!passkeyAvailable()) { err.textContent = 'Passkeys are unavailable in this browser.'; return; }
  if (!backend.rk.resource) { err.textContent = 'Verify the 2FA first.'; return; }
  const name = $('#bkRkName').value.trim() || 'Browser 2FA wallet';
  const noPassword = !!($('#bkRkNoPassword') && $('#bkRkNoPassword').checked);
  const pw = $('#bkRkPw').value;
  if (!noPassword && pw.length < 6) { err.textContent = 'Password must be at least 6 characters (or check “No password”).'; return; }
  const btn = $('#bkRkCreatePasskey');
  btn.disabled = true; btn.textContent = 'Waiting for passkey…';
  bkStatus('busy', 'passkey keygen (2FA)…');
  try {
    // Reuse the passkey enrolled against this RemoteKey; if the user never
    // enrolled one, register a fresh PRF-capable passkey now.
    let credId = backend.rk.passkeyCredId;
    if (!credId) credId = await passkeyRegisterLocal(name);
    // Share 1 is always the passkey's prf.first (one biometric gesture).
    const saltFirst = bkRandBytes(32);
    let secret1Hex, secret2Hex, saltSecond = null;
    if (noPassword) {
      // Weaker: both local shares from the same passkey, two distinct salts.
      saltSecond = bkRandBytes(32);
      ({ secret1Hex, secret2Hex } = await passkeyDeriveTwo(credId, saltFirst, saltSecond));
    } else {
      // Default: passkey seals share 1, the entered password seals share 2.
      ({ secret1Hex } = await passkeyDeriveTwo(credId, saltFirst, saltFirst));
    }
    btn.textContent = 'Running keygen…'; bkStatus('busy', 'TSS keygen (2FA)…');
    const share2Key = noPassword ? secret2Hex : pw;
    const keys = [
      { Type: 'Password',  Key: secret1Hex },
      { Type: 'Password',  Key: share2Key },
      { Type: 'RemoteKey', Key: backend.rk.resource }
    ];
    // multiCreate builds a PAIR of committees (secp256k1 + ed25519) from the
    // SAME key shares — one committee, two curves (EVM/BTC + Solana).
    const pair = await backendRequest('Wallet:multiCreate', 'POST', { Name: name, Keys: keys });
    const w = pair.secp256k1 ?? pair.Secp256k1;
    const wEd = pair.ed25519 ?? pair.Ed25519;
    backend.wallet = w;
    backend.walletEd = wEd || null;
    backend.password = null;
    backend.passkey = null;
    // Keep the credential, salt(s) and (for the default) the password so signing
    // can re-derive both local-share secrets.
    backend.mpc = {
      credentialId: credId,
      saltFirst,
      mode: noPassword ? 'passkey' : 'password',
      saltSecond: noPassword ? saltSecond : null,
      password: noPassword ? null : pw
    };
    backend.accounts = [];
    $('#bkAccountList').innerHTML = '';
    $('#bkCreateAccount').disabled = false;
    refreshSignAccounts();

    bkStatus('live', '2FA wallet created · #' + backend.handle);
    toast('ok', 'Passkey 2FA wallet created', noPassword
      ? 'One passkey seals two local shares; a server-held RemoteKey is the third.'
      : 'Passkey + password + RemoteKey — three distinct factors.');
    backendListWallets();
    // Derive addresses BEFORE the backup so the record captures them, then land
    // in the real MPC dashboard (not the Backend console).
    session.addresses = await deriveMpcAddresses();
    await saveMpcWallet();
    await enterMpcDashboard();
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'passkey 2FA keygen failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Create with passkey (2 shares + RemoteKey)';
  }
}

// Passkey verify — a drop-in for the code path (steps 1+2) at the SAME target.
// RemoteKey:new{verify:'passkey'} → passkeyAuthBegin → credentials.get →
// passkeyAuthFinish → the same {RemoteKey:"crws-…:crwsv-…"} resource. All the
// WebAuthn calls run directly in this click task (user activation, no setTimeout).
async function backendRkPasskeyVerify() {
  const err = $('#bkRkErr');
  err.textContent = '';
  if (!passkeyAvailable()) { err.textContent = 'Passkeys are unavailable in this browser.'; return; }
  if (!backend.clientId) { err.textContent = 'Set a Client ID above first.'; return; }
  const target = $('#bkRkTarget').value.trim();
  if (!target) { err.textContent = 'Enter an email or phone number.'; return; }
  const btn = $('#bkRkPasskeyVerify');
  btn.disabled = true; btn.textContent = 'Waiting for passkey…';
  bkStatus('busy', 'passkey verify…');
  try {
    const params = target.includes('@') ? { email: target } : { number: target };
    params.verify = 'passkey';
    const s = await backendRequest('RemoteKey:new', 'POST', params);
    const session = (s && (s.session ?? s.Session)) ?? s;
    backend.rk.session = session;

    const beginData = await backendRequest('RemoteKey:passkeyAuthBegin', 'POST', { session });
    const asr = await navigator.credentials.get({ publicKey: decodeRequestOptions(beginData.publicKey ?? beginData) });

    const fin = await backendRequest('RemoteKey:passkeyAuthFinish', 'POST', {
      session, id: asr.id,
      clientDataJSON: bufToB64url(asr.response.clientDataJSON),
      authenticatorData: bufToB64url(asr.response.authenticatorData),
      signature: bufToB64url(asr.response.signature),
      userHandle: asr.response.userHandle ? bufToB64url(asr.response.userHandle) : undefined
    });
    const resource = (fin && (fin.RemoteKey ?? fin.remoteKey)) ?? fin;
    if (!resource) throw new Error('No RemoteKey in response.');
    backend.rk.resource = resource;

    $('#bkRkStep3').classList.remove('hidden');   // skip the code step
    bkStatus('live', '2FA verified · #' + backend.handle);
    toast('ok', 'Verified with passkey', 'RemoteKey issued — name your wallet and create it.');
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'passkey verify failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Use passkey';
  }
}

// Enroll a passkey for a just-verified RemoteKey (crwsv from a code verify), so
// future logins can skip the code. RemoteKey:passkeyRegisterBegin →
// credentials.create → passkeyRegisterFinish. Runs in the click task.
async function backendRkEnrollPasskey() {
  const err = $('#bkRkErr');
  err.textContent = '';
  if (!passkeyAvailable()) { err.textContent = 'Passkeys are unavailable in this browser.'; return; }
  if (!backend.rk.resource) { err.textContent = 'Verify by code once first, then enroll a passkey.'; return; }
  const btn = $('#bkRkEnroll');
  btn.disabled = true; btn.textContent = 'Waiting for passkey…';
  bkStatus('busy', 'passkey enroll…');
  try {
    const beginData = await backendRequest('RemoteKey:passkeyRegisterBegin', 'POST', { key: backend.rk.resource });
    const cred = await navigator.credentials.create({ publicKey: decodeCreationOptions(beginData.publicKey ?? beginData) });
    await backendRequest('RemoteKey:passkeyRegisterFinish', 'POST', {
      key: backend.rk.resource, id: cred.id,
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      attestationObject: bufToB64url(cred.response.attestationObject),
      transports: cred.response.getTransports?.()
    });
    // Remember this credential so "Create with passkey" can reuse the SAME
    // (PRF-capable) passkey to seal the two local shares.
    backend.rk.passkeyCredId = new Uint8Array(cred.rawId);
    bkStatus('live', 'passkey enrolled · #' + backend.handle);
    toast('ok', 'Passkey enrolled', 'Next time verify with your device, no code.');
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'passkey enroll failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Enroll a passkey (skip the code next time)';
  }
}

// Spot:status — start the in-browser spotlib client and report whether it has
// connected to the KLB Spot relay. Sync backend call; the connection completes
// on the browser event loop, so a first check may read offline — check again.
async function backendSpotStatus() {
  const err = $('#bkSpotErr');
  const out = $('#bkSpotOut');
  const pill = $('#bkSpotStateText');
  err.textContent = '';
  const btn = $('#bkSpotStatus');
  btn.disabled = true; btn.textContent = 'Checking…';
  try {
    const s = await backendRequest('Spot:status', 'GET');
    const online = !!s.online;
    pill.textContent = online ? 'online' : 'connecting…';
    out.classList.remove('hidden');
    out.innerHTML = `
      <div class="kv"><span class="k">Online</span><span class="v">${online ? 'yes' : 'not yet'}</span></div>
      <div class="kv"><span class="k">Target id</span><span class="v mono">${bkEsc(s.target_id || '')}</span></div>
      <div class="kv"><span class="k">Connections</span><span class="v">${(s.connections && s.connections.online) || 0} / ${(s.connections && s.connections.total) || 0}</span></div>`;
  } catch (e) {
    pill.textContent = 'error';
    err.textContent = e.message || String(e);
  } finally {
    btn.disabled = false; btn.textContent = 'Check Spot status';
  }
}

// Experimental — Wallet:initiateKeygen: leader-side distributed FROST keygen
// over the KLB Spot network. Real multi-party ceremony; needs the live fleet and
// a paired agent/wdrone or it times out. Peers come from Crypto/WalletSign:newAgent.
async function backendInitiateKeygen() {
  const err = $('#bkAkErr');
  const out = $('#bkAkOut');
  err.textContent = '';
  const remote_key = $('#bkAkRemoteKey').value.trim();
  const name = $('#bkAkName').value.trim() || 'Agent wallet';
  const me_moniker = $('#bkAkMoniker').value.trim();
  let peers;
  try {
    peers = JSON.parse($('#bkAkPeers').value);
  } catch (e) {
    err.textContent = 'Peers JSON: ' + (e.message || String(e));
    return;
  }
  if (!remote_key) { err.textContent = 'Enter a RemoteKey.'; return; }
  if (!Array.isArray(peers) || peers.length === 0) { err.textContent = 'Peers must be a non-empty JSON array.'; return; }
  const btn = $('#bkAkRun');
  btn.disabled = true; btn.textContent = 'Running keygen…';
  bkStatus('busy', 'keygen ceremony…');
  try {
    const data = await backendRequest('Wallet:initiateKeygen', 'POST', {
      remote_key, name, curve: 'ed25519', me_moniker, peers
    });
    out.classList.remove('hidden');
    out.innerHTML = `
      <div class="panel" style="padding:4px 16px">
        <div class="kv"><span class="k">Wallet id</span><span class="v">${bkEsc(data.wlt_id || '')}</span></div>
        <div class="kv"><span class="k">Solana</span><span class="v">${bkEsc(data.solana_address || '')}</span></div>
        <div class="kv"><span class="k">Pubkey</span><span class="v">${bkEsc(data.pubkey || '')}</span></div>
      </div>`;
    bkStatus('live', 'keygen done · #' + backend.handle);
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'keygen failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Run keygen';
  }
}

// Experimental — Wallet:joinSign: joiner-side distributed FROST signature over the
// KLB Spot network. Same live-fleet requirement as initiateKeygen.
async function backendJoinSign() {
  const err = $('#bkAsErr');
  const out = $('#bkAsOut');
  err.textContent = '';
  const wlt_id = $('#bkAsWallet').value.trim();
  const remote_key = $('#bkAsRemoteKey').value.trim();
  const digest = $('#bkAsDigest').value.trim();
  let peers;
  try {
    peers = JSON.parse($('#bkAsPeers').value);
  } catch (e) {
    err.textContent = 'Peers JSON: ' + (e.message || String(e));
    return;
  }
  if (!wlt_id) { err.textContent = 'Enter a wallet id.'; return; }
  if (!remote_key) { err.textContent = 'Enter a RemoteKey.'; return; }
  if (!digest) { err.textContent = 'Enter a digest.'; return; }
  if (!Array.isArray(peers) || peers.length === 0) { err.textContent = 'Peers must be a non-empty JSON array.'; return; }
  const btn = $('#bkAsRun');
  btn.disabled = true; btn.textContent = 'Running sign…';
  bkStatus('busy', 'sign ceremony…');
  try {
    const data = await backendRequest('Wallet:joinSign', 'POST', {
      wlt_id, remote_key, curve: 'ed25519', digest, peers
    });
    out.classList.remove('hidden');
    out.innerHTML = `
      <div class="panel" style="padding:4px 16px">
        <div class="kv"><span class="k">Signature</span><span class="v mono">${bkEsc(data.signature || '')}</span></div>
      </div>`;
    bkStatus('live', 'sign done · #' + backend.handle);
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'sign failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Run sign';
  }
}

async function loadBackendVersion() {
  try {
    const v = await backendRequest('Info:version', 'GET');
    const rows = [
      ['version', v.version || '(dev build — untagged)'],
      ['gitTag', v.gitTag || '—'],
      ['dateTag', v.dateTag || '—']
    ];
    $('#bkVersion').innerHTML = rows
      .map(([k, val]) => `<div class="kv"><span class="k">${k}</span><span class="v">${bkEsc(val)}</span></div>`)
      .join('');
    bkStatus('live', 'Info:version ✓ · #' + backend.handle);
  } catch (e) {
    $('#bkVersion').innerHTML = `<div class="kv"><span class="k">Info:version failed</span><span class="v">${bkEsc(e.message)}</span></div>`;
  }
}

async function backendListNetworks() {
  try {
    const nets = await backendRequest('Network', 'GET') || [];
    $('#bkNetworks').textContent = nets.length
      ? nets.map(n => `${(n.Type || '').padEnd(8)} ${(n.ChainId || '').padEnd(14)} ${n.Name || ''}  ${n.CurrencySymbol || ''}${n.TestNet ? '  · testnet' : ''}`).join('\n')
      : '(no networks)';
  } catch (e) {
    $('#bkNetworks').textContent = 'Network list failed: ' + e.message;
  }
}

async function backendListWallets() {
  const list = $('#bkWalletList');
  try {
    const wallets = await backendRequest('Wallet', 'GET') || [];
    if (!wallets.length) { list.innerHTML = `<p class="subtitle">No wallets yet — generate one above.</p>`; return; }
    list.innerHTML = wallets.map(w => backendWalletCardHtml(w)).join('');
  } catch (e) {
    list.innerHTML = `<p class="err-inline">Wallet list failed: ${bkEsc(e.message)}</p>`;
  }
}

function backendWalletCardHtml(w) {
  return `
    <div class="asset" data-chain="evm">
      <div class="asset-head">
        <div class="asset-name">
          <span class="chain-badge">W</span>
          <span class="meta"><span class="n">${bkEsc(w.Name || 'Wallet')}</span><br><span class="t">${bkEsc(w.Curve || '')} · ${bkEsc(w.Protocol || '')} · ${w.Threshold + 1}-of-${(w.Keys || []).length}</span></span>
        </div>
      </div>
      <div class="panel" style="padding:4px 16px">
        <div class="kv"><span class="k">Id</span><span class="v">${bkEsc(w.Id)}</span></div>
        <div class="kv"><span class="k">Pubkey</span><span class="v">${bkEsc(short(w.Pubkey || '', 14, 12))}</span></div>
        <div class="kv"><span class="k">Key shares</span><span class="v">${(w.Keys || []).map(k => k.Type).join(' · ')}</span></div>
      </div>
    </div>`;
}

// ── Passkey device share (WebAuthn PRF) ──────────────────────────────────────
// A passkey's PRF extension returns a stable 32-byte secret, gated by a
// biometric/PIN user-verification gesture and never leaving the authenticator.
// We use hex(that secret) as the committee's share password (Type:Password), so
// the device-custody share is passwordless + hardware-backed, and re-derived per
// signature. NOTE: navigator.credentials.create/get need transient user
// activation, so they must run directly in the click task (no setTimeout).

const PASSKEY_RP_NAME = 'Tibane Wallet';

function passkeyAvailable() {
  return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
}
function bkRandBytes(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function bkBufToHex(buf) { return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join(''); }

// --- WebAuthn base64url codec + server-JSON option marshalling -------------
// The RemoteKey passkey proxies exchange WebAuthn options/responses as JSON with
// binary fields base64url-encoded; navigator.credentials wants ArrayBuffers.
function b64urlToBuf(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s + pad);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b.buffer;
}
function bufToB64url(buf) {
  const b = new Uint8Array(buf); let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
// Turn the server's *JSON* options into real WebAuthn options (ArrayBuffers).
// Prefer the native parsers when present; else decode the known binary fields.
function decodeCreationOptions(o) {
  if (window.PublicKeyCredential?.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  const opts = { ...o, challenge: b64urlToBuf(o.challenge), user: { ...o.user, id: b64urlToBuf(o.user.id) } };
  if (Array.isArray(o.excludeCredentials)) opts.excludeCredentials = o.excludeCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
  return opts;
}
function decodeRequestOptions(o) {
  if (window.PublicKeyCredential?.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  const opts = { ...o, challenge: b64urlToBuf(o.challenge) };
  if (Array.isArray(o.allowCredentials)) opts.allowCredentials = o.allowCredentials.map(c => ({ ...c, id: b64urlToBuf(c.id) }));
  return opts;
}

// Register a new passkey with PRF enabled, then derive its secret for a fresh
// salt. Returns {credentialId:Uint8Array, salt:Uint8Array, secretHex}. Throws if
// the platform/authenticator can't do PRF (caller falls back to a password).
async function passkeyCreateAndDerive(walletName) {
  const salt = bkRandBytes(32);
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: PASSKEY_RP_NAME, id: location.hostname },
    user: { id: bkRandBytes(16), name: walletName || 'wallet', displayName: walletName || 'wallet' },
    challenge: bkRandBytes(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    timeout: 60000,
    extensions: { prf: {} },
  }});
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || ext.prf.enabled === false) {
    throw new Error('This device/browser has no passkey PRF support — use a password.');
  }
  const secretHex = await passkeyDerive(cred.rawId, salt);
  return { credentialId: new Uint8Array(cred.rawId), salt, secretHex };
}

// Derive the PRF secret for an existing credential + salt (biometric gesture).
async function passkeyDerive(credentialId, salt) {
  const assertion = await navigator.credentials.get({ publicKey: {
    challenge: bkRandBytes(32),
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required',
    timeout: 60000,
    extensions: { prf: { eval: { first: salt } } },
  }});
  const prf = assertion.getClientExtensionResults()?.prf?.results?.first;
  if (!prf) throw new Error('Passkey did not return a PRF secret (unsupported here).');
  return bkBufToHex(prf);
}

// Derive TWO PRF secrets from one credential in a single user-verification
// gesture (prf.eval {first, second}). Returns { secret1Hex, secret2Hex }.
async function passkeyDeriveTwo(credentialId, salt1, salt2) {
  const asr = await navigator.credentials.get({ publicKey: {
    challenge: bkRandBytes(32),
    allowCredentials: [{ type: 'public-key', id: credentialId }],
    userVerification: 'required',
    timeout: 60000,
    extensions: { prf: { eval: { first: salt1, second: salt2 } } },
  }});
  const r = asr.getClientExtensionResults()?.prf?.results;
  if (!r?.first || !r?.second) throw new Error('Passkey did not return two PRF secrets (unsupported here).');
  return { secret1Hex: bkBufToHex(r.first), secret2Hex: bkBufToHex(r.second) };
}
// Register a passkey with PRF enabled and return its rawId (Uint8Array). Used
// when the user hasn't enrolled one for the RemoteKey yet.
async function passkeyRegisterLocal(name) {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { name: PASSKEY_RP_NAME, id: location.hostname },
    user: { id: bkRandBytes(16), name: name || 'wallet', displayName: name || 'wallet' },
    challenge: bkRandBytes(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
    authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
    timeout: 60000, extensions: { prf: {} },
  }});
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || ext.prf.enabled === false) throw new Error('This device/browser has no passkey PRF support.');
  return new Uint8Array(cred.rawId);
}

async function backendCreateWallet() {
  const name = $('#bkWalletName').value.trim() || 'Browser TSS wallet';
  const usePasskey = !!($('#bkPasskey') && $('#bkPasskey').checked);
  const pw = $('#bkWalletPw').value;
  const err = $('#bkWalletErr');
  err.textContent = '';
  if (!usePasskey && pw.length < 4) { err.textContent = 'Enter a share password (4+ characters).'; return; }

  const btn = $('#bkCreateWallet');
  btn.disabled = true;
  try {
    // The device share's secret: the passkey PRF (biometric) or the password.
    let shareSecret = pw;
    let passkey = null;
    if (usePasskey) {
      btn.textContent = 'Waiting for passkey…'; bkStatus('busy', 'passkey…');
      const pk = await passkeyCreateAndDerive(name);        // must be in this click task
      shareSecret = pk.secretHex;
      passkey = { credentialId: pk.credentialId, salt: pk.salt };
    }
    btn.textContent = 'Running keygen…'; bkStatus('busy', 'TSS keygen…');
    // A modern TSS wallet is inherently multi-party: the backend mandates a
    // ≥3-share committee (threshold 1 → 1-of-3). Three local Password shares
    // sealed with the same secret (password, or the passkey PRF output) — an
    // all-local, server-free committee.
    const keys = [
      { Type: 'Password', Key: shareSecret },
      { Type: 'Password', Key: shareSecret },
      { Type: 'Password', Key: shareSecret },
    ];
    // multiCreate builds a PAIR of committees (secp256k1 + ed25519) from the
    // SAME key shares — one committee, two curves (EVM/BTC + Solana).
    const pair = await backendRequest('Wallet:multiCreate', 'POST', { Name: name, Keys: keys });
    const w = pair.secp256k1 ?? pair.Secp256k1;
    const wEd = pair.ed25519 ?? pair.Ed25519;
    backend.wallet = w;
    backend.walletEd = wEd || null;
    backend.password = usePasskey ? null : pw;
    backend.passkey = passkey;
    backend.accounts = [];
    $('#bkAccountList').innerHTML = '';
    $('#bkCreateAccount').disabled = false;
    refreshSignAccounts();

    bkStatus('live', 'wallet created · #' + backend.handle);
    toast('ok', usePasskey ? 'Passkey wallet created' : 'Real wallet created',
      usePasskey
        ? 'Shares sealed with your device passkey (WebAuthn PRF) — no password.'
        : 'TSS keygen ran in your browser (' + w.Curve + ' / ' + w.Protocol + ').');
    backendListWallets();
    // Derive addresses BEFORE the backup so the record captures them, then land
    // in the real MPC dashboard (not the Backend console).
    session.addresses = await deriveMpcAddresses();
    await saveMpcWallet();
    await enterMpcDashboard();
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', usePasskey ? 'passkey/keygen failed' : 'keygen failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Generate wallet';
  }
}

async function backendCreateAccount() {
  const err = $('#bkAccountErr');
  err.textContent = '';
  if (!backend.wallet) { err.textContent = 'Create a wallet first.'; return; }
  const type = $('#bkAccountType').value;
  const index = backend.accounts.filter(a => a.Type === type).length;
  try {
    const a = await backendRequest('Account', 'POST', {
      Name: '', Wallet: backend.wallet.Id, Type: type, Index: index
    });
    backend.accounts.push(a);
    $('#bkAccountList').insertAdjacentHTML('beforeend', backendAccountCardHtml(a));
    refreshSignAccounts();
    toast('ok', 'Address derived', `${type} · ${short(a.Address, 8, 8)}`);
  } catch (e) {
    err.textContent = e.message || String(e);
  }
}

function backendAccountCardHtml(a) {
  const chain = a.Type === 'ethereum' ? 'evm' : (a.Type === 'solana' ? 'solana' : 'bitcoin');
  const badge = a.Type === 'ethereum' ? 'Ξ' : (a.Type === 'solana' ? '◎' : '₿');
  return `
    <div class="asset" data-chain="${chain}">
      <div class="asset-head">
        <div class="asset-name">
          <span class="chain-badge">${badge}</span>
          <span class="meta"><span class="n">${bkEsc(a.Name || a.Type)}</span><br><span class="t">${bkEsc(a.Type)} · ${bkEsc(a.Path || '')}</span></span>
        </div>
      </div>
      <div class="addr-row">
        <span class="addr" title="${bkEsc(a.Address)}">${bkEsc(a.Address)}</span>
        <button class="copy" type="button" data-copy="${bkEsc(a.Address)}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M5 15V5a2 2 0 012-2h10" stroke="currentColor" stroke-width="1.8"/></svg>
          Copy
        </button>
      </div>
    </div>`;
}

// Only Ethereum (secp256k1 EIP-191) accounts are offered for signMessage —
// the personal_sign path returns a clean 0x signature.
function refreshSignAccounts() {
  const sel = $('#bkSignAccount');
  const signable = backend.accounts.filter(a => a.Type === 'ethereum');
  if (!signable.length) {
    sel.innerHTML = '<option value="">Derive an Ethereum account first</option>';
    $('#bkSignBtn').disabled = true;
    return;
  }
  sel.innerHTML = signable
    .map(a => `<option value="${bkEsc(a.Id)}">${bkEsc(a.Type)} · ${bkEsc(short(a.Address, 10, 8))}</option>`)
    .join('');
  $('#bkSignBtn').disabled = false;
}

// Re-derive `wallet`'s committee Password shares and return the `Keys` array
// expected by Account:signMessage / Account:signTransaction. Single source of
// truth for committee-secret derivation (used by backendSignMessage and by the
// MPC EVM send broadcast). Runs a WebAuthn `get` (biometric) for passkey-backed
// wallets, so callers MUST invoke it inside a user-gesture task (button click)
// so the transient activation is valid.
async function mpcCommitteeKeys(wallet) {
  const pwShares = (wallet.Keys || []).filter(k => k.Type === 'Password');
  if (backend.mpc) {
    // Passkey-2FA committee: two local Password shares mapped IN ORDER to
    // [share1secret, share2secret]. Share 1 is always the passkey's prf.first;
    // share 2 is the passkey's prf.second (mode 'passkey') or the stored
    // password (mode 'password'). The committee was created as
    // [Password(prf.first), Password(share2), RemoteKey] and Wallet:create
    // preserves Keys order, so index 0→share1, 1→share2. The `?? share1secret`
    // guard handles wallets with more/fewer than two Password shares.
    let share1secret, share2secret;
    if (backend.mpc.mode === 'passkey') {
      // Both secrets from one biometric (two distinct PRF salts).
      const r = await passkeyDeriveTwo(backend.mpc.credentialId, backend.mpc.saltFirst, backend.mpc.saltSecond);
      share1secret = r.secret1Hex; share2secret = r.secret2Hex;
    } else {
      // Passkey unlocks share 1; the stored password unlocks share 2.
      const r = await passkeyDeriveTwo(backend.mpc.credentialId, backend.mpc.saltFirst, backend.mpc.saltFirst);
      share1secret = r.secret1Hex; share2secret = backend.mpc.password;
    }
    const order = [share1secret, share2secret];
    return pwShares.map((k, i) => ({ Type: 'Password', Id: k.Id, Key: order[i] ?? share1secret }));
  }
  // Single-secret wallet: the passkey PRF (biometric) or the create-time
  // password unlocks every Password share with the same secret.
  let secret;
  if (backend.passkey) {
    secret = await passkeyDerive(backend.passkey.credentialId, backend.passkey.salt);
  } else {
    secret = backend.password;
  }
  return pwShares.map(k => ({ Type: 'Password', Id: k.Id, Key: secret }));
}

async function backendSignMessage() {
  const err = $('#bkSignErr');
  err.textContent = '';
  const accountId = $('#bkSignAccount').value;
  const message = $('#bkSignMsg').value;
  if (!accountId) { err.textContent = 'Choose an account to sign with.'; return; }
  if (!message) { err.textContent = 'Enter a message.'; return; }
  if (!backend.wallet) { err.textContent = 'Create a wallet first.'; return; }
  if (!backend.mpc && !backend.passkey && !backend.password) { err.textContent = 'No unlock material for this wallet in this session.'; return; }

  const btn = $('#bkSignBtn');
  btn.disabled = true;
  try {
    // Reconstruct the signing committee's Password shares via the shared
    // derivation (single implementation, see mpcCommitteeKeys). All WebAuthn
    // happens in this click task (transient activation).
    if (backend.mpc || backend.passkey) { btn.textContent = 'Waiting for passkey…'; bkStatus('busy', 'passkey…'); }
    const keys = await mpcCommitteeKeys(backend.wallet);
    btn.textContent = 'Signing…'; bkStatus('busy', 'TSS sign…');
    const res = await backendRequest(`Account/${accountId}:signMessage`, 'POST', {
      Message: b64utf8(message), Keys: keys
    });
    const out = $('#bkSignOut');
    out.classList.remove('hidden');
    out.innerHTML = `
      <div class="panel" style="padding:4px 16px;margin-top:4px">
        <div class="kv"><span class="k">Message</span><span class="v">${bkEsc(message)}</span></div>
        <div class="kv"><span class="k">Signature</span><span class="v" style="max-width:100%">${bkEsc(res.signature || JSON.stringify(res))}</span></div>
      </div>`;
    bkStatus('live', 'signed · #' + backend.handle);
    toast('ok', 'Message signed', (backend.passkey || backend.mpc) ? 'TSS signature unlocked with your device passkey.' : 'Real EIP-191 TSS signature produced in-browser.');
  } catch (e) {
    err.textContent = e.message || String(e);
    bkStatus('err', 'sign failed');
  } finally {
    btn.disabled = false; btn.textContent = 'Sign message';
  }
}

async function backendRunRaw() {
  const out = $('#bkRawOut');
  let reqObj;
  try { reqObj = JSON.parse($('#bkRawReq').value); }
  catch (e) { out.textContent = '// invalid JSON: ' + e.message; return; }
  try {
    const data = await backendRequest(reqObj.path, reqObj.verb || 'GET', reqObj.params);
    out.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    out.textContent = '// error ' + (e.code ? '(' + e.code + ') ' : '') + (e.message || String(e));
  }
}

function wireBackendEvents() {
  $('#bkCreateWallet').onclick  = backendCreateWallet;
  $('#bkRkSend').onclick        = backendRkSend;
  $('#bkRkVerify').onclick      = backendRkVerify;
  $('#bkRkCreate').onclick      = backendRkCreate;
  $('#bkRkCreatePasskey').onclick = backendRkCreatePasskey;
  $('#bkRkPasskeyVerify').onclick = backendRkPasskeyVerify;
  $('#bkRkEnroll').onclick      = backendRkEnrollPasskey;
  $('#bkSpotStatus').onclick    = backendSpotStatus;
  $('#bkAkRun').onclick         = backendInitiateKeygen;
  $('#bkAsRun').onclick         = backendJoinSign;
  $('#bkListWallets').onclick   = backendListWallets;
  $('#bkCreateAccount').onclick = backendCreateAccount;
  $('#bkSignBtn').onclick       = backendSignMessage;
  $('#bkRawRun').onclick        = backendRunRaw;
  $('#bkLogClear').onclick      = () => { $('#bkLog').innerHTML = ''; };

  // Passkey toggle: greys out the password field when on; disable + note when
  // the browser lacks WebAuthn entirely.
  const pk = $('#bkPasskey');
  if (pk) {
    if (!passkeyAvailable()) {
      pk.checked = false; pk.disabled = true;
      $('#bkPasskeyAvail').textContent = '(passkeys unavailable in this browser)';
    } else {
      pk.onchange = () => { $('#bkWalletPw').disabled = pk.checked; };
    }
  }

  // RemoteKey passkey affordances: disable + note when WebAuthn is unavailable.
  if (!passkeyAvailable()) {
    const pv = $('#bkRkPasskeyVerify'), en = $('#bkRkEnroll'), cp = $('#bkRkCreatePasskey'), note = $('#bkRkPasskeyAvail');
    if (pv) pv.disabled = true;
    if (en) en.disabled = true;
    if (cp) cp.disabled = true;
    if (note) note.textContent = '(passkeys unavailable)';
  }

  // Delegated copy for dynamically-rendered addresses in the backend pane.
  $('[data-pane="backend"]').addEventListener('click', e => {
    const btn = e.target.closest('[data-copy]');
    if (btn) copyText(btn.dataset.copy, btn);
  });
}

// Confirm-remove modal (used from both unlock and dashboard).
function confirmRemove() {
  openModal(`
    <div class="card-pad stack" style="--gap:16px">
      <div class="eyebrow" style="color:var(--danger)">Irreversible</div>
      <h2 class="title">Remove this wallet?</h2>
      <p class="subtitle">The encrypted vault will be deleted from this browser. You can only get it back with your recovery phrase — make sure you have it written down.</p>
      <div class="btn-row">
        <button class="btn subtle" type="button" data-close>Keep wallet</button>
        <button class="btn danger grow" type="button" id="confirmRemoveGo">Remove wallet</button>
      </div>
    </div>`);
  $('#confirmRemoveGo').onclick = removeWallet;
}
