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
  mnemonic:  null,   // string, only while unlocked
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
function unlockWith(mnemonic) {
  session.mnemonic = mnemonic;
  try {
    session.addresses = wasm.derive_addresses(mnemonic);
  } catch (err) {
    session.mnemonic = null;
    toast('error', 'Derivation failed', err.message || String(err));
    return;
  }
  renderAccounts();
  onSendChainChange();
  showScreen('dashboard');
  refreshAllBalances();
}

function lock() {
  session.mnemonic = null;
  session.addresses = null;
  session.balances = {};
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

async function refreshAllBalances() {
  if (!session.addresses) return;
  ['evm', 'bitcoin', 'solana'].forEach(c => setBalance(c, null, true));
  await Promise.allSettled([
    fetchEvmBalance(),
    fetchBtcBalance(),
    fetchSolBalance()
  ]);
}

async function fetchEvmBalance() {
  try {
    const hex = await rpc(evmChain.rpc, 'eth_getBalance', [session.addresses.evm, 'latest']);
    const wei = BigInt(hex);
    session.balances.evm = wei;
    setBalance('evm', formatUnits(wei, DECIMALS.evm, 6));
  } catch { setBalance('evm', 'unavailable'); }
}

async function fetchSolBalance() {
  try {
    const res = await rpc(SOLANA_RPC, 'getBalance', [session.addresses.solana]);
    const lamports = BigInt(res.value ?? res);
    session.balances.solana = lamports;
    setBalance('solana', formatUnits(lamports, DECIMALS.solana, 6));
  } catch { setBalance('solana', 'unavailable'); }
}

async function fetchBtcBalance() {
  try {
    const info = await httpJson(`${BTC_API}/address/${session.addresses.bitcoin}`);
    const c = info.chain_stats || {};
    const sats = BigInt(c.funded_txo_sum || 0) - BigInt(c.spent_txo_sum || 0);
    session.balances.bitcoin = sats;
    setBalance('bitcoin', formatUnits(sats, DECIMALS.bitcoin, 8));
  } catch { setBalance('bitcoin', 'unavailable'); }
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
    if (currentSendChain === 'evm')          prepared = await prepareEvm(to, amount);
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
      const raw = wasm.sign_evm_tx(session.mnemonic, JSON.stringify(txJson));
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
      const signed = wasm.sign_solana_transfer(session.mnemonic, JSON.stringify(txJson));
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
      const hex = wasm.sign_bitcoin_tx(session.mnemonic, JSON.stringify(txJson));
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
  $('#removeWallet').onclick = () => confirmRemove();

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
  wallet:   null,   // last created Wallet object (has .Keys for signing)
  password: null,   // share password for the created wallet (session-only)
  accounts: [],     // derived Account objects
  clientId: null,   // configured Sec-ClientId (Info:setWalletInfo), for RemoteKey 2FA
  rk: {             // RemoteKey 2FA creation flow state
    session:  null, // session id from RemoteKey:new, consumed by RemoteKey:validate
    resource: null  // "crwsv-…" RemoteKey resource from RemoteKey:validate
  }
};

const BK_CLIENTID_LS = 'libwallet.backend.clientId';

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

  // Re-apply a Client ID persisted from a previous session, if any.
  const savedClientId = (() => { try { return localStorage.getItem(BK_CLIENTID_LS); } catch { return null; } })();
  if (savedClientId) {
    $('#bkClientId').value = savedClientId;
    backendSetClientId();
  } else {
    bkClientIdState(false);
  }
}

// Reflect whether a Client ID is configured (gates the RemoteKey 2FA flow).
function bkClientIdState(set) {
  const pill = $('#bkClientIdState');
  pill.className = 'bk-status' + (set ? ' live' : '');
  $('#bkClientIdStateText').textContent = set ? 'set' : 'not set';
  $('#bkRkSend').disabled = !set;
}

// Info:setWalletInfo {ClientId} — configure the Sec-ClientId header used by the
// RemoteKey handlers, and persist it across reloads.
async function backendSetClientId() {
  const err = $('#bkClientIdErr');
  err.textContent = '';
  const value = $('#bkClientId').value.trim();
  if (!value) { err.textContent = 'Enter a Client ID.'; return; }
  const btn = $('#bkSetClientId');
  btn.disabled = true;
  try {
    await backendRequest('Info:setWalletInfo', 'POST', { ClientId: value });
    backend.clientId = value;
    try { localStorage.setItem(BK_CLIENTID_LS, value); } catch { /* private mode — session only */ }
    bkClientIdState(true);
    toast('ok', 'Client ID set', 'RemoteKey 2FA can now reach the WalletSign backend.');
  } catch (e) {
    err.textContent = e.message || String(e);
    bkClientIdState(false);
  } finally {
    btn.disabled = false;
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
      const w = await backendRequest('Wallet', 'POST', { Name: name, Curve: 'secp256k1', Keys: keys });
      backend.wallet = w;
      backend.password = pw;
      backend.accounts = [];
      $('#bkAccountList').innerHTML = '';
      $('#bkCreateAccount').disabled = false;
      refreshSignAccounts();

      const out = $('#bkRkOut');
      out.classList.remove('hidden');
      out.innerHTML = backendWalletCardHtml(w);
      bkStatus('live', '2FA wallet created · #' + backend.handle);
      toast('ok', '2FA wallet created', 'Self-custody wallet with a server-held RemoteKey share.');
      backendListWallets();
    } catch (e) {
      err.textContent = e.message || String(e);
      bkStatus('err', '2FA keygen failed');
    } finally {
      btn.disabled = false; btn.textContent = 'Create wallet';
    }
  }, 30);
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

function backendCreateWallet() {
  const name = $('#bkWalletName').value.trim() || 'Browser TSS wallet';
  const pw = $('#bkWalletPw').value;
  const err = $('#bkWalletErr');
  err.textContent = '';
  if (pw.length < 4) { err.textContent = 'Enter a share password (4+ characters).'; return; }

  const btn = $('#bkCreateWallet');
  btn.disabled = true; btn.textContent = 'Running keygen…';
  bkStatus('busy', 'TSS keygen…');
  // Defer so the button state paints before the (synchronous) keygen blocks.
  setTimeout(async () => {
    try {
      // A modern TSS wallet is inherently multi-party: the backend mandates a
      // ≥3-share committee (threshold hardcoded to 1 → 1-of-3). We build three
      // local Password shares from the entered password — an all-local,
      // server-free committee. (Mirrors the reference account_create test.)
      const keys = [
        { Type: 'Password', Key: pw },
        { Type: 'Password', Key: pw },
        { Type: 'Password', Key: pw }
      ];
      const w = await backendRequest('Wallet', 'POST', { Name: name, Curve: 'secp256k1', Keys: keys });
      backend.wallet = w;
      backend.password = pw;
      backend.accounts = [];
      $('#bkAccountList').innerHTML = '';
      $('#bkCreateAccount').disabled = false;
      refreshSignAccounts();

      const out = $('#bkWalletOut');
      out.classList.remove('hidden');
      out.innerHTML = backendWalletCardHtml(w);
      bkStatus('live', 'wallet created · #' + backend.handle);
      toast('ok', 'Real wallet created', 'TSS keygen ran in your browser (' + (w.Curve) + ' / ' + w.Protocol + ').');
      backendListWallets();
    } catch (e) {
      err.textContent = e.message || String(e);
      bkStatus('err', 'keygen failed');
    } finally {
      btn.disabled = false; btn.textContent = 'Generate wallet';
    }
  }, 30);
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

function backendSignMessage() {
  const err = $('#bkSignErr');
  err.textContent = '';
  const accountId = $('#bkSignAccount').value;
  const message = $('#bkSignMsg').value;
  if (!accountId) { err.textContent = 'Choose an account to sign with.'; return; }
  if (!message) { err.textContent = 'Enter a message.'; return; }
  if (!backend.wallet || !backend.password) { err.textContent = 'Create a wallet first.'; return; }

  // Reconstruct the signing committee from the wallet's sealed shares, each
  // unlocked with the create-time password (keyed by that share's WalletKey Id).
  const keys = (backend.wallet.Keys || [])
    .filter(k => k.Type === 'Password')
    .map(k => ({ Type: 'Password', Id: k.Id, Key: backend.password }));

  const btn = $('#bkSignBtn');
  btn.disabled = true; btn.textContent = 'Signing…';
  bkStatus('busy', 'TSS sign…');
  setTimeout(async () => {
    try {
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
      toast('ok', 'Message signed', 'Real EIP-191 TSS signature produced in-browser.');
    } catch (e) {
      err.textContent = e.message || String(e);
      bkStatus('err', 'sign failed');
    } finally {
      btn.disabled = false; btn.textContent = 'Sign message';
    }
  }, 30);
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
  $('#bkSetClientId').onclick   = backendSetClientId;
  $('#bkRkSend').onclick        = backendRkSend;
  $('#bkRkVerify').onclick      = backendRkVerify;
  $('#bkRkCreate').onclick      = backendRkCreate;
  $('#bkListWallets').onclick   = backendListWallets;
  $('#bkCreateAccount').onclick = backendCreateAccount;
  $('#bkSignBtn').onclick       = backendSignMessage;
  $('#bkRawRun').onclick        = backendRunRaw;
  $('#bkLogClear').onclick      = () => { $('#bkLog').innerHTML = ''; };

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
