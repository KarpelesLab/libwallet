// Recover a Bitfi wallet. Everything sensitive stays in this tab's memory: nothing
// here touches localStorage, cookies or IndexedDB, and libwallet keeps the derived
// key in memory until the session closes. Page text from the network (token names)
// only ever goes in through textContent.

import { formatUnits, toBaseUnits, findAddress, inputWarnings } from './bitfi-format.mjs';

const COINS = [
  { symbol: 'btc', name: 'Bitcoin' },
  { symbol: 'eth', name: 'Ethereum' },
  { symbol: 'ltc', name: 'Litecoin' },
  { symbol: 'bch', name: 'Bitcoin Cash' },
  { symbol: 'doge', name: 'Dogecoin' },
  { symbol: 'mona', name: 'Monacoin' },
];
const KIND = { legacy: 'Legacy', segwit: 'SegWit', ethereum: 'Address', monero: 'Address' };
const FIRST_SCAN = 6; // Positions 0-5. Bitfi's first address is position 1.
const MORE = 10;

const $ = id => document.getElementById(id);
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

let wasm, handle, session;
let scanned = 0;
let rows = []; // Every address checked: {coin, Position, Kind, Address, Assets?, Error?}
let monero = [];

async function call(path, params) {
  const reply = JSON.parse(await wasm.libwallet_request(handle, JSON.stringify({ path, verb: 'POST', params })));
  if (reply.result === 'error') throw new Error(reply.error);
  return reply.data;
}

// --- Entering the salt and secret ------------------------------------------

function showHints() {
  for (const [id, min, label] of [['salt', 6, 'Salt'], ['secret', 30, 'Secret phrase']]) {
    const hint = $(`${id}Hint`);
    const { level, text } = inputWarnings(label, $(id).value, min);
    hint.className = `recover-hint ${level}`;
    hint.textContent = text;
  }
}

async function unlock(event) {
  event.preventDefault();
  const [salt, secret] = [$('salt').value, $('secret').value];
  $('unlockError').textContent = '';
  const button = $('unlockButton');
  button.disabled = true;
  button.textContent = 'Working out your keys…';
  // Let the button repaint: deriving the key holds this thread for a moment.
  await new Promise(resolve => setTimeout(resolve, 50));
  try {
    session = (await call('Bitfi:open', { Salt: salt, Secret: secret })).Session;
  } catch (err) {
    $('unlockError').textContent = err.message;
    button.disabled = false;
    button.textContent = 'Check for funds';
    return;
  }
  for (const id of ['salt', 'secret']) {
    $(id).value = '';
    $(id).type = 'password';
  }
  showHints();
  button.disabled = false;
  button.textContent = 'Check for funds';
  $('start').hidden = true;
  $('results').hidden = false;
  $('summary').focus();
  await scan(0, FIRST_SCAN);
}

// --- Looking for funds -----------------------------------------------------

async function balances(coin, positions) {
  try {
    const reply = await call('Bitfi:balances', { Session: session, Coin: coin.symbol, Positions: positions });
    return reply.Addresses.map(row => ({ ...row, coin }));
  } catch (err) {
    return positions.map(Position => ({ coin, Position, Kind: '', Address: '', Error: err.message }));
  }
}

async function scan(from, count) {
  const positions = Array.from({ length: count }, (_, i) => from + i);
  $('more').disabled = true;
  $('summary').textContent = 'Checking for funds';
  $('summaryDetail').textContent = `Looking at positions ${from} to ${from + count - 1}.`;

  const found = await Promise.all(COINS.map(coin => balances(coin, positions)));
  rows.push(...found.flat());

  const xmr = await call('Bitfi:addresses', { Session: session, Coin: 'xmr', Positions: positions });
  monero.push(...xmr.Positions.map(p => ({ Position: p.Position, Address: p.Addresses[0].address })));

  scanned = from + count;
  $('more').disabled = false;
  render();
}

/** Check again everything a coin couldn't answer for. */
async function retry(coin) {
  const positions = [...new Set(rows.filter(r => r.coin === coin && r.Error).map(r => r.Position))];
  $('summaryDetail').textContent = `Trying ${coin.name} again.`;
  const found = await balances(coin, positions);
  rows = rows.filter(r => !(r.coin === coin && positions.includes(r.Position)));
  rows.push(...found);
  rows.sort((a, b) => a.Position - b.Position);
  render();
}

function render() {
  const held = rows.filter(r => r.Assets && r.Assets.length);
  const failedCoins = COINS.filter(coin => rows.some(r => r.coin === coin && r.Error));
  const range = `positions 0 to ${scanned - 1}`;

  if (held.length) {
    $('summary').textContent = held.length === 1 ? 'Found funds at 1 address' : `Found funds at ${held.length} addresses`;
    $('summaryDetail').textContent = `Checked ${range}. Move funds to a wallet with a new recovery phrase.`;
  } else if (failedCoins.length) {
    $('summary').textContent = 'Couldn’t finish checking';
    $('summaryDetail').textContent = `No funds yet at ${range}, but some coins couldn't be checked. Try them again before relying on this.`;
  } else {
    $('summary').textContent = 'No funds found';
    $('summaryDetail').textContent = `Checked ${range}. The salt and secret must match exactly, including capitals and spaces: any difference gives a different, empty wallet. Use “Check an address you know” below to confirm.`;
  }

  $('funds').replaceChildren(...held.map(fundCard), ...failedCoins.map(failedCard));
  $('monero').replaceChildren(...monero.filter(m => m.Position === 1).map(moneroRow));
  $('moneroMore').replaceChildren(...monero.filter(m => m.Position !== 1).map(moneroRow));
  $('all').replaceChildren(...rows.filter(r => r.Address).map(addressRow));
  checkKnown();
}

function fundCard(row) {
  const card = el('article', 'recover-fund');
  const amounts = el('div', 'recover-amounts');
  for (const asset of row.Assets) {
    const line = el('div', 'recover-amount');
    line.append(el('b', '', `${formatUnits(asset.Balance, asset.Decimals ?? 18)} ${asset.Symbol || 'unnamed token'}`));
    amounts.append(line);
  }
  const hasTokens = row.Assets.some(a => a.Asset !== 'NATIVE');
  card.append(
    amounts,
    el('p', 'recover-meta', `${row.coin.name}, ${KIND[row.Kind]}, position ${row.Position}`),
    el('p', 'recover-address', row.Address),
  );
  if (hasTokens) card.append(el('p', 'recover-meta', 'Anyone can send a token to an address, so ignore ones you don’t recognize.'));

  const actions = el('div', 'recover-actions');
  for (const asset of row.Assets) {
    const label = row.Assets.length > 1 ? `Move ${asset.Symbol || 'token'}` : 'Move';
    const move = el('button', 'btn primary sm', label);
    move.type = 'button';
    move.addEventListener('click', () => openSend(row, asset));
    actions.append(move);
  }
  actions.append(revealKeys(card, row.coin.symbol, row.Position));
  card.append(actions);
  return card;
}

function failedCard(coin) {
  const card = el('article', 'recover-fund failed');
  const count = rows.filter(r => r.coin === coin && r.Error).length;
  card.append(el('p', 'recover-meta', `${coin.name} couldn't be checked at ${count} ${count === 1 ? 'address' : 'addresses'}: our server didn't give a usable answer. Funds may still be there.`));
  const again = el('button', 'btn ghost sm', `Try ${coin.name} again`);
  again.type = 'button';
  again.addEventListener('click', () => { again.disabled = true; retry(coin); });
  const actions = el('div', 'recover-actions');
  actions.append(again);
  card.append(actions);
  return card;
}

function addressRow(row) {
  const line = el('div', 'recover-row');
  const status = row.Error ? 'not checked' : row.Assets.length ? 'has funds' : 'empty';
  line.append(
    el('span', 'recover-meta', `${row.coin.name}, ${KIND[row.Kind]}, position ${row.Position}: ${status}`),
    el('p', 'recover-address', row.Address),
  );
  return line;
}

function moneroRow(row) {
  const line = el('div', 'recover-row');
  line.append(el('span', 'recover-meta', `Position ${row.Position}`), el('p', 'recover-address', row.Address));
  const actions = el('div', 'recover-actions');
  actions.append(revealKeys(line, 'xmr', row.Position));
  line.append(actions);
  return line;
}

/** A button that shows, and hides again, the private keys for an address. */
function revealKeys(parent, coin, position) {
  const button = el('button', 'btn ghost sm', 'Show private key');
  button.type = 'button';
  let shown = null;
  button.addEventListener('click', async () => {
    if (shown) {
      shown.remove();
      shown = null;
      button.textContent = 'Show private key';
      return;
    }
    try {
      const keys = await call('Bitfi:export', { Session: session, Coin: coin, Position: position });
      const list = el('dl', 'recover-keys');
      for (const [label, value] of keyEntries(keys)) list.append(el('dt', '', label), el('dd', '', value));
      shown = list;
      parent.append(list);
      button.textContent = 'Hide private key';
    } catch (err) {
      parent.append(el('p', 'err-inline', err.message));
    }
  });
  return button;
}

function keyEntries(keys) {
  const labels = { PrivateKey: 'Private key (hex)', Legacy: 'Legacy address key (WIF)', Segwit: 'SegWit address key (WIF)', SpendKey: 'Spend key', ViewKey: 'View key' };
  return Object.entries(labels).filter(([name]) => keys[name]).map(([name, label]) => [label, keys[name]]);
}

function checkKnown() {
  const result = $('knownResult');
  const value = $('known').value;
  const all = [
    ...rows.filter(r => r.Address).map(r => ({ address: r.Address, label: `${r.coin.name}, ${KIND[r.Kind]}, position ${r.Position}` })),
    ...monero.map(m => ({ address: m.Address, label: `Monero, position ${m.Position}` })),
  ];
  const { level, text } = findAddress(value, all, scanned);
  result.className = `recover-hint ${level}`;
  result.textContent = text;
}

// --- Moving funds ----------------------------------------------------------

let sending = null; // {row, asset, prepared?}

function openSend(row, asset) {
  sending = { row, asset };
  $('sendTitle').textContent = `Move ${asset.Symbol || 'token'}`;
  $('sendFrom').textContent = `From ${row.Address}`;
  $('sendTo').value = '';
  $('sendAmount').value = '';
  $('sendTo').disabled = $('sendAmount').disabled = false;
  $('sendError').textContent = '';
  $('review').hidden = true;
  $('sendAction').textContent = 'Review';
  $('sendAction').disabled = false;
  $('sendMax').hidden = false;
  $('sendCancel').textContent = 'Cancel';
  $('sendDialog').showModal();
}

function reviewList(entries) {
  $('review').replaceChildren(...entries.flatMap(([label, value]) => [el('dt', '', label), el('dd', '', value)]));
  $('review').hidden = false;
}

async function review() {
  const { row, asset } = sending;
  const typed = $('sendAmount').value.trim();
  const decimals = asset.Decimals ?? 18;
  let Amount;
  try {
    Amount = typed.toLowerCase() === 'max' ? 'max' : toBaseUnits(typed, decimals);
  } catch (err) {
    $('sendError').textContent = err.message;
    return;
  }
  const params = { Session: session, Coin: row.coin.symbol, Position: row.Position, To: $('sendTo').value.trim(), Amount };
  if (row.coin.symbol !== 'eth') params.Kind = row.Kind;
  if (asset.Asset !== 'NATIVE') params.Token = asset.Asset;

  $('sendAction').disabled = true;
  $('sendAction').textContent = 'Preparing…';
  $('sendError').textContent = '';
  try {
    const prepared = await call('Bitfi:prepareSend', params);
    const native = row.coin.symbol === 'eth' ? 'ETH' : row.coin.symbol.toUpperCase();
    const nativeDecimals = row.coin.symbol === 'eth' ? 18 : 8;
    const feeLabel = row.coin.symbol === 'eth' ? 'Network fee (at most)' : 'Network fee';
    reviewList([
      ['Sending', `${formatUnits(prepared.Amount, decimals)} ${asset.Symbol || 'token'}`],
      ['To', prepared.To],
      [feeLabel, `${formatUnits(prepared.Fee, nativeDecimals)} ${native}`],
    ]);
    sending.prepared = prepared;
    $('sendTo').disabled = $('sendAmount').disabled = true;
    $('sendMax').hidden = true;
    $('sendAction').textContent = 'Send';
  } catch (err) {
    $('sendError').textContent = err.message;
    $('sendAction').textContent = 'Review';
  }
  $('sendAction').disabled = false;
}

async function send() {
  const { row, prepared } = sending;
  $('sendAction').disabled = true;
  $('sendAction').textContent = 'Sending…';
  $('sendError').textContent = '';
  try {
    const { Txid } = await call('Bitfi:broadcast', { Coin: row.coin.symbol, Raw: prepared.Raw });
    reviewList([['Sent. Transaction ID', String(Txid)]]);
    sending = null;
    $('sendAction').hidden = true;
    $('sendCancel').textContent = 'Close';
  } catch (err) {
    $('sendError').textContent = err.message;
    $('sendAction').textContent = 'Send';
    $('sendAction').disabled = false;
  }
}

function closeSend() {
  $('sendDialog').close();
  $('sendAction').hidden = false;
  sending = null;
}

// --- Leaving ---------------------------------------------------------------

function forget() {
  if (session) wasm.libwallet_request(handle, JSON.stringify({ path: 'Bitfi:close', verb: 'POST', params: { Session: session } }));
  session = null;
  rows = [];
  monero = [];
  scanned = 0;
  for (const id of ['funds', 'monero', 'moneroMore', 'all']) $(id).replaceChildren();
  $('known').value = '';
  $('knownResult').textContent = '';
  $('results').hidden = true;
  $('start').hidden = false;
}

// --- Start -----------------------------------------------------------------

for (const button of document.querySelectorAll('[data-reveal]')) {
  button.addEventListener('click', () => {
    const input = $(button.dataset.reveal);
    const hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    button.textContent = hidden ? 'Hide' : 'Show';
  });
}
$('salt').addEventListener('input', showHints);
$('secret').addEventListener('input', showHints);
$('unlock').addEventListener('submit', unlock);
$('more').addEventListener('click', () => scan(scanned, MORE));
$('forget').addEventListener('click', forget);
$('known').addEventListener('input', checkKnown);
$('sendMax').addEventListener('click', () => { $('sendAmount').value = 'max'; });
$('sendCancel').addEventListener('click', closeSend);
$('sendAction').addEventListener('click', () => (sending && sending.prepared ? send() : review()));
$('sendForm').addEventListener('submit', event => event.preventDefault());
window.addEventListener('pagehide', () => { if (session) forget(); });

try {
  wasm = await import('../pkg/libwallet.js');
  await wasm.default();
  handle = wasm.libwallet_init();
  $('start').hidden = false;
  showHints();
} catch (err) {
  $('fatal').textContent = `This page couldn’t load its wallet code: ${err.message || err}`;
}
