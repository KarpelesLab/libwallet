#!/usr/bin/env node
// Runs Bitfi recovery in the built WASM module, against vectors generated
// separately from the published algorithm with @noble and @scure libraries. These
// aren't output from Bitfi's own software, and the secrets are made up.
//   node web/tools/test-bitfi.mjs [pkg dir, default web/pkg]
// Expects the glue already patched by inject-entropy.mjs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { findAddress, formatUnits, inputWarnings, toBaseUnits } from '../recover/bitfi-format.mjs';

const pkg = resolve(process.argv[2] || 'web/pkg');
const wasm = await import(pathToFileURL(`${pkg}/libwallet.js`).href);
await wasm.default({ module_or_path: readFileSync(`${pkg}/libwallet_bg.wasm`) });
const handle = wasm.libwallet_init();
async function call(path, params) {
  const reply = JSON.parse(await wasm.libwallet_request(handle, JSON.stringify({ path, verb: 'POST', params })));
  if (reply.result === 'error') throw new Error(reply.error);
  return reply.data;
}

const SALT = 'test-salt-0001';
const SECRET = 'correct horse battery staple is thirty+ chars';
const EXPECTED = [
  ['btc', 'legacy', '17T2SFMtkaX1joxyntCU9vjnhAgSvjKNmQ'],
  ['btc', 'segwit', 'bc1q89ajfm8vw9j0lwjmjng9sp92yay3fx8xahdvn4'],
  ['ltc', 'legacy', 'LedMh3fzwX1fkARCsq2NNr1hAKBh8aLAD2'],
  ['ltc', 'segwit', 'ltc1q9h8zz9l6c4el0upxs676xursl8fj5w0k85c0g3'],
  ['doge', 'legacy', 'DJtFzcEGr73unEKkyqfdmaG8ANog12MMCM'],
  ['mona', 'legacy', 'MMV2Yq91K2MaFRXkHhNcKVhpUArYp1gyPA'],
  ['mona', 'segwit', 'mona1qp36jtvre4lxy8g4pfwa9fvdc7wfu9fj8cxnyz9'],
];

const results = [];
async function test(name, run) {
  try {
    await run();
    results.push(true);
    console.log(`ok    ${name}`);
  } catch (err) {
    results.push(false);
    console.log(`FAIL  ${name}\n      ${err.message}`);
  }
}

const started = Date.now();
const { Session } = await call('Bitfi:open', { Salt: SALT, Secret: SECRET });
console.log(`key derivation took ${Date.now() - started} ms`);

for (const [coin, kind, address] of EXPECTED) {
  await test(`${coin} ${kind} address matches the vector`, async () => {
    const { Positions } = await call('Bitfi:addresses', { Session, Coin: coin, Positions: [1] });
    assert.equal(Positions[0].Addresses.find(a => a.kind === kind).address, address);
  });
}

await test('Ethereum and Monero addresses derive', async () => {
  const eth = await call('Bitfi:addresses', { Session, Coin: 'eth', Positions: [1] });
  assert.equal(eth.Positions[0].Addresses[0].address.toLowerCase(), '0xf45a414dbc4eef65d7ea540db0aa6fa0fa6f9b3f');
  const xmr = await call('Bitfi:addresses', { Session, Coin: 'xmr', Positions: [1] });
  assert.match(xmr.Positions[0].Addresses[0].address, /^4[1-9A-HJ-NP-Za-km-z]{94}$/);
});

await test('Monero keys export, and balances say they are not available', async () => {
  const keys = await call('Bitfi:export', { Session, Coin: 'xmr', Position: 1 });
  assert.match(keys.SpendKey, /^[0-9a-f]{64}$/);
  assert.match(keys.ViewKey, /^[0-9a-f]{64}$/);
  await assert.rejects(call('Bitfi:balances', { Session, Coin: 'xmr', Positions: [1] }), /aren't available yet/);
});

await test('refuses non-ASCII and coins we have no server for', async () => {
  await assert.rejects(call('Bitfi:open', { Salt: 'salé-1234', Secret: SECRET }), /ASCII/);
  await assert.rejects(call('Bitfi:addresses', { Session, Coin: 'xrp', Positions: [1] }), /unsupported coin/);
});

await test('closing forgets the session', async () => {
  await call('Bitfi:close', { Session });
  await assert.rejects(call('Bitfi:addresses', { Session, Coin: 'btc', Positions: [1] }), /session not found/);
});

await test('amounts convert exactly, beyond what a number can hold', () => {
  assert.equal(toBaseUnits('1.5', 8), '150000000');
  assert.equal(toBaseUnits('.5', 18), '500000000000000000');
  assert.equal(toBaseUnits('123456789.123456789012345678', 18), '123456789123456789012345678');
  assert.equal(formatUnits('123456789123456789012345678', 18), '123456789.123456789012345678');
  assert.equal(formatUnits('150000000', 8), '1.5');
  assert.equal(formatUnits('5', 8), '0.00000005');
  assert.equal(formatUnits('7', 0), '7');
  for (const bad of ['', '.', '0', '1.123456789', '-1', '1e5', '1,5', 'abc']) assert.throws(() => toBaseUnits(bad, 8), `${bad} should be refused`);
});

await test('input hints flag what changes the key, without changing it', () => {
  assert.equal(inputWarnings('Salt', 'salé-1234', 6).level, 'bad');
  assert.equal(inputWarnings('Salt', 'abcdefg ', 6).level, 'warn');
  assert.equal(inputWarnings('Salt', 'abc', 6).level, 'warn');
  assert.equal(inputWarnings('Salt', 'abcdefg', 6).level, '');
});

await test('a known address matches whatever its case or CashAddr prefix', () => {
  const all = [{ address: '0xAbC', label: 'E' }, { address: 'bitcoincash:qq1', label: 'B' }];
  assert.equal(findAddress(' 0xabc ', all, 6).level, 'good');
  assert.equal(findAddress('qq1', all, 6).level, 'good');
  assert.equal(findAddress('nope', all, 6).level, 'warn');
  assert.equal(findAddress('', all, 6).level, '');
});

const failed = results.filter(ok => !ok).length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
