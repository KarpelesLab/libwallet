#!/usr/bin/env node
// Runs Solana transaction signing in the built WASM module, the way a browser
// calls it: every account type, legacy and v0, and the refusals.
//   node web/tools/test-solana-sign.mjs [pkg dir, default web/pkg]
// Expects the glue already patched by inject-entropy.mjs.

import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  createDemoAccount, demoTransaction, fromBase64, messageOf, openSession, signSolanaTransaction, toBase64,
} from '../examples/solana-sign.mjs';

const pkg = resolve(process.argv[2] || 'web/pkg');
const wasm = await import(pathToFileURL(`${pkg}/libwallet.js`).href);
await wasm.default({ module_or_path: readFileSync(`${pkg}/libwallet_bg.wasm`) });
const request = openSession(wasm);

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function fromBase58(text) {
  let n = 0n;
  for (const c of text) n = n * 58n + BigInt(BASE58.indexOf(c));
  const bytes = [];
  for (; n > 0n; n >>= 8n) bytes.unshift(Number(n & 255n));
  for (const c of text) { if (c !== '1') break; bytes.unshift(0); }
  return Uint8Array.from(bytes);
}

function toBase58(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let text = '';
  for (; n > 0n; n /= 58n) text = BASE58[Number(n % 58n)] + text;
  for (const b of bytes) { if (b !== 0) break; text = '1' + text; }
  return text;
}

const fill = (n, v) => new Array(n).fill(v);
const unsigned = (signers, message) => toBase64(Uint8Array.from([signers, ...fill(signers * 64, 0), ...message]));
const legacyMessage = signer => [1, 0, 1, 2, ...signer, ...fill(32, 0x42), ...fill(32, 9), 1, 1, 1, 0, 1, 0xaa];
// Another fee payer in slot 0, so the account has to find its own slot.
const cosignedV0Message = signer =>
  [0x80, 2, 0, 1, 3, ...fill(32, 0x55), ...signer, ...fill(32, 0x42), ...fill(32, 9),
    1, 2, 2, 0, 1, 3, 0xde, 0xad, 0xbe, 1, ...fill(32, 0x77), 1, 0, 0];

function assertSignedBy(address, message, signature) {
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), fromBase58(address)]);
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  assert.ok(verify(null, Uint8Array.from(message), key, signature), 'signature must verify under the account key');
}

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

const SECRET = 'seal-password';
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
async function importedAccount(path, secret, Index = 0) {
  const wallet = await request(path, 'POST', { Name: 'i', Curve: 'ed25519', ...secret, Keys: [{ Type: 'Password', Key: SECRET }] });
  const keys = [{ Type: 'Password', Id: wallet.Keys[0].Id, Key: SECRET }];
  return { keys, account: await request('Account', 'POST', { Wallet: wallet.Id, Type: 'solana', Index, Keys: keys }) };
}
async function mpcAccount(Index) {
  const secrets = ['passwordone', 'passwordtwo', 'passwordthree'];
  const wallet = await request('Wallet', 'POST', { Name: 'w', Curve: 'ed25519', Keys: secrets.map(Key => ({ Type: 'Password', Key })) });
  const keys = [0, 2].map(i => ({ Type: 'Password', Id: wallet.Keys[i].Id, Key: secrets[i] }));
  return { keys, account: await request('Account', 'POST', { Wallet: wallet.Id, Type: 'solana', Index }) };
}

const accounts = {
  'MPC': () => mpcAccount(0),
  'derived MPC': () => mpcAccount(1),
  'seed phrase': () => importedAccount('Wallet:importMnemonic', { Mnemonic: MNEMONIC }),
  'imported key': () => importedAccount('Wallet:importPrivateKey', { PrivateKey: '11'.repeat(32) }),
  'derived imported key': () => importedAccount('Wallet:importPrivateKey', { PrivateKey: '22'.repeat(32) }, 1),
};

for (const [kind, create] of Object.entries(accounts)) {
  await test(`${kind}: signs legacy and v0 without changing the message`, async () => {
    const { account, keys } = await create();
    const signer = fromBase58(account.Address);
    for (const [message, signers, slot] of [[legacyMessage(signer), 1, 0], [cosignedV0Message(signer), 2, 1]]) {
      const signed = await signSolanaTransaction(request, account.Id, keys, unsigned(signers, message));
      const bytes = fromBase64(signed.transaction);
      assert.deepEqual([...fromBase58(signed.raw)], [...bytes], 'raw and transaction must be the same bytes');
      assert.deepEqual([...messageOf(bytes)], message);
      const signature = bytes.subarray(1 + slot * 64, 1 + (slot + 1) * 64);
      assert.deepEqual([...fromBase58(signed.signature)], [...signature]);
      assertSignedBy(account.Address, message, signature);
      if (slot === 1) assert.ok(bytes.subarray(1, 65).every(b => b === 0), "the other signer's slot must stay as it was");
    }
  });
}

const { account, keys } = await createDemoAccount(request);
const signer = fromBase58(account.Address);
const legacy = legacyMessage(signer);
const legacyTx = unsigned(1, legacy);
const sign = Transaction => request('Account:signTransaction', 'POST', { Id: account.Id, Keys: keys, Transaction });
const refused = (promise, pattern) => assert.rejects(promise, pattern);

await test('the example in examples/solana-sign.mjs signs its demo transaction', async () => {
  const signed = await signSolanaTransaction(request, account.Id, keys, demoTransaction(signer));
  assert.equal(fromBase64(signed.transaction).length, 1 + 64 + messageOf(fromBase64(demoTransaction(signer))).length);
});

for (const field of ['transaction', 'serializedTransaction', 'raw']) {
  await test(`accepts {${field}}`, async () => {
    const signed = await sign({ [field]: legacyTx });
    assert.deepEqual([...messageOf(fromBase64(signed.transaction))], legacy);
  });
}

await test('accepts base58 as well as base64', async () => {
  const signed = await sign(toBase58(fromBase64(legacyTx)));
  assert.deepEqual([...messageOf(fromBase64(signed.transaction))], legacy);
});
const transfer = { to: '11111111111111111111111111111112', value: '1000', recentBlockhash: '11111111111111111111111111111111' };
await test('native {to, value, recentBlockhash} still builds', async () => {
  assert.equal(typeof (await sign(transfer)).raw, 'string');
});
for (const field of ['mint', 'token', 'instructions']) {
  await test(`refuses a transfer carrying ${field}, rather than sending SOL`, () =>
    refused(sign({ ...transfer, [field]: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' }), new RegExp(field)));
}
await test('refuses a serialized transaction next to other fields', () =>
  refused(sign({ transaction: legacyTx, to: transfer.to }), /only field/));
await test('refuses a transaction that does not name the account as a signer', () =>
  refused(sign(unsigned(1, legacyMessage(fill(32, 0x33)))), /required signer/));
await test('refuses bytes that are not a transaction', () =>
  refused(sign(toBase64(Uint8Array.from([1, 2, 3]))), /serialized Solana transaction/));
await test('refuses a transaction whose signature count does not match its message', () =>
  refused(sign(unsigned(1, cosignedV0Message(signer))), /required signer/));
await test('signMessage still refuses a transaction', () =>
  refused(request('Account:signMessage', 'POST', { Id: account.Id, Keys: keys, Message: toBase64(Uint8Array.from(legacy)) }), /use signTransaction/));

const failed = results.filter(ok => !ok).length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
