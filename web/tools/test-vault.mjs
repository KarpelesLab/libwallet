#!/usr/bin/env node
// Runs the browser-extension vault flow (web/examples/vault-extension.mjs) in
// the built WASM module: set up, sign, "restart" into a new session from what
// was stored, unlock, sign again, lock, and the refusals.
//   node web/tools/test-vault.mjs [pkg dir, default web/pkg]
// Expects the glue already patched by inject-entropy.mjs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { lock, openSession, restore, setUp, unlock, vaultKeys } from '../examples/vault-extension.mjs';

const pkg = resolve(process.argv[2] || 'web/pkg');
const wasm = await import(pathToFileURL(`${pkg}/libwallet.js`).href);
await wasm.default({ module_or_path: readFileSync(`${pkg}/libwallet_bg.wasm`) });

const M = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'correct horse battery';
const disk = new Map();
const store = { get: async k => disk.get(k), set: async (k, v) => disk.set(k, structuredClone(v)) };
const message = btoa('hello from the vault');

async function sign(request, wallet, entry) {
  const [acct] = (await request('Account', 'GET', { Wallet: wallet.Id })).filter(a => a.Type === 'ethereum');
  const account = acct || await request('Account', 'POST', { Name: 'ETH', Wallet: wallet.Id, Type: 'ethereum', Index: 0, Keys: vaultKeys(wallet, entry) });
  return request('Account:signMessage', 'POST', { Id: account.Id, Message: message, Keys: vaultKeys(wallet, entry) });
}

// Session 1: first run.
let request = openSession(wasm);
const wallet = await setUp(request, store, PASSWORD, M);
const entry = disk.get('vault').entry;
const first = await sign(request, wallet, entry);
assert.match(first.signature, /^0x[0-9a-f]{130}$/i);

// What is on disk holds no secret in the clear.
const onDisk = JSON.stringify([...disk.values()]);
assert.ok(!onDisk.includes('abandon'), 'the phrase is not on disk');
assert.ok(!onDisk.includes(PASSWORD), 'the password is not on disk');

// Session 2: the extension restarts.
request = openSession(wasm);
assert.equal(await restore(request, store), entry);
await assert.rejects(sign(request, wallet, entry), /locked/, 'locked until the password is entered');
await assert.rejects(unlock(request, entry, 'wrong password!'), /wrong password/);
await unlock(request, entry, PASSWORD);
const second = await sign(request, wallet, entry);
assert.match(second.signature, /^0x[0-9a-f]{130}$/i, 'the restored wallet signs once unlocked');

// Lock wipes it; a tampered blob is refused.
await lock(request);
await assert.rejects(sign(request, wallet, entry), /locked/);
const blob = disk.get('vault').blob;
const tampered = blob.slice(0, 40) + (blob[40] === 'A' ? 'B' : 'A') + blob.slice(41);
await assert.rejects(request('Vault:load', 'POST', { Blob: tampered }).then(e => request(`Vault/${e.Id}:unlock`, 'POST', { Password: PASSWORD })));

// Secure (hardware) entries do not exist in a browser, and say so.
const caps = await request('Vault:capabilities', 'GET', {});
assert.equal(caps.Secure, false);

console.log('vault (browser extension flow): ok');
