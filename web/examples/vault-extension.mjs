// Keeping a wallet in a browser extension (or any page without secure
// hardware) with libwallet's vault. The only protection available is the
// user's password, so:
//   - the wallet's key share is sealed to a vault entry, never to a key the
//     extension holds;
//   - the entry is a password-sealed blob (Argon2id), opened inside the WASM
//     module, so neither the password-derived key nor the secret ever
//     becomes a JavaScript value;
//   - what goes to disk (chrome.storage, IndexedDB…) is that blob and the
//     wallet backup, both useless without the password.
// Guide: docs/secret-storage.md. Exercised by web/tools/test-vault.mjs.

/** A `request(path, verb, params)` for one libwallet session. Throws on an error reply. */
export function openSession(wasm) {
  const handle = wasm.libwallet_init();
  return async (path, verb, params) => {
    const reply = JSON.parse(await wasm.libwallet_request(handle, JSON.stringify({ path, verb, params })));
    if (reply.result === 'error') throw new Error(reply.error);
    return reply.data;
  };
}

/**
 * First run: create the vault entry under `password`, import the user's
 * recovery phrase sealed to it, and persist both to `store` (an object with
 * async `get(key)` / `set(key, value)`, e.g. a chrome.storage.local wrapper).
 * The entry stays unlocked for this session. Returns the wallet.
 */
export async function setUp(request, store, password, mnemonic) {
  const entry = await request('Vault:create', 'POST', {
    Kind: 'storekey',
    Backend: 'password',
    Password: password,
    Label: 'extension',
    // Stay unlocked until lock() — the extension asks for the password once
    // per browser session, like a classic wallet extension.
    Policy: { CacheSeconds: -1 },
  });
  const wallet = await request('Wallet:importMnemonic', 'POST', {
    Name: 'Wallet',
    Curve: 'secp256k1',
    Mnemonic: mnemonic,
    Keys: [{ Type: 'Vault', Key: entry.Id }],
  });
  await request(`Vault/${entry.Id}:unlock`, 'POST', { Password: password });
  await store.set('vault', { entry: entry.Id, blob: entry.Blob });
  await save(request, store);
  return wallet;
}

/** Persist the wallets (their shares are sealed: safe at rest). */
export async function save(request, store) {
  await store.set('wallets', await request('Wallet:backup', 'GET', {}));
}

/**
 * Startup: bring the stored wallets and vault entry back into a fresh
 * session. Nothing is unlocked yet. Returns the entry id, or null on first run.
 */
export async function restore(request, store) {
  const saved = await store.get('vault');
  if (!saved) return null;
  await request('Vault:load', 'POST', { Blob: saved.blob });
  const wallets = (await store.get('wallets')) || [];
  if (wallets.length) await request('Wallet:restore', 'POST', { files: wallets });
  return saved.entry;
}

/** The user typed their password: unlock for the session (throws if wrong). */
export const unlock = (request, entry, password) =>
  request(`Vault/${entry}:unlock`, 'POST', { Password: password });

/** Idle timeout, "lock" button, browser closing: wipe the unlocked secret. */
export const lock = (request) => request('Vault:lock', 'POST', {});

/** The Keys a signing request takes: the vault entry stands for the share. */
export function vaultKeys(wallet, entry) {
  return [{ Type: 'Vault', Id: wallet.Keys[0].Id, Key: entry }];
}
