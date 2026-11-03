// Signing a serialized Solana transaction with libwallet in the browser. Your
// code builds the transaction (a swap from an aggregator, an SPL transfer) and
// gets the user's approval; libwallet adds the account's signature and leaves
// the message alone. Used by solana-sign.html and web/tools/test-solana-sign.mjs.
// Request and response format: docs/solana-signing.md

/** A `request(path, verb, params)` for one libwallet session. Throws on an error reply. */
export function openSession(wasm) {
  const handle = wasm.libwallet_init();
  return async (path, verb, params) => {
    const reply = JSON.parse(await wasm.libwallet_request(handle, JSON.stringify({ path, verb, params })));
    if (reply.result === 'error') throw new Error(reply.error);
    return reply.data;
  };
}

/** The bytes of a base64 string. */
export const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

/** The base64 string of some bytes. */
export const toBase64 = bytes => btoa(String.fromCharCode(...bytes));

/** The message of a serialized transaction: what the user approves and signers sign. */
export function messageOf(tx) {
  let count = 0, length = 0, byte;
  do {
    byte = tx[length];
    count |= (byte & 0x7f) << (7 * length++);
  } while (byte & 0x80);
  return tx.subarray(length + count * 64);
}

/**
 * Sign a base64 serialized transaction (legacy or v0) with an account, and
 * return it ready to broadcast, as `{transaction (base64), raw (base58), signature}`.
 * `keys` unlocks the account's shares. Fails if the message comes back changed,
 * since it would no longer be what the user approved.
 */
export async function signSolanaTransaction(request, accountId, keys, transaction) {
  const signed = await request('Account:signTransaction', 'POST', {
    Id: accountId,
    Keys: keys,
    Transaction: transaction,
  });
  const approved = messageOf(fromBase64(transaction));
  const returned = messageOf(fromBase64(signed.transaction));
  if (approved.length !== returned.length || approved.some((b, i) => b !== returned[i])) {
    throw new Error('signed message differs from the approved one');
  }
  return signed;
}

/**
 * A throwaway 2-of-3 MPC wallet and its Solana account, held in this session's
 * memory only. A real app has its own wallet: `keys` is then whichever shares
 * the user unlocked.
 */
export async function createDemoAccount(request) {
  const secrets = ['demo-password-one', 'demo-password-two', 'demo-password-three'];
  const wallet = await request('Wallet', 'POST', {
    Name: 'demo',
    Curve: 'ed25519',
    Keys: secrets.map(Key => ({ Type: 'Password', Key })),
  });
  const account = await request('Account', 'POST', { Wallet: wallet.Id, Type: 'solana', Index: 0 });
  return {
    account,
    keys: [0, 1].map(i => ({ Type: 'Password', Id: wallet.Keys[i].Id, Key: secrets[i] })),
  };
}

/**
 * Stands in for your transaction builder: an unsigned v0 transaction paid by
 * `payer` (32 bytes), with one instruction and an address lookup table. Its
 * program and blockhash are placeholders, so it cannot land on chain.
 */
export function demoTransaction(payer) {
  const fill = (n, v) => new Array(n).fill(v);
  const message = [
    0x80, 1, 0, 1, 2,                  // v0; 1 signer, 0 + 1 read-only; 2 keys
    ...payer, ...fill(32, 0x42),       // fee payer, program
    ...fill(32, 0x09),                 // recent blockhash
    1, 1, 1, 0, 3, 0xde, 0xad, 0xbe,   // 1 instruction: program 1, account 0, 3 bytes
    1, ...fill(32, 0x77), 1, 0, 0,     // 1 lookup table: writable [0], read-only []
  ];
  return toBase64(Uint8Array.from([1, ...fill(64, 0), ...message])); // 1 empty signature
}
