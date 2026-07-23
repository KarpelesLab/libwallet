#!/usr/bin/env node
// Wire purecrypto's wasm entropy import into the wasm-bindgen glue.
//
// purecrypto's wasm32-unknown-unknown OsRng backend imports a host function
// `purecrypto.random_get(ptr, len)` that the embedder MUST supply (typically
// crypto.getRandomValues). wasm-pack's generated glue only provides the `wbg`
// import module, so without this the module fails to instantiate with a
// LinkError. We add a `purecrypto` import that fills the wasm linear-memory
// range [ptr, ptr+len) from the browser CSPRNG, chunked to the 65536-byte
// crypto.getRandomValues limit.
//
// Injection is idempotent and anchored on the imports object the init flow
// builds, so it doesn't depend on the internal shape of the wbg module.

import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2] || 'web/pkg/libwallet.js';
let src = readFileSync(file, 'utf8');

if (src.includes('imports.purecrypto')) {
  console.log(`inject-entropy: already wired in ${file}, skipping`);
  process.exit(0);
}

const anchor = 'const imports = __wbg_get_imports();';
if (!src.includes(anchor)) {
  console.error(`inject-entropy: anchor not found in ${file} — wasm-bindgen glue shape changed`);
  process.exit(1);
}

const shim = `${anchor}
    // purecrypto's wasm OsRng imports this host entropy function; supply it
    // from the browser CSPRNG (see web/tools/inject-entropy.mjs).
    imports.purecrypto = {
        random_get(ptr, len) {
            const view = new Uint8Array(wasm.memory.buffer, ptr >>> 0, len >>> 0);
            for (let off = 0; off < view.length; off += 65536) {
                crypto.getRandomValues(view.subarray(off, Math.min(off + 65536, view.length)));
            }
        },
    };`;

src = src.split(anchor).join(shim);
writeFileSync(file, src);
console.log(`inject-entropy: wired purecrypto.random_get into ${file}`);
