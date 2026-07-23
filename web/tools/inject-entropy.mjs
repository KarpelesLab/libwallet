#!/usr/bin/env node
// Wire purecrypto's wasm entropy import into the wasm-bindgen glue.
//
// purecrypto's wasm32-unknown-unknown OsRng backend imports a host function
// `purecrypto.random_get(ptr, len)` that the embedder MUST supply (typically
// crypto.getRandomValues). wasm-bindgen (--target web) handles this by emitting
// a bare ES import `import * as importN from "purecrypto"` at the top of the
// glue and passing it as the `purecrypto` import object. That bare specifier is
// UNRESOLVABLE without a bundler or import map, so the module fails to load in a
// plain browser. We do two things, both idempotent:
//   1. Replace the bare `import * as importN from "purecrypto"` with a local
//      `const importN = {}` stub so the module loads.
//   2. Override `imports.purecrypto` with a real `random_get` that fills the
//      requested wasm linear-memory range from the browser CSPRNG (chunked to
//      the 65536-byte crypto.getRandomValues limit).

import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2] || 'web/pkg/libwallet.js';
let src = readFileSync(file, 'utf8');
let changed = false;

// (1) Neutralize the unresolvable bare purecrypto import → local stub.
const bareImport = /import \* as (\w+) from ['"]purecrypto['"];?/;
const m = src.match(bareImport);
if (m) {
  src = src.replace(bareImport, `const ${m[1]} = {}; // purecrypto host import neutralized (see inject-entropy.mjs)`);
  changed = true;
}

// (2) Provide random_get at runtime.
if (!src.includes('imports.purecrypto =')) {
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
  changed = true;
}

if (changed) {
  writeFileSync(file, src);
  console.log(`inject-entropy: wired purecrypto entropy + neutralized bare import in ${file}`);
} else {
  console.log(`inject-entropy: already wired in ${file}, skipping`);
}
