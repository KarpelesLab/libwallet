# Storing secrets with libwallet

A wallet app holds secrets that unlock the user's funds: the StoreKey or
password a key share is sealed to, a recovery phrase, an MPC share. This guide
covers where those secrets should live, how libwallet's **vault** keeps them
out of your app's memory, and how to move an existing app onto it.

The short version:

- **Let libwallet hold the secret.** Create it in the vault (`client.vault`),
  refer to it by id, and the secret never enters Dart or JavaScript.
- **Use the device's secure storage when there is one.** That means the Secure
  Enclave or Keychain on iOS and macOS, and the Keystore (StrongBox or TEE) on
  Android, behind Face ID, Touch ID, fingerprint or passcode.
- **Without secure storage, use a password-sealed blob.** This covers browser
  extensions, the web, Linux and Windows. Only libwallet, given the password,
  can open the blob.
- **Always keep a recovery path.** Device-bound secrets are deliberately lost
  with the device.

---

## Why not keep secrets in the app?

| Where the secret lives | What can go wrong |
|---|---|
| A Dart `String` / JS string | Immutable: it can't be wiped. It stays in the heap until GC reuses the memory, gets copied by every string operation, and can end up in crash dumps, logs, `toString()`, and the debugger. |
| `flutter_secure_storage`, `localStorage` and friends | It's encrypted at rest, but the app reads the plaintext back into a `String` (see above) every time it uses it. |
| A file or preference you encrypt yourself | You now own the KDF, the nonce handling, the key storage and the format versioning. |

The vault replaces all of these with **use by reference**. The app passes an
entry id. libwallet unseals the secret inside Rust at the moment it's needed,
derives the key, uses it, and overwrites the memory. Request parameters are
overwritten after every request too, so a password the app had to pass in
doesn't stay in the parsed request.

## Concepts

**Entry**: one secret, created with `client.vault.create` (generated inside
libwallet: the preferred way) or `client.vault.import` (an existing secret,
for migration).

| Kind | Holds | Used as |
|---|---|---|
| `storekey` | 64 random bytes | The key a wallet share is sealed to: `KeyDescription.vault(id)` at wallet creation, `SigningKey.vault(…)` to unlock. Has a public key, so sealing a share to it never unseals it. |
| `password` | A password (generated: 256 random bits) | Unlocks `Password`-type shares. |
| `data` | Up to 64 KiB of opaque bytes | Read back only with `export` (if exportable). |

**Backend**: how the entry is sealed.

| Backend | Provider | Protection |
|---|---|---|
| `secure` | `apple-se` | A Secure Enclave P-256 key per entry; the data key is released by an ECDH that only the enclave can perform. |
| `secure` | `apple-keychain` | The same scheme with a Keychain key, on devices without an enclave (simulator, some Macs). |
| `secure` | `android-keystore` | An RSA-2048 Keystore key per entry, in StrongBox when present or the TEE otherwise; the data key is released by a decryption only the Keystore can perform. |
| `password` | `argon2id` | Argon2id (64 MiB, 3 passes) + XChaCha20-Poly1305; a portable blob. |

On every backend the entry's secret is encrypted by Rust with
XChaCha20-Poly1305. The platform only ever guards the 32-byte key that
decrypts it.

**Policy**: fixed at creation and sealed with the entry, so editing it in
the database makes the entry unopenable rather than weaker.

| Field | Default | Meaning |
|---|---|---|
| `userPresence` | `true` | Each unseal needs Face ID / Touch ID / fingerprint / device passcode (secure backend; enforced by the OS, not by libwallet). |
| `cacheSeconds` | `0` | `0`: unseal on every use. `N`: keep the unsealed secret in libwallet's memory for N seconds after `unlock`. `-1`: until `lock` or backgrounding. |
| `exportable` | `false` | Allow `export` to hand the secret to the app. |

## Choosing a setup

| Your host | Recommended |
|---|---|
| iOS / Android app | `secure` `storekey` entry with `userPresence: true` for each share the device holds. |
| macOS app (signed, sandboxed or not) | Same as iOS. |
| Linux / Windows desktop | `password` entry (no secure backend yet; `capabilities()` says so). |
| Browser extension, web page | `password` entry; store its `blob` and the wallet backup (see below). |
| Unsigned dev build / CI runner on macOS | `capabilities().secure` is false (no keychain entitlement); use `password` entries in tests. |

Always check first:

```dart
final caps = await client.vault.capabilities();
final backend = caps.secure ? 'secure' : 'password';
```

`caps.biometry` tells you what the prompt will be (`faceID`, `touchID`,
`opticID`, `biometric`, `passcode`, `none`), and `caps.hardware` whether the
keys live in dedicated hardware. `caps.reason` explains a `false`.

## Quick start (Dart)

```dart
// 1. A device key, created inside libwallet and protected by Face ID etc.
final device = await client.vault.create(kind: 'storekey', label: 'this device');

// 2. A 2-of-3 MPC wallet: one share sealed to the device entry, one held by
//    the WalletSign backend (RemoteKey), one sealed to a recovery password.
late Wallet wallet;
await for (final e in client.wallets.create(name: 'Main', keys: [
  KeyDescription.vault(device.id),          // no prompt: sealing uses the public key
  KeyDescription.remoteKey(remoteKeyId),
  KeyDescription.password(recoveryPassword), // shown to the user once, for backup
])) {
  if (e case Complete(:final value)) wallet = value;
}

// 3. Sign with the device share + the remote share. libwallet shows the OS
//    prompt with your reason text, then signs; nothing secret reaches Dart.
final sig = await client.accounts.signMessage(account.id,
    message: bytes,
    keys: [
      SigningKey.vault(wallet.keys[0].id, device.id, reason: 'Approve the payment').toJson(),
      // the remote share's unlock …
    ]);
```

Any request that takes `Keys` accepts `{Type: "Vault", Key: <entry id>}`:
wallet creation, signing, `Wallet/Key:recrypt` (`walletKeys.rekey`), resharing
and promotion. On the wire it looks like this:

```json
{"Type": "Vault", "Id": "<wallet key id, when unlocking>", "Key": "<vault entry id>",
 "Reason": "<optional prompt text>", "Password": "<password entries only, for this use>"}
```

### Prompts and caching

With the default policy every use prompts. A flow that signs several times
in a row (a batch, a multi-share MPC ceremony) can unlock once instead:

```dart
final entry = await client.vault.create(
    kind: 'storekey', policy: const VaultPolicy(cacheSeconds: 30));
await client.vault.unlock(entry.id, reason: 'Sign 3 transactions');
// … uses within 30 s don't prompt …
await client.vault.lock(entry.id); // or let it expire
```

Keep `cacheSeconds` short. **Tell libwallet when the app leaves the
foreground**. On `hidden`, `paused` or `detached` it wipes every cached
secret, whatever the policy, and dismisses any prompt still on screen.
`inactive` is ignored on purpose: iOS reports it while the Face ID sheet is
showing.

```dart
AppLifecycleListener(onStateChange: (s) => client.lifecycle.update(s.name));
```

A pending prompt also ends with a "user cancelled" error when you call
`vault.lock()`. On Android an unanswered prompt gives up after 5 minutes.

## Migrating an existing app

Run the migration once, on the first launch of the new version, then delete the
app's copies.

**A StoreKey the app kept** (from `storeKeys.create()`, in
flutter_secure_storage or similar):

```dart
final old = await secureStorage.read(key: 'storekey'); // the base64url `private`
final entry = await client.vault.import(kind: 'storekey', secret: old!);
assert(entry.publicKey == storedPublicKey);            // same key, same shares
await secureStorage.delete(key: 'storekey');
// From now on unlock with SigningKey.vault(walletKeyId, entry.id)
```

The shares don't change. They are still sealed to the same public key, and
only the place the private half lives moves.

**A password-protected share** (the user's password, or one the app stored):

```dart
final entry = await client.vault.create(kind: 'storekey');
await client.walletKeys.moveToVault(walletKeyId,
    from: KeyDescription.password(oldPassword), entryId: entry.id);
```

`moveToVault` re-seals the share to the entry's public key without
prompting. Do this for each share the device holds, and keep at least one
share recoverable without this device (see [Recovery](#recovery)).

**The web wallet's legacy `encrypt_blob` storage** (PBKDF2, decrypts the
phrase into JavaScript): decrypt it one last time, import the phrase sealed
to a password vault entry (as in the extension example below), store the new
blob, and delete the old one.

## Browser extensions and pages without secure hardware

A browser offers no secure element, so the only key is the user's
password. The pattern, implemented in
[`web/examples/vault-extension.mjs`](../web/examples/vault-extension.mjs)
and tested against the built WASM by `web/tools/test-vault.mjs`, is:

1. **First run:** `Vault:create` a `storekey` entry with
   `Backend: "password"`, the user's password and `Policy: {CacheSeconds: -1}`.
   Import or create the wallet with `Keys: [{Type: "Vault", Key: entry.Id}]`.
2. **Persist** the entry's `Blob` and `Wallet:backup` in `chrome.storage` or
   IndexedDB. Both are sealed and useless without the password; the phrase
   and the password never touch disk.
3. **Startup:** `Vault:load {Blob}`, then `Wallet:restore`. Nothing is unlocked yet.
4. **Unlock:** when the user types their password, `Vault/<id>:unlock {Password}`.
   The secret now lives only inside the WASM module's memory.
5. **Lock:** call `Vault:lock` on idle timeout, on "lock" in the UI, and when
   the service worker or popup closes.

Notes:

- The password has to pass through JavaScript once per unlock, because the
  user types it. Don't store it, don't log it, and clear the input field.
- `Vault/<id>:changePassword {Password, NewPassword}` re-seals the entry under
  a new password. Save the new blob afterwards.
- Argon2id defaults to 64 MiB × 3 passes (about a second in a browser). A host on
  weak hardware can lower it with `Kdf: {MemoryKiB, Iterations}` at creation,
  but not below OWASP's floor of 19 MiB × 2.
- The blob's cleartext header shows the entry's id, label, kind and policy, but not
  the secret. Don't put anything sensitive in `Label`.

## Platform requirements

### iOS / iPadOS

- **Add `NSFaceIDUsageDescription` to Info.plist** if any entry uses
  `userPresence`: iOS requires it before an app may use Face ID.
- A **device passcode** must be set for `userPresence` entries to be usable
  (`capabilities().biometry == 'none'` otherwise).
- Keys are `WhenUnlockedThisDeviceOnly`. They are never in iCloud Keychain,
  never in a backup, never restored to a new phone, and **deleted with the app**.
- The simulator has a Secure Enclave on recent runtimes; older ones use the
  Keychain fallback. Builds must be signed, ad-hoc being enough for the simulator
  (`CODE_SIGNING_ALLOWED=NO` builds have no keychain access).
- The podspec links `Security` and `LocalAuthentication`; nothing to add.

### macOS

- The app must be **signed with a keychain-access-groups entitlement** (any
  Xcode-signed app has one). Unsigned binaries and test runners get
  `secure: false` with that reason.

### Android

- **`MainActivity` must extend `FlutterFragmentActivity`**, which the system
  biometric prompt needs. A plain `FlutterActivity` works for entries
  without `userPresence`, but prompting fails with a message saying so.
- The plugin declares `USE_BIOMETRIC`; nothing to add to your manifest.
- `userPresence` entries need a **screen lock**. They accept strong biometrics
  or the device credential (PIN, pattern, password) on Android 11+, and strong
  biometrics only on 6–10.
- `userPresence` keys survive adding a fingerprint, but Android destroys
  them if the screen lock is removed. All keys go with the app's data
  (uninstall, "clear storage").
- Android 6.0 (API 23) or later; older devices report `secure: false`.

## Recovery

Everything the secure backend protects is **bound to one device and one
install**. That is the point, and it also means it's gone when the phone is lost,
reset, or the app is reinstalled. Before the user relies on a vault-protected
wallet, make sure at least one of these exists:

- another share of an MPC wallet that doesn't depend on this device: a
  `RemoteKey`, a share on a second device, or a share sealed to a recovery
  password the user wrote down;
- the recovery phrase of a single-key wallet, shown once and backed up by
  the user (`wallets.exportSecret` for imported wallets);
- a `password` vault entry's blob, stored somewhere the user controls.

Deleting a vault entry (`vault.delete`) destroys its device key immediately.
Any share sealed only to it is unrecoverable.

## Checklist

**Do**

- Create secrets in the vault (`create`); use `import` only for migration.
- Use `secure` entries with `userPresence: true` wherever `capabilities().secure`.
- Pass a meaningful `reason` ("Approve sending 0.5 ETH"): it's what the user
  sees in the prompt.
- Report app lifecycle changes (`lifecycle.update`) so backgrounding locks the vault.
- Keep `cacheSeconds` at 0, or short.
- Keep a recovery path that doesn't depend on this device.
- Delete the app's own copy of a secret as soon as it's imported.

**Don't**

- Keep secrets in Dart/JS strings, `SharedPreferences`, `localStorage` or logs.
- Create entries with `exportable: true` unless the user explicitly needs to
  see or move the secret, and gate `export` behind a confirmation.
- Put secrets in an entry's `label`.
- Treat a secure entry as a backup: it's the opposite of one.

## What libwallet does and doesn't guarantee

libwallet unseals secrets only inside Rust, wipes them (and the keys derived
from them) as soon as they're used, and wipes request parameters and raw
request strings once a request is answered. Some copies are outside its reach:

- **What the user types.** A password entered in a Flutter text field or an
  HTML input exists in Dart or JS before libwallet sees it.
- **The 32-byte data key on its way out of the platform.** iOS returns the
  ECDH result in a CoreFoundation buffer, which libwallet zeroes before
  releasing. On Android the Keystore returns the data key into the JVM, and both
  Java arrays that carry it are zeroed. The entry's secret itself is never
  decrypted outside Rust.
- **Copies the compiler or OS made.** That covers registers, spilled stack slots,
  swap and core dumps. Wiping narrows the window a secret lingers in memory; it
  doesn't defend against an attacker who can already read process memory.
- **Policy enforcement.** `userPresence` is enforced by the Secure Enclave or
  Keystore, so even libwallet can't skip it. `cacheSeconds` and `exportable`
  are enforced by libwallet and sealed into the entry, so they can't be loosened
  from outside.

## Endpoint reference

For hosts calling the request API directly (browser, native bridges):

| Endpoint | Params | Returns |
|---|---|---|
| `Vault:capabilities` | – | `{Secure, Hardware, Biometry, Provider, Reason?}` |
| `Vault:create` | `{Kind, Backend, Label?, Policy?, Password?, Kdf?}` | entry (+ `Blob` for password entries) |
| `Vault:import` | as create + `{Secret, Encoding?}` | entry |
| `Vault` GET | – | `[entry]` |
| `Vault/<id>` GET / DELETE | – | entry / `{Deleted}` |
| `Vault/<id>:unlock` | `{Password?, Reason?}` | `{Unlocked, Expires}` (Unix ms, null = until locked) |
| `Vault:lock` | `{Id?}` | `{Locked}` |
| `Vault/<id>:status` | – | `{Unlocked}` |
| `Vault/<id>:export` | `{Password?, Reason?}` | `{Secret}` (exportable entries only) |
| `Vault/<id>:blob` | – | `{Blob}` (password entries) |
| `Vault:load` | `{Blob}` | entry |
| `Vault/<id>:changePassword` | `{Password, NewPassword, Kdf?}` | entry |

An entry is `{Id, Label, Kind, Backend, Provider, Public?, Policy, Created}`.
