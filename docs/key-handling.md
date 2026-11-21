# Key handling: the standard 2-of-3 wallet

This guide is the reference layout for libwallet wallets. Every host (iOS,
Android, desktop, browser) should follow it so that wallets behave the same
everywhere, backups made by one app restore in another, and nobody ends up with
a wallet that can't sign.

Related guides:

- [secret-storage.md](secret-storage.md): the vault, platform requirements, and
  where secrets live on each host.
- [dart/doc/device_share.md](../dart/doc/device_share.md): device-to-device
  transfer, and more detail on the RemoteKey session lifecycle.

---

## The layout

A wallet is a threshold (MPC) committee of **3 shares with `Threshold: 1`**.

> **About the numbers:** libwallet's `Threshold` is the TSS threshold *t*. A
> signature needs **t + 1** shares. `Threshold: 1` with 3 shares therefore
> means **any 2 of the 3 shares can sign** (or reshare). Older docs call this
> "1-of-3", which is the same thing.

| # | Share | Wallet key `Type` | Where it lives | How it's protected | In a backup? |
|---|---|---|---|---|---|
| 1 | **Device share** | `StoreKey` | This device | Sealed to a `storekey` vault entry on the `secure` backend: Secure Enclave, Keychain or Android Keystore, behind Face ID / fingerprint / passcode | The blob is, but it can't be opened anywhere else. **Not recoverable.** |
| 2 | **Password share** | `Password` | This device | Sealed to a key derived from the user's password (Argon2id, salted with the wallet key id; see [Password KDF](#password-kdf)). At least 8 characters. The password can be remembered in the vault if the user agrees (see below). | **Yes.** Opens anywhere with the password. |
| 3 | **Remote share** | `RemoteKey` | Tibane's WalletSign servers (the wdrone fleet) | Encrypted to the fleet's keys, which are held in physical TPMs. Released for a ceremony only after 2FA (SMS / email code, or a passkey). | The wallet keeps a fleet-encrypted copy, used only by `Wallet:repairRemoteKey`. |

What each pair of shares means:

| Shares used | When | Notes |
|---|---|---|
| Device + Password | Everyday signing, offline | No server round-trip. |
| Device + Remote | Everyday signing without typing the password; password reset | Needs network + 2FA. |
| Password + Remote | **Restore on a new device** | The only pair that survives losing the device. |

Losing one share is always recoverable through the other two (see
[Restore](#restore)). Losing two shares, for example the device *and* the
password, is a lockout: Tibane's share alone can't sign, by design.

### Creating the wallet

```dart
// 1. Device share: generated inside libwallet, sealed by the Secure Enclave
//    or Keystore. Check capabilities first (see secret-storage.md).
final caps = await client.vault.capabilities();
final device = await client.vault.create(
  kind: 'storekey',
  backend: caps.secure ? 'secure' : 'password',
  password: caps.secure ? null : devicePassword, // browser/desktop fallback
  label: 'device share',
);

// 2. Remote share: 2FA with the WalletSign backend.
final s = await client.remoteKeys.create(email: userEmail);
final v = await client.remoteKeys.validate(session: s.session, code: code);

// 3. The committee. Create the secp256k1 and ed25519 wallets together
//    (Wallet:multiCreate) when the app supports both curve families.
await for (final e in client.wallets.create(name: 'Main', keys: [
  KeyDescription.vault(device.id),       // device share
  KeyDescription.password(userPassword), // password share
  KeyDescription.remoteKey(v.remoteKey), // remote share
])) { /* Progress … Complete(wallet) */ }

// 4. Take a backup straight away (see below).
```

On the wire, wallet creation is `POST Wallet {Name, Curve, Keys: [...]}`
(`Threshold` is 1 for every new wallet) or `Wallet:multiCreate {Name, Keys}`.

On hosts without secure hardware (browser, Linux, Windows), the device share
is sealed to a `password`-backend vault entry and its blob is persisted by the
app. That protects less than an enclave, so treat it as a weaker setup and
keep the rest of the flow unchanged. See
[secret-storage.md](secret-storage.md#browser-extensions-and-pages-without-secure-hardware).

## Remembering the password in the enclave

If the user agrees, the app may keep the wallet password in the vault so that
signing only needs Face ID / fingerprint instead of typing it. Do it by
**importing the password the user chose** into a `secure` `password` entry:

```dart
final pw = await client.vault.import(
  kind: 'password',
  backend: 'secure',
  secret: userPassword,
  label: 'wallet password',
);
// Sign with the device share + the password share, one biometric prompt each
// (or one, with a short cacheSeconds; see secret-storage.md).
keys: [
  SigningKey.vault(deviceKey.id, device.id, reason: 'Approve the payment').toJson(),
  SigningKey.vault(passwordKey.id, pw.id, reason: 'Approve the payment').toJson(),
]
```

The share itself stays sealed to the password, not to the enclave, so it still
opens from a backup on another device with the password the user typed.

Rules:

- **Ask first and say what it means.** With the password in the enclave,
  whoever passes the device's biometric/passcode check holds full signing
  authority, without the server. Most single-key wallets work like this, so
  it's acceptable, but it must be the user's choice.
- **Import the user's password. Don't generate one.** `vault.create(kind:
  'password')` makes a random password that nobody knows. A Password share
  sealed to it is lost with the device just like the device share, which
  leaves the backup with only the remote share, and the wallet can't be
  restored.
- The user must still remember (or write down) the password: it's what
  restores the wallet.
- When the password changes (`walletKeys.recrypt`), re-import it into the
  vault and delete the old entry.

## Password KDF

Every Password share **records how its key was derived**: a cleartext `kdf`
header on the sealed share, for example `argon2id$v=19$m=65536,t=3,p=1`. It
travels with the share everywhere the share goes (database, backup, device
transfer), and libwallet derives the key with exactly those parameters. This
is what keeps compatibility incremental: the cost of new shares can go up in a
later release without breaking any share sealed before it, and a share naming
a scheme the running libwallet doesn't know fails with an "update libwallet"
error, not a bogus "wrong password". The header isn't secret and doesn't need
to be authenticated: altered parameters derive a key that doesn't open the
share. Parameters read from a share are bounded (Argon2 memory ≤ 1 GiB, ≤ 16
passes) before any memory is spent, since a backup is untrusted input.

New shares get **Argon2id** (64 MiB, 3 passes), the same cost as the vault's
password backend: about 0.1 s natively and up to a second in a browser, per
derivation. Every place a Password share is *created* uses it: wallet
creation, reshare, promote, import and the target side of `recrypt`. Sealing
refuses passwords shorter than **8 characters**.

Shares without the header predate it, and still open:

| Sealed by | KDF | How libwallet tells |
|---|---|---|
| libwallet before 0.5.11, Go wltwallet | PBKDF2-SHA256, 4,096 iterations: cheap to brute-force offline | The PBKDF2 key matches the share's recorded public key (`key`) |
| libwallet 0.5.11 | Argon2id 64 MiB × 3, not recorded | Otherwise |
| libwallet 0.5.12 and later | Whatever the `kdf` header says | The header |

Old shares open with the same password, even one shorter than 8 characters,
and old backups restore.

`walletKeys.verify` reports a share's `kdf`, its exact `kdfParams`, and
`kdfUpgrade` when they differ from what new shares get. Re-seal such a share
to the same password:

```dart
final c = await client.walletKeys.verify(key.id, key: KeyDescription.password(pw));
if (c.valid && c.needsKdfUpgrade) {
  await client.walletKeys.recrypt(key.id, oldPassword: pw, newPassword: pw);
}
```

A password shorter than 8 characters can't be re-sealed: ask the user for a
new one (`newPassword`). A good moment for this is the next time the user types
the password. After the upgrade, take a new backup (see below): the previous
backup still holds the old copy.

**Compatibility:** libwallet older than 0.5.11 can't open Argon2id shares, and
0.5.11 ignores the `kdf` header (it assumes its own fixed cost, which is what
0.5.12 writes today). A backup made by an up-to-date app may not restore its
Password share in an app on an older libwallet.

## Backup

`Wallet:backup` (`client.wallets.backup(id)`) returns, per wallet, the public
material (pubkey, chain code, accounts) and the sealed blob of **every** share.
It holds nothing that signs on its own, so it is safe to put in iCloud, Drive,
a file the user saves, or Tibane's backup storage.

What a backup can bring back on another device:

| Share | After restoring elsewhere |
|---|---|
| Device | ❌ Its vault key never leaves the original device. This is expected. |
| Password | ✅ With the user's password. |
| Remote | ✅ Still on Tibane's servers, after 2FA. |

Password + Remote is 2 shares, enough to reshare, so a backup is always enough
to recover the wallet as long as the user knows the password and can pass 2FA.

The other side of this: someone who has the backup, the password and the
user's 2FA (their phone or mailbox) has the wallet. A backup lets an attacker
guess passwords offline, which Argon2id slows down but can't stop for a weak
password. So encourage a real password (8 characters is only libwallet's
floor), and store backups where only the user can read them.

**Back up again after any change to the key material.**

- A **reshare** replaces every share. Backups made before it can't restore the
  wallet any more: replace them, and tell the user old backup files are
  useless.
- A **`recrypt`** (password change, KDF upgrade) re-seals the same share. An
  old backup still restores, *with the old password*, and keeps the old
  KDF. Replace it so an old or leaked password stops working.
- A **`repairRemoteKey`** changes the server's copy, not the local shares, but
  back up anyway so the stored backup matches what the server holds.

Don't add the device share's secret to the backup. If a user really wants a
backup that skips the reshare, that's the opt-in manual transfer described in
[device_share.md](../dart/doc/device_share.md#when-to-export-the-device-share-with-the-backup--the-manual-transfer-case).
For two devices the user holds at the same time, use `Wallet:exportToDevice`.

## Restore

After `Wallet:restore`, **check every local share before offering any signing
UI**. If either local share is unusable, reshare the wallet onto fresh local
shares straight away. The wallet's public key, and so every address, survives
the reshare: funds don't move.

### 1. Check the local shares

For each restored wallet, check its local keys (`wallet.keys`) with
`walletKeys.verify` (`Wallet/Key/<id>:verify`). It changes nothing.

| Share | Check | Usable when |
|---|---|---|
| `StoreKey` | `verify(key.id)`, no key | `valid`: a vault entry on this device holds the share's key (`entryId` names it). Nothing is unsealed and there's no prompt. On a new device, or after a reinstall, it's `false`. |
| `Password` | `verify(key.id, key: KeyDescription.password(p))`, or `KeyDescription.vault(pwEntry.id)` if the password is remembered in the vault | `valid`: the share opened with that password. `needsKdfUpgrade` means it should be [re-sealed](#password-kdf). |
| `RemoteKey` | Not checked up front: it costs the user a 2FA code. It's used in step 2. | |

```dart
final device = wallet.keys.firstWhere((k) => k.type == 'StoreKey');
final pass = wallet.keys.firstWhere((k) => k.type == 'Password');
final deviceOk = (await client.walletKeys.verify(device.id)).valid;
final passCheck = await client.walletKeys.verify(pass.id,
    key: KeyDescription.password(userPassword));
```

The no-key StoreKey check proves the vault entry exists, not that the OS key
behind it still works (Android destroys it when the screen lock is removed).
To be certain, verify with the entry, `key: KeyDescription.vault(entryId)`,
which decrypts the share at the cost of a prompt. A wrong key gives
`valid: false`; a cancelled prompt throws. Apps that still keep StoreKeys
themselves pass `KeyDescription.storeKey(private)`.

If both local shares are usable (a restore on the same device and install), the
wallet is ready.

### 2. Reshare onto fresh local shares

Otherwise, use two working shares as the old committee and three fresh shares
as the new one. Usually the device share is the one missing:

```dart
final wallet = await client.wallets.get(walletId);
final remote = wallet.keys.firstWhere((k) => k.type == 'RemoteKey');
final pass   = wallet.keys.firstWhere((k) => k.type == 'Password');

// a. A fresh RemoteKey session. The one stored on the wallet is `done` and
//    can't be reused. Get one per wallet, and reshare wallets one at a time
//    (see below).
final s = await client.remoteKeys.reshare(key: remote.key);
final v = await client.remoteKeys.validate(session: s.session, code: code);

// b. A new device share for this device.
final device = await client.vault.create(kind: 'storekey', label: 'device share');

// c. Reshare. Exactly two old shares (t + 1). The new RemoteKey session goes
//    on BOTH the old and the new remote descriptor.
await for (final e in client.wallets.reshare(wallet.id,
  oldKeys: [
    KeyDescription(type: 'RemoteKey', id: remote.id, key: v.remoteKey),
    KeyDescription(type: 'Password',  id: pass.id,   key: userPassword),
  ],
  newKeys: [
    KeyDescription.vault(device.id),
    KeyDescription.password(userPassword),
    KeyDescription.remoteKey(v.remoteKey),
  ],
)) { /* Progress … Complete(wallet) */ }
```

The `Password` descriptors carry **the password itself**, not a derived
public key. libwallet derives the sealing key from it and the wallet key id.

The same shape covers the other single-share losses:

| Missing | Old committee | New committee |
|---|---|---|
| Device share (new phone, reinstall) | Password + Remote | new device entry, same password, Remote |
| Password (user forgot it) | Device + Remote | same device entry or a new one, **new** password, Remote |
| Remote share (server desync) | Run `Wallet:repairRemoteKey` first, then Device + Password if a reshare is still needed | Device, Password, Remote (fresh session) |

For a password reset, prove the user's identity through the 2FA step. It is
the only thing standing in for the forgotten password.

**Several wallets** (the secp256k1 + ed25519 pair from `Wallet:multiCreate`
share one RemoteKey): reshare them **one after the other, each with its own
fresh `remoteKeys.reshare` + `validate` session**, so the user enters one 2FA
code per wallet. Don't reuse a session across wallets or run two reshares at
once: the signing fleet keeps one ceremony per session, and a session used for
one reshare is expected to be `done` by the next.

### 3. Verify, then back up

After the reshare completes:

1. Run the step 1 checks again on the **new** wallet keys: `verify` the new
   device share with the new vault entry and the new Password share with the
   password. Don't offer signing until both are `valid`.
2. Delete the vault entries the wallet no longer uses (the old device entry,
   if this device had one).
3. Take a new backup and replace the old one. Backups made before the reshare
   can no longer restore the wallet.

If the reshare fails, report what failed: a wrong or expired 2FA code, a
password that didn't unlock the share, or the WalletSign backend being
unreachable. Then retry. A failed reshare leaves the wallet as it was, so
retrying is safe. If a retry stalls with "participant stopped responding",
the server's remote share may be out of sync with the wallet: run
`Wallet:repairRemoteKey` with its own fresh session, then reshare again (see
the `repairRemoteKey` doc comment in `dart/lib/src/api/wallet_api.dart`).

## Implementor checklist

- [ ] New wallets: 3 shares (device in the vault, password, RemoteKey),
      `Threshold: 1`.
- [ ] Device share: `secure` vault `storekey` entry with `userPresence`;
      `password` backend only where `capabilities().secure` is false.
- [ ] Password remembered in the enclave only with the user's consent, and
      only by **importing** the password they chose.
- [ ] Backup right after creation, and again after every reshare, recrypt or
      RemoteKey repair.
- [ ] On restore: `walletKeys.verify` both local shares; if either is
      unusable, reshare with two working shares onto three fresh ones (one
      fresh RemoteKey session per wallet, one wallet at a time), verify the
      new local shares, back up again. No signing UI until then.
- [ ] Password shares with `needsKdfUpgrade`: re-seal them (`recrypt` to the
      same password, or a new one if it's under 8 characters), then back up.
- [ ] Never put a device share secret in a default backup.
- [ ] Tell the user plainly that losing both the device and the password
      loses the wallet.
