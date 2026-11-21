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
| 2 | **Password share** | `Password` | This device | Sealed to a key derived from the user's password (PBKDF2-SHA256, salted with the wallet key id). The password can be remembered in the vault if the user agrees (see below). | **Yes.** Opens anywhere with the password. |
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
user's 2FA (their phone or mailbox) has the wallet. The Password share's KDF is
PBKDF2-SHA256 with 4,096 iterations, which is cheap to brute-force offline. So
require a real password (libwallet's floor is 6 characters, far too low), and
store backups where only the user can read them.

**Back up again after any change to the key material.** A reshare, a
`recrypt` (password change) or a `repairRemoteKey` changes the shares, and an
older backup holds shares that no longer match the server's or each other's.
Replace the stored backup after each of these, and tell the user that old
backup files are now useless.

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

For each restored wallet, look at its keys (`wallet.keys`). A wallet key's
`key` field is the public key its share is sealed to (base64url PKIX), so the
checks need no secret and no prompt:

| Share | Usable when |
|---|---|
| `StoreKey` | Some vault entry on this device has `publicKey == walletKey.key` (`client.vault.list()`). On a new device, or after a reinstall, there won't be one. Legacy apps that kept StoreKeys themselves: their keystore holds the matching private key. |
| `Password` | The user enters the password and `storeKeys.derivePassword(password: p, walletKeyId: walletKey.id)` equals `walletKey.key`. If the password is remembered in the vault, the entry must exist on this device too. |
| `RemoteKey` | Not checked up front: it costs the user a 2FA code. It's used in step 2. |

A vault entry that exists can still fail to unseal, for example on Android
after the screen lock was removed. When unsure, `vault.unlock(entry.id)`
proves it, at the cost of a prompt.

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
//    can't be reused. Do this for each wallet you reshare.
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

### 3. Verify, then back up

After the reshare completes:

1. Run the step 1 checks again on the **new** wallet keys: the device share's
   key matches the new vault entry, and the password derives to the new
   Password key. Don't offer signing until both pass.
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
- [ ] On restore: check both local shares; if either is unusable, reshare
      with two working shares onto three fresh ones, verify the new local
      shares, back up again. No signing UI until then.
- [ ] Never put a device share secret in a default backup.
- [ ] Tell the user plainly that losing both the device and the password
      loses the wallet.
