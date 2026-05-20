# Device share — backup, restore, and rotation

libwallet wallets are 1-of-3 threshold-signed: every new wallet
holds three key shares — `StoreKey` + `RemoteKey` + `Password` —
and any two of them can sign or reshare. The `StoreKey` share is
the **device share**: its private key never leaves the device's
secure storage (iOS Keychain, Android Keystore, equivalent on
desktop) and is the only one of the three the host app owns
end-to-end.

This guide explains why the device share is deliberately excluded
from `Wallet:backup`, what implementors must do at restore time,
and the narrow case where exporting the device share alongside the
backup is appropriate.

## Mental model — three shares, three custodians

| Share | Custodian | Survives a fresh install? |
|---|---|---|
| `StoreKey` (device share) | OS secure storage on the device | ❌ no — wiped with the app |
| `RemoteKey` (server share) | WalletSign backend, reached over Spot | ✅ yes |
| `Password` (knowledge share) | Re-derivable from the user's password | ✅ yes |

A `Wallet:backup` JSON carries the encrypted blob of every share
plus the public material the wallet needs (chain code, address,
protocol, etc.). It does **NOT** carry the device share's private
key — because libwallet never has that key. The host app stored it
in the platform keystore at wallet-creation time; libwallet only
ever sees its public half.

This is by design. The device share is the "something you have"
factor; bundling its private key into the same blob as everything
else collapses the 1-of-3 into a 1-of-2 and removes the security
boundary that makes the device share useful in the first place.

## Restoring a backup on a fresh device — auto-rotation

After `Wallet:restore`, the device share's encrypted blob is back
on disk but the matching private key isn't — the OS keystore on
this device never held it. The wallet has 2 of 3 reachable shares
(`RemoteKey` + `Password`), which is **exactly T+1 for the 1-of-3
committee**, so the right response is to **reshare immediately
with a freshly-minted `StoreKey`** before the user signs anything.
This is sometimes called "device-share rotation".

Reference flow:

```dart
// 1. User restored the wallet JSON via Wallet:restore. Try to load
//    the device share from your OS keystore — it won't be there.
final devicePriv = await keystore.readDeviceShare(password: password);
if (devicePriv != null) {
  // Happy path — backup was made before app data was wiped on the
  // SAME device, or user used the opt-in transfer flow (below).
  return; // device share is reachable, sign normally.
}

// 2. Mint a fresh device-share pair for this device.
final freshPair = await client.storeKeys.create();
// freshPair = { private: <64-byte base64>, public: <X.509 PKIX b64> }
await keystore.writeDeviceShare(value: freshPair.private, password: password);

// 3. Reshare to a NEW committee with the same shape, swapping in the
//    fresh StoreKey public. oldKeys lists the two reachable shares
//    (Remote + Password); newKeys lists the new committee.
await client.wallets.reshare(
  walletId: wallet.id,
  old: [
    KeyDescription(id: remoteWalletKeyId, type: 'RemoteKey', key: remoteSessionKey),
    KeyDescription(id: passwordWalletKeyId, type: 'Password', key: passwordPublicForKeyId),
  ],
  newKeys: [
    KeyDescription(type: 'StoreKey', key: freshPair.public),
    KeyDescription(type: 'RemoteKey', key: remoteSessionKey),
    KeyDescription(type: 'Password', key: passwordPublicForKeyId),
  ],
);

// 4. Wallet.modified is now newer; the wallet's address (Pubkey /
//    Chaincode) is preserved by the reshare, so existing
//    on-chain assets stay where they are.
```

Reshare preserves the public key — every address derived from the
wallet stays the same. The user does not need to move funds.

### Why rotate instead of carrying the old encrypted device share forward

The encrypted blob is still on disk after restore, but the private
key that decrypts it isn't. Keeping the blob around buys nothing
(it's unreadable) and confuses telemetry that uses
`WalletKey.Id` to identify the device share. Rotating it out via
reshare gives you a clean 3-share committee whose IDs all reflect
the keys you actually hold.

### What if reshare fails?

A reshare can fail if either `RemoteKey` (server unreachable) or
`Password` (user mistyped) is currently unusable. Surface a
specific error per failure mode — "couldn't reach WalletSign
backend, try again on a stable connection" vs. "password didn't
unlock the wallet" — and retry. Do **not** prompt the user to
"restore from another backup"; that's a different remediation
that only applies when the wallet itself is gone, not just one of
its shares.

## When to export the device share with the backup — the manual transfer case

There's one legitimate case for including the device share's
private key in a user-facing backup file: **the user is migrating
to a new device and wants to skip the reshare ceremony**.

UX shape:

```
[ ] Include device share (for transferring to a new device)

   Without this, restoring this backup on another device will
   trigger a one-time refresh that rotates your device share. With
   this, the backup acts like a copy of your current device — but
   anyone who reads the file can use your wallet as if they had
   your phone.
```

Implementation notes for hosts that want to offer this:

- The device share private key is owned by your app — libwallet
  doesn't store it. Read it from your platform keystore at backup
  time.
- Wrap it with a password-derived KDF (the user's wallet password
  is the obvious choice — pbkdf2 against `WalletKey.Id.UUID` as
  the salt mirrors `StoreKey:derivePassword`'s shape).
- Bundle the wrapped device share alongside the `Wallet:backup`
  output in a single user-facing file. On restore, decrypt with
  the password and write to the platform keystore **before**
  calling `Wallet:restore` — that way the unlock-after-restore
  path finds the share without falling into the auto-rotation
  branch above.
- Make the checkbox **opt-in**, default off. A backup file that
  contains the device share is a single-factor secret; treat it
  like a seed phrase in your UX (warn loudly, push the user to an
  encrypted destination, never auto-upload).
- If the user backs up and shares the file with the device-share
  included, they've effectively turned the wallet into a 1-of-2
  for the lifetime of that file. Suggest they rotate after the
  transfer is complete by deleting the file.

The auto-rotation path is the default for a reason — it preserves
the three-share security model. Manual transfer is a power-user
escape hatch.

## Wallet-state checklist for implementors

When wiring backup / restore in your host app:

- [ ] `Wallet:backup` calls return a JSON that is **safe to back
      up to iCloud / Drive / a flash drive** — there's nothing
      single-factor in it. The wallet is still 1-of-3 after
      restore.
- [ ] At restore time, attempt to read the device share from
      platform keystore. If absent, run the rotation flow above
      **before** the user is offered any signing UI.
- [ ] Surface a clear error when neither the device share is
      present **nor** the user can authenticate against Remote +
      Password. This is the only true lockout, and it shouldn't
      happen for a healthy wallet — it means either the wallet
      backup is corrupt or the user lost both their password and
      their server account.
- [ ] If you implement the opt-in transfer export, gate it behind
      an explicit confirmation, default off. The default
      backup MUST stay device-share-free.

## Why libwallet's design refuses to back up the device share

Three concrete reasons:

1. **Defense in depth.** The whole point of a 1-of-3 split is
   that compromise of any single share doesn't compromise the
   wallet. The device share is the share an attacker has to
   physically reach the phone to get; making it backupable
   removes that physical requirement.
2. **Custody layering.** The `RemoteKey` lives on the server, the
   `Password` lives in the user's head, the `StoreKey` lives on
   the device. Each custodian can be revoked independently
   (rotate password, rotate server session, wipe device). A
   backup that includes all three shares collapses this into a
   single secret.
3. **The auto-rotation path is fast.** Reshare in libwallet ≥
   0.4.35 runs DKLs23 / FROST end-to-end against the server in
   well under a second. The cost of doing it on every fresh-
   device restore is small compared to the security loss of
   bundling the device share into every backup file.
