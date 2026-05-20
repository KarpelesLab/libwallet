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

### The non-obvious step: the wallet's stored RemoteKey session is `done`

Before getting into the code, one trap that has burned every host
that's wired this flow: the `crws-…:crwsv-…` resource id stored
on the wallet's RemoteKey share (`WalletKey.key`) is **the
identifier of the original keygen session, which the server
marked `done` once the wallet was created**. You can't reshare
against a `done` session — the server rejects the OLD-committee
RemoteKey participant with:

```
failed to start remote peer wkey-…: failed to init remote:
invalid status for wallet sign session: done
```

The fix is to run `RemoteKey:reshare` + `RemoteKey:validate`
**first**, which mints a fresh session and returns its new
`crws-…:crwsv-NEW` resource id. That new id replaces the old one
in the wallet's RemoteKey share — and crucially, **it must be
passed on both the old-committee and new-committee RemoteKey
descriptors when calling `Wallet:reshare`**. See
`RemoteKeyValidation.remoteKey`'s docstring for the explanation
of the server-side session lifecycle.

### Reference flow

```dart
// 1. User restored the wallet JSON via Wallet:restore. Try to load
//    the device share from your OS keystore — it won't be there.
final devicePriv = await keystore.readDeviceShare(password: password);
if (devicePriv != null) {
  // Happy path — backup was made before app data was wiped on the
  // SAME device, or user used the device-transfer flow (below).
  return; // device share is reachable, sign normally.
}

// 2. Mint a NEW RemoteKey session. This sends an SMS/email code
//    to the user; once they enter it and validate, we get a fresh
//    crws-…:crwsv-NEW id that supersedes the wallet's stored one.
//    NOTE: key must be WalletKey.key (the crws-…:crwsv-… string),
//    NOT WalletKey.id (the wkey-… uuid).
final wallet = await client.wallets.get(walletId);
final oldRemoteKey = wallet.keys.firstWhere((k) => k.type == 'RemoteKey');
final remoteSession = await client.remoteKeys.reshare(
  key: oldRemoteKey.key,     // ← the crws-…:crwsv-… resource id
  curve: wallet.curve,
);

// 2a. Prompt the user for the code, then validate.
final validation = await client.remoteKeys.validate(
  session: remoteSession.session,
  code: userEnteredSmsCode,
);
final newRemoteKey = validation.remoteKey;   // crws-…:crwsv-NEW

// 3. Mint a fresh device-share pair for this device.
final freshPair = await client.storeKeys.create();
// freshPair = { private: <64-byte base64>, public: <X.509 PKIX b64> }
await keystore.writeDeviceShare(value: freshPair.private, password: password);

// 3a. Derive the Password share's pubkey for this wallet's WalletKey
//     id (the password's pubkey is salted with the WalletKey uuid
//     server-side — see StoreKeyApi.derivePassword).
final oldPassword = wallet.keys.firstWhere((k) => k.type == 'Password');
final passwordPub = await client.storeKeys.derivePassword(
  password: password,
  walletKeyId: oldPassword.id,
);

// 4. Reshare. The same newRemoteKey value goes on BOTH the
//    old-committee RemoteKey AND the new-committee RemoteKey
//    descriptors — the server has internally bound the new
//    session to the wallet's RemoteKey share for the duration of
//    the reshare ceremony.
await client.wallets.reshare(
  walletId: wallet.id,
  old: [
    // Local Plain / StoreKey shares — id is enough, no key needed.
    // We list the StoreKey here even though its private is gone,
    // so libwallet knows about the share we're replacing.
    KeyDescription(id: oldRemoteKey.id,
                   key: newRemoteKey,        // ← NEW id, NOT oldRemoteKey.key
                   type: 'RemoteKey'),
    KeyDescription(id: oldPassword.id,
                   key: passwordPub.publicKey,
                   type: 'Password'),
  ],
  newKeys: [
    KeyDescription(type: 'StoreKey',  key: freshPair.public),
    KeyDescription(type: 'RemoteKey', key: newRemoteKey),       // ← same NEW id
    KeyDescription(type: 'Password',  key: passwordPub.publicKey),
  ],
);

// 5. Wallet.modified is now newer; the wallet's address (Pubkey /
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

A reshare can fail if either `RemoteKey` (server unreachable, or
the SMS code was wrong / expired) or `Password` (user mistyped)
is currently unusable. Surface a specific error per failure mode
— "couldn't reach WalletSign backend, try again on a stable
connection" vs. "password didn't unlock the wallet" — and retry.
Do **not** prompt the user to "restore from another backup";
that's a different remediation that only applies when the wallet
itself is gone, not just one of its shares.

If you see `invalid status for wallet sign session: done`, you
skipped step 2 — the wallet's stored RemoteKey id is the OLD
(done) session and you need to run `RemoteKey:reshare` +
`:validate` to get a fresh one. The error is the server
correctly refusing to re-engage a retired session.

## Device-to-device transfer — QR-driven, no reshare needed

When the user has both phones in hand at the same time (the "I'm
moving to my new iPhone" case), the cleanest UX is to skip the
file-export step entirely and copy the wallet directly between
devices over a transient encrypted channel. libwallet ships this
as a first-party flow:

| Side | Endpoint | What the host does |
|---|---|---|
| Old device | `client.wallets.exportToDevice(walletId)` | Receive an opaque pairing code, paint it as a QR. |
| New device | `client.wallets.importFromDevice(scannedCode)` | Scan the QR, hand the string back; wait for the import to land. |
| Old device | `client.wallets.exportToDeviceConfirm(sid: …, deviceShares: [...])` | After biometric, read the device share private from the OS keystore and approve. |
| Old device | `client.wallets.exportToDeviceCancel(sid)` | Optional — user declines. |

The session is single-use, lasts 5 minutes, and ships the wallet
JSON + the device share private key in one AES-256-GCM-sealed
payload over Spot. The new device's host receives both pieces back
from the `importFromDevice` future and only needs to:

1. Write each `DeviceShareEntry.privateKey` to its platform
   keystore (Keychain on iOS, Keystore on Android, …) before the
   next `unlock(password)` call.
2. Surface the wallet — it has already been written to libwallet's
   local store by the time the future returns (the standard
   `wallet:restored` host event fires).

Recommended UX (old device):

```dart
// 1. Open the session, paint the QR.
final session = await client.wallets.exportToDevice(walletId);
showQrSheet(session.pairingCode, expiresAt: session.expiresAt);

// 2. Listen for the new device's pair request. The handler emits
//    `wallet:transfer:pair_received` carrying { sid, wallet_id,
//    peer_spot_id, peer_fingerprint } — render the peer info in a
//    confirmation prompt so the user can verify they're scanning
//    on their own new phone.
events.on('wallet:transfer:pair_received').listen((evt) async {
  final ok = await showConfirmDialog(
    'Send your wallet to a new device?',
    fingerprint: evt['peer_fingerprint'],
  );
  if (!ok) {
    await client.wallets.exportToDeviceCancel(evt['sid']);
    return;
  }

  // 3. Biometric prompt + keystore read. Biometric gates the
  //    keystore on iOS/Android; libwallet never sees the prompt.
  final shares = await keystore.readAllStoreKeyShares(
    walletKeyIds: [evt['wallet_id_storekey']],
    biometricReason: 'Confirm transfer to your new device',
  );
  await client.wallets.exportToDeviceConfirm(
    sid: evt['sid'],
    deviceShares: shares,
  );
});
```

New device:

```dart
final code = await scanQrCode();
try {
  final result = await client.wallets.importFromDevice(code);
  // Wallet JSON already restored locally. Write the device shares
  // BEFORE the user is offered any signing UI.
  for (final share in result.deviceShares) {
    await keystore.writeDeviceShare(
      walletKeyId: share.walletKeyId,
      value: share.privateKey,
      password: password,
    );
  }
  // Now ready to unlock + sign.
} on PairingDeclinedException {
  showToast("Transfer declined on the other device.");
} on PairingTokenExpiredException {
  showToast("QR code expired. Generate a new one and try again.");
} on PairingPeerUnreachableException {
  showToast("Couldn't reach the other device. Both online?");
}
```

### Why this is safe to ship as the default migration UX

- **Out-of-band pairing token.** The QR carries a fresh 32-byte
  random; the payload is encrypted with a key derived from that
  token via HKDF-SHA-256. An attacker on the Spot transport can't
  decrypt without the QR.
- **Old-device user confirmation.** Even with a stolen QR, the
  payload is only released after the user on the source device
  approves the prompt + passes biometric. A QR snapshot taken
  through someone's shoulder doesn't bypass that.
- **5-minute single-use.** Once the new device's request lands,
  the session burns; a captured QR can't be replayed against a
  later session.
- **Same security model as the manual-export case below**, but
  without a file ever touching disk. No "where did I save the
  backup?" forgetfulness, no third-party storage in the threat
  model.

The auto-rotation path (Reshare on missing device share) stays in
place as the fallback for users who lost their old device — they
can't run a device-to-device flow without it.

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
