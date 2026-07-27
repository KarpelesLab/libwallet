# Passkeys in the wallet

Passkeys (WebAuthn/FIDO2) play **two independent roles** here. They compose: one
physical passkey can serve both.

| Role | Where it runs | Server work | Status |
|---|---|---|---|
| **A. Device-share seal** (encrypt a local MPC share) | 100% client (browser) | **none** | ✅ implemented |
| **B. Fleet-auth 2FA** (authorize RemoteKey / co-sign) | client + server | **required** | ⏳ to build (this doc) |

The wallet is MPC: a wallet is a ≥3-share committee. Role A hardens the **device
share**; role B hardens the **RemoteKey (fleet) share**. Together they give a
fully passwordless, phishing-resistant wallet where loss of the passkey is
recoverable through the other committee members (reshare).

---

## Role A — device-share seal (client only, already implemented)

Uses the WebAuthn **PRF extension** (`hmac-secret`). After a biometric/PIN user
verification, the authenticator returns a stable 32-byte secret keyed to
`(credential, salt)` that **never leaves the authenticator**. The web app
(`web/app.js`) uses `hex(prf)` as the committee's share secret via the existing
`Password` `KeyDescription` — so the crypto is unchanged; the "password" is just
the passkey PRF output instead of a typed string:

```
create:  navigator.credentials.create({... extensions:{ prf:{} }})   // enable PRF
         navigator.credentials.get({... extensions:{ prf:{ eval:{ first: salt }}}})  // derive
         → hex(prf.results.first)  →  Keys:[{Type:'Password', Key:hex(prf)}, …]
sign:    re-derive the same PRF (biometric) → same Key → unseal + TSS-sign
```

**The server sees none of this.** No endpoint, no stored secret. The `salt` and
`credentialId` are non-secret and kept client-side (localStorage / session).

Caveats (client): needs a platform authenticator with PRF/`hmac-secret` support
(current Chrome/Safari/Edge; Firefox recent) — fall back to a password otherwise
(already handled). With **synced** passkeys (iCloud Keychain / Google PM) the PRF
output is the same across the user's devices, so the share unlocks everywhere the
passkey syncs — verify this per target platform before relying on it.

---

## Role B — fleet-auth 2FA (what the server needs to build)

Today the RemoteKey (fleet) share is gated by an **email/SMS one-time code**
(`Crypto/WalletSign:new` → user gets a code → `Crypto/WalletSign:verify` →
returns the `crws-…:crwsv-…` resource). Role B **replaces the code step with a
WebAuthn assertion**: the same two-step shape, but the second step is a passkey
signature the server verifies. It authorizes the fleet operations —
`setGeneratedKey` (share upload), `reshare`, and optionally `joinSign` co-sign.

The browser already talks to the backend over **Spot** (`@/p_api`, `{path, verb,
params}` envelope, `client_id` in params — see `docs`/the `rest` package). These
new endpoints should follow the same convention.

### Endpoints

**Registration** (bind a passkey to the AtOnline account / RemoteKey), once per
device:

- `Crypto/WalletSign:passkeyRegisterBegin` → returns server‑built
  `PublicKeyCredentialCreationOptions`:
  `{ challenge, rp:{id,name}, user:{id,name,displayName},
     pubKeyCredParams:[{alg:-7},{alg:-257}], excludeCredentials:[…already
     registered…], authenticatorSelection:{ userVerification:"required",
     residentKey:"preferred" }, timeout, extensions:{ prf:{} } }`.
  Include `extensions.prf` so the **same** credential also works for Role A.
- `Crypto/WalletSign:passkeyRegisterFinish` ← the browser's
  `credential.response` (`clientDataJSON`, `attestationObject`). Server verifies
  the attestation and **stores the credential** (see data model). Returns
  `{credential_id}` / status.

**Authentication** (the 2FA step), each time a fleet op needs authorization:

- `Crypto/WalletSign:passkeyAuthBegin {rk_session?}` → server‑built
  `PublicKeyCredentialRequestOptions`:
  `{ challenge, rpId, allowCredentials:[{type:"public-key", id, transports}],
     userVerification:"required", timeout }`.
- `Crypto/WalletSign:passkeyAuthFinish` ← `assertion.response`
  (`clientDataJSON`, `authenticatorData`, `signature`, `userHandle`). Server
  verifies the assertion and, on success, returns the **same
  `{RemoteKey:"crws-…:crwsv-…"}`** shape `WalletSign:verify` returns today (so
  the client flow is unchanged downstream), or a short‑lived authorization token
  the subsequent `setGeneratedKey`/`reshare` call presents.

> Simplest integration: make `passkeyAuthBegin/Finish` a drop-in alternative to
> `WalletSign:new`/`verify`. The wallet's RemoteKey creation flow then offers
> "verify with passkey" instead of "enter the code".

### Server verification (WebAuthn L2/L3)

Standard checks — a library does these (Go: `github.com/go-webauthn/webauthn`;
also `duo-labs`), but the essentials:

Registration (attestation):
1. `clientDataJSON`: `type=="webauthn.create"`, `challenge` == the one you
   issued (single-use), `origin` in your allowlist.
2. `attestationObject` → `authData`: `rpIdHash == SHA256(rpId)`; flags **UP** set,
   **UV** set (you required it), **AT** set.
3. Extract the credential **public key (COSE)**, **credential id**, **AAGUID**,
   initial **signCount**. Verify the attestation statement per `fmt` (or accept
   `none` if you don't need attestation).
4. Reject if the credential id is already registered. Store it.

Authentication (assertion):
1. Look up the stored credential by `rawId`.
2. `clientDataJSON`: `type=="webauthn.get"`, `challenge` matches the issued one,
   `origin` allowed.
3. `authenticatorData`: `rpIdHash` matches, **UP** set, **UV** set.
4. Signature: verify `COSE_pubkey.verify(authenticatorData ‖ SHA256(clientDataJSON))`.
5. **signCount**: must be > stored count (or both 0 for counters-less
   authenticators); update it. A regression means a cloned authenticator → reject.
6. Bind the result to the account / RemoteKey and return the resource/token.

### RP ID & origin (important for GitHub Pages)

- Web origin: `https://karpeleslab.github.io` (or your custom wallet domain).
- **RP ID** must be a registrable-domain suffix of the origin's host. `github.io`
  is on the Public Suffix List, so the RP ID **must be
  `karpeleslab.github.io`**, not `github.io`. The client already uses
  `rp.id = location.hostname`; the server's `rpId` and origin allowlist must
  match. A custom domain (e.g. `wallet.tibane.app`) is cleaner if you want
  passkeys to survive a hosting change.

### Data model

Per credential (a user/account may register several — multi-device):
`{ account_id, credential_id (bytes, unique), public_key (COSE), sign_count,
   aaguid, transports[], rp_id, created_at, last_used_at }`.
Bind credentials to the AtOnline **account/clientId** so an assertion for one
account can't authorize another.

### Challenge & binding

- Server-issued, **single-use, time-boxed** challenges (nonce store), tied to the
  `client_id`/session; drop after use.
- **Scope the challenge to the operation.** A generic "logged in" assertion
  should not authorize an arbitrary `setGeneratedKey`. Put the operation (and, for
  uploads, a hash of the payload / the target `key`) into the challenge or the
  server-side session the challenge references, so a captured assertion can't be
  replayed against a different action.
- Rate-limit begin/finish; expire sessions.

---

## One passkey, both roles

The **same credential** can do both: it's created with `extensions.prf` enabled
(Role A: client derives the PRF secret to seal the device share) **and** its
public key is registered server-side (Role B: the server verifies assertions to
gate the fleet share). One enrollment, one biometric per action, and the two
factors (device share + fleet share) are cryptographically independent. That is
the passwordless, phishing-resistant end state; losing the passkey is recoverable
via the remaining committee members (reshare), so it is never a single point of
failure.
