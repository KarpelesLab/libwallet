# Signing Solana transactions

`Account:signTransaction` signs a complete serialized Solana transaction, legacy or v0, with any Solana account: MPC, seed phrase or imported key, root or derived. Use it for swaps and SPL token transfers. Your code gets the quote, builds the transaction, gets the user's approval and broadcasts it. libwallet only adds the account's signature, and no secret leaves it.

The call works the same in the browser (`libwallet_request`) and in native builds. Quote and swap handlers such as `Swap:quote`, `Swap:execute` and `Transaction:signAndSend` are native-only, and return `unknown endpoint` in the browser.

A working example is in [`web/examples/`](../web/examples/): [`solana-sign.mjs`](../web/examples/solana-sign.mjs) is the code and [`solana-sign.html`](../web/examples/solana-sign.html) runs it on a page.

## Request

```js
const reply = JSON.parse(await libwallet_request(handle, JSON.stringify({
  path: 'Account:signTransaction',
  verb: 'POST',
  params: {
    Id: accountId,
    Keys: [{ Type: 'Password', Id: walletKeyId, Key: password }],
    Transaction: unsignedTransactionBase64,
  },
})));
if (reply.result === 'error') throw new Error(reply.error);
const { transaction, raw, signature } = reply.data;
```

`Keys` holds the shares that unlock the account: the threshold's worth for an MPC wallet (2 of a 2-of-3), or the single key of a seed phrase or imported key wallet. On wallets with a RemoteKey share, pass the local `Password` shares.

`Transaction` takes the serialized transaction, in base64 or base58, in any of these forms:

| Form | Example |
|---|---|
| Bare string | `"AQAAAA…"` |
| `transaction` | `{ "transaction": "AQAAAA…" }` |
| `serializedTransaction` | `{ "serializedTransaction": "AQAAAA…" }` |
| `raw` | `{ "raw": "AQAAAA…" }` |

In an object, that field must be the only one.

## Response

| Field | Contents |
|---|---|
| `transaction` | The signed transaction, base64 |
| `raw` | The same bytes, base58 |
| `signature` | This account's signature, base58 |

The message bytes are signed and returned unchanged, and libwallet does not update the blockhash or fees. The signature goes in the account's own signer slot and other signers' slots are left as they were, so a transaction with another fee payer can be co-signed. Broadcast it once every required signature is present.

To have libwallet broadcast it, call `Account:signAndSendTransaction` with the same parameters. It returns `signature`, `raw` and `transaction`.

## Refusals

These return an error, with code 400, and sign nothing:

| Input | Error |
|---|---|
| Not a base64 or base58 Solana transaction | `transaction is not a base64 or base58 serialized Solana transaction` |
| The account is not a required signer, or the signature array doesn't match the message header | `transaction does not name this account as a required signer` |
| A serialized transaction next to other fields | `<field> must be the only field of a serialized Solana Transaction` |
| A transfer object with any other field, such as `mint` | `unsupported field "mint": …` |

`Account:signMessage` refuses a payload that parses as a transaction for the account, so a transaction can't be signed as a message. Use `Account:signTransaction` instead.

libwallet checks who signs, not what the transaction does. Show the user what they're approving, and simulate it, before you ask libwallet to sign it.

## Native SOL transfers

For a plain SOL transfer, libwallet can build the transaction itself. Pass an object with exactly these fields:

```json
{ "to": "<base58 address>", "value": "<lamports, as a string>", "recentBlockhash": "<base58>" }
```

The response is `{ raw }`, base58. `Account:signAndSendTransaction` fetches the blockhash itself, so `recentBlockhash` can be left out there.

Any other field is refused, because this form can only move SOL. Before 0.5.7, fields such as `mint` were ignored and `value` was sent as lamports of SOL.
