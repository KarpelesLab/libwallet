# Swap integration guide

libwallet ships a first-party swap surface — Jupiter Ultra (primary)
and dFlow (fallback) on Solana, 1inch on EVM. This guide covers the
flow, the data each step provides, and the UX patterns wallets like
Phantom / Rabby have taught users to expect. If you're wiring a swap
screen, read this end-to-end before you draw the first widget.

## Mental model — three steps

1. **Quote.** Ask the aggregator "how much X would I get for Y?"
   Free, idempotent, cached server-side for 90 s.
2. **Approval** *(EVM ERC-20 input only)*. Give the aggregator's
   router contract permission to move your tokens. One-time per
   token + spender (unless revoked).
3. **Execute.** Sign the swap tx. The aggregator broadcasts (Jupiter)
   or we broadcast directly (dFlow / 1inch).

Native-currency input (SOL / ETH) skips step 2. Solana always skips
step 2 — SPL transfers don't use an allowance model.

## Minimum viable wiring

```dart
// 1. Quote
final quote = await client.swap.quote(
  tokenIn: SwapTokenRef(address: 'NATIVE', decimals: 9),
  tokenOut: SwapTokenRef(
    address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    symbol: 'USDC',
    decimals: 6,
  ),
  amountIn: '10000000', // 0.01 SOL in lamports
);

// 2. Optional approval (EVM-only; native SOL → skip)
if (quote.requiresApproval) {
  final preview = await client.swap.buildApproval(quoteId: quote.quoteId);
  // … show approval sheet, see "Approval sheet" below …
  await client.transactions.signAndSendSimple(preview.tx, keys: keys);
}

// 3. Execute
final result = await client.swap.execute(
  quoteId: quote.quoteId,
  keys: keys,
);
print('swap landed: ${result.url}');
```

## Step 1 — the quote sheet

Call `client.swap.quote(...)` as soon as the user has entered both
tokens and an amount. Re-quote whenever any input changes; quotes
are cheap (one HTTP hit).

### Fields the app has on `SwapQuote`

| Field | What it is | Show as |
|-------|------------|---------|
| `tokenIn` / `tokenOut` | Address + symbol + decimals | Token rows |
| `amountIn` / `amountOut` | Input / expected output | Big headline numbers |
| `minAmountOut` | Worst-case output after slippage | "You receive at least X" |
| `priceImpact` | Drift vs. mid-market as a fraction | Show `%`, warn > 1% |
| `providerLabel` | "Jupiter Ultra" / "dFlow" / "1inch" | "via Jupiter Ultra" |
| `referralFee` | 50 bps in input-token units | "Platform fee" line |
| `networkFee` | Est. chain gas in native currency | "Network fee" line |
| `slippageBps` | Tolerance currently applied | Slippage selector current value |
| `route[]` | Which AMMs the swap routes through | "via Raydium 60%, Meteora 40%" |
| `expiresAt` | Server-side quote deadline | Countdown timer |

### Recommended sheet layout

```
┌─────────────────────────────────────────┐
│ You pay                                 │
│   0.01 SOL                              │
│                                         │
│ You receive (estimated)                 │
│   2.3451 USDC                           │
│                                         │
│ Minimum received                        │
│   2.3334 USDC  (0.5% slippage)          │
│                                         │
│ Rate: 1 SOL = 234.51 USDC               │
│                                         │
│ Price impact            0.15%           │
│ Platform fee            0.00005 SOL     │
│ Network fee             0.000005 SOL    │
│                                         │
│ Routing: via Jupiter Ultra              │
│   Raydium 60% · Meteora 40%             │
│                                         │
│ ⏱  Quote expires in 87s                 │
│                                         │
│         [ Review and swap ]             │
└─────────────────────────────────────────┘
```

### Quote countdown + auto-refresh

Render a countdown from `quote.expiresAt`. Two options when it hits
zero:

- **Auto-refresh** (recommended when the sheet is visible): call
  `quote()` again with the same inputs and replace the displayed
  quote. Do this silently unless the new `amountOut` differs from
  the previous by more than the slippage tolerance — then flash the
  new number.
- **Stale warning**: disable the "Swap" button and show "Quote
  expired — refresh" until the user taps refresh.

Never let the user tap execute on an expired quote — `execute()`
will return `quote_expired` and they'll tap twice to get the same
result.

### Warning thresholds (opinionated defaults)

- **Price impact ≥ 1%**: yellow banner "High price impact — review
  the rate carefully".
- **Price impact ≥ 5%**: red banner, require the user to tick a
  confirmation checkbox before Execute unlocks.
- **`amountOut < user's expectation`**: if you store the user's "I
  want at least X" input, compare against `minAmountOut` and block
  execution when below.

### Provider / route copy

Use `providerLabel` verbatim. Don't invent your own mapping — if we
add a new provider later, the label updates automatically. Prefix
with "via": `"via ${quote.providerLabel}"`.

For the route, show `venue` names as comma-separated or small chips.
When `share > 0`, render as "Raydium 60% · Meteora 40%". When
`share == 0` (single hop), just show the venue.

## Step 2 — the approval sheet (EVM ERC-20 only)

When `quote.requiresApproval == true`, call
`client.swap.buildApproval(quoteId: …)` to get an `ApprovalPreview`.
Everything needed for the sheet is in the struct; no further
round-trips required.

### Fields on `ApprovalPreview`

| Field | What it is | Show as |
|-------|------------|---------|
| `token` | Token being approved (symbol, decimals) | "Approve USDC" |
| `spender` | Router contract address | Truncated: `0x1111…0582` |
| `spenderLabel` | Human-friendly name | "1inch Aggregation Router" |
| `amount` | Amount being approved | "1.0 USDC" |
| `isUnlimited` | True when ≥ 2²⁵⁵ | Prominent warning if true |
| `currentAllowance` | What's already approved | "Current 0 → New 1.0" |
| `networkFee` | Estimated gas cost | "Network fee ≈ 0.0004 ETH" |
| `tx` | Validated `Transaction` to sign | Pass to signAndSendSimple |

### Why approval is a separate step (and why users should care)

An ERC-20 `approve()` lets a contract move your tokens on your
behalf. If the contract is later compromised — the router gets
hacked, or a malicious upgrade lands — it can drain *up to the
amount you approved* out of your wallet.

This is the #1 vector for wallet drainers. Make the default and the
explanation clear:

- **Default**: libwallet approves *exactly the swap's input amount*.
  If the router is ever exploited, the blast radius is capped at
  what the user was already going to swap right now.
- **User opt-in**: if the user trades often and wants to skip the
  approval step for future swaps, pass `approvalAmount: 'max'` or a
  custom decimal. The `preview.isUnlimited` flag surfaces the
  widened risk.

### Recommended sheet layout — tight default

```
┌─────────────────────────────────────────┐
│ Approve USDC                            │
│                                         │
│ Granting permission to                  │
│   1inch Aggregation Router              │
│   0x1111…0582                           │
│                                         │
│ Amount                                  │
│   1.0 USDC     (exact swap amount)      │
│                                         │
│ Current allowance    0 USDC             │
│ New allowance        1.0 USDC           │
│                                         │
│ Network fee ≈ 0.0004 ETH                │
│                                         │
│ ℹ  This lets 1inch Router V6 move up to │
│    1.0 USDC from your wallet, one time. │
│    Approving more saves gas on future   │
│    swaps but increases the amount a     │
│    compromised router could take.       │
│                                         │
│     [ Approve ]     [ Approve more ▾ ]  │
└─────────────────────────────────────────┘
```

### Recommended sheet layout — unlimited warning

When the user opts into unlimited (`approvalAmount: 'max'`), re-
call `buildApproval` with the new amount and rerender:

```
┌─────────────────────────────────────────┐
│ Approve USDC                            │
│                                         │
│ ⚠  UNLIMITED APPROVAL                   │
│                                         │
│ You are about to let                    │
│   1inch Aggregation Router              │
│ move ANY amount of USDC from your       │
│ wallet, at any future time, until you   │
│ manually revoke.                        │
│                                         │
│ If 1inch's router is ever compromised,  │
│ the attacker can drain your full USDC   │
│ balance without your approval.          │
│                                         │
│ Network fee ≈ 0.0004 ETH                │
│                                         │
│    [ I understand — approve ]           │
│    [ Use tight approval instead ]       │
└─────────────────────────────────────────┘
```

Do not ship this path without the "revoke later" story in place —
add a way for the user to see active allowances and revoke them
(standard ERC-20 approve-to-zero call).

### Signing the approval

```dart
await client.transactions.signAndSendSimple(
  preview.tx,
  keys: keys,
);
```

Wait for the broadcast to return before calling `swap.execute()` —
the swap will revert if the approval hasn't landed yet. Show a
progress indicator: "Approving USDC…" → "Swapping…".

## Step 3 — the execute call + success sheet

```dart
final result = await client.swap.execute(
  quoteId: quote.quoteId,
  keys: keys,
);
```

### Fields on `SwapResult`

| Field | What it is |
|-------|------------|
| `hash` | On-chain tx signature (Solana) / hash (EVM) |
| `url` | Block explorer link |
| `provider` / `providerLabel` | Which aggregator ran it |
| `quote` | Full echoed quote — inputs, expected output, route |

### Recommended success sheet

```
┌─────────────────────────────────────────┐
│ ✓ Swap sent                             │
│                                         │
│ You paid                                │
│   0.01 SOL                              │
│                                         │
│ You received (estimated)                │
│   2.3451 USDC                           │
│                                         │
│ via Jupiter Ultra                       │
│                                         │
│ Transaction                             │
│   5c…9f2e ↗                             │
│                                         │
│         [ View on Solscan ]             │
│         [ Done ]                        │
└─────────────────────────────────────────┘
```

Note "You received (estimated)" — the exact delivered amount is only
known after the tx confirms on-chain and the token transfer logs are
parsed. For most wallets the estimate is close enough; if you need
the actual value, poll `client.transactions.get(id)` once the tx has
a few confirmations and parse the balance delta.

## Error handling

`SwapApi.quote()` / `buildApproval()` / `execute()` all throw
`LibwalletException` with a stable `code` you can pattern-match on.

| Code | When | Recommended UI |
|------|------|----------------|
| `quote_expired` / `quote_not_found` | Quote outside 90 s TTL | Auto-re-quote; if that fails, "Refresh" button |
| `no_liquidity` | No route for pair+size | "Try a smaller amount or different pair" |
| `slippage_exceeded` | Price moved past tolerance | "Market moved — re-quote" + let user increase slippage |
| `provider_unavailable` | 5xx / timeout | "Aggregator is having issues — try again" (Solana auto-falls-back to dFlow on quote) |
| `provider_bad_request` | 4xx from aggregator | Show provider's error verbatim |
| `unsupported_chain` | Current network has no provider | Hide the Swap feature for this network |
| `unsupported_token_pair` | No path exists | "Can't swap these two tokens here" |
| `missing_api_key` | 1inch key not configured | Surface to the developer, not the user — set `wltswap.OneInchAPIKey` |
| `invalid_request` | Client-side bug | Log + show generic "something went wrong" |

## Slippage — how to let the user tune it

Default is 50 bps (0.5%). For stable → stable swaps (USDC → USDT),
that's plenty. For volatile pairs (SOL → small-cap memecoin), users
often need 2–5%.

Expose a preset picker: **0.1% · 0.5% · 1% · Custom**. Re-quote when
the user changes the value (aggregator quotes depend on
`slippageBps`). Warn above 3% — "High slippage; you may lose up to
3% of your output to MEV".

## Handling user-canceled approvals

If the user taps "Cancel" on your approval sheet — don't call
`execute()`. The quote is still in the cache for its remaining TTL;
the user can come back and approve later, or you re-quote if
they've left the sheet open past expiry.

If the user canceled because they don't want the router spending
the token at all, offer a "cancel swap" that just dismisses
everything. Quotes in the cache are ephemeral — no cleanup needed.

## Testing checklist before you ship

- [ ] Native SOL → USDC on Solana (Jupiter Ultra)
- [ ] Native SOL → USDC on Solana with `provider: 'dflow'` forced
- [ ] SPL token → SPL token on Solana (no approval step)
- [ ] Native ETH → USDC on Ethereum (no approval step)
- [ ] ERC-20 → ERC-20 on Ethereum (exercises approval path)
- [ ] ERC-20 → ERC-20 with `approvalAmount: 'max'` (unlimited UI)
- [ ] Quote expires mid-session (verify auto-refresh or stale banner)
- [ ] Approve tx fails (gas too low) — verify the swap isn't fired
- [ ] Execute fails (slippage exceeded) — verify re-quote works
- [ ] No liquidity (obscure token pair) — verify friendly error
- [ ] Aggregator returns 500 — verify `provider_unavailable` copy
- [ ] Post-success: user taps explorer link, tx is visible on-chain
- [ ] 50 bps fee actually lands at the configured fee account
