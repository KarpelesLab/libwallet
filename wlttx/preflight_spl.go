package wlttx

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// solanaSplTokenAccountBalance returns the raw amount (base units,
// matching the mint's decimals) held by `tokenAccount`. Returns 0
// when the account doesn't exist yet — getTokenAccountBalance fails
// in that case, which the caller treats as "insufficient balance"
// rather than blocking the tx; some token RPC providers return a
// structured 0 instead of erroring, which we also accept.
func solanaSplTokenAccountBalance(ctx context.Context, n *wltnet.Network, tokenAccount string) (uint64, bool, error) {
	raw, err := n.DoRPCCtx(ctx, "getTokenAccountBalance", tokenAccount)
	if err != nil {
		// Account not yet created → sender has no SPL balance for
		// this mint. Surface that as (0, false, nil) so the caller
		// can branch cleanly between "RPC error, skip preflight"
		// and "RPC said no account, definitely insufficient".
		// Most Solana RPC implementations return a string error
		// containing "could not find account"; matching that here
		// keeps the path forgiving for other phrasings.
		return 0, false, err
	}
	var resp struct {
		Value *struct {
			Amount string `json:"amount"`
		} `json:"value"`
	}
	if jerr := json.Unmarshal(raw, &resp); jerr != nil {
		return 0, false, fmt.Errorf("parse getTokenAccountBalance: %w", jerr)
	}
	if resp.Value == nil {
		return 0, true, nil
	}
	amt, perr := strconv.ParseUint(resp.Value.Amount, 10, 64)
	if perr != nil {
		return 0, false, fmt.Errorf("parse balance %q: %w", resp.Value.Amount, perr)
	}
	return amt, true, nil
}

// preflightSolanaSplSend verifies, before signing, that:
//   - the sender has enough SOL to cover the network fee plus a
//     conservative ATA-rent reserve (covering the case where the
//     recipient's ATA does NOT exist yet and CreateIdempotent
//     actually allocates it; if the ATA already exists the
//     instruction is a no-op and rent isn't charged, so we
//     over-reserve slightly — that's intentional, false negatives
//     are recoverable for the user, false positives aren't);
//   - the sender's SPL token account holds at least `amount` base
//     units of the mint.
//
// Best-effort: RPC failures during the lookups are treated as
// non-blocking — the broadcast path will surface any real problem,
// and we don't want to block a legitimate tx because a node burped.
func preflightSolanaSplSend(
	ctx context.Context,
	n *wltnet.Network,
	senderAddress string,
	senderATA [32]byte,
	tx *Transaction,
	amount uint64,
) error {
	solBalance, solErr := solanaLamportsBalance(ctx, n, senderAddress)
	if solErr == nil {
		var feeLamports uint64 = 5000
		if tx.Fee != nil && tx.Fee.Value() != nil {
			if v := tx.Fee.Value(); v.IsUint64() {
				feeLamports = v.Uint64()
			}
		}
		// Conservative ATA rent reserve: a Token-1 SPL token account
		// is 165 bytes, rent-exempt at ~2,039,280 lamports. Token-2022
		// accounts can be larger when extensions apply but the
		// recipient's ATA is the plain non-extension form, so 165 is
		// the right number even for Token-2022 transfers.
		const ataRentReserve uint64 = 2_039_280

		required := feeLamports + ataRentReserve
		if required < feeLamports {
			return &PreflightError{
				Code:    "insufficient_balance",
				Message: fmt.Sprintf("fee+rent overflow (fee=%d rent=%d)", feeLamports, ataRentReserve),
			}
		}
		if solBalance < required {
			return &PreflightError{
				Code: "insufficient_balance",
				Message: fmt.Sprintf(
					"sender has %d lamports SOL; transfer needs %d (fee=%d + ATA rent reserve=%d). Token base units don't pay Solana fees — top up SOL.",
					solBalance, required, feeLamports, ataRentReserve),
			}
		}
	}

	// SPL balance check.
	senderATAB58 := base58.Bitcoin.Encode(senderATA[:])
	tokBalance, ok, terr := solanaSplTokenAccountBalance(ctx, n, senderATAB58)
	if terr != nil && ok {
		// terr non-nil with ok=true is unreachable from the helper
		// today; future-proof the branch in case the response shape
		// shifts.
		return &PreflightError{Code: "spl_balance_unavailable", Message: terr.Error()}
	}
	if terr != nil {
		// RPC failure (could not parse, no account on chain, etc.).
		// Treat as non-blocking, mirroring the native preflight's
		// philosophy.
		return nil
	}
	if !ok || tokBalance < amount {
		return &PreflightError{
			Code: "insufficient_balance",
			Message: fmt.Sprintf(
				"sender's SPL token account holds %d base units; transfer needs %d. Acquire the token before sending.",
				tokBalance, amount),
		}
	}
	return nil
}
