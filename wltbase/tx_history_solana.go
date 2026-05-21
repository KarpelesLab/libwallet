package wltbase

// Solana side of runTxHistoryBackfill. Pulls signatures for the
// account via getSignaturesForAddress (paginated, newest → oldest),
// fetches each transaction with jsonParsed encoding, and inserts
// one Transaction row per signature describing the dominant
// transfer in that tx. The same dedup + event-broadcast machinery
// the EVM path uses applies — the shared
// `existingTxByHash` / `broadcastTxHistoryUpdated` helpers in
// tx_history.go don't care which chain produced the row.
//
// Why two RPC calls per row instead of Helius's pre-parsed REST:
// Helius's Enhanced Transactions API at
// /v0/addresses/{addr}/transactions requires an API key the
// libwallet binary doesn't carry; the RPC fallback works against
// any Solana RPC including the bare-bones ones the host can
// configure. The cost is one extra RPC round trip per tx, bounded
// by `solanaTxHistoryPageSize` × `txHistoryMaxPages` (≈ 500 txs
// per backfill sweep), which fits comfortably in the
// `txHistoryTimeout` budget.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

const (
	// solanaTxHistoryPageSize is how many signatures we ask for per
	// getSignaturesForAddress call. Solana RPCs cap this at 1000;
	// 100 strikes a balance between RPC-roundtrip cost and time to
	// detect "user has scrolled back into already-known history".
	solanaTxHistoryPageSize = 100
	// solanaSystemProgram is the address of the Solana system
	// program — the source of native SOL transfer instructions
	// when getTransaction is called with jsonParsed encoding.
	solanaSystemProgram = "11111111111111111111111111111111"
	// solanaTokenProgram + solanaToken2022Program own SPL token
	// transfers. Either appears as `program: "spl-token"` /
	// `"spl-token-2022"` in the parsed instruction shape.
	solanaTokenProgram     = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	solanaToken2022Program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
)

// solanaSignatureEntry is the shape getSignaturesForAddress returns
// per signature. Only the fields the backfill needs are decoded —
// extras like `confirmationStatus` are ignored so a future Solana
// RPC schema bump doesn't break parsing.
type solanaSignatureEntry struct {
	Signature string `json:"signature"`
	Slot      uint64 `json:"slot"`
	BlockTime *int64 `json:"blockTime"`
	Err       any    `json:"err"`
}

// solanaParsedTx is the slice of getTransaction's jsonParsed output
// that we read. The full response is much larger; we ignore most of
// it.
type solanaParsedTx struct {
	BlockTime *int64 `json:"blockTime"`
	Slot      uint64 `json:"slot"`
	Meta      *struct {
		Err          any      `json:"err"`
		PreBalances  []uint64 `json:"preBalances"`
		PostBalances []uint64 `json:"postBalances"`
		Fee          uint64   `json:"fee"`
	} `json:"meta"`
	Transaction *struct {
		Message *struct {
			AccountKeys []json.RawMessage `json:"accountKeys"`
			Instructions []*solanaInstruction `json:"instructions"`
		} `json:"message"`
		Signatures []string `json:"signatures"`
	} `json:"transaction"`
}

type solanaInstruction struct {
	Program string          `json:"program,omitempty"`
	Parsed  json.RawMessage `json:"parsed,omitempty"`
}

// solanaParsedSystemTransfer matches the shape jsonParsed emits for
// a system-program Transfer instruction. Field names mirror Solana
// RPC's parsed output verbatim.
type solanaParsedSystemTransfer struct {
	Type string `json:"type"`
	Info struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Lamports    uint64 `json:"lamports"`
	} `json:"info"`
}

// solanaParsedTokenTransfer covers both `transfer` and
// `transferChecked` instructions emitted by the spl-token /
// spl-token-2022 programs.
type solanaParsedTokenTransfer struct {
	Type string `json:"type"`
	Info struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Authority   string `json:"authority"`
		Mint        string `json:"mint"`
		Amount      string `json:"amount,omitempty"`
		TokenAmount *struct {
			Amount   string `json:"amount"`
			Decimals int    `json:"decimals"`
		} `json:"tokenAmount,omitempty"`
	} `json:"info"`
}

// backfillSolanaFromSignatures walks the account's signature history
// via getSignaturesForAddress and turns each signature into a
// Transaction row. Returns the number of newly-inserted rows. Bails
// out as soon as it sees a signature whose hash is already in the
// local DB — the EVM path uses the same "stop on first known"
// invariant so the recurring sweep cost is O(page-size) per
// activation, not O(full-history).
func backfillSolanaFromSignatures(ctx context.Context, e *env, acct *wltacct.Account, n *wltnet.Network) (int, error) {
	owner := acct.GetAddress()
	if owner == "" {
		return 0, fmt.Errorf("backfillSolanaFromSignatures: empty address")
	}

	before := "" // pagination cursor (oldest signature seen so far)
	total := 0

	for page := 0; page < txHistoryMaxPages; page++ {
		opts := map[string]any{"limit": solanaTxHistoryPageSize}
		if before != "" {
			opts["before"] = before
		}
		raw, err := n.DoRPCCtx(ctx, "getSignaturesForAddress", owner, opts)
		if err != nil {
			return total, err
		}
		var sigs []*solanaSignatureEntry
		if err := json.Unmarshal(raw, &sigs); err != nil {
			return total, fmt.Errorf("decode signatures page %d: %w", page, err)
		}
		if len(sigs) == 0 {
			return total, nil
		}

		sawKnown := false
		for _, s := range sigs {
			if s.Signature == "" {
				continue
			}
			if existingTxByHash(e, s.Signature, n) {
				sawKnown = true
				continue
			}
			tx, err := fetchAndBuildSolanaTx(ctx, n, acct, s)
			if err != nil {
				// Skip individual decode failures — one weird tx
				// shouldn't stop the entire backfill. The error
				// burns one RPC round trip; total budget stays
				// bounded by txHistoryTimeout.
				continue
			}
			if tx == nil {
				continue
			}
			if err := psql.Replace(e, tx); err != nil {
				continue
			}
			total++
		}

		if sawKnown {
			return total, nil
		}
		// Advance the cursor to the oldest signature on this page —
		// getSignaturesForAddress returns newest first.
		last := sigs[len(sigs)-1]
		if last.Signature == "" || last.Signature == before {
			return total, nil
		}
		before = last.Signature
	}
	return total, nil
}

// fetchAndBuildSolanaTx pulls the full parsed transaction for one
// signature and condenses it into a single Transaction row. The
// reduction strategy:
//
//   - If any spl-token / spl-token-2022 transfer is present where
//     the account is sender or receiver, prefer that — it's a real
//     asset transfer the user cares about and carries mint info.
//   - Else if any system-program transfer involves the account,
//     use it as a native SOL transfer.
//   - Else use the account's net SOL balance delta as a fallback
//     amount with type "other" so the user still sees the row.
//
// Returns nil if the tx has nothing observable for this account
// (shouldn't happen since the signature came from
// getSignaturesForAddress, but we tolerate it).
func fetchAndBuildSolanaTx(ctx context.Context, n *wltnet.Network, acct *wltacct.Account, sig *solanaSignatureEntry) (*wlttx.Transaction, error) {
	opts := map[string]any{
		"encoding":                       "jsonParsed",
		"maxSupportedTransactionVersion": 0,
	}
	raw, err := n.DoRPCCtx(ctx, "getTransaction", sig.Signature, opts)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var parsed solanaParsedTx
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode tx %s: %w", sig.Signature, err)
	}
	if parsed.Transaction == nil || parsed.Transaction.Message == nil {
		return nil, nil
	}

	owner := acct.GetAddress()
	ts := time.Time{}
	if sig.BlockTime != nil {
		ts = time.Unix(*sig.BlockTime, 0)
	} else if parsed.BlockTime != nil {
		ts = time.Unix(*parsed.BlockTime, 0)
	}

	// Walk instructions, prefer SPL transfers, fall back to system
	// transfers, then fall back to balance delta.
	var (
		bestType   = ""
		bestAsset  = ""
		bestFrom   = ""
		bestTo     = ""
		bestAmount *big.Int
		bestDec    int
	)
	for _, inst := range parsed.Transaction.Message.Instructions {
		if inst == nil || len(inst.Parsed) == 0 {
			continue
		}
		switch inst.Program {
		case "system":
			if bestType == "spl-token" {
				continue // SPL already wins
			}
			var ptx solanaParsedSystemTransfer
			if err := json.Unmarshal(inst.Parsed, &ptx); err != nil {
				continue
			}
			if ptx.Type != "transfer" && ptx.Type != "transferWithSeed" {
				continue
			}
			if ptx.Info.Source != owner && ptx.Info.Destination != owner {
				continue
			}
			bestType = "transfer"
			bestAsset = n.String() + ".NATIVE"
			bestFrom = ptx.Info.Source
			bestTo = ptx.Info.Destination
			bestAmount = new(big.Int).SetUint64(ptx.Info.Lamports)
			bestDec = 9 // lamports → SOL
		case "spl-token", "spl-token-2022":
			var ptx solanaParsedTokenTransfer
			if err := json.Unmarshal(inst.Parsed, &ptx); err != nil {
				continue
			}
			if ptx.Type != "transfer" && ptx.Type != "transferChecked" {
				continue
			}
			// authority is the wallet that signed; for transfers
			// initiated by the wallet, authority == owner. For
			// transfers TO the wallet, the destination's owner is
			// the wallet. The parsed shape gives token-account
			// addresses for source/destination (not wallet
			// addresses), so we match on authority + a separate
			// "destination resolves to this owner" path that
			// jsonParsed doesn't expose without a getAccountInfo
			// follow-up. Conservative for now: trust authority for
			// outgoing, and surface incoming only when the source
			// or destination string contains the owner's pubkey
			// (rare; usually false). A future enhancement could
			// resolve token-account → owner via getAccountInfo for
			// completeness.
			if ptx.Info.Authority != owner &&
				ptx.Info.Source != owner &&
				ptx.Info.Destination != owner {
				continue
			}
			bestType = "spl-token"
			bestAsset = n.String() + "." + ptx.Info.Mint
			bestFrom = ptx.Info.Source
			bestTo = ptx.Info.Destination
			amountStr := ptx.Info.Amount
			dec := 0
			if ptx.Info.TokenAmount != nil {
				amountStr = ptx.Info.TokenAmount.Amount
				dec = ptx.Info.TokenAmount.Decimals
			}
			amt, ok := new(big.Int).SetString(amountStr, 10)
			if !ok {
				continue
			}
			bestAmount = amt
			bestDec = dec
		}
	}

	// Fallback: no recognised transfer for this account — use the
	// account's net SOL balance change as the amount and label the
	// row "other" so the UI still surfaces it. This covers DEX
	// swaps, NFT mints, multi-step program calls, etc.
	if bestType == "" {
		delta, decimals := solanaBalanceDelta(parsed, owner)
		if delta == nil {
			return nil, nil
		}
		bestType = "other"
		bestAsset = n.String() + ".NATIVE"
		bestFrom = owner
		// destination unknown for opaque program calls — leave blank
		bestAmount = delta
		bestDec = decimals
	}

	id, err := xuid.NewRandom("tx")
	if err != nil {
		return nil, err
	}

	return &wlttx.Transaction{
		Id:      id,
		Type:    bestType,
		Asset:   bestAsset,
		From:    bestFrom,
		To:      bestTo,
		Hash:    sig.Signature,
		Network: n.Id,
		Amount:  wltobj.NewAmountRaw(bestAmount, bestDec),
		URL:     n.TransactionUrl(sig.Signature),
		Created: &ts,
	}, nil
}

// solanaBalanceDelta returns this account's net SOL balance change
// across the transaction (postBalance - preBalance for the slot
// matching the owner's address in accountKeys). Used as a fallback
// when no recognised transfer instruction touches the owner — a
// signed-by-owner DEX swap that exits with less SOL still produces
// a meaningful row this way. Returns (nil, 0) if the owner isn't
// in accountKeys or balance info isn't present.
func solanaBalanceDelta(parsed solanaParsedTx, owner string) (*big.Int, int) {
	if parsed.Meta == nil || parsed.Transaction == nil || parsed.Transaction.Message == nil {
		return nil, 0
	}
	keys := parsed.Transaction.Message.AccountKeys
	idx := -1
	for i, raw := range keys {
		// jsonParsed encodes accountKeys as either bare strings or
		// {pubkey, signer, writable} objects — try both.
		var asStr string
		if err := json.Unmarshal(raw, &asStr); err == nil && asStr == owner {
			idx = i
			break
		}
		var asObj struct {
			Pubkey string `json:"pubkey"`
		}
		if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Pubkey == owner {
			idx = i
			break
		}
	}
	if idx < 0 || idx >= len(parsed.Meta.PreBalances) || idx >= len(parsed.Meta.PostBalances) {
		return nil, 0
	}
	pre := new(big.Int).SetUint64(parsed.Meta.PreBalances[idx])
	post := new(big.Int).SetUint64(parsed.Meta.PostBalances[idx])
	delta := new(big.Int).Sub(post, pre)
	if delta.Sign() == 0 {
		// Net-zero (program call with no balance impact on this
		// account). Still worth recording? For now skip — the row
		// would be amount=0 and noisy.
		return nil, 0
	}
	// Use absolute value for the amount field; the From/To
	// distinction conveys direction at a higher level for the UI.
	delta.Abs(delta)
	return delta, 9
}

// _ keeps strings imported when the future Helius-API integration
// adds string-based mint resolution.
var _ = strings.ToLower
