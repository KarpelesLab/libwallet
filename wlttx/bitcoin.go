package wlttx

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

// walletByAccount fetches the wallet associated with an account.
func walletByAccount(e wltintf.Env, a *wltacct.Account) (*wltwallet.Wallet, error) {
	return wltwallet.WalletById(e, a.Wallet)
}

// bitcoinTxo is one entry in the modchain_lookupTxoBIP32 response.
//
// modchain serializes Bitcoin amounts via outscript.BtcAmount, which
// marshals to a decimal string (e.g. "0.00000001"). The BtcAmount
// type's UnmarshalJSON handles both decimal and integer forms.
//
// Path is the modern form ("m/0/0", "m/1/3"); I is the legacy
// per-chain index. Newer modchain versions emit Path only; older
// ones emit I + branch. childIndex() returns whichever is present.
type bitcoinTxo struct {
	Txo    string              `json:"txo"` // "<txid>:<vout>"
	Height int64               `json:"height"`
	Amt    outscript.BtcAmount `json:"amt"`  // satoshi, decoded from "0.00000001" form
	Path   string              `json:"path"` // full HD path ("m/0/0"); preferred
	I      int                 `json:"i"`    // legacy per-chain index; fallback when Path is empty
	Script string              `json:"script"` // flavor: p2pkh, p2wpkh, etc
	// Spent is null/absent for an unspent output; non-null when
	// modchain knows the spend (its value is the spending tx info).
	// We only ever want unspent entries — selecting a spent one
	// makes sendrawtransaction fail with "bad-txns-inputs-
	// missingorspent" at broadcast time.
	Spent json.RawMessage `json:"spent,omitempty"`
}

// isSpent reports whether this txo entry has been spent. Treats both
// null literals and an empty/absent Spent field as unspent.
func (t bitcoinTxo) isSpent() bool {
	s := strings.TrimSpace(string(t.Spent))
	return s != "" && s != "null"
}

// childIndex returns the BIP32 child index this txo's address was
// derived at. Reads Path's trailing segment when set ("m/0/3" → 3),
// else falls back to the legacy I field.
func (t bitcoinTxo) childIndex() int {
	if t.Path != "" {
		if i := strings.LastIndexByte(t.Path, '/'); i >= 0 && i+1 < len(t.Path) {
			if n, err := strconv.Atoi(t.Path[i+1:]); err == nil {
				return n
			}
		}
	}
	return t.I
}

// chainFromPath returns 0 for m/0/* (receive), 1 for m/1/* (change).
// Defaults to 0 when Path is missing or malformed (the legacy receive-
// only behaviour).
func (t bitcoinTxo) chainFromPath() int {
	if t.Path == "" {
		return 0
	}
	// Expected shape "m/<chain>/<index>"; split on '/' and read index 1.
	parts := strings.Split(t.Path, "/")
	if len(parts) < 2 {
		return 0
	}
	c, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return c
}

// vsize returns the contribution of this input to the transaction's
// vsize, in vbytes. p2wpkh witness inputs are tiny (~68); legacy
// p2pkh inputs are ~148; p2sh-p2wpkh sits in the middle (~91).
// Estimating from the actual input script type means a wallet with
// mixed shapes (a sender used your legacy address) doesn't under-pay.
func (t bitcoinTxo) vsize() int {
	switch t.Script {
	case "p2wpkh", "p2wsh":
		return 68
	case "p2sh:p2wpkh", "p2sh-p2wpkh":
		return 91
	case "p2pkh", "p2pukh":
		return 148
	}
	// Unknown script: assume the most expensive form so the broadcast
	// is over-paid rather than under-paid.
	return 148
}

type bitcoinTxoResp struct {
	Txo     []bitcoinTxo        `json:"txo"`
	Balance outscript.BtcAmount `json:"balance"`
	LastI   int                 `json:"lastI"`
}

// buildBitcoinTx assembles and signs a Bitcoin-family transaction for
// tx.Type == "bitcoin_transfer". On success it sets tx.Raw, tx.Hash, tx.Fee.
func buildBitcoinTx(ctx *SignContext, tx *Transaction, n *wltnet.Network, acct *wltacct.Account, keys []*wltsign.KeyDescription) error {
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return errors.New("invalid amount")
	}
	if tx.To == "" {
		return errors.New("recipient (To) is required")
	}

	xpub, err := acct.Xpub()
	if err != nil {
		return fmt.Errorf("xpub: %w", err)
	}

	// 1. Fetch every spendable UTXO across both the receive (m/0)
	//    and change (m/1) chains in one call. Older code only
	//    scanned m/0 — change UTXOs were unspendable until they
	//    happened to land on a future receive address.
	allUTXOs, err := fetchBitcoinAllUTXOs(n, xpub)
	if err != nil {
		return err
	}
	if len(allUTXOs) == 0 {
		return errors.New("no spendable UTXOs")
	}

	// 2. Parse recipient
	recipientOut, err := outscript.ParseBitcoinBasedAddress(bitcoinNetworkName(n.ChainId), tx.To)
	if err != nil {
		return fmt.Errorf("parse recipient address: %w", err)
	}

	// 3. Coin selection (greedy — simple but effective)
	wantSats := tx.Amount.Value().Int64()
	// Fee estimation: modchain exposes fee via JSON-RPC; fall back to a
	// conservative estimate based on tx size if the RPC call fails.
	feeRateSatPerVB, err := bitcoinFeeRate(n)
	if err != nil {
		feeRateSatPerVB = 10 // conservative fallback
	}

	var selected []bitcoinTxo
	var totalIn int64
	if len(tx.UTXOs) > 0 {
		// Manual selection: caller pinned exact (txid:vout) entries.
		// Verify each is owned and reject the request otherwise so a
		// typo can't accidentally short-pay or include a foreign
		// output we can't sign.
		owned := make(map[string]bitcoinTxo, len(allUTXOs))
		for _, u := range allUTXOs {
			owned[u.Txo] = u
		}
		for _, ref := range tx.UTXOs {
			u, ok := owned[ref]
			if !ok {
				return fmt.Errorf("UTXO %q is not owned by this account", ref)
			}
			selected = append(selected, u)
			totalIn += int64(u.Amt)
		}
	} else {
		selected, totalIn, err = selectUTXOs(allUTXOs, wantSats, feeRateSatPerVB)
		if err != nil {
			return err
		}
	}

	// 4. Derive next change address (m/1/{lastChangeI+1})
	changeUtxos, err := fetchBitcoinUTXOs(n, xpub, "m/1")
	changeIndex := 0
	if err == nil {
		changeIndex = changeUtxos.LastI + 1
	}
	changeAddr, err := acct.ChangeAddress(n.ChainId, changeIndex)
	if err != nil {
		return fmt.Errorf("derive change address: %w", err)
	}
	changeOut, err := outscript.ParseBitcoinBasedAddress(bitcoinNetworkName(n.ChainId), changeAddr)
	if err != nil {
		return fmt.Errorf("parse change address: %w", err)
	}

	// 5. Build the transaction
	btx := &outscript.BtcTx{Version: 2}
	for _, u := range selected {
		txid, vout, err := parseTxoRef(u.Txo)
		if err != nil {
			return err
		}
		var hex32 outscript.Hex32
		copy(hex32[:], txid)
		btx.In = append(btx.In, &outscript.BtcTxInput{
			TXID:     hex32,
			Vout:     vout,
			Sequence: 0xfffffffd, // RBF-enabled
		})
	}

	// Output to recipient
	btx.Out = append(btx.Out, &outscript.BtcTxOutput{
		Amount: outscript.BtcAmount(wantSats),
		Script: recipientOut.Bytes(),
	})

	// Compute size-based fee from the actual selected inputs, then
	// derive change. Per-input vsize is needed when selected mixes
	// segwit and legacy shapes — otherwise a single legacy input
	// makes us under-pay.
	estVSize := estimateMixedTxVSize(selected, 2) // send + change
	fee := int64(estVSize) * feeRateSatPerVB
	change := totalIn - wantSats - fee
	if change < 0 {
		return fmt.Errorf("insufficient funds: have %d sats, need %d + fee %d", totalIn, wantSats, fee)
	}

	// Dust threshold: ~546 sats for p2pkh, skip change below that
	var changeVout uint32
	hasChange := false
	if change > 546 {
		btx.Out = append(btx.Out, &outscript.BtcTxOutput{
			Amount: outscript.BtcAmount(change),
			Script: changeOut.Bytes(),
		})
		changeVout = uint32(len(btx.Out) - 1)
		hasChange = true
	} else {
		// Give dust to miners
		fee += change
		change = 0
	}

	// 6. Build signers for each input
	sighash := uint32(1) // SIGHASH_ALL
	if n.ChainId == "bitcoin-cash" {
		sighash = 0x41 // SIGHASH_ALL | SIGHASH_FORKID
	}

	signers := make([]*outscript.BtcTxSign, len(selected))
	for i, u := range selected {
		// Chain comes from the UTXO's own path (m/0/* receive,
		// m/1/* change) — earlier code hardcoded chain=0 because
		// it only ever fetched m/0; with m/1 in the mix that
		// would derive the wrong key.
		signer, err := newBtcInputSigner(ctx, acct, u.chainFromPath(), u.childIndex(), keys)
		if err != nil {
			return fmt.Errorf("new signer for input %d: %w", i, err)
		}
		scheme := u.Script // p2wpkh, p2pkh, etc
		signers[i] = &outscript.BtcTxSign{
			Key:     signer,
			Scheme:  scheme,
			Amount:  u.Amt,
			SigHash: sighash,
		}
	}

	if err := btx.Sign(signers...); err != nil {
		return fmt.Errorf("tx sign: %w", err)
	}

	// 7. Serialize and store
	rawBytes, err := btx.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal tx: %w", err)
	}
	tx.Raw = rawBytes
	tx.Fee = wltobj.NewAmountRaw(big.NewInt(fee), 8)

	// Capture what we spent + the change we created so SignAndSend
	// can register them with the in-memory UTXO tracker after the
	// broadcast lands. Lets a follow-up send spend the change
	// without waiting for modchain to reindex past this tx.
	tx.btcSpentRefs = make([]string, 0, len(selected))
	for _, u := range selected {
		tx.btcSpentRefs = append(tx.btcSpentRefs, u.Txo)
	}
	if hasChange {
		// Txo is filled in after broadcast (needs the fresh tx
		// hash); the tracker-commit step in transaction.go does
		// that.
		changeScript := bitcoinChangeScript(n.ChainId)
		tx.btcPendingChange = &bitcoinTxo{
			Path:   fmt.Sprintf("m/1/%d", changeIndex),
			Amt:    outscript.BtcAmount(change),
			Script: changeScript,
			I:      changeIndex,
		}
		// Stash vout in the Height field temporarily — we never
		// use Height before the tracker commit fills in the real
		// (zero, since unconfirmed) value, and it saves a parallel
		// scratch field on Transaction.
		tx.btcPendingChange.Height = int64(changeVout)
	}
	return nil
}

// bitcoinChangeScript returns the script type bitcoinAddress emits
// for the change-chain receive address on chainId. Mirrors the
// switch in btc_address.go's bitcoinAddress so the tracker entry's
// Script matches what the tx actually paid into.
func bitcoinChangeScript(chainId string) string {
	switch chainId {
	case "bitcoin", "litecoin", "monacoin":
		return "p2wpkh"
	case "bitcoin-cash", "dogecoin":
		return "p2pkh"
	}
	return "p2wpkh"
}

// SignRawBitcoinTx signs every input in a pre-built bitcoin-family
// transaction that belongs to acct's xpub tree. Returns the signed tx
// bytes.
//
// This is the entry point for mpurse_signRawTransaction and any other flow
// where the dApp constructs the transaction offline and hands us the raw
// bytes. Ownership is resolved by scanning modchain_lookupTxoBIP32 on both
// the receive (m/0) and change (m/1) chains and matching each input's
// (txid:vout) to the result set.
//
// v1 is strict: returns an error if any input is not owned. This covers
// Counterparty / monacoin asset txs (all inputs are the user's) without
// paying the complexity cost of partial-sign multi-party transactions.
func SignRawBitcoinTx(ctx *SignContext, acct *wltacct.Account, n *wltnet.Network, rawTx []byte, keys []*wltsign.KeyDescription) ([]byte, error) {
	btx := &outscript.BtcTx{}
	if err := btx.UnmarshalBinary(rawTx); err != nil {
		return nil, fmt.Errorf("parse tx: %w", err)
	}
	if len(btx.In) == 0 {
		return nil, errors.New("tx has no inputs")
	}

	xpub, err := acct.Xpub()
	if err != nil {
		return nil, fmt.Errorf("xpub: %w", err)
	}

	type ownedEntry struct {
		chain, index int
		amount       outscript.BtcAmount
		scheme       string
	}
	owned := make(map[string]ownedEntry)
	allUTXOs, err := fetchBitcoinAllUTXOs(n, xpub)
	if err != nil {
		return nil, fmt.Errorf("scan utxos: %w", err)
	}
	for _, t := range allUTXOs {
		owned[t.Txo] = ownedEntry{
			chain:  t.chainFromPath(),
			index:  t.childIndex(),
			amount: t.Amt,
			scheme: t.Script,
		}
	}

	sighash := uint32(1)
	if n.ChainId == "bitcoin-cash" {
		sighash = 0x41
	}

	signers := make([]*outscript.BtcTxSign, len(btx.In))
	for i, in := range btx.In {
		// outscript stores BtcTxInput.TXID in displayable (big-
		// endian) byte order — UnmarshalBinary reverses the wire
		// bytes for us (btctx.go line 626). Hex-encode directly
		// to get a key that matches modchain's txo refs (which
		// use the same displayable form). An earlier version of
		// this loop reversed TXID before encoding, which produced
		// the byte-reversed lookup key and made every input
		// resolve to "not owned by this account".
		ref := fmt.Sprintf("%x:%d", in.TXID, in.Vout)
		entry, ok := owned[ref]
		if !ok {
			return nil, fmt.Errorf("input %d (%s) is not owned by this account", i, ref)
		}
		signer, err := newBtcInputSigner(ctx, acct, entry.chain, entry.index, keys)
		if err != nil {
			return nil, fmt.Errorf("new signer for input %d: %w", i, err)
		}
		signers[i] = &outscript.BtcTxSign{
			Key:     signer,
			Scheme:  entry.scheme,
			Amount:  entry.amount,
			SigHash: sighash,
		}
	}

	if err := btx.Sign(signers...); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return btx.MarshalBinary()
}

// broadcastBitcoinTx sends the raw transaction via sendrawtransaction.
// On failure the error message carries the full set of (txid:vout)
// inputs the build path selected and the hex-encoded tx — without
// these, "bad-txns-inputs-missingorspent" reports give us no way
// to figure out which of the candidate UTXOs the node thinks is
// missing, and re-running locally is the only diagnostic path.
func broadcastBitcoinTx(tx *Transaction, n *wltnet.Network) error {
	if len(tx.Raw) == 0 {
		return errors.New("empty raw tx")
	}
	hexRaw := hex.EncodeToString(tx.Raw)
	raw, err := n.DoRPC("sendrawtransaction", hexRaw)
	if err != nil {
		inputs := strings.Join(tx.btcSpentRefs, ",")
		if inputs == "" {
			inputs = "(none recorded)"
		}
		return fmt.Errorf("sendrawtransaction: %w (inputs=%s rawhex=%s)", err, inputs, hexRaw)
	}
	var txid string
	if err := json.Unmarshal(raw, &txid); err != nil {
		return fmt.Errorf("parse sendrawtransaction response: %w", err)
	}
	tx.Hash = txid
	tx.URL = n.TransactionUrl(txid)
	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

// SignContext is the minimal context needed by buildBitcoinTx. Exported for
// wlttx use; we wrap it so the function signature is stable.
type SignContext struct {
	Env wltintf.Env
}

func fetchBitcoinUTXOs(n *wltnet.Network, xpub, path string) (*bitcoinTxoResp, error) {
	raw, err := n.DoRPC("modchain_lookupTxoBIP32", xpub, path, true)
	if err != nil {
		return nil, fmt.Errorf("modchain_lookupTxoBIP32: %w", err)
	}
	var resp bitcoinTxoResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse txo response: %w", err)
	}
	return &resp, nil
}

// fetchBitcoinAllUTXOs returns every spendable UTXO under xpub across
// both the receive (m/0) and change (m/1) chains in a single
// modchain_assets call. Each txo's Path identifies which chain +
// index it came from; consumers use childIndex() and chainFromPath()
// to derive the right signing key.
//
// Replaces the old per-chain modchain_lookupTxoBIP32 loop for the
// hot input-discovery path — the bug that motivated this was that
// the old buildBitcoinTx only fetched m/0, so any UTXO that landed
// on a change address (m/1/i) was invisible to coin selection and
// the user couldn't spend their own change.
func fetchBitcoinAllUTXOs(n *wltnet.Network, xpub string) ([]bitcoinTxo, error) {
	raw, err := n.DoRPC("modchain_assets", xpub)
	if err != nil {
		return nil, fmt.Errorf("modchain_assets: %w", err)
	}
	var resp struct {
		Assets []struct {
			Asset string       `json:"asset"`
			Txo   []bitcoinTxo `json:"txo"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse modchain_assets: %w", err)
	}
	for _, a := range resp.Assets {
		if a.Asset != "NATIVE" {
			continue
		}
		// Drop any entry modchain marked as spent. Belt-and-braces:
		// the "spendable_outputs" asset type already implies
		// unspent-only, but if a partial backend rollout ever
		// surfaces spent entries here we don't want to feed them
		// into the tx (the broadcast would then fail with
		// "bad-txns-inputs-missingorspent" at send time).
		out := make([]bitcoinTxo, 0, len(a.Txo))
		for _, t := range a.Txo {
			if t.isSpent() {
				continue
			}
			out = append(out, t)
		}
		// Layer the in-memory tracker on top so back-to-back
		// sends don't blow up while modchain reindexes — drops
		// entries we just spent locally and injects the change
		// outputs from those sends.
		return utxoTrackerInstance.Apply(xpub, out), nil
	}
	return nil, nil
}

func bitcoinFeeRate(n *wltnet.Network) (int64, error) {
	raw, err := n.DoRPC("estimatesmartfee", 6)
	if err != nil {
		return 0, err
	}
	var resp struct {
		FeeRate float64 `json:"feerate"` // BTC/kB
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, err
	}
	// Convert BTC/kB → sat/vB
	satPerVB := int64(resp.FeeRate * 1e8 / 1000)
	if satPerVB < 1 {
		satPerVB = 1
	}
	return satPerVB, nil
}

// selectUTXOs does naive greedy coin selection. Returns selected UTXOs and
// their total input amount. Does not fee-bump iteratively; caller recomputes
// fee based on selected input count.
//
// vsize math is per-input via bitcoinTxo.vsize() — a wallet holding a
// mix of segwit and legacy inputs gets a fee that actually covers the
// final tx, instead of under-paying because we assumed every input is
// p2wpkh (~68 vb) when one is p2pkh (~148 vb).
func selectUTXOs(all []bitcoinTxo, wantSats, feeRatePerVB int64) ([]bitcoinTxo, int64, error) {
	// Sort largest first (mutate a copy)
	utxos := make([]bitcoinTxo, len(all))
	copy(utxos, all)
	// Insertion sort works fine for typical wallet sizes
	for i := 1; i < len(utxos); i++ {
		for j := i; j > 0 && utxos[j-1].Amt < utxos[j].Amt; j-- {
			utxos[j-1], utxos[j] = utxos[j], utxos[j-1]
		}
	}

	var total int64
	var out []bitcoinTxo
	for _, u := range utxos {
		out = append(out, u)
		total += int64(u.Amt)
		estFee := int64(estimateMixedTxVSize(out, 2)) * feeRatePerVB
		if total >= wantSats+estFee {
			return out, total, nil
		}
	}
	return nil, 0, fmt.Errorf("insufficient funds: have %d sats across %d utxos", total, len(out))
}

// estimateTxVSize returns a rough vsize estimate assuming all inputs
// are p2wpkh. Kept for callers that don't have the actual script
// types yet (e.g. maxsendable's pre-selection estimate); prefer
// estimateMixedTxVSize once you've selected concrete UTXOs.
func estimateTxVSize(ins, outs int) int {
	// p2wpkh segwit: input ~68 vbytes, output ~31 vbytes, overhead ~11
	return 11 + ins*68 + outs*31
}

// estimateMixedTxVSize returns the vsize of a transaction whose
// inputs are the given UTXOs (each contributing per its script type)
// plus `outs` p2wpkh outputs. Use this in the final fee math after
// coin selection so the broadcast pays the correct rate even when
// inputs are a mix of segwit and legacy.
func estimateMixedTxVSize(ins []bitcoinTxo, outs int) int {
	total := 11 + outs*31
	for _, u := range ins {
		total += u.vsize()
	}
	return total
}

func parseTxoRef(ref string) ([]byte, uint32, error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid txo ref %q", ref)
	}
	txid, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, fmt.Errorf("invalid txid hex: %w", err)
	}
	if len(txid) != 32 {
		return nil, 0, fmt.Errorf("txid must be 32 bytes, got %d", len(txid))
	}
	// Return the txid in displayable (big-endian) byte order — that
	// is the convention outscript.BtcTxInput.TXID expects, and
	// outscript reverses to wire (little-endian) order itself when
	// it serializes the tx (BtcTxInput.Bytes line 548 does
	// `slices.Reverse(txid)` before emitting). An earlier version
	// here pre-reversed the bytes, which compounded with outscript's
	// reverse and emitted wire bytes whose displayable form was the
	// reversal of the modchain-reported txid — every bitcoin
	// broadcast hit "bad-txns-inputs-missingorspent" because the
	// node was looking for a UTXO at the wrong txid.
	var vout uint32
	if _, err := fmt.Sscanf(parts[1], "%d", &vout); err != nil {
		return nil, 0, fmt.Errorf("invalid vout: %w", err)
	}
	return txid, vout, nil
}

func bitcoinNetworkName(chainId string) string {
	switch chainId {
	case "bitcoin":
		return "bitcoin"
	case "bitcoin-cash":
		return "bitcoincash"
	case "litecoin":
		return "litecoin"
	case "dogecoin":
		return "dogecoin"
	default:
		return "auto"
	}
}

// ── per-input TSS signer ────────────────────────────────────────────────────

// btcInputSigner implements crypto.Signer for a single BTC input. It derives
// the child public key at m/{chain}/{index} relative to the account's chaincode
// and uses the account's wallet (with cumulative IL) to produce a real
// TSS signature.
type btcInputSigner struct {
	ctx      *SignContext
	acct     *wltacct.Account
	childIL  *big.Int
	childPub *secp256k1.PublicKey
	keys     []*wltsign.KeyDescription
}

func newBtcInputSigner(ctx *SignContext, acct *wltacct.Account, chain, index int, keys []*wltsign.KeyDescription) (*btcInputSigner, error) {
	ccBytes, err := base64.RawURLEncoding.DecodeString(acct.Chaincode)
	if err != nil {
		return nil, fmt.Errorf("chaincode: %w", err)
	}
	childIL, childPub, err := wltacct.DerivePublicKey(acct.PublicKey(), ccBytes, fmt.Sprintf("m/%d/%d", chain, index))
	if err != nil {
		return nil, fmt.Errorf("derive child: %w", err)
	}

	// Combine with account's own IL (if any) since the wallet signs from
	// the wallet root, and the account's IL is the first hop. We need the
	// TOTAL IL from wallet root to this specific child.
	finalIL := new(big.Int)
	if acct.IL != nil {
		finalIL.Add(finalIL, acct.IL)
	}
	finalIL.Add(finalIL, childIL)
	// Modular reduction happens inside TSS signing

	return &btcInputSigner{
		ctx:      ctx,
		acct:     acct,
		childIL:  finalIL,
		childPub: childPub,
		keys:     keys,
	}, nil
}

func (s *btcInputSigner) Public() crypto.PublicKey {
	// Return *secp256k1.PublicKey directly — outscript's
	// pubkey:comp generator (used to embed the spending pubkey in
	// p2pkh / p2sh:p2wpkh / p2wpkh witnesses, btctx.go:143/188/268)
	// requires a type that implements SerializeCompressed().
	// *ecdsa.PublicKey has X/Y coordinates but no SerializeCompressed,
	// so signing any non-p2wpkh input with it fired
	// "pubkey of type *ecdsa.PublicKey does not support pubkey:comp
	// export" — typically hit on the first p2pkh / p2sh-wrapped
	// input the wallet ever spent.
	return s.childPub
}

func (s *btcInputSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Delegate to the wallet with our custom combined IL.
	w, err := walletByAccount(s.ctx.Env, s.acct)
	if err != nil {
		return nil, err
	}
	aopts := &wltsign.Opts{
		Context: s.ctx.Env,
		IL:      s.childIL,
		Keys:    s.keys,
	}
	return w.Sign(rand, digest, aopts)
}
